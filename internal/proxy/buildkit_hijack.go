package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"

	control "github.com/moby/buildkit/api/services/control"
	"google.golang.org/protobuf/proto"

	"github.com/koitococo/docker-hardened-proxy/internal/audit"
	"github.com/koitococo/docker-hardened-proxy/internal/config"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	buildKitControlDiskUsageMethod          = "/moby.buildkit.v1.Control/DiskUsage"
	buildKitControlPruneMethod              = "/moby.buildkit.v1.Control/Prune"
	buildKitControlSolveMethod              = "/moby.buildkit.v1.Control/Solve"
	buildKitControlStatusMethod             = "/moby.buildkit.v1.Control/Status"
	buildKitControlSessionMethod            = "/moby.buildkit.v1.Control/Session"
	buildKitControlListWorkersMethod        = "/moby.buildkit.v1.Control/ListWorkers"
	buildKitControlInfoMethod               = "/moby.buildkit.v1.Control/Info"
	buildKitControlListenBuildHistoryMethod = "/moby.buildkit.v1.Control/ListenBuildHistory"
	buildKitControlUpdateBuildHistoryMethod = "/moby.buildkit.v1.Control/UpdateBuildHistory"
	buildKitControlMaxMessageSize           = 4 << 20
)

type buildKitControlInspection struct {
	MethodPath    string
	GRPCMessage   []byte
	BufferedBytes []byte
}

func auditBuildKitControlRequest(r io.Reader, cfg *config.Config) (*audit.BuildKitAuditResult, error) {
	_, result, err := inspectAndAuditBuildKitControlRequest(r, cfg)
	return result, err
}

func inspectAndAuditBuildKitControlRequest(r io.Reader, cfg *config.Config) (*buildKitControlInspection, *audit.BuildKitAuditResult, error) {
	inspection, err := inspectBuildKitControlStream(r, buildKitControlMaxMessageSize)
	if err != nil {
		return nil, nil, err
	}
	if reason := denyBuildKitControlMethod(inspection.MethodPath, cfg); reason != "" {
		return inspection, &audit.BuildKitAuditResult{Denied: true, Reason: reason}, nil
	}
	if inspection.MethodPath != buildKitControlSolveMethod {
		return inspection, &audit.BuildKitAuditResult{}, nil
	}

	var req control.SolveRequest
	if err := proto.Unmarshal(inspection.GRPCMessage, &req); err != nil {
		return nil, nil, fmt.Errorf("decoding buildkit solve request: %w", err)
	}
	result, err := audit.AuditBuildKitSolve(&req, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("auditing buildkit solve request: %w", err)
	}
	return inspection, result, nil
}

func (h *Handler) hijackBuildKitControl(w http.ResponseWriter, r *http.Request) {
	upstreamConn, err := h.dialBuildKitUpstream()
	if err != nil {
		h.logger.Error("failed to dial upstream for buildkit control", "error", err)
		http.Error(w, "upstream connection failed", http.StatusBadGateway)
		return
	}
	defer upstreamConn.Close()

	if err := r.Write(upstreamConn); err != nil {
		h.logger.Error("failed to write buildkit control request upstream", "error", err)
		http.Error(w, "upstream write failed", http.StatusBadGateway)
		return
	}

	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamReader, r)
	if err != nil {
		h.logger.Error("failed to read buildkit control upgrade response", "error", err)
		http.Error(w, "upstream upgrade failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		h.logger.Error("response writer does not support hijacking")
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		h.logger.Error("failed to hijack buildkit control client connection", "error", err)
		return
	}
	defer clientConn.Close()

	if err := resp.Write(clientConn); err != nil {
		h.logger.Error("failed to forward buildkit control upgrade response", "error", err)
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return
	}

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		io.Copy(clientConn, io.MultiReader(upstreamReader, upstreamConn))
		closeWrite(clientConn)
	}()

	inspection, result, err := inspectAndAuditBuildKitControlRequest(clientConn, h.cfg)
	if err != nil {
		h.logger.Warn("denied",
			"endpoint", "buildkit_control",
			"reason", err.Error(),
		)
		return
	}
	if result.Denied {
		h.logger.Warn("denied",
			"endpoint", "buildkit_control",
			"method", inspection.MethodPath,
			"reason", result.Reason,
		)
		return
	}

	if _, err := upstreamConn.Write(inspection.BufferedBytes); err != nil {
		h.logger.Error("failed to replay buildkit control preface upstream", "error", err)
		return
	}
	io.Copy(upstreamConn, clientConn)
	closeWrite(upstreamConn)
	<-serverDone
}

func (h *Handler) dialBuildKitUpstream() (net.Conn, error) {
	rawConn, err := net.Dial(h.cfg.Upstream.Network, h.cfg.Upstream.Address)
	if err != nil {
		return nil, err
	}

	if h.cfg.Upstream.TLSConfig == nil {
		return rawConn, nil
	}

	cfg := h.cfg.Upstream.TLSConfig.Clone()
	if cfg.ServerName == "" {
		host, _, _ := net.SplitHostPort(h.cfg.Upstream.Address)
		if host != "" {
			cfg.ServerName = host
		}
	}
	tlsConn := tls.Client(rawConn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("upstream TLS handshake failed: %w", err)
	}
	return tlsConn, nil
}

func inspectBuildKitControlStream(r io.Reader, maxMessageSize int) (*buildKitControlInspection, error) {
	var captured bytes.Buffer
	tee := io.TeeReader(r, &captured)

	if err := readHTTP2ClientPreface(tee); err != nil {
		return nil, err
	}

	framer := http2.NewFramer(io.Discard, tee)
	streamID, methodPath, err := readBuildKitControlMethod(framer)
	if err != nil {
		return nil, err
	}

	inspection := &buildKitControlInspection{MethodPath: methodPath}
	if isBuildKitUnaryMethod(methodPath) {
		message, err := readUnaryGRPCMessage(framer, streamID, maxMessageSize)
		if err != nil {
			return nil, err
		}
		inspection.GRPCMessage = message
	}
	inspection.BufferedBytes = bytes.Clone(captured.Bytes())

	return inspection, nil
}

func readHTTP2ClientPreface(r io.Reader) error {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(r, preface); err != nil {
		return fmt.Errorf("reading HTTP/2 client preface: %w", err)
	}
	if string(preface) != http2.ClientPreface {
		return fmt.Errorf("invalid HTTP/2 client preface")
	}
	return nil
}

func readBuildKitControlMethod(framer *http2.Framer) (uint32, string, error) {
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return 0, "", fmt.Errorf("reading HTTP/2 control frame: %w", err)
		}

		switch typed := frame.(type) {
		case *http2.SettingsFrame, *http2.WindowUpdateFrame, *http2.PingFrame:
			continue
		case *http2.HeadersFrame:
			methodPath, err := decodeBuildKitControlMethod(framer, typed)
			if err != nil {
				return 0, "", err
			}
			return typed.Header().StreamID, methodPath, nil
		default:
			return 0, "", fmt.Errorf("expected HTTP/2 HEADERS frame, got %s", frame.Header().Type)
		}
	}
}

func decodeBuildKitControlMethod(framer *http2.Framer, headers *http2.HeadersFrame) (string, error) {
	fragments := append([]byte{}, headers.HeaderBlockFragment()...)
	streamID := headers.Header().StreamID

	for !headers.HeadersEnded() {
		frame, err := framer.ReadFrame()
		if err != nil {
			return "", fmt.Errorf("reading HTTP/2 continuation frame: %w", err)
		}
		continuation, ok := frame.(*http2.ContinuationFrame)
		if !ok {
			return "", fmt.Errorf("expected HTTP/2 CONTINUATION frame, got %s", frame.Header().Type)
		}
		if continuation.Header().StreamID != streamID {
			return "", fmt.Errorf("received CONTINUATION for unexpected stream %d", continuation.Header().StreamID)
		}
		fragments = append(fragments, continuation.HeaderBlockFragment()...)
		if continuation.HeadersEnded() {
			break
		}
	}

	var methodPath string
	decoder := hpack.NewDecoder(4096, func(field hpack.HeaderField) {
		if field.Name == ":path" {
			methodPath = field.Value
		}
	})
	if _, err := decoder.Write(fragments); err != nil {
		return "", fmt.Errorf("decoding HTTP/2 header block: %w", err)
	}
	if methodPath == "" {
		return "", fmt.Errorf("missing :path in HTTP/2 control request")
	}

	return methodPath, nil
}

func readUnaryGRPCMessage(framer *http2.Framer, streamID uint32, maxMessageSize int) ([]byte, error) {
	var message bytes.Buffer
	messageLength := -1

	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return nil, fmt.Errorf("reading unary gRPC message: %w", err)
		}

		switch typed := frame.(type) {
		case *http2.SettingsFrame, *http2.WindowUpdateFrame, *http2.PingFrame:
			continue
		case *http2.DataFrame:
			if typed.Header().StreamID != streamID {
				continue
			}
			if _, err := message.Write(typed.Data()); err != nil {
				return nil, fmt.Errorf("buffering gRPC message: %w", err)
			}
			if messageLength < 0 && message.Len() >= 5 {
				envelope := message.Bytes()
				if envelope[0] != 0 {
					return nil, fmt.Errorf("gRPC message compression is not supported")
				}
				messageLength = int(binary.BigEndian.Uint32(envelope[1:5]))
				if messageLength > maxMessageSize {
					return nil, fmt.Errorf("gRPC message length %d exceeds limit %d", messageLength, maxMessageSize)
				}
			}
			if messageLength >= 0 && message.Len() >= 5+messageLength {
				return bytes.Clone(message.Bytes()[5 : 5+messageLength]), nil
			}
			if typed.StreamEnded() {
				return nil, fmt.Errorf("truncated gRPC message")
			}
		default:
			continue
		}
	}
}

func denyBuildKitControlMethod(methodPath string, cfg *config.Config) string {
	switch methodPath {
	case buildKitControlSolveMethod, buildKitControlStatusMethod, buildKitControlListWorkersMethod, buildKitControlInfoMethod:
		return ""
	case buildKitControlDiskUsageMethod:
		if cfg.Audit.BuildKit.AllowDiskUsage {
			return ""
		}
	case buildKitControlPruneMethod:
		if cfg.Audit.BuildKit.AllowPrune {
			return ""
		}
	case buildKitControlListenBuildHistoryMethod, buildKitControlUpdateBuildHistoryMethod:
		if cfg.Audit.BuildKit.AllowHistory {
			return ""
		}
	case buildKitControlSessionMethod:
		return fmt.Sprintf("buildkit control method %q is denied by policy", methodPath)
	default:
		return fmt.Sprintf("unknown buildkit control method %q", methodPath)
	}

	return fmt.Sprintf("buildkit control method %q is denied by policy", methodPath)
}

func isBuildKitUnaryMethod(methodPath string) bool {
	switch methodPath {
	case buildKitControlDiskUsageMethod,
		buildKitControlSolveMethod,
		buildKitControlListWorkersMethod,
		buildKitControlInfoMethod,
		buildKitControlUpdateBuildHistoryMethod:
		return true
	default:
		return false
	}
}
