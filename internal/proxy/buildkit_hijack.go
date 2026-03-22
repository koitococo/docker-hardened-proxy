package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	control "github.com/moby/buildkit/api/services/control"
	gateway "github.com/moby/buildkit/frontend/gateway/pb"
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
	buildKitControlTraceExportMethod        = "/opentelemetry.proto.collector.trace.v1.TraceService/Export"
	buildKitControlListenBuildHistoryMethod = "/moby.buildkit.v1.Control/ListenBuildHistory"
	buildKitControlUpdateBuildHistoryMethod = "/moby.buildkit.v1.Control/UpdateBuildHistory"
	buildKitControlMaxMessageSize           = 4 << 20

	// LLBBridge (frontend) service methods
	buildKitLLBBridgePingMethod               = "/moby.buildkit.v1.frontend.LLBBridge/Ping"
	buildKitLLBBridgeResolveImageConfigMethod = "/moby.buildkit.v1.frontend.LLBBridge/ResolveImageConfig"
	buildKitLLBBridgeResolveSourceMetaMethod  = "/moby.buildkit.v1.frontend.LLBBridge/ResolveSourceMeta"
	buildKitLLBBridgeSolveMethod              = "/moby.buildkit.v1.frontend.LLBBridge/Solve"
	buildKitLLBBridgeReadFileMethod           = "/moby.buildkit.v1.frontend.LLBBridge/ReadFile"
	buildKitLLBBridgeReadDirMethod            = "/moby.buildkit.v1.frontend.LLBBridge/ReadDir"
	buildKitLLBBridgeStatFileMethod           = "/moby.buildkit.v1.frontend.LLBBridge/StatFile"
	buildKitLLBBridgeEvaluateMethod           = "/moby.buildkit.v1.frontend.LLBBridge/Evaluate"
	buildKitLLBBridgeReturnMethod             = "/moby.buildkit.v1.frontend.LLBBridge/Return"
	buildKitLLBBridgeInputsMethod             = "/moby.buildkit.v1.frontend.LLBBridge/Inputs"
	buildKitLLBBridgeNewContainerMethod       = "/moby.buildkit.v1.frontend.LLBBridge/NewContainer"
	buildKitLLBBridgeReleaseContainerMethod   = "/moby.buildkit.v1.frontend.LLBBridge/ReleaseContainer"
	buildKitLLBBridgeExecProcessMethod        = "/moby.buildkit.v1.frontend.LLBBridge/ExecProcess"
	buildKitLLBBridgeReadFileContainerMethod  = "/moby.buildkit.v1.frontend.LLBBridge/ReadFileContainer"
	buildKitLLBBridgeReadDirContainerMethod   = "/moby.buildkit.v1.frontend.LLBBridge/ReadDirContainer"
	buildKitLLBBridgeStatFileContainerMethod  = "/moby.buildkit.v1.frontend.LLBBridge/StatFileContainer"
	buildKitLLBBridgeWarnMethod               = "/moby.buildkit.v1.frontend.LLBBridge/Warn"
)

type buildKitControlInspection struct {
	MethodPath    string
	GRPCMessage   []byte
	BufferedBytes []byte
}

type buildKitControlStreamState struct {
	MethodPath       string
	Allowed          bool
	PendingFrames    []buildKitBufferedFrame
	PendingGRPCBytes int
	GRPCData         bytes.Buffer
	MessageLength    int
}

type buildKitBufferedFrame struct {
	raw       []byte
	grpcBytes int
}

type frameCaptureReader struct {
	r   io.Reader
	buf bytes.Buffer
}

type buildKitHeaderDecoder struct {
	methodPath string
	decoder    *hpack.Decoder
}

func newBuildKitHeaderDecoder() *buildKitHeaderDecoder {
	result := &buildKitHeaderDecoder{}
	result.decoder = hpack.NewDecoder(4096, func(field hpack.HeaderField) {
		if field.Name == ":path" {
			result.methodPath = field.Value
		}
	})
	return result
}

func (d *buildKitHeaderDecoder) DecodePath(fragments []byte) (string, error) {
	d.methodPath = ""
	if _, err := d.decoder.Write(fragments); err != nil {
		return "", err
	}
	return d.methodPath, nil
}

func (r *frameCaptureReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		if _, writeErr := r.buf.Write(p[:n]); writeErr != nil {
			return n, writeErr
		}
	}
	return n, err
}

func (r *frameCaptureReader) Take() []byte {
	data := bytes.Clone(r.buf.Bytes())
	r.buf.Reset()
	return data
}

func auditBuildKitControlRequest(r io.Reader, cfg *config.Config) (*audit.BuildKitAuditResult, error) {
	_, result, err := inspectAndAuditBuildKitControlRequest(r, cfg)
	return result, err
}

func proxyBuildKitControlFrames(client io.Reader, upstream io.Writer, cfg *config.Config) error {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(client, preface); err != nil {
		return fmt.Errorf("reading HTTP/2 client preface: %w", err)
	}
	if string(preface) != http2.ClientPreface {
		return fmt.Errorf("invalid HTTP/2 client preface")
	}
	if _, err := upstream.Write(preface); err != nil {
		return fmt.Errorf("forwarding HTTP/2 client preface: %w", err)
	}

	capture := &frameCaptureReader{r: client}
	framer := http2.NewFramer(io.Discard, capture)
	headerDecoder := newBuildKitHeaderDecoder()
	streams := make(map[uint32]*buildKitControlStreamState)

	for {
		frame, err := framer.ReadFrame()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading buildkit control frame: %w", err)
		}
		rawFrame := capture.Take()

		switch typed := frame.(type) {
		case *http2.SettingsFrame, *http2.PingFrame:
			if err := writeRawBuildKitFrame(upstream, rawFrame); err != nil {
				return err
			}
		case *http2.WindowUpdateFrame, *http2.PriorityFrame:
			if err := forwardBuildKitStreamFrame(upstream, streams, frame.Header().StreamID, rawFrame); err != nil {
				return err
			}
		case *http2.RSTStreamFrame:
			streamID := typed.Header().StreamID
			state, ok := streams[streamID]
			if ok && !state.Allowed {
				delete(streams, streamID)
				continue
			}
			if err := writeRawBuildKitFrame(upstream, rawFrame); err != nil {
				return err
			}
			delete(streams, streamID)
		case *http2.HeadersFrame:
			path, completeRaw, err := readBuildKitControlHeaders(framer, capture, typed, rawFrame, headerDecoder)
			if err != nil {
				return err
			}
			if err := processBuildKitHeadersFrame(upstream, streams, typed, path, completeRaw, cfg); err != nil {
				return err
			}
		case *http2.DataFrame:
			if err := processBuildKitDataFrame(upstream, streams, typed, rawFrame, cfg); err != nil {
				return err
			}
		default:
			if err := forwardBuildKitStreamFrame(upstream, streams, frame.Header().StreamID, rawFrame); err != nil {
				return err
			}
		}
	}
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

	err = proxyBuildKitControlFrames(clientConn, upstreamConn, h.cfg)
	if err != nil {
		h.logger.Warn("denied",
			"endpoint", "buildkit_control",
			"reason", err.Error(),
		)
		return
	}
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
	fragments, err := readBuildKitHeaderFragments(framer, headers)
	if err != nil {
		return "", fmt.Errorf("reading HTTP/2 header fragments: %w", err)
	}
	path, err := decodeBuildKitHeaderPath(fragments)
	if err != nil {
		return "", fmt.Errorf("decoding HTTP/2 header block: %w", err)
	}
	if path == "" {
		return "", fmt.Errorf("missing :path in HTTP/2 control request")
	}

	return path, nil
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
	// Control service methods
	switch methodPath {
	case buildKitControlSolveMethod, buildKitControlStatusMethod, buildKitControlListWorkersMethod, buildKitControlInfoMethod, buildKitControlTraceExportMethod:
		return ""
	case buildKitControlDiskUsageMethod:
		if cfg.Audit.BuildKit.AllowDiskUsage {
			return ""
		}
		return fmt.Sprintf("buildkit control method %q is denied by policy", methodPath)
	case buildKitControlPruneMethod:
		if cfg.Audit.BuildKit.AllowPrune {
			return ""
		}
		return fmt.Sprintf("buildkit control method %q is denied by policy", methodPath)
	case buildKitControlListenBuildHistoryMethod, buildKitControlUpdateBuildHistoryMethod:
		if cfg.Audit.BuildKit.AllowHistory {
			return ""
		}
		return fmt.Sprintf("buildkit control method %q is denied by policy", methodPath)
	case buildKitControlSessionMethod:
		return fmt.Sprintf("buildkit control method %q is denied by policy", methodPath)
	}

	// LLBBridge (frontend) service methods - safe read-only operations
	switch methodPath {
	case buildKitLLBBridgePingMethod,
		buildKitLLBBridgeResolveImageConfigMethod,
		buildKitLLBBridgeResolveSourceMetaMethod,
		buildKitLLBBridgeReadFileMethod,
		buildKitLLBBridgeReadDirMethod,
		buildKitLLBBridgeStatFileMethod,
		buildKitLLBBridgeEvaluateMethod,
		buildKitLLBBridgeInputsMethod,
		buildKitLLBBridgeReadFileContainerMethod,
		buildKitLLBBridgeReadDirContainerMethod,
		buildKitLLBBridgeStatFileContainerMethod,
		buildKitLLBBridgeWarnMethod,
		buildKitLLBBridgeReturnMethod:
		// Return is used by frontend to return build results - safe to allow
		return ""
	case buildKitLLBBridgeSolveMethod:
		// LLBBridge.Solve also needs auditing like Control.Solve
		// For now, allow it but it will be audited if unary
		return ""
	case buildKitLLBBridgeNewContainerMethod,
		buildKitLLBBridgeReleaseContainerMethod,
		buildKitLLBBridgeExecProcessMethod:
		// These involve container lifecycle or exec - deny by default
		return fmt.Sprintf("buildkit frontend method %q is denied by policy", methodPath)
	}

	// Unknown method
	return fmt.Sprintf("unknown buildkit control method %q", methodPath)
}

func isBuildKitUnaryMethod(methodPath string) bool {
	switch methodPath {
	// Control service unary methods
	case buildKitControlDiskUsageMethod,
		buildKitControlSolveMethod,
		buildKitControlListWorkersMethod,
		buildKitControlInfoMethod,
		buildKitControlUpdateBuildHistoryMethod:
		return true
	// LLBBridge service unary methods
	case buildKitLLBBridgePingMethod,
		buildKitLLBBridgeResolveImageConfigMethod,
		buildKitLLBBridgeResolveSourceMetaMethod,
		buildKitLLBBridgeSolveMethod,
		buildKitLLBBridgeReadFileMethod,
		buildKitLLBBridgeReadDirMethod,
		buildKitLLBBridgeStatFileMethod,
		buildKitLLBBridgeEvaluateMethod,
		buildKitLLBBridgeReturnMethod,
		buildKitLLBBridgeInputsMethod,
		buildKitLLBBridgeNewContainerMethod,
		buildKitLLBBridgeReleaseContainerMethod,
		buildKitLLBBridgeReadFileContainerMethod,
		buildKitLLBBridgeReadDirContainerMethod,
		buildKitLLBBridgeStatFileContainerMethod,
		buildKitLLBBridgeWarnMethod:
		return true
	default:
		return false
	}
}

func isBuildKitSolveMethod(methodPath string) bool {
	return methodPath == buildKitControlSolveMethod || methodPath == buildKitLLBBridgeSolveMethod
}

func processBuildKitHeadersFrame(upstream io.Writer, streams map[uint32]*buildKitControlStreamState, headers *http2.HeadersFrame, path string, rawFrame []byte, cfg *config.Config) error {
	streamID := headers.Header().StreamID
	state, ok := streams[streamID]
	if path == "" {
		if !ok {
			return fmt.Errorf("missing :path in HTTP/2 control request")
		}
		if state.Allowed {
			if err := writeRawBuildKitFrame(upstream, rawFrame); err != nil {
				return err
			}
		} else {
			bufferBuildKitFrame(state, rawFrame, 0)
		}
		if headers.StreamEnded() {
			delete(streams, streamID)
		}
		return nil
	}
	if ok {
		return fmt.Errorf("received duplicate initial headers for stream %d", streamID)
	}

	state = &buildKitControlStreamState{MethodPath: path, MessageLength: -1}
	streams[streamID] = state
	if reason := denyBuildKitControlMethod(path, cfg); reason != "" {
		return errors.New(reason)
	}
	if err := writeRawBuildKitFrame(upstream, rawFrame); err != nil {
		return err
	}
	if !isBuildKitSolveMethod(path) {
		state.Allowed = true
		if headers.StreamEnded() {
			delete(streams, streamID)
		}
		return nil
	}
	if headers.StreamEnded() {
		return fmt.Errorf("truncated gRPC message")
	}
	return nil
}

func processBuildKitDataFrame(upstream io.Writer, streams map[uint32]*buildKitControlStreamState, frame *http2.DataFrame, rawFrame []byte, cfg *config.Config) error {
	streamID := frame.Header().StreamID
	state, ok := streams[streamID]
	if !ok {
		return fmt.Errorf("received DATA for unknown stream %d", streamID)
	}
	if state.Allowed {
		if err := writeRawBuildKitFrame(upstream, rawFrame); err != nil {
			return err
		}
		if frame.StreamEnded() {
			delete(streams, streamID)
		}
		return nil
	}

	bufferBuildKitFrame(state, rawFrame, len(frame.Data()))
	state.GRPCData.Write(frame.Data())
	if state.MessageLength < 0 && state.GRPCData.Len() >= 5 {
		envelope := state.GRPCData.Bytes()
		if envelope[0] != 0 {
			return fmt.Errorf("gRPC message compression is not supported")
		}
		state.MessageLength = int(binary.BigEndian.Uint32(envelope[1:5]))
		if state.MessageLength > buildKitControlMaxMessageSize {
			return fmt.Errorf("gRPC message length %d exceeds limit %d", state.MessageLength, buildKitControlMaxMessageSize)
		}
	}
	if err := flushBuildKitSolvePrefix(upstream, state); err != nil {
		return err
	}
	if state.MessageLength >= 0 && state.GRPCData.Len() >= 5+state.MessageLength {
		if state.GRPCData.Len() > 5+state.MessageLength {
			return fmt.Errorf("unexpected extra gRPC payload in unary request")
		}
		payload := bytes.Clone(state.GRPCData.Bytes()[5 : 5+state.MessageLength])
		result, err := auditBuildKitControlPayload(state.MethodPath, payload, cfg)
		if err != nil {
			return err
		}
		if result.Denied {
			return errors.New(result.Reason)
		}
		state.Allowed = true
		if err := flushAllBuildKitFrames(upstream, state); err != nil {
			return err
		}
		if frame.StreamEnded() {
			delete(streams, streamID)
		}
		return nil
	}
	if frame.StreamEnded() {
		return fmt.Errorf("truncated gRPC message")
	}
	return nil
}

func forwardBuildKitStreamFrame(upstream io.Writer, streams map[uint32]*buildKitControlStreamState, streamID uint32, rawFrame []byte) error {
	if streamID == 0 {
		return writeRawBuildKitFrame(upstream, rawFrame)
	}
	state, ok := streams[streamID]
	if !ok || state.Allowed {
		return writeRawBuildKitFrame(upstream, rawFrame)
	}
	bufferBuildKitFrame(state, rawFrame, 0)
	return nil
}

// bufferBuildKitFrame stores a raw frame that already has exclusive ownership.
// Callers must only pass frame bytes obtained from frameCaptureReader.Take or an
// equivalent immutable copy, because buffered frames are retained for later
// forwarding without taking an additional defensive copy here.
func bufferBuildKitFrame(state *buildKitControlStreamState, rawFrame []byte, grpcBytes int) {
	state.PendingFrames = append(state.PendingFrames, buildKitBufferedFrame{
		raw:       rawFrame,
		grpcBytes: grpcBytes,
	})
	state.PendingGRPCBytes += grpcBytes
}

func flushBuildKitSolvePrefix(upstream io.Writer, state *buildKitControlStreamState) error {
	if state.MessageLength < 0 {
		return nil
	}
	fullMessageBytes := 5 + state.MessageLength
	for len(state.PendingFrames) > 0 {
		frame := state.PendingFrames[0]
		forwardedGRPCBytes := state.GRPCData.Len() - state.PendingGRPCBytes
		if frame.grpcBytes > 0 && forwardedGRPCBytes+frame.grpcBytes >= fullMessageBytes {
			break
		}
		if err := writeRawBuildKitFrame(upstream, frame.raw); err != nil {
			return err
		}
		state.PendingGRPCBytes -= frame.grpcBytes
		state.PendingFrames = state.PendingFrames[1:]
	}
	return nil
}

func flushAllBuildKitFrames(upstream io.Writer, state *buildKitControlStreamState) error {
	for len(state.PendingFrames) > 0 {
		frame := state.PendingFrames[0]
		if err := writeRawBuildKitFrame(upstream, frame.raw); err != nil {
			return err
		}
		state.PendingGRPCBytes -= frame.grpcBytes
		state.PendingFrames = state.PendingFrames[1:]
	}
	return nil
}

func writeRawBuildKitFrame(upstream io.Writer, raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	if _, err := upstream.Write(raw); err != nil {
		return fmt.Errorf("forwarding buildkit control frame: %w", err)
	}
	return nil
}

func readBuildKitControlHeaders(framer *http2.Framer, capture *frameCaptureReader, headers *http2.HeadersFrame, initialRaw []byte, decoder *buildKitHeaderDecoder) (string, []byte, error) {
	fragments := append([]byte{}, headers.HeaderBlockFragment()...)
	completeRaw := append([]byte{}, initialRaw...)
	streamID := headers.Header().StreamID

	for !headers.HeadersEnded() {
		frame, err := framer.ReadFrame()
		if err != nil {
			return "", nil, fmt.Errorf("reading HTTP/2 continuation frame: %w", err)
		}
		continuation, ok := frame.(*http2.ContinuationFrame)
		if !ok {
			return "", nil, fmt.Errorf("expected HTTP/2 CONTINUATION frame, got %s", frame.Header().Type)
		}
		if continuation.Header().StreamID != streamID {
			return "", nil, fmt.Errorf("received CONTINUATION for unexpected stream %d", continuation.Header().StreamID)
		}
		fragments = append(fragments, continuation.HeaderBlockFragment()...)
		completeRaw = append(completeRaw, capture.Take()...)
		if continuation.HeadersEnded() {
			break
		}
	}

	path, err := decoder.DecodePath(fragments)
	if err != nil {
		return "", nil, fmt.Errorf("decoding HTTP/2 header block: %w", err)
	}
	return path, completeRaw, nil
}

func readBuildKitHeaderFragments(framer *http2.Framer, headers *http2.HeadersFrame) ([]byte, error) {
	fragments := append([]byte{}, headers.HeaderBlockFragment()...)
	streamID := headers.Header().StreamID
	for !headers.HeadersEnded() {
		frame, err := framer.ReadFrame()
		if err != nil {
			return nil, fmt.Errorf("reading HTTP/2 continuation frame: %w", err)
		}
		continuation, ok := frame.(*http2.ContinuationFrame)
		if !ok {
			return nil, fmt.Errorf("expected HTTP/2 CONTINUATION frame, got %s", frame.Header().Type)
		}
		if continuation.Header().StreamID != streamID {
			return nil, fmt.Errorf("received CONTINUATION for unexpected stream %d", continuation.Header().StreamID)
		}
		fragments = append(fragments, continuation.HeaderBlockFragment()...)
		if continuation.HeadersEnded() {
			break
		}
	}
	return fragments, nil
}

func decodeBuildKitHeaderPath(fragments []byte) (string, error) {
	var methodPath string
	decoder := hpack.NewDecoder(4096, func(field hpack.HeaderField) {
		if field.Name == ":path" {
			methodPath = field.Value
		}
	})
	if _, err := decoder.Write(fragments); err != nil {
		return "", err
	}
	return methodPath, nil
}

func auditBuildKitControlPayload(methodPath string, payload []byte, cfg *config.Config) (*audit.BuildKitAuditResult, error) {
	switch methodPath {
	case buildKitControlSolveMethod:
		var req control.SolveRequest
		if err := proto.Unmarshal(payload, &req); err != nil {
			return nil, fmt.Errorf("decoding buildkit control solve request: %w", err)
		}
		result, err := audit.AuditBuildKitSolve(&req, cfg)
		if err != nil {
			return nil, fmt.Errorf("auditing buildkit control solve request: %w", err)
		}
		return result, nil
	case buildKitLLBBridgeSolveMethod:
		var req gateway.SolveRequest
		if err := proto.Unmarshal(payload, &req); err != nil {
			return nil, fmt.Errorf("decoding buildkit llbbridge solve request: %w", err)
		}
		// Convert LLBBridge SolveRequest to control SolveRequest for auditing
		controlReq := convertLLBBridgeToControlSolveRequest(&req)
		result, err := audit.AuditBuildKitSolve(controlReq, cfg)
		if err != nil {
			return nil, fmt.Errorf("auditing buildkit llbbridge solve request: %w", err)
		}
		return result, nil
	default:
		return &audit.BuildKitAuditResult{}, nil
	}
}

// convertLLBBridgeToControlSolveRequest converts a gateway.SolveRequest to control.SolveRequest
// for auditing purposes. This maps the common fields used for security checks.
func convertLLBBridgeToControlSolveRequest(req *gateway.SolveRequest) *control.SolveRequest {
	controlReq := &control.SolveRequest{
		Definition: req.Definition,
		Frontend:   req.Frontend,
	}
	// Copy FrontendAttrs if present
	if len(req.FrontendOpt) > 0 {
		controlReq.FrontendAttrs = req.FrontendOpt
	}
	// Note: LLBBridge.Solve doesn't have Entitlements field directly
	// It's typically handled through FrontendOpt
	return controlReq
}
