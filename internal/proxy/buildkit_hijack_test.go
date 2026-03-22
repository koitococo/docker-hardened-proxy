package proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	control "github.com/moby/buildkit/api/services/control"
	pb "github.com/moby/buildkit/solver/pb"
	"google.golang.org/protobuf/proto"

	"github.com/koitococo/docker-hardened-proxy/internal/config"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestBuildKitControlInspectorRecoversMethodPath(t *testing.T) {
	raw := buildBuildKitControlHeadersOnly(t, buildKitControlStatusMethod)

	inspection, err := inspectBuildKitControlStream(bytes.NewReader(raw), 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inspection.MethodPath != buildKitControlStatusMethod {
		t.Fatalf("MethodPath = %q, want %q", inspection.MethodPath, buildKitControlStatusMethod)
	}
	if inspection.GRPCMessage != nil {
		t.Fatalf("GRPCMessage = %v, want nil", inspection.GRPCMessage)
	}
}

func TestBuildKitControlMethodPolicy(t *testing.T) {
	tests := []struct {
		name       string
		methodPath string
		configure  func(*config.Config)
		wantDenied bool
		wantReason string
	}{
		{
			name:       "allow solve by default",
			methodPath: buildKitControlSolveMethod,
		},
		{
			name:       "deny prune by default",
			methodPath: buildKitControlPruneMethod,
			wantDenied: true,
			wantReason: "buildkit control method \"/moby.buildkit.v1.Control/Prune\" is denied by policy",
		},
		{
			name:       "allow disk usage when enabled",
			methodPath: buildKitControlDiskUsageMethod,
			configure: func(cfg *config.Config) {
				cfg.Audit.BuildKit.AllowDiskUsage = true
			},
		},
		{
			name:       "deny unknown control method",
			methodPath: "/moby.buildkit.v1.Control/Unknown",
			wantDenied: true,
			wantReason: "unknown buildkit control method \"/moby.buildkit.v1.Control/Unknown\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testCfg()
			if tt.configure != nil {
				tt.configure(cfg)
			}
			reason := denyBuildKitControlMethod(tt.methodPath, cfg)
			if denied := reason != ""; denied != tt.wantDenied {
				t.Fatalf("denied = %v, want %v (reason=%q)", denied, tt.wantDenied, reason)
			}
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestBuildKitControlInspectorParsesUnaryGRPCMessage(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef, 0x01}
	raw := buildBuildKitControlUnaryRequest(t, buildKitControlSolveMethod, payload, 0, uint32(len(payload)), 4)

	inspection, err := inspectBuildKitControlStream(bytes.NewReader(raw), 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inspection.MethodPath != buildKitControlSolveMethod {
		t.Fatalf("MethodPath = %q, want %q", inspection.MethodPath, buildKitControlSolveMethod)
	}
	if !bytes.Equal(inspection.GRPCMessage, payload) {
		t.Fatalf("GRPCMessage = %v, want %v", inspection.GRPCMessage, payload)
	}
}

func TestBuildKitControlInspectorRejectsCompressedMessage(t *testing.T) {
	raw := buildBuildKitControlUnaryRequest(t, buildKitControlSolveMethod, []byte{0x01, 0x02}, 1, 2, 0)

	_, err := inspectBuildKitControlStream(bytes.NewReader(raw), 1024)
	if err == nil {
		t.Fatal("expected error for compressed gRPC message")
	}
	if !strings.Contains(err.Error(), "compression is not supported") {
		t.Fatalf("error = %q, want compression failure", err)
	}
}

func TestBuildKitControlInspectorRejectsTruncatedMessage(t *testing.T) {
	raw := buildBuildKitControlUnaryRequest(t, buildKitControlSolveMethod, []byte{0x01, 0x02}, 0, 5, 0)

	_, err := inspectBuildKitControlStream(bytes.NewReader(raw), 1024)
	if err == nil {
		t.Fatal("expected error for truncated gRPC message")
	}
	if !strings.Contains(err.Error(), "truncated gRPC message") {
		t.Fatalf("error = %q, want truncated message failure", err)
	}
}

func TestBuildKitControlTelemetryExportAllowed(t *testing.T) {
	raw := buildBuildKitControlHeadersOnly(t, "/opentelemetry.proto.collector.trace.v1.TraceService/Export")

	result, err := auditBuildKitControlRequest(bytes.NewReader(raw), testCfg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatalf("Denied = true, want false (reason=%q)", result.Reason)
	}
}

func TestProxyBuildKitControlFramesAllowsMultipleRequests(t *testing.T) {
	cfg := testCfg()
	solvePayload := mustMarshalBuildKitProto(t, &control.SolveRequest{
		Definition: &pb.Definition{Def: [][]byte{mustMarshalBuildKitProto(t, &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{}}})}},
	})
	raw := buildBuildKitControlConnection(t,
		buildKitControlRequestSpec{StreamID: 1, MethodPath: buildKitControlSolveMethod, Payload: solvePayload},
		buildKitControlRequestSpec{StreamID: 3, MethodPath: buildKitControlStatusMethod},
	)

	var forwarded bytes.Buffer
	err := proxyBuildKitControlFrames(bytes.NewReader(raw), &forwarded, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(forwarded.Bytes(), raw) {
		t.Fatal("expected all allowed requests to be forwarded unchanged")
	}
}

func TestBuildKitControlHPACKDynamicTableAcrossRequests(t *testing.T) {
	cfg := testCfg()
	raw := buildBuildKitControlConnectionStatefulHPACK(t,
		buildKitControlRequestSpec{StreamID: 1, MethodPath: buildKitControlStatusMethod},
		buildKitControlRequestSpec{StreamID: 3, MethodPath: buildKitControlStatusMethod},
	)

	var forwarded bytes.Buffer
	if err := proxyBuildKitControlFrames(bytes.NewReader(raw), &forwarded, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(forwarded.Bytes(), raw) {
		t.Fatal("expected HPACK-reused requests to be forwarded unchanged")
	}
}

func TestProxyBuildKitControlFramesClosesConnectionOnLaterDeniedSolve(t *testing.T) {
	cfg := testCfg()
	safePayload := mustMarshalBuildKitProto(t, &control.SolveRequest{
		Definition: &pb.Definition{Def: [][]byte{mustMarshalBuildKitProto(t, &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{}}})}},
	})
	unsafePayload := mustMarshalBuildKitProto(t, &control.SolveRequest{Entitlements: []string{"network.host"}})
	raw := buildBuildKitControlConnection(t,
		buildKitControlRequestSpec{StreamID: 1, MethodPath: buildKitControlSolveMethod, Payload: safePayload},
		buildKitControlRequestSpec{StreamID: 3, MethodPath: buildKitControlSolveMethod, Payload: unsafePayload},
	)
	firstAllowed := buildBuildKitControlConnection(t,
		buildKitControlRequestSpec{StreamID: 1, MethodPath: buildKitControlSolveMethod, Payload: safePayload},
	)
	secondHeaders := buildBuildKitControlHeadersChunk(t, 3, buildKitControlSolveMethod, false)
	wantForwardedPrefix := append(firstAllowed, secondHeaders...)

	var forwarded bytes.Buffer
	err := proxyBuildKitControlFrames(bytes.NewReader(raw), &forwarded, cfg)
	if err == nil {
		t.Fatal("expected deny error")
	}
	if !strings.Contains(err.Error(), "network.host") {
		t.Fatalf("error = %q, want solve deny reason", err)
	}
	if !bytes.Equal(forwarded.Bytes(), wantForwardedPrefix) {
		t.Fatal("expected denied solve to forward only pre-message bytes")
	}
}

func TestProxyBuildKitControlFramesStreamsSafeSolveBeforeFullAuditCompletes(t *testing.T) {
	cfg := testCfg()
	largeSolve := mustMarshalBuildKitProto(t, &control.SolveRequest{Frontend: strings.Repeat("safe", 6000)})
	firstChunk, secondChunk, expectedPrefix := buildSplitBuildKitControlSolveRequest(t, 1, largeSolve, 16384)

	clientReader, clientWriter := io.Pipe()
	upstreamWriter := &waitBuffer{}
	errCh := make(chan error, 1)
	go func() {
		errCh <- proxyBuildKitControlFrames(clientReader, upstreamWriter, cfg)
	}()

	if _, err := clientWriter.Write(firstChunk); err != nil {
		t.Fatalf("write first chunk: %v", err)
	}
	forwardedPrefix, err := upstreamWriter.WaitFor(len(expectedPrefix), 250*time.Millisecond)
	if err != nil {
		t.Fatalf("expected early forwarded bytes, got error: %v", err)
	}
	if !bytes.Equal(forwardedPrefix, expectedPrefix) {
		t.Fatal("expected safe solve prefix to be forwarded before full audit completes")
	}

	if _, err := clientWriter.Write(secondChunk); err != nil {
		t.Fatalf("write second chunk: %v", err)
	}
	clientWriter.Close()
	if err := <-errCh; err != nil {
		t.Fatalf("unexpected proxy error: %v", err)
	}
}

func TestBufferBuildKitFrameReusesOwnedRawFrameBytes(t *testing.T) {
	state := &buildKitControlStreamState{}
	rawFrame := []byte{0x01, 0x02, 0x03, 0x04}

	bufferBuildKitFrame(state, rawFrame, 2)

	if len(state.PendingFrames) != 1 {
		t.Fatalf("len(PendingFrames) = %d, want 1", len(state.PendingFrames))
	}
	if len(state.PendingFrames[0].raw) != len(rawFrame) {
		t.Fatalf("len(buffered raw) = %d, want %d", len(state.PendingFrames[0].raw), len(rawFrame))
	}
	if &state.PendingFrames[0].raw[0] != &rawFrame[0] {
		t.Fatal("expected buffered frame to reuse owned raw frame bytes")
	}
}

func TestFrameCaptureReaderTakeReturnsOwnedCopy(t *testing.T) {
	source := []byte{0x01, 0x02, 0x03, 0x04}
	reader := &frameCaptureReader{r: bytes.NewReader(source)}
	buf := make([]byte, len(source))

	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("read full: %v", err)
	}
	captured := reader.Take()
	if !bytes.Equal(captured, source) {
		t.Fatalf("captured = %v, want %v", captured, source)
	}
	if &captured[0] == &source[0] {
		t.Fatal("expected Take to return an owned copy")
	}
}

func buildBuildKitControlHeadersOnly(t *testing.T, methodPath string) []byte {
	t.Helper()

	var raw bytes.Buffer
	raw.WriteString(http2.ClientPreface)

	framer := http2.NewFramer(&raw, nil)
	if err := framer.WriteSettings(); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: encodeBuildKitControlHeaders(t, methodPath),
		EndHeaders:    true,
	}); err != nil {
		t.Fatalf("write headers: %v", err)
	}

	return raw.Bytes()
}

func buildBuildKitControlUnaryRequest(t *testing.T, methodPath string, payload []byte, compressedFlag byte, declaredLen uint32, splitAt int) []byte {
	t.Helper()

	raw := buildBuildKitControlHeadersOnly(t, methodPath)
	var out bytes.Buffer
	out.Write(raw)

	framer := http2.NewFramer(&out, nil)
	envelope := make([]byte, 5+len(payload))
	envelope[0] = compressedFlag
	binary.BigEndian.PutUint32(envelope[1:5], declaredLen)
	copy(envelope[5:], payload)

	if splitAt > 0 && splitAt < len(envelope) {
		if err := framer.WriteData(1, false, envelope[:splitAt]); err != nil {
			t.Fatalf("write first data frame: %v", err)
		}
		if err := framer.WriteData(1, true, envelope[splitAt:]); err != nil {
			t.Fatalf("write second data frame: %v", err)
		}
		return out.Bytes()
	}

	if err := framer.WriteData(1, true, envelope); err != nil {
		t.Fatalf("write data frame: %v", err)
	}
	return out.Bytes()
}

func encodeBuildKitControlHeaders(t *testing.T, methodPath string) []byte {
	t.Helper()

	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "docker"},
		{Name: ":path", Value: methodPath},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "te", Value: "trailers"},
	} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatalf("encode header %q: %v", field.Name, err)
		}
	}
	return block.Bytes()
}

type buildKitControlRequestSpec struct {
	StreamID       uint32
	MethodPath     string
	Payload        []byte
	CompressedFlag byte
	DeclaredLen    uint32
	SplitAt        int
}

func buildBuildKitControlConnection(t *testing.T, specs ...buildKitControlRequestSpec) []byte {
	t.Helper()

	var raw bytes.Buffer
	raw.WriteString(http2.ClientPreface)

	framer := http2.NewFramer(&raw, nil)
	if err := framer.WriteSettings(); err != nil {
		t.Fatalf("write settings: %v", err)
	}

	for _, spec := range specs {
		if err := framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      spec.StreamID,
			BlockFragment: encodeBuildKitControlHeaders(t, spec.MethodPath),
			EndHeaders:    true,
			EndStream:     len(spec.Payload) == 0,
		}); err != nil {
			t.Fatalf("write headers: %v", err)
		}
		if len(spec.Payload) == 0 {
			continue
		}

		declaredLen := spec.DeclaredLen
		if declaredLen == 0 {
			declaredLen = uint32(len(spec.Payload))
		}
		envelope := make([]byte, 5+len(spec.Payload))
		envelope[0] = spec.CompressedFlag
		binary.BigEndian.PutUint32(envelope[1:5], declaredLen)
		copy(envelope[5:], spec.Payload)

		if spec.SplitAt > 0 && spec.SplitAt < len(envelope) {
			if err := framer.WriteData(spec.StreamID, false, envelope[:spec.SplitAt]); err != nil {
				t.Fatalf("write first data frame: %v", err)
			}
			if err := framer.WriteData(spec.StreamID, true, envelope[spec.SplitAt:]); err != nil {
				t.Fatalf("write second data frame: %v", err)
			}
			continue
		}

		if err := framer.WriteData(spec.StreamID, true, envelope); err != nil {
			t.Fatalf("write data frame: %v", err)
		}
	}

	return raw.Bytes()
}

func buildBuildKitControlConnectionStatefulHPACK(t *testing.T, specs ...buildKitControlRequestSpec) []byte {
	t.Helper()

	var raw bytes.Buffer
	raw.WriteString(http2.ClientPreface)

	framer := http2.NewFramer(&raw, nil)
	if err := framer.WriteSettings(); err != nil {
		t.Fatalf("write settings: %v", err)
	}

	var headerBuf bytes.Buffer
	encoder := hpack.NewEncoder(&headerBuf)
	for _, spec := range specs {
		headerBuf.Reset()
		for _, field := range []hpack.HeaderField{
			{Name: ":method", Value: "POST"},
			{Name: ":scheme", Value: "http"},
			{Name: ":authority", Value: "docker"},
			{Name: ":path", Value: spec.MethodPath},
			{Name: "content-type", Value: "application/grpc"},
			{Name: "te", Value: "trailers"},
		} {
			if err := encoder.WriteField(field); err != nil {
				t.Fatalf("encode header %q: %v", field.Name, err)
			}
		}
		if err := framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      spec.StreamID,
			BlockFragment: bytes.Clone(headerBuf.Bytes()),
			EndHeaders:    true,
			EndStream:     true,
		}); err != nil {
			t.Fatalf("write headers: %v", err)
		}
	}

	return raw.Bytes()
}

func buildBuildKitControlHeadersChunk(t *testing.T, streamID uint32, methodPath string, endStream bool) []byte {
	t.Helper()

	var raw bytes.Buffer
	framer := http2.NewFramer(&raw, nil)
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: encodeBuildKitControlHeaders(t, methodPath),
		EndHeaders:    true,
		EndStream:     endStream,
	}); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	return raw.Bytes()
}

func mustMarshalBuildKitProto(t *testing.T, msg proto.Message) []byte {
	t.Helper()
	payload, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal proto: %v", err)
	}
	return payload
}

func buildSplitBuildKitControlSolveRequest(t *testing.T, streamID uint32, payload []byte, firstFramePayloadLen int) ([]byte, []byte, []byte) {
	t.Helper()

	envelope := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(envelope[1:5], uint32(len(payload)))
	copy(envelope[5:], payload)
	if firstFramePayloadLen <= 0 || firstFramePayloadLen >= len(envelope) {
		t.Fatalf("invalid firstFramePayloadLen %d for envelope size %d", firstFramePayloadLen, len(envelope))
	}

	var first bytes.Buffer
	first.WriteString(http2.ClientPreface)
	framer := http2.NewFramer(&first, nil)
	if err := framer.WriteSettings(); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: encodeBuildKitControlHeaders(t, buildKitControlSolveMethod),
		EndHeaders:    true,
	}); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	if err := framer.WriteData(streamID, false, envelope[:firstFramePayloadLen]); err != nil {
		t.Fatalf("write first data frame: %v", err)
	}

	var second bytes.Buffer
	framer = http2.NewFramer(&second, nil)
	if err := framer.WriteData(streamID, true, envelope[firstFramePayloadLen:]); err != nil {
		t.Fatalf("write second data frame: %v", err)
	}

	return first.Bytes(), second.Bytes(), first.Bytes()
}

func readWithTimeout(r io.Reader, p []byte, timeout time.Duration) (int, error) {
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		n, err := io.ReadFull(r, p)
		ch <- result{n: n, err: err}
	}()

	select {
	case res := <-ch:
		return res.n, res.err
	case <-time.After(timeout):
		return 0, fmt.Errorf("read timed out after %s", timeout)
	}
}

type waitBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *waitBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *waitBuffer) WaitFor(n int, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for {
		w.mu.Lock()
		if w.buf.Len() >= n {
			data := bytes.Clone(w.buf.Bytes()[:n])
			w.mu.Unlock()
			return data, nil
		}
		w.mu.Unlock()
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("buffer did not reach %d bytes within %s", n, timeout)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
