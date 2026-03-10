package proxy

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

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
	wantForwarded := buildBuildKitControlConnection(t,
		buildKitControlRequestSpec{StreamID: 1, MethodPath: buildKitControlSolveMethod, Payload: safePayload},
	)

	var forwarded bytes.Buffer
	err := proxyBuildKitControlFrames(bytes.NewReader(raw), &forwarded, cfg)
	if err == nil {
		t.Fatal("expected deny error")
	}
	if !strings.Contains(err.Error(), "network.host") {
		t.Fatalf("error = %q, want solve deny reason", err)
	}
	if !bytes.Equal(forwarded.Bytes(), wantForwarded) {
		t.Fatal("expected only frames before denied request to be forwarded")
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

func mustMarshalBuildKitProto(t *testing.T, msg proto.Message) []byte {
	t.Helper()
	payload, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal proto: %v", err)
	}
	return payload
}
