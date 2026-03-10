package proxy

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

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
