package audit

import (
	"net/http"
	"testing"

	control "github.com/moby/buildkit/api/services/control"
	pb "github.com/moby/buildkit/solver/pb"
	"google.golang.org/protobuf/proto"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
)

func testBuildKitAuditConfig() *config.Config {
	return &config.Config{
		Audit: config.AuditConfig{
			BuildKit: config.BuildKitConfig{
				Session: config.BuildKitSessionConfig{
					AllowFilesync: true,
					AllowUpload:   true,
				},
			},
		},
	}
}

func TestAuditBuildKitSessionHeaders(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantDenied bool
		wantReason string
	}{
		{
			name: "allow filesync and upload methods",
			headers: http.Header{
				"X-Docker-Expose-Session-Grpc-Method": []string{
					"/moby.filesync.v1.FileSync/DiffCopy",
					"/moby.upload.v1.Upload/Pull",
				},
			},
		},
		{
			name: "deny secrets method",
			headers: http.Header{
				"X-Docker-Expose-Session-Grpc-Method": []string{
					"/moby.buildkit.secrets.v1.Secrets/GetSecret",
				},
			},
			wantDenied: true,
			wantReason: "buildkit session method \"moby.buildkit.secrets.v1.Secrets/GetSecret\" is denied by policy",
		},
		{
			name: "deny ssh method",
			headers: http.Header{
				"X-Docker-Expose-Session-Grpc-Method": []string{
					"/moby.sshforward.v1.SSH/ForwardAgent",
				},
			},
			wantDenied: true,
			wantReason: "buildkit session method \"moby.sshforward.v1.SSH/ForwardAgent\" is denied by policy",
		},
		{
			name: "deny auth method",
			headers: http.Header{
				"X-Docker-Expose-Session-Grpc-Method": []string{
					"/moby.filesync.v1.Auth/Credentials",
				},
			},
			wantDenied: true,
			wantReason: "buildkit session method \"moby.filesync.v1.Auth/Credentials\" is denied by policy",
		},
		{
			name: "deny unknown method",
			headers: http.Header{
				"X-Docker-Expose-Session-Grpc-Method": []string{
					"/moby.unknown.v1.Service/Call",
				},
			},
			wantDenied: true,
			wantReason: "unknown buildkit session method \"moby.unknown.v1.Service/Call\"",
		},
		{
			name:       "deny missing method header",
			headers:    http.Header{},
			wantDenied: true,
			wantReason: "buildkit session request missing X-Docker-Expose-Session-Grpc-Method header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AuditBuildKitSessionHeaders(tt.headers, testBuildKitAuditConfig())
			if result.Denied != tt.wantDenied {
				t.Fatalf("Denied = %v, want %v", result.Denied, tt.wantDenied)
			}
			if result.Reason != tt.wantReason {
				t.Fatalf("Reason = %q, want %q", result.Reason, tt.wantReason)
			}
		})
	}
}

func TestAuditBuildKitSolve(t *testing.T) {
	tests := []struct {
		name       string
		request    *control.SolveRequest
		wantDenied bool
		wantReason string
	}{
		{
			name: "deny network host entitlement",
			request: &control.SolveRequest{
				Entitlements: []string{"network.host"},
			},
			wantDenied: true,
			wantReason: "buildkit solve entitlement \"network.host\" is denied by policy",
		},
		{
			name: "deny security insecure entitlement",
			request: &control.SolveRequest{
				Entitlements: []string{"security.insecure"},
			},
			wantDenied: true,
			wantReason: "buildkit solve entitlement \"security.insecure\" is denied by policy",
		},
		{
			name: "deny device entitlement",
			request: &control.SolveRequest{
				Entitlements: []string{"device"},
			},
			wantDenied: true,
			wantReason: "buildkit solve entitlement \"device\" is denied by policy",
		},
		{
			name:       "deny host network exec op",
			request:    buildSolveRequest(t, &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{Network: pb.NetMode_HOST}}}),
			wantDenied: true,
			wantReason: "buildkit exec op uses host network mode",
		},
		{
			name:       "deny insecure exec op",
			request:    buildSolveRequest(t, &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{Security: pb.SecurityMode_INSECURE}}}),
			wantDenied: true,
			wantReason: "buildkit exec op uses insecure security mode",
		},
		{
			name:       "deny secret mount",
			request:    buildSolveRequest(t, &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{Mounts: []*pb.Mount{{MountType: pb.MountType_SECRET}}}}}),
			wantDenied: true,
			wantReason: "buildkit exec op uses secret mount",
		},
		{
			name:       "deny ssh mount",
			request:    buildSolveRequest(t, &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{Mounts: []*pb.Mount{{MountType: pb.MountType_SSH}}}}}),
			wantDenied: true,
			wantReason: "buildkit exec op uses SSH mount",
		},
		{
			name:       "deny secret env",
			request:    buildSolveRequest(t, &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{Secretenv: []*pb.SecretEnv{{ID: "my-secret"}}}}}),
			wantDenied: true,
			wantReason: "buildkit exec op exposes secret environment variables",
		},
		{
			name:       "deny cdi devices",
			request:    buildSolveRequest(t, &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{CdiDevices: []*pb.CDIDevice{{Name: "vendor.com/gpu=device0"}}}}}),
			wantDenied: true,
			wantReason: "buildkit exec op requests CDI devices",
		},
		{
			name:       "allow safe solve request",
			request:    buildSolveRequest(t, &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{}}}),
			wantDenied: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AuditBuildKitSolve(tt.request, testBuildKitAuditConfig())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Denied != tt.wantDenied {
				t.Fatalf("Denied = %v, want %v", result.Denied, tt.wantDenied)
			}
			if result.Reason != tt.wantReason {
				t.Fatalf("Reason = %q, want %q", result.Reason, tt.wantReason)
			}
		})
	}
}

func buildSolveRequest(t *testing.T, ops ...*pb.Op) *control.SolveRequest {
	t.Helper()

	def := make([][]byte, 0, len(ops))
	for _, op := range ops {
		payload, err := proto.Marshal(op)
		if err != nil {
			t.Fatalf("marshal op: %v", err)
		}
		def = append(def, payload)
	}

	return &control.SolveRequest{
		Definition: &pb.Definition{Def: def},
	}
}
