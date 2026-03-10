package audit

import (
	"net/http"
	"testing"

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
