package audit

import (
	"net/url"
	"testing"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
)

func TestAuditPullListPolicyNormalizedReferences(t *testing.T) {
	cfg := testPullCfg("list", []string{"registry.example.com:5000/team/app", "alpine"})

	tests := []struct {
		name       string
		fromImage  string
		wantDenied bool
	}{
		{
			name:       "allow host port repository",
			fromImage:  "registry.example.com:5000/team/app",
			wantDenied: false,
		},
		{
			name:       "allow canonical docker hub name for familiar allowlist entry",
			fromImage:  "docker.io/library/alpine:latest",
			wantDenied: false,
		},
		{
			name:       "deny different repository on same registry",
			fromImage:  "registry.example.com:5000/team/other",
			wantDenied: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AuditPull(url.Values{"fromImage": {tt.fromImage}}, cfg)
			if result.Denied != tt.wantDenied {
				t.Fatalf("Denied = %v, want %v (reason=%q)", result.Denied, tt.wantDenied, result.Reason)
			}
		})
	}
}

func TestAuditPullListPolicyDockerHubLibraryPrefixMatchesFamiliarNames(t *testing.T) {
	cfg := testPullCfg("list", []string{"docker.io/library/"})

	result := AuditPull(url.Values{"fromImage": {"evil-image"}}, cfg)
	if result.Denied {
		t.Fatalf("Denied = true, want false (reason=%q)", result.Reason)
	}
}

func testPullCfg(policy string, allowed []string) *config.Config {
	cfg := buildCfg("allow", nil)
	cfg.Audit.Pull.Policy = policy
	cfg.Audit.Pull.Allowed = allowed
	return cfg
}
