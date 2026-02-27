package audit

import (
	"net/url"
	"testing"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
)

func buildCfg(policy string, allowed []string) *config.Config {
	return &config.Config{
		Namespace: "testns",
		Upstream:  config.UpstreamConfig{URL: "unix:///var/run/docker.sock", Network: "unix", Address: "/var/run/docker.sock"},
		Audit: config.AuditConfig{
			Build: config.BuildConfig{
				Policy:  policy,
				Allowed: allowed,
			},
		},
	}
}

func TestAuditBuildDenyPolicy(t *testing.T) {
	cfg := buildCfg("deny", nil)
	result := AuditBuild(url.Values{}, cfg)
	if !result.Denied {
		t.Fatal("expected denied")
	}
}

func TestAuditBuildAllowPolicy(t *testing.T) {
	cfg := buildCfg("allow", nil)
	result := AuditBuild(url.Values{"t": {"myimage:latest"}}, cfg)
	if result.Denied {
		t.Fatalf("expected allowed, got denied: %s", result.Reason)
	}
}

func TestAuditBuildListPolicyAllowed(t *testing.T) {
	cfg := buildCfg("list", []string{"myapp", "registry.example.com/"})

	tests := []struct {
		tag  string
		want bool
	}{
		{"myapp", false},
		{"myapp:v1", false},
		{"registry.example.com/foo", false},
		{"registry.example.com/foo:latest", false},
		{"other", true},
		{"otherapp:v1", true},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			result := AuditBuild(url.Values{"t": {tt.tag}}, cfg)
			if result.Denied != tt.want {
				t.Errorf("tag %q: denied=%v, want %v (reason: %s)", tt.tag, result.Denied, tt.want, result.Reason)
			}
		})
	}
}

func TestAuditBuildListPolicyNoTag(t *testing.T) {
	cfg := buildCfg("list", []string{"myapp"})
	result := AuditBuild(url.Values{}, cfg)
	if !result.Denied {
		t.Fatal("expected denied for untagged build")
	}
}

func TestAuditBuildDenyNetworkModeHost(t *testing.T) {
	cfg := buildCfg("allow", nil)
	result := AuditBuild(url.Values{"networkmode": {"host"}}, cfg)
	if !result.Denied {
		t.Fatal("expected denied for networkmode=host")
	}
}

func TestAuditBuildAllowNetworkModeBridge(t *testing.T) {
	cfg := buildCfg("allow", nil)
	result := AuditBuild(url.Values{"networkmode": {"bridge"}}, cfg)
	if result.Denied {
		t.Fatalf("expected allowed, got denied: %s", result.Reason)
	}
}

func TestAuditBuildStripEntitlements(t *testing.T) {
	cfg := buildCfg("allow", nil)

	tests := []struct {
		name      string
		allow     string
		wantAllow string
		wantDel   bool
	}{
		{"network.host only", "network.host", "", true},
		{"security.insecure only", "security.insecure", "", true},
		{"both dangerous", "network.host,security.insecure", "", true},
		{"mixed", "network.host,some.other", "some.other", false},
		{"safe only", "some.other", "some.other", false},
		{"empty", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := url.Values{}
			if tt.allow != "" {
				q.Set("allow", tt.allow)
			}
			result := AuditBuild(q, cfg)
			if result.Denied {
				t.Fatalf("unexpected deny: %s", result.Reason)
			}
			got := result.Query.Get("allow")
			if tt.wantDel {
				if got != "" {
					t.Errorf("allow = %q, want deleted", got)
				}
			} else {
				if got != tt.wantAllow {
					t.Errorf("allow = %q, want %q", got, tt.wantAllow)
				}
			}
		})
	}
}

func TestMatchAllowed(t *testing.T) {
	allowed := []string{"myapp", "registry.example.com/"}

	tests := []struct {
		tag  string
		want bool
	}{
		{"myapp", true},
		{"myapp:v1", true},
		{"myappx", false},
		{"registry.example.com/foo", true},
		{"registry.example.com/foo:latest", true},
		{"other.registry.com/foo", false},
		{"other", false},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			got := matchAllowed(tt.tag, allowed)
			if got != tt.want {
				t.Errorf("matchAllowed(%q) = %v, want %v", tt.tag, got, tt.want)
			}
		})
	}
}
