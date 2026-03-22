package config

import (
	"strings"
	"testing"
)

func TestParseFullConfig(t *testing.T) {
	data := []byte(`
listeners:
  tcp:
    address: "127.0.0.1:2375"
  unix:
    path: "/var/run/docker-proxy.sock"
    mode: 0660
upstream:
  url: "unix:///var/run/docker.sock"
namespace: "myns"
audit:
  deny_privileged: true
  denied_capabilities: ["ALL", "SYS_ADMIN"]
  bind_mounts:
    default_action: "deny"
    rules:
      - source_prefix: "/home/ubuntu"
        rewrite_prefix: "/mnt/home/ubuntu"
        action: "allow"
  namespaces:
    network_mode: { deny_host: true }
    ipc_mode: { deny_host: true }
    pid_mode: { deny_host: false }
    uts_mode: { deny_host: true }
logging:
  level: "debug"
  format: "text"
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Listeners.TCP.Address) != 1 || cfg.Listeners.TCP.Address[0] != "127.0.0.1:2375" {
		t.Errorf("tcp address = %v, want [\"127.0.0.1:2375\"]", cfg.Listeners.TCP.Address)
	}
	if cfg.Listeners.Unix.Path != "/var/run/docker-proxy.sock" {
		t.Errorf("unix path = %q", cfg.Listeners.Unix.Path)
	}
	if cfg.Upstream.URL != "unix:///var/run/docker.sock" {
		t.Errorf("upstream url = %q", cfg.Upstream.URL)
	}
	if cfg.Upstream.Network != "unix" {
		t.Errorf("upstream network = %q, want %q", cfg.Upstream.Network, "unix")
	}
	if cfg.Upstream.Address != "/var/run/docker.sock" {
		t.Errorf("upstream address = %q", cfg.Upstream.Address)
	}
	if cfg.Namespace != "myns" {
		t.Errorf("namespace = %q, want %q", cfg.Namespace, "myns")
	}
	if !cfg.Audit.DenyPrivileged {
		t.Error("deny_privileged should be true")
	}
	if len(cfg.Audit.DeniedCapabilities) != 2 {
		t.Errorf("denied_capabilities len = %d", len(cfg.Audit.DeniedCapabilities))
	}
	if cfg.Audit.BindMounts.DefaultAction != "deny" {
		t.Errorf("default_action = %q", cfg.Audit.BindMounts.DefaultAction)
	}
	if len(cfg.Audit.BindMounts.Rules) != 1 {
		t.Fatalf("rules len = %d", len(cfg.Audit.BindMounts.Rules))
	}
	r := cfg.Audit.BindMounts.Rules[0]
	if r.SourcePrefix != "/home/ubuntu" || r.RewritePrefix != "/mnt/home/ubuntu" || r.Action != "allow" {
		t.Errorf("rule = %+v", r)
	}
	if !cfg.Audit.Namespaces.NetworkMode.DenyHost {
		t.Error("network_mode.deny_host should be true")
	}
	if cfg.Audit.Namespaces.PIDMode.DenyHost {
		t.Error("pid_mode.deny_host should be false")
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("level = %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "text" {
		t.Errorf("format = %q", cfg.Logging.Format)
	}
}

func TestParseDefaults(t *testing.T) {
	data := []byte(`
namespace: test
listeners:
  tcp:
    address: ":8080"
upstream:
  url: "tcp://localhost:2376"
audit:
  deny_privileged: true
  deny_buildkit: false
`)

	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if cfg.Namespace != "test" {
		t.Errorf("namespace = %q, want test", cfg.Namespace)
	}
	if len(cfg.Listeners.TCP.Address) != 1 || cfg.Listeners.TCP.Address[0] != ":8080" {
		t.Errorf("tcp address = %v, want [\":8080\"]", cfg.Listeners.TCP.Address)
	}
	if cfg.Upstream.URL != "tcp://localhost:2376" {
		t.Errorf("upstream url = %q, want tcp://localhost:2376", cfg.Upstream.URL)
	}
	if !cfg.Audit.DenyPrivileged {
		t.Error("expected deny_privileged to be true")
	}
	if cfg.Audit.DenyBuildkit {
		t.Error("expected deny_buildkit to be false")
	}

	// Verify BuildKit secure defaults are applied
	bk := cfg.Audit.BuildKit
	if !bk.Session.AllowFilesync {
		t.Error("expected buildkit session allow_filesync to default to true")
	}
	if !bk.Session.AllowUpload {
		t.Error("expected buildkit session allow_upload to default to true")
	}
	if bk.Session.AllowSecrets {
		t.Error("expected buildkit session allow_secrets to default to false")
	}
	if bk.Session.AllowSSH {
		t.Error("expected buildkit session allow_ssh to default to false")
	}
	if bk.Session.AllowAuth {
		t.Error("expected buildkit session allow_auth to default to false")
	}
}

func TestParseBuildKitDefaults(t *testing.T) {
	data := []byte(`
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "unix:///var/run/docker.sock"
audit:
  deny_buildkit: false
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Audit.DenyBuildkit {
		t.Fatal("deny_buildkit = true, want false")
	}
	if cfg.Audit.BuildKit.AllowDiskUsage {
		t.Error("allow_disk_usage should default to false")
	}
	if cfg.Audit.BuildKit.AllowPrune {
		t.Error("allow_prune should default to false")
	}
	if cfg.Audit.BuildKit.AllowHistory {
		t.Error("allow_history should default to false")
	}
	if !cfg.Audit.BuildKit.Session.AllowFilesync {
		t.Error("allow_filesync should default to true when BuildKit is enabled")
	}
	if !cfg.Audit.BuildKit.Session.AllowUpload {
		t.Error("allow_upload should default to true when BuildKit is enabled")
	}
	if cfg.Audit.BuildKit.Session.AllowSecrets {
		t.Error("allow_secrets should default to false")
	}
	if cfg.Audit.BuildKit.Session.AllowSSH {
		t.Error("allow_ssh should default to false")
	}
	if cfg.Audit.BuildKit.Session.AllowAuth {
		t.Error("allow_auth should default to false")
	}
}

func TestParseBuildKitExplicitOverrides(t *testing.T) {
	data := []byte(`
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "unix:///var/run/docker.sock"
audit:
  deny_buildkit: false
  buildkit:
    allow_disk_usage: true
    allow_prune: true
    allow_history: true
    session:
      allow_filesync: false
      allow_upload: false
      allow_secrets: true
      allow_ssh: true
      allow_auth: true
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Audit.BuildKit.AllowDiskUsage {
		t.Error("allow_disk_usage = false, want true")
	}
	if !cfg.Audit.BuildKit.AllowPrune {
		t.Error("allow_prune = false, want true")
	}
	if !cfg.Audit.BuildKit.AllowHistory {
		t.Error("allow_history = false, want true")
	}
	if cfg.Audit.BuildKit.Session.AllowFilesync {
		t.Error("allow_filesync = true, want false")
	}
	if cfg.Audit.BuildKit.Session.AllowUpload {
		t.Error("allow_upload = true, want false")
	}
	if !cfg.Audit.BuildKit.Session.AllowSecrets {
		t.Error("allow_secrets = false, want true")
	}
	if !cfg.Audit.BuildKit.Session.AllowSSH {
		t.Error("allow_ssh = false, want true")
	}
	if !cfg.Audit.BuildKit.Session.AllowAuth {
		t.Error("allow_auth = false, want true")
	}
}

func TestParseNoListener(t *testing.T) {
	data := []byte(`
upstream:
  url: "unix:///var/run/docker.sock"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for missing listeners")
	}
}

func TestParseNoUpstream(t *testing.T) {
	data := []byte(`
listeners:
  tcp:
    address: ":2375"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for missing upstream")
	}
}

func TestParseNoTLSConfig(t *testing.T) {
	data := []byte(`
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "unix:///var/run/docker.sock"
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Upstream.TLSConfig != nil {
		t.Error("TLSConfig should be nil when tls section is absent")
	}
}

func TestParseTLSCertOnly(t *testing.T) {
	data := []byte(`
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "tcp://host:2376"
  tls:
    cert: "/some/cert.pem"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error when cert is set without key")
	}
}

func TestParseTLSBadCA(t *testing.T) {
	data := []byte(`
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "tcp://host:2376"
  tls:
    ca: "/nonexistent/ca.pem"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for nonexistent CA file")
	}
}

func TestParseUpstreamTCP(t *testing.T) {
	data := []byte(`
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "tcp://192.168.1.100:2375"
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Upstream.Network != "tcp" {
		t.Errorf("network = %q, want %q", cfg.Upstream.Network, "tcp")
	}
	if cfg.Upstream.Address != "192.168.1.100:2375" {
		t.Errorf("address = %q, want %q", cfg.Upstream.Address, "192.168.1.100:2375")
	}
}

func TestParseUpstreamInvalidScheme(t *testing.T) {
	data := []byte(`
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "http://localhost:2375"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for http:// scheme")
	}
}

func TestParseInvalidBindAction(t *testing.T) {
	data := []byte(`
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "unix:///var/run/docker.sock"
audit:
  bind_mounts:
    default_action: "invalid"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for invalid default_action")
	}
}

func TestParseInvalidRuleAction(t *testing.T) {
	data := []byte(`
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "unix:///var/run/docker.sock"
audit:
  bind_mounts:
    default_action: "deny"
    rules:
      - source_prefix: "/foo"
        action: "invalid"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for invalid rule action")
	}
}

func TestParseBuildPolicyDefault(t *testing.T) {
	data := []byte(`
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "unix:///var/run/docker.sock"
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Audit.Build.Policy != "deny" {
		t.Errorf("build policy = %q, want %q", cfg.Audit.Build.Policy, "deny")
	}
}

func TestParseBuildPolicyAllow(t *testing.T) {
	data := []byte(`
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "unix:///var/run/docker.sock"
audit:
  build:
    policy: "allow"
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Audit.Build.Policy != "allow" {
		t.Errorf("build policy = %q, want %q", cfg.Audit.Build.Policy, "allow")
	}
}

func TestParseBuildPolicyList(t *testing.T) {
	data := []byte(`
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "unix:///var/run/docker.sock"
audit:
  build:
    policy: "list"
    allowed:
      - "myapp"
      - "registry.example.com/"
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Audit.Build.Policy != "list" {
		t.Errorf("build policy = %q, want %q", cfg.Audit.Build.Policy, "list")
	}
	if len(cfg.Audit.Build.Allowed) != 2 {
		t.Errorf("allowed len = %d, want 2", len(cfg.Audit.Build.Allowed))
	}
}

func TestParseBuildPolicyInvalid(t *testing.T) {
	data := []byte(`
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "unix:///var/run/docker.sock"
audit:
  build:
    policy: "invalid"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for invalid build policy")
	}
}

func TestParseBuildPolicyListEmptyAllowed(t *testing.T) {
	data := []byte(`
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "unix:///var/run/docker.sock"
audit:
  build:
    policy: "list"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for list policy with empty allowed")
	}
}

func TestParseDeniedResponseMode(t *testing.T) {
	tests := []struct {
		name     string
		config   string
		wantMode string
		wantErr  string
	}{
		{
			name: "default mode",
			config: `
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "unix:///var/run/docker.sock"
`,
			wantMode: "reason",
		},
		{
			name: "explicit reason mode",
			config: `
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "unix:///var/run/docker.sock"
audit:
  denied_response_mode: "reason"
`,
			wantMode: "reason",
		},
		{
			name: "explicit generic mode",
			config: `
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "unix:///var/run/docker.sock"
audit:
  denied_response_mode: "generic"
`,
			wantMode: "generic",
		},
		{
			name: "invalid mode",
			config: `
listeners:
  tcp:
    address: ":2375"
upstream:
  url: "unix:///var/run/docker.sock"
audit:
  denied_response_mode: "noisy"
`,
			wantErr: "audit.denied_response_mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tt.config))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error for denied_response_mode")
				}
				if got := err.Error(); got == "" || !strings.Contains(got, tt.wantErr) {
					t.Fatalf("error = %q, want substring %q", got, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Audit.DeniedResponseMode != tt.wantMode {
				t.Fatalf("denied_response_mode = %q, want %q", cfg.Audit.DeniedResponseMode, tt.wantMode)
			}
		})
	}
}
