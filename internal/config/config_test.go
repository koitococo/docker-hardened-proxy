package config

import (
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
  socket: "/var/run/docker.sock"
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
	if cfg.Listeners.TCP.Address != "127.0.0.1:2375" {
		t.Errorf("tcp address = %q, want %q", cfg.Listeners.TCP.Address, "127.0.0.1:2375")
	}
	if cfg.Listeners.Unix.Path != "/var/run/docker-proxy.sock" {
		t.Errorf("unix path = %q", cfg.Listeners.Unix.Path)
	}
	if cfg.Upstream.Socket != "/var/run/docker.sock" {
		t.Errorf("upstream socket = %q", cfg.Upstream.Socket)
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
listeners:
  tcp:
    address: ":2375"
upstream:
  socket: "/var/run/docker.sock"
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Namespace != "default" {
		t.Errorf("namespace = %q, want %q", cfg.Namespace, "default")
	}
	if cfg.Audit.BindMounts.DefaultAction != "deny" {
		t.Errorf("default_action = %q, want %q", cfg.Audit.BindMounts.DefaultAction, "deny")
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("level = %q, want %q", cfg.Logging.Level, "info")
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("format = %q, want %q", cfg.Logging.Format, "json")
	}
}

func TestParseNoListener(t *testing.T) {
	data := []byte(`
upstream:
  socket: "/var/run/docker.sock"
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

func TestParseInvalidBindAction(t *testing.T) {
	data := []byte(`
listeners:
  tcp:
    address: ":2375"
upstream:
  socket: "/var/run/docker.sock"
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
  socket: "/var/run/docker.sock"
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
