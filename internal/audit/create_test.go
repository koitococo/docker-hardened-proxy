package audit

import (
	"encoding/json"
	"testing"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
)

func testConfig() *config.Config {
	return &config.Config{
		Namespace: "testns",
		Audit: config.AuditConfig{
			DenyPrivileged:     true,
			DeniedCapabilities: []string{"ALL", "SYS_ADMIN", "NET_ADMIN"},
			BindMounts: config.BindMountsConfig{
				DefaultAction: "deny",
			},
		},
	}
}

func TestAuditCreatePrivilegedDenied(t *testing.T) {
	body := []byte(`{"Image":"alpine","HostConfig":{"Privileged":true}}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for privileged container")
	}
	if result.Reason != "privileged mode is denied" {
		t.Errorf("reason = %q", result.Reason)
	}
}

func TestAuditCreatePrivilegedAllowed(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.DenyPrivileged = false

	body := []byte(`{"Image":"alpine","HostConfig":{"Privileged":true}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("should not deny when deny_privileged is false")
	}
}

func TestAuditCreateCapabilityDenied(t *testing.T) {
	body := []byte(`{"Image":"alpine","HostConfig":{"CapAdd":["SYS_ADMIN"]}}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for SYS_ADMIN cap")
	}
}

func TestAuditCreateCapabilityAllowed(t *testing.T) {
	body := []byte(`{"Image":"alpine","HostConfig":{"CapAdd":["SYS_PTRACE"]}}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("SYS_PTRACE should not be denied")
	}
}

func TestAuditCreateLabelsInjected(t *testing.T) {
	body := []byte(`{"Image":"alpine","Labels":{"existing":"value"}}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("should not be denied")
	}

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(result.Body, &parsed); err != nil {
		t.Fatalf("failed to parse result body: %v", err)
	}

	var labels map[string]string
	if err := json.Unmarshal(parsed["Labels"], &labels); err != nil {
		t.Fatalf("failed to parse labels: %v", err)
	}

	if labels[LabelNamespace] != "testns" {
		t.Errorf("namespace label = %q, want %q", labels[LabelNamespace], "testns")
	}
	if labels[LabelManagedBy] != ManagedByValue {
		t.Errorf("managed-by label = %q, want %q", labels[LabelManagedBy], ManagedByValue)
	}
	if labels["existing"] != "value" {
		t.Errorf("existing label = %q, want %q", labels["existing"], "value")
	}
}

func TestAuditCreateNoHostConfig(t *testing.T) {
	body := []byte(`{"Image":"alpine"}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("should not be denied without HostConfig")
	}
}

func TestAuditCreatePreservesUnknownFields(t *testing.T) {
	body := []byte(`{"Image":"alpine","Cmd":["echo","hello"],"Env":["FOO=bar"]}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(result.Body, &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if _, ok := parsed["Image"]; !ok {
		t.Error("Image field missing")
	}
	if _, ok := parsed["Cmd"]; !ok {
		t.Error("Cmd field missing")
	}
	if _, ok := parsed["Env"]; !ok {
		t.Error("Env field missing")
	}
}
