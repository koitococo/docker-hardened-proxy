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
				Rules: []config.BindMountRule{
					{
						SourcePrefix:  "/home/ubuntu",
						RewritePrefix: "/mnt/home/ubuntu",
						Action:        "allow",
					},
					{
						SourcePrefix: "/tmp",
						Action:       "allow",
					},
				},
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

func TestAuditCreateBindsDenied(t *testing.T) {
	body := []byte(`{"Image":"alpine","HostConfig":{"Binds":["/etc/passwd:/mnt/passwd"]}}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for /etc bind mount")
	}
}

func TestAuditCreateBindsAllowedWithRewrite(t *testing.T) {
	body := []byte(`{"Image":"alpine","HostConfig":{"Binds":["/home/ubuntu/project:/app"]}}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("should be allowed")
	}

	var parsed map[string]json.RawMessage
	json.Unmarshal(result.Body, &parsed)
	var hc map[string]json.RawMessage
	json.Unmarshal(parsed["HostConfig"], &hc)
	var binds []string
	json.Unmarshal(hc["Binds"], &binds)

	if len(binds) != 1 {
		t.Fatalf("binds len = %d", len(binds))
	}
	if binds[0] != "/mnt/home/ubuntu/project:/app" {
		t.Errorf("rewritten bind = %q", binds[0])
	}
}

func TestAuditCreateBindsAllowedNoRewrite(t *testing.T) {
	body := []byte(`{"Image":"alpine","HostConfig":{"Binds":["/tmp/data:/data"]}}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("should be allowed for /tmp")
	}

	var parsed map[string]json.RawMessage
	json.Unmarshal(result.Body, &parsed)
	var hc map[string]json.RawMessage
	json.Unmarshal(parsed["HostConfig"], &hc)
	var binds []string
	json.Unmarshal(hc["Binds"], &binds)

	if binds[0] != "/tmp/data:/data" {
		t.Errorf("bind should be unchanged, got %q", binds[0])
	}
}

func TestAuditCreateBindsNamedVolume(t *testing.T) {
	body := []byte(`{"Image":"alpine","HostConfig":{"Binds":["myvolume:/data"]}}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("named volumes should pass through")
	}
}

func TestAuditCreateMountsDenied(t *testing.T) {
	body := []byte(`{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"bind","Source":"/etc/passwd","Target":"/mnt/passwd"}]}}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for /etc bind mount via Mounts")
	}
}

func TestAuditCreateMountsRewritten(t *testing.T) {
	body := []byte(`{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"bind","Source":"/home/ubuntu/code","Target":"/app"}]}}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("should be allowed")
	}

	var parsed map[string]json.RawMessage
	json.Unmarshal(result.Body, &parsed)
	var hc map[string]json.RawMessage
	json.Unmarshal(parsed["HostConfig"], &hc)
	var mounts []map[string]json.RawMessage
	json.Unmarshal(hc["Mounts"], &mounts)

	if len(mounts) != 1 {
		t.Fatalf("mounts len = %d", len(mounts))
	}
	var source string
	json.Unmarshal(mounts[0]["Source"], &source)
	if source != "/mnt/home/ubuntu/code" {
		t.Errorf("rewritten source = %q", source)
	}
}

func TestAuditCreateMountsNonBind(t *testing.T) {
	body := []byte(`{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"volume","Source":"myvolume","Target":"/data"}]}}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("non-bind mounts should pass through")
	}
}

func TestMatchBindRule(t *testing.T) {
	cfg := &config.BindMountsConfig{
		DefaultAction: "deny",
		Rules: []config.BindMountRule{
			{SourcePrefix: "/home/ubuntu", RewritePrefix: "/mnt/home/ubuntu", Action: "allow"},
			{SourcePrefix: "/tmp", Action: "allow"},
			{SourcePrefix: "/var/log", Action: "deny"},
		},
	}

	tests := []struct {
		source      string
		wantAllowed bool
		wantPath    string
	}{
		{"/home/ubuntu/code", true, "/mnt/home/ubuntu/code"},
		{"/home/ubuntu", true, "/mnt/home/ubuntu"},
		{"/tmp/data", true, "/tmp/data"},
		{"/var/log/syslog", false, "/var/log/syslog"},
		{"/etc/passwd", false, "/etc/passwd"},
		// Path boundary: sibling dirs sharing string prefix must NOT match
		{"/home/ubuntuevil", false, "/home/ubuntuevil"},
		{"/home/ubuntu2/secrets", false, "/home/ubuntu2/secrets"},
		{"/tmp2", false, "/tmp2"},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			allowed, path := matchBindRule(tt.source, cfg)
			if allowed != tt.wantAllowed {
				t.Errorf("allowed = %v, want %v", allowed, tt.wantAllowed)
			}
			if path != tt.wantPath {
				t.Errorf("path = %q, want %q", path, tt.wantPath)
			}
		})
	}
}

func TestMatchBindRuleLongestPrefix(t *testing.T) {
	cfg := &config.BindMountsConfig{
		DefaultAction: "deny",
		Rules: []config.BindMountRule{
			{SourcePrefix: "/home", Action: "allow"},
			{SourcePrefix: "/home/ubuntu/secrets", Action: "deny"},
		},
	}

	tests := []struct {
		source      string
		wantAllowed bool
		wantPath    string
	}{
		// More specific deny rule should win over broader allow
		{"/home/ubuntu/secrets/key", false, "/home/ubuntu/secrets/key"},
		// Broader allow should still work for non-secret paths
		{"/home/ubuntu/code", true, "/home/ubuntu/code"},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			allowed, path := matchBindRule(tt.source, cfg)
			if allowed != tt.wantAllowed {
				t.Errorf("allowed = %v, want %v", allowed, tt.wantAllowed)
			}
			if path != tt.wantPath {
				t.Errorf("path = %q, want %q", path, tt.wantPath)
			}
		})
	}
}

func TestAuditCreateBindPathTraversalDenied(t *testing.T) {
	body := []byte(`{"Image":"alpine","HostConfig":{"Binds":["/home/ubuntu/../../etc/shadow:/mnt/shadow"]}}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for path traversal bind mount")
	}
}

func TestAuditCreateMountsPathTraversalDenied(t *testing.T) {
	body := []byte(`{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"bind","Source":"/home/ubuntu/../../etc/shadow","Target":"/mnt/shadow"}]}}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for path traversal mount source")
	}
}

func TestAuditCreateNetworkModeHostDenied(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.Namespaces.NetworkMode.DenyHost = true

	body := []byte(`{"Image":"alpine","HostConfig":{"NetworkMode":"host"}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for NetworkMode=host")
	}
}

func TestAuditCreateNetworkModeContainerDenied(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.Namespaces.NetworkMode.DenyHost = true

	body := []byte(`{"Image":"alpine","HostConfig":{"NetworkMode":"container:foreign_id"}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for NetworkMode=container:foreign_id")
	}
}

func TestAuditCreatePidModeContainerDenied(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.Namespaces.PIDMode.DenyHost = true

	body := []byte(`{"Image":"alpine","HostConfig":{"PidMode":"container:foreign_id"}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for PidMode=container:foreign_id")
	}
}

func TestAuditCreateNetworkModeBridge(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.Namespaces.NetworkMode.DenyHost = true

	body := []byte(`{"Image":"alpine","HostConfig":{"NetworkMode":"bridge"}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("bridge mode should be allowed")
	}
}

func TestAuditCreatePidModeHostDenied(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.Namespaces.PIDMode.DenyHost = true

	body := []byte(`{"Image":"alpine","HostConfig":{"PidMode":"host"}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for PidMode=host")
	}
}

func TestAuditCreateIpcModeHostDenied(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.Namespaces.IPCMode.DenyHost = true

	body := []byte(`{"Image":"alpine","HostConfig":{"IpcMode":"host"}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for IpcMode=host")
	}
}

func TestAuditCreateUTSModeHostDenied(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.Namespaces.UTSMode.DenyHost = true

	body := []byte(`{"Image":"alpine","HostConfig":{"UTSMode":"host"}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for UTSMode=host")
	}
}

func TestAuditCreateUsernsModeHostDenied(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.Namespaces.UserNSMode.DenyHost = true

	body := []byte(`{"Image":"alpine","HostConfig":{"UsernsMode":"host"}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for UsernsMode=host")
	}
}

func TestAuditCreateCgroupnsModeHostDenied(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.Namespaces.CgroupNSMode.DenyHost = true

	body := []byte(`{"Image":"alpine","HostConfig":{"CgroupnsMode":"host"}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for CgroupnsMode=host")
	}
}

func TestAuditCreateNamespaceModeNotDenied(t *testing.T) {
	cfg := testConfig()
	// All deny_host flags are false by default

	body := []byte(`{"Image":"alpine","HostConfig":{"NetworkMode":"host","PidMode":"host"}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("should not deny when deny_host is false")
	}
}

func TestAuditCreateSecurityOptDenied(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.DenySecurityOptOverride = true

	body := []byte(`{"Image":"alpine","HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for seccomp=unconfined")
	}
}

func TestAuditCreateSecurityOptAllowed(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.DenySecurityOptOverride = true

	body := []byte(`{"Image":"alpine","HostConfig":{"SecurityOpt":["no-new-privileges:true"]}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("no-new-privileges:true should be allowed")
	}
}

func TestAuditCreateDevicesDenied(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.DenyDevices = true

	body := []byte(`{"Image":"alpine","HostConfig":{"Devices":[{"PathOnHost":"/dev/sda","PathInContainer":"/dev/sda"}]}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for device access")
	}
}

func TestAuditCreateDevicesEmptyAllowed(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.DenyDevices = true

	body := []byte(`{"Image":"alpine","HostConfig":{"Devices":[]}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("empty devices list should be allowed")
	}
}

func TestAuditCreateMalformedPrivilegedDenied(t *testing.T) {
	body := []byte(`{"Image":"alpine","HostConfig":{"Privileged":"yes"}}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for malformed Privileged field")
	}
}

func TestAuditCreateMalformedCapAddDenied(t *testing.T) {
	body := []byte(`{"Image":"alpine","HostConfig":{"CapAdd":"SYS_ADMIN"}}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for malformed CapAdd field")
	}
}

func TestAuditCreateMalformedBindsDenied(t *testing.T) {
	body := []byte(`{"Image":"alpine","HostConfig":{"Binds":"/etc/passwd:/mnt"}}`)
	result, err := AuditCreate(body, testConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for malformed Binds field")
	}
}

func TestAuditCreateMalformedNetworkModeDenied(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.Namespaces.NetworkMode.DenyHost = true

	body := []byte(`{"Image":"alpine","HostConfig":{"NetworkMode":123}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for malformed NetworkMode field")
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

func TestAuditCreateSysctlsDenied(t *testing.T) {
	cfg := testConfig()
	// default_action defaults to "deny"

	body := []byte(`{"Image":"alpine","HostConfig":{"Sysctls":{"net.ipv4.ip_forward":"1"}}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for non-allowlisted sysctl")
	}
}

func TestAuditCreateSysctlsAllowlisted(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.Sysctls.DefaultAction = "deny"
	cfg.Audit.Sysctls.Allowed = []string{"net.ipv4.ping_group_range"}

	body := []byte(`{"Image":"alpine","HostConfig":{"Sysctls":{"net.ipv4.ping_group_range":"0 2147483647"}}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("allowlisted sysctl should be allowed")
	}
}

func TestAuditCreateSysctlsAllowAll(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.Sysctls.DefaultAction = "allow"

	body := []byte(`{"Image":"alpine","HostConfig":{"Sysctls":{"kernel.core_pattern":"|/exploit"}}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("should be allowed when default_action is allow")
	}
}

func TestAuditCreateSysctlsEmpty(t *testing.T) {
	cfg := testConfig()

	body := []byte(`{"Image":"alpine","HostConfig":{"Sysctls":{}}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("empty sysctls should be allowed")
	}
}

func TestAuditCreateOomKillDisableDenied(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.DenyOomKillDisable = true

	body := []byte(`{"Image":"alpine","HostConfig":{"OomKillDisable":true}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for OomKillDisable=true")
	}
}

func TestAuditCreateOomKillDisableAllowed(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.DenyOomKillDisable = true

	body := []byte(`{"Image":"alpine","HostConfig":{"OomKillDisable":false}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("OomKillDisable=false should be allowed")
	}
}

func TestAuditCreatePidsLimitUnlimitedDenied(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.DenyPidsLimitOverride = true

	body := []byte(`{"Image":"alpine","HostConfig":{"PidsLimit":-1}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for PidsLimit=-1 (unlimited)")
	}
}

func TestAuditCreatePidsLimitZeroDenied(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.DenyPidsLimitOverride = true

	body := []byte(`{"Image":"alpine","HostConfig":{"PidsLimit":0}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for PidsLimit=0 (unlimited)")
	}
}

func TestAuditCreatePidsLimitPositiveAllowed(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.DenyPidsLimitOverride = true

	body := []byte(`{"Image":"alpine","HostConfig":{"PidsLimit":1024}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("PidsLimit=1024 should be allowed")
	}
}

func TestAuditCreateLogConfigDenied(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.DenyLogConfigOverride = true

	body := []byte(`{"Image":"alpine","HostConfig":{"LogConfig":{"Type":"syslog","Config":{"syslog-address":"tcp://evil:514"}}}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected deny for custom log driver")
	}
}

func TestAuditCreateLogConfigEmptyAllowed(t *testing.T) {
	cfg := testConfig()
	cfg.Audit.DenyLogConfigOverride = true

	body := []byte(`{"Image":"alpine","HostConfig":{"LogConfig":{"Type":""}}}`)
	result, err := AuditCreate(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Denied {
		t.Fatal("empty log driver (daemon default) should be allowed")
	}
}
