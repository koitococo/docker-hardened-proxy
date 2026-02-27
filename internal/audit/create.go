package audit

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
)

const (
	LabelNamespace = "ltkk.run/namespace"
	LabelManagedBy = "ltkk.run/managed-by"
	ManagedByValue = "docker-hardened-proxy"
)

// CreateRequest represents the subset of a container create request we inspect.
// We use json.RawMessage for everything to preserve unknown fields through round-trip.
type CreateRequest struct {
	raw        map[string]json.RawMessage
	hostConfig map[string]json.RawMessage
}

// ParseCreateRequest parses a container create request body.
func ParseCreateRequest(body []byte) (*CreateRequest, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing create request: %w", err)
	}

	cr := &CreateRequest{raw: raw}

	if hc, ok := raw["HostConfig"]; ok {
		var hostConfig map[string]json.RawMessage
		if err := json.Unmarshal(hc, &hostConfig); err != nil {
			return nil, fmt.Errorf("parsing HostConfig: %w", err)
		}
		cr.hostConfig = hostConfig
	}

	return cr, nil
}

// AuditResult holds the result of auditing a create request.
type AuditResult struct {
	Denied  bool
	Reason  string
	Rewrite bool
	Body    []byte
	// ReferencedContainers holds container IDs from "container:{id}" namespace
	// modes that need cross-namespace validation by the caller.
	ReferencedContainers []string
}

// AuditCreate audits a container create request against the config policy.
func AuditCreate(body []byte, cfg *config.Config) (*AuditResult, error) {
	cr, err := ParseCreateRequest(body)
	if err != nil {
		return nil, err
	}

	// Check privileged
	if cfg.Audit.DenyPrivileged {
		if denied, reason := cr.checkPrivileged(); denied {
			return &AuditResult{Denied: true, Reason: reason}, nil
		}
	}

	// Check capabilities
	if len(cfg.Audit.DeniedCapabilities) > 0 {
		if denied, reason := cr.checkCapabilities(cfg.Audit.DeniedCapabilities); denied {
			return &AuditResult{Denied: true, Reason: reason}, nil
		}
	}

	// Check sysctls
	if denied, reason := cr.checkSysctls(&cfg.Audit.Sysctls); denied {
		return &AuditResult{Denied: true, Reason: reason}, nil
	}

	// Check bind mounts
	if denied, reason := cr.checkBindMounts(&cfg.Audit.BindMounts); denied {
		return &AuditResult{Denied: true, Reason: reason}, nil
	}

	// Check security options
	if cfg.Audit.DenySecurityOptOverride {
		if denied, reason := cr.checkSecurityOpt(); denied {
			return &AuditResult{Denied: true, Reason: reason}, nil
		}
	}

	// Check devices
	if cfg.Audit.DenyDevices {
		if denied, reason := cr.checkDevices(); denied {
			return &AuditResult{Denied: true, Reason: reason}, nil
		}
	}

	// Check OomKillDisable
	if cfg.Audit.DenyOomKillDisable {
		if denied, reason := cr.checkOomKillDisable(); denied {
			return &AuditResult{Denied: true, Reason: reason}, nil
		}
	}

	// Check PidsLimit
	if cfg.Audit.DenyPidsLimitOverride {
		if denied, reason := cr.checkPidsLimit(); denied {
			return &AuditResult{Denied: true, Reason: reason}, nil
		}
	}

	// Check LogConfig
	if cfg.Audit.DenyLogConfigOverride {
		if denied, reason := cr.checkLogConfig(); denied {
			return &AuditResult{Denied: true, Reason: reason}, nil
		}
	}

	// Check namespace modes
	denied, reason, referencedContainers := cr.checkNamespaceModes(&cfg.Audit.Namespaces)
	if denied {
		return &AuditResult{Denied: true, Reason: reason}, nil
	}

	// Inject namespace labels
	cr.injectLabels(cfg.Namespace)

	// Serialize back
	result, err := cr.serialize()
	if err != nil {
		return nil, err
	}

	return &AuditResult{Rewrite: true, Body: result, ReferencedContainers: referencedContainers}, nil
}

func (cr *CreateRequest) checkPrivileged() (bool, string) {
	if cr.hostConfig == nil {
		return false, ""
	}
	priv, ok := cr.hostConfig["Privileged"]
	if !ok {
		return false, ""
	}
	var privileged bool
	if err := json.Unmarshal(priv, &privileged); err != nil {
		return true, "Privileged field has invalid type"
	}
	if privileged {
		return true, "privileged mode is denied"
	}
	return false, ""
}

func (cr *CreateRequest) checkCapabilities(denied []string) (bool, string) {
	if cr.hostConfig == nil {
		return false, ""
	}
	capAdd, ok := cr.hostConfig["CapAdd"]
	if !ok {
		return false, ""
	}
	var caps []string
	if err := json.Unmarshal(capAdd, &caps); err != nil {
		return true, "CapAdd field has invalid type"
	}

	deniedSet := make(map[string]struct{}, len(denied))
	for _, d := range denied {
		deniedSet[strings.ToUpper(d)] = struct{}{}
	}

	for _, cap := range caps {
		if _, found := deniedSet[strings.ToUpper(cap)]; found {
			return true, fmt.Sprintf("capability %q is denied", cap)
		}
	}
	return false, ""
}

func (cr *CreateRequest) checkSysctls(cfg *config.SysctlsConfig) (bool, string) {
	if cr.hostConfig == nil {
		return false, ""
	}
	raw, ok := cr.hostConfig["Sysctls"]
	if !ok {
		return false, ""
	}
	var sysctls map[string]string
	if err := json.Unmarshal(raw, &sysctls); err != nil {
		return true, "Sysctls field has invalid type"
	}
	if len(sysctls) == 0 {
		return false, ""
	}
	if cfg.DefaultAction == "allow" {
		return false, ""
	}
	// Default action is "deny": only allow sysctls in the allowlist
	allowedSet := make(map[string]struct{}, len(cfg.Allowed))
	for _, a := range cfg.Allowed {
		allowedSet[a] = struct{}{}
	}
	for key := range sysctls {
		if _, ok := allowedSet[key]; !ok {
			return true, fmt.Sprintf("sysctl %q is denied", key)
		}
	}
	return false, ""
}

func (cr *CreateRequest) checkBindMounts(cfg *config.BindMountsConfig) (bool, string) {
	if cr.hostConfig == nil {
		return false, ""
	}

	// Check HostConfig.Binds (string format: "source:dest[:options]")
	if bindsRaw, ok := cr.hostConfig["Binds"]; ok {
		var binds []string
		if err := json.Unmarshal(bindsRaw, &binds); err != nil {
			return true, "Binds field has invalid type"
		}
		newBinds := make([]string, 0, len(binds))
		for _, bind := range binds {
			parts := strings.SplitN(bind, ":", 3)
			if len(parts) < 2 {
				newBinds = append(newBinds, bind)
				continue
			}
			source := parts[0]
			// Skip non-absolute paths (named volumes)
			if !strings.HasPrefix(source, "/") {
				newBinds = append(newBinds, bind)
				continue
			}
			allowed, rewritten := matchBindRule(source, cfg)
			if !allowed {
				return true, fmt.Sprintf("bind mount source %q is denied", source)
			}
			if rewritten != source {
				parts[0] = rewritten
			}
			newBinds = append(newBinds, strings.Join(parts, ":"))
		}
		encoded, _ := json.Marshal(newBinds)
		cr.hostConfig["Binds"] = encoded
	}

	// Check HostConfig.Mounts (object format)
	if mountsRaw, ok := cr.hostConfig["Mounts"]; ok {
		var mounts []map[string]json.RawMessage
		if err := json.Unmarshal(mountsRaw, &mounts); err != nil {
			return true, "Mounts field has invalid type"
		}
		for i, mount := range mounts {
			var mountType string
			if t, ok := mount["Type"]; ok {
				if err := json.Unmarshal(t, &mountType); err != nil {
					return true, "Mount Type field has invalid type"
				}
			}
			if mountType != "bind" {
				continue
			}
			var source string
			if s, ok := mount["Source"]; ok {
				if err := json.Unmarshal(s, &source); err != nil {
					return true, "Mount Source field has invalid type"
				}
			}
			if source == "" {
				continue
			}
			allowed, rewritten := matchBindRule(source, cfg)
			if !allowed {
				return true, fmt.Sprintf("bind mount source %q is denied", source)
			}
			if rewritten != source {
				encoded, _ := json.Marshal(rewritten)
				mounts[i]["Source"] = encoded
			}
		}
		encoded, _ := json.Marshal(mounts)
		cr.hostConfig["Mounts"] = encoded
	}

	return false, ""
}

// matchesPathPrefix checks if source starts with prefix at a path component boundary.
// e.g., "/home/ubuntu" matches "/home/ubuntu/code" but NOT "/home/ubuntuevil".
func matchesPathPrefix(source, prefix string) bool {
	prefix = strings.TrimRight(prefix, "/")
	if !strings.HasPrefix(source, prefix) {
		return false
	}
	// Exact match or next char is a path separator
	return len(source) == len(prefix) || source[len(prefix)] == '/'
}

// matchBindRule checks a bind mount source against configured rules.
// Uses longest-prefix-match semantics so more specific rules always win.
// Returns (allowed, rewrittenPath).
//
// NOTE: This function operates on string paths only and does not resolve
// symlinks. If a user has write access to an allowed directory, they can
// create symlinks that escape the intended boundary. Using rewrite_prefix
// mitigates this since Docker uses the rewritten path (which won't contain
// the attacker's symlink). For allow-without-rewrite rules, ensure the
// allowed directory is not writable by untrusted users.
func matchBindRule(source string, cfg *config.BindMountsConfig) (bool, string) {
	source = path.Clean(source)

	bestIdx := -1
	bestLen := 0
	for i, rule := range cfg.Rules {
		if matchesPathPrefix(source, rule.SourcePrefix) && len(rule.SourcePrefix) > bestLen {
			bestIdx = i
			bestLen = len(rule.SourcePrefix)
		}
	}

	if bestIdx < 0 {
		// No rule matched — use default action
		return cfg.DefaultAction == "allow", source
	}

	rule := cfg.Rules[bestIdx]
	if rule.Action == "deny" {
		return false, source
	}
	// Apply rewrite if configured
	if rule.RewritePrefix != "" {
		rewritten := rule.RewritePrefix + source[len(rule.SourcePrefix):]
		return true, rewritten
	}
	return true, source
}

// dangerousSecurityOpts lists SecurityOpt values that disable security mechanisms.
var dangerousSecurityOpts = []string{
	"seccomp=unconfined",
	"seccomp:unconfined",
	"apparmor=unconfined",
	"apparmor:unconfined",
	"label:disable",
	"label=disable",
	"no-new-privileges:false",
	"no-new-privileges=false",
}

func (cr *CreateRequest) checkSecurityOpt() (bool, string) {
	if cr.hostConfig == nil {
		return false, ""
	}
	raw, ok := cr.hostConfig["SecurityOpt"]
	if !ok {
		return false, ""
	}
	var opts []string
	if err := json.Unmarshal(raw, &opts); err != nil {
		return true, "SecurityOpt field has invalid type"
	}
	for _, opt := range opts {
		for _, dangerous := range dangerousSecurityOpts {
			if strings.EqualFold(opt, dangerous) {
				return true, fmt.Sprintf("security option %q is denied", opt)
			}
		}
	}
	return false, ""
}

func (cr *CreateRequest) checkDevices() (bool, string) {
	if cr.hostConfig == nil {
		return false, ""
	}
	raw, ok := cr.hostConfig["Devices"]
	if !ok {
		return false, ""
	}
	var devices []json.RawMessage
	if err := json.Unmarshal(raw, &devices); err != nil {
		return true, "Devices field has invalid type"
	}
	if len(devices) > 0 {
		return true, "host device access is denied"
	}
	return false, ""
}

func (cr *CreateRequest) checkOomKillDisable() (bool, string) {
	if cr.hostConfig == nil {
		return false, ""
	}
	raw, ok := cr.hostConfig["OomKillDisable"]
	if !ok {
		return false, ""
	}
	var disabled bool
	if err := json.Unmarshal(raw, &disabled); err != nil {
		return true, "OomKillDisable field has invalid type"
	}
	if disabled {
		return true, "OomKillDisable is denied"
	}
	return false, ""
}

func (cr *CreateRequest) checkPidsLimit() (bool, string) {
	if cr.hostConfig == nil {
		return false, ""
	}
	raw, ok := cr.hostConfig["PidsLimit"]
	if !ok {
		return false, ""
	}
	var limit int64
	if err := json.Unmarshal(raw, &limit); err != nil {
		return true, "PidsLimit field has invalid type"
	}
	if limit <= 0 {
		return true, "unlimited PidsLimit is denied"
	}
	return false, ""
}

func (cr *CreateRequest) checkLogConfig() (bool, string) {
	if cr.hostConfig == nil {
		return false, ""
	}
	raw, ok := cr.hostConfig["LogConfig"]
	if !ok {
		return false, ""
	}
	var logConfig map[string]json.RawMessage
	if err := json.Unmarshal(raw, &logConfig); err != nil {
		return true, "LogConfig field has invalid type"
	}
	if driverRaw, ok := logConfig["Type"]; ok {
		var driver string
		if err := json.Unmarshal(driverRaw, &driver); err != nil {
			return true, "LogConfig.Type field has invalid type"
		}
		if driver != "" {
			return true, fmt.Sprintf("custom log driver %q is denied", driver)
		}
	}
	return false, ""
}

// checkNamespaceModes checks namespace mode fields and returns any "container:{id}"
// references that need cross-namespace validation by the caller.
func (cr *CreateRequest) checkNamespaceModes(cfg *config.NamespacesConfig) (denied bool, reason string, referencedContainers []string) {
	if cr.hostConfig == nil {
		return false, "", nil
	}

	checks := []struct {
		field    string
		denyHost bool
		name     string
	}{
		{"NetworkMode", cfg.NetworkMode.DenyHost, "NetworkMode"},
		{"IpcMode", cfg.IPCMode.DenyHost, "IpcMode"},
		{"PidMode", cfg.PIDMode.DenyHost, "PidMode"},
		{"UTSMode", cfg.UTSMode.DenyHost, "UTSMode"},
		{"UsernsMode", cfg.UserNSMode.DenyHost, "UsernsMode"},
		{"CgroupnsMode", cfg.CgroupNSMode.DenyHost, "CgroupnsMode"},
	}

	for _, check := range checks {
		if !check.denyHost {
			continue
		}
		raw, ok := cr.hostConfig[check.field]
		if !ok {
			continue
		}
		var mode string
		if err := json.Unmarshal(raw, &mode); err != nil {
			return true, fmt.Sprintf("%s field has invalid type", check.name), nil
		}
		if mode == "host" {
			return true, fmt.Sprintf("%s=%q is denied", check.name, mode), nil
		}
		if strings.HasPrefix(mode, "container:") {
			containerID := strings.TrimPrefix(mode, "container:")
			if containerID == "" {
				return true, fmt.Sprintf("%s=%q has empty container ID", check.name, mode), nil
			}
			referencedContainers = append(referencedContainers, containerID)
		}
	}

	return false, "", referencedContainers
}

func (cr *CreateRequest) injectLabels(namespace string) {
	var labels map[string]string

	if raw, ok := cr.raw["Labels"]; ok {
		json.Unmarshal(raw, &labels)
	}
	if labels == nil {
		labels = make(map[string]string)
	}

	labels[LabelNamespace] = namespace
	labels[LabelManagedBy] = ManagedByValue

	encoded, _ := json.Marshal(labels)
	cr.raw["Labels"] = encoded
}

func (cr *CreateRequest) serialize() ([]byte, error) {
	// Write hostConfig back into raw
	if cr.hostConfig != nil {
		hc, err := json.Marshal(cr.hostConfig)
		if err != nil {
			return nil, fmt.Errorf("serializing HostConfig: %w", err)
		}
		cr.raw["HostConfig"] = hc
	}
	return json.Marshal(cr.raw)
}
