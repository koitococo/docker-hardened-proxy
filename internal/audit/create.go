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

	// Check bind mounts
	if denied, reason := cr.checkBindMounts(&cfg.Audit.BindMounts); denied {
		return &AuditResult{Denied: true, Reason: reason}, nil
	}

	// Check namespace modes
	if denied, reason := cr.checkNamespaceModes(&cfg.Audit.Namespaces); denied {
		return &AuditResult{Denied: true, Reason: reason}, nil
	}

	// Inject namespace labels
	cr.injectLabels(cfg.Namespace)

	// Serialize back
	result, err := cr.serialize()
	if err != nil {
		return nil, err
	}

	return &AuditResult{Rewrite: true, Body: result}, nil
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

// matchBindRule checks a bind mount source against configured rules.
// Returns (allowed, rewrittenPath).
func matchBindRule(source string, cfg *config.BindMountsConfig) (bool, string) {
	source = path.Clean(source)
	for _, rule := range cfg.Rules {
		if strings.HasPrefix(source, rule.SourcePrefix) {
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
	}
	// No rule matched — use default action
	return cfg.DefaultAction == "allow", source
}

func (cr *CreateRequest) checkNamespaceModes(cfg *config.NamespacesConfig) (bool, string) {
	if cr.hostConfig == nil {
		return false, ""
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
			return true, fmt.Sprintf("%s field has invalid type", check.name)
		}
		if mode == "host" || strings.HasPrefix(mode, "container:") {
			return true, fmt.Sprintf("%s=%q is denied", check.name, mode)
		}
	}

	return false, ""
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
