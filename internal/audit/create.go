package audit

import (
	"encoding/json"
	"fmt"
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
		return false, ""
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
		return false, ""
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
