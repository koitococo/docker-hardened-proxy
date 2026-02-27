package audit

import (
	"encoding/json"
	"fmt"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
)

// AuditExecCreate audits an exec create request body.
// It checks for Privileged: true when deny_privileged is enabled.
func AuditExecCreate(body []byte, cfg *config.Config) (*AuditResult, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing exec create request: %w", err)
	}

	if cfg.Audit.DenyPrivileged {
		if priv, ok := raw["Privileged"]; ok {
			var privileged bool
			if err := json.Unmarshal(priv, &privileged); err != nil {
				return &AuditResult{Denied: true, Reason: "Privileged field has invalid type"}, nil
			}
			if privileged {
				return &AuditResult{Denied: true, Reason: "privileged exec is denied"}, nil
			}
		}
	}

	return &AuditResult{}, nil
}
