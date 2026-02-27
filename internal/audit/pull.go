package audit

import (
	"fmt"
	"net/url"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
)

// PullAuditResult holds the result of auditing an image pull request.
type PullAuditResult struct {
	Denied bool
	Reason string
}

// AuditPull audits a Docker image pull request's query parameters against the config policy.
func AuditPull(query url.Values, cfg *config.Config) *PullAuditResult {
	policy := cfg.Audit.Pull.Policy

	if policy == "deny" {
		return &PullAuditResult{Denied: true, Reason: "image pull is denied by policy"}
	}

	if policy == "list" {
		fromImage := query.Get("fromImage")
		if fromImage == "" {
			return &PullAuditResult{Denied: true, Reason: "image pull without fromImage is denied by policy"}
		}
		if !matchAllowed(fromImage, cfg.Audit.Pull.Allowed) {
			return &PullAuditResult{Denied: true, Reason: fmt.Sprintf("image %q is not in allowed list", fromImage)}
		}
	}

	return &PullAuditResult{}
}
