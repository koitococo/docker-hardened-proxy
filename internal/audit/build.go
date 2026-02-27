package audit

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
)

// BuildAuditResult holds the result of auditing a build request.
type BuildAuditResult struct {
	Denied  bool
	Reason  string
	Query   url.Values // rewritten query values (nil if denied)
}

// AuditBuild audits a Docker build request's query parameters against the config policy.
// It enforces:
//   - Build policy (deny/allow/list)
//   - No dangerous entitlements (network.host, security.insecure)
//   - No host network mode
func AuditBuild(query url.Values, cfg *config.Config) *BuildAuditResult {
	policy := cfg.Audit.Build.Policy

	if policy == "deny" {
		return &BuildAuditResult{Denied: true, Reason: "build is denied by policy"}
	}

	// For "list" policy, check tags against allowed list
	if policy == "list" {
		tags := query["t"]
		if len(tags) == 0 {
			return &BuildAuditResult{Denied: true, Reason: "untagged build is denied by policy"}
		}
		for _, tag := range tags {
			if !matchAllowed(tag, cfg.Audit.Build.Allowed) {
				return &BuildAuditResult{Denied: true, Reason: fmt.Sprintf("build tag %q is not in allowed list", tag)}
			}
		}
	}

	// Build a rewritten copy of the query
	rewritten := make(url.Values)
	for k, v := range query {
		rewritten[k] = v
	}

	// Deny host network mode
	if nm := rewritten.Get("networkmode"); nm == "host" {
		return &BuildAuditResult{Denied: true, Reason: "build with networkmode=host is denied"}
	}

	// Strip dangerous entitlements from "allow" query parameter
	rewritten = stripEntitlements(rewritten)

	return &BuildAuditResult{Query: rewritten}
}

// dangerousEntitlements are BuildKit entitlements that must be stripped.
var dangerousEntitlements = map[string]bool{
	"network.host":     true,
	"security.insecure": true,
}

// stripEntitlements removes dangerous entitlements from the "allow" query parameter.
func stripEntitlements(query url.Values) url.Values {
	allow := query.Get("allow")
	if allow == "" {
		return query
	}

	parts := strings.Split(allow, ",")
	filtered := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !dangerousEntitlements[p] {
			filtered = append(filtered, p)
		}
	}

	if len(filtered) == 0 {
		query.Del("allow")
	} else {
		query.Set("allow", strings.Join(filtered, ","))
	}
	return query
}

// matchAllowed checks if a tag matches any entry in the allowed list.
// If an allowed entry ends with "/", it acts as a prefix match (e.g., "registry.example.com/").
// Otherwise, it matches the image name exactly (with or without tag).
func matchAllowed(tag string, allowed []string) bool {
	// Extract image name without tag (e.g., "myimage:v1" → "myimage")
	name := tag
	if idx := strings.LastIndex(tag, ":"); idx > 0 {
		name = tag[:idx]
	}

	for _, a := range allowed {
		if strings.HasSuffix(a, "/") {
			// Prefix match for registry/org paths
			if strings.HasPrefix(tag, a) {
				return true
			}
		} else {
			// Exact image name match (ignoring tag)
			if tag == a || name == a {
				return true
			}
		}
	}
	return false
}
