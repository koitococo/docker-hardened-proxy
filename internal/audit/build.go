package audit

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/distribution/reference"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
)

// BuildAuditResult holds the result of auditing a build request.
type BuildAuditResult struct {
	Denied bool
	Reason string
	Query  url.Values // rewritten query values (nil if denied)
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
	rewritten := cloneQueryValues(query)

	// Deny host network mode
	if nm := rewritten.Get("networkmode"); nm == "host" {
		return &BuildAuditResult{Denied: true, Reason: "build with networkmode=host is denied"}
	}

	// Strip dangerous entitlements from "allow" query parameter
	rewritten = stripEntitlements(rewritten)

	return &BuildAuditResult{Query: rewritten}
}

func cloneQueryValues(query url.Values) url.Values {
	cloned := make(url.Values, len(query))
	for key, values := range query {
		cloned[key] = append([]string(nil), values...)
	}
	return cloned
}

// dangerousEntitlements are BuildKit entitlements that must be stripped.
var dangerousEntitlements = map[string]bool{
	"network.host":      true,
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

type parsedImageReference struct {
	repository string
	tag        string
	digest     string
}

// matchAllowed checks if an image reference matches any entry in the allowed list.
// If an allowed entry ends with "/", it acts as a repository prefix match.
// Otherwise, a repository-only rule matches any tag/digest for that repository,
// while tag- and digest-specific rules require an exact match on that component.
func matchAllowed(tag string, allowed []string) bool {
	candidate, err := parseImageReference(tag)
	if err != nil {
		return false
	}

	for _, entry := range allowed {
		if strings.HasSuffix(entry, "/") {
			prefix, prefixErr := normalizeAllowedPrefix(entry)
			if prefixErr != nil {
				continue
			}
			if strings.HasPrefix(candidate.repository, prefix) {
				return true
			}
			continue
		}

		allowedRef, allowedErr := parseImageReference(entry)
		if allowedErr != nil {
			continue
		}
		if candidate.repository != allowedRef.repository {
			continue
		}
		if allowedRef.digest != "" {
			if candidate.digest == allowedRef.digest {
				return true
			}
			continue
		}
		if allowedRef.tag != "" {
			if candidate.tag == allowedRef.tag {
				return true
			}
			continue
		}

		return true
	}

	return false
}

func parseImageReference(value string) (parsedImageReference, error) {
	named, err := reference.ParseNormalizedNamed(value)
	if err != nil {
		return parsedImageReference{}, fmt.Errorf("parse image reference %q: %w", value, err)
	}

	parsed := parsedImageReference{repository: reference.TrimNamed(named).Name()}
	if tagged, ok := named.(reference.Tagged); ok {
		parsed.tag = tagged.Tag()
	}
	if digested, ok := named.(reference.Digested); ok {
		parsed.digest = digested.Digest().String()
	}

	return parsed, nil
}

func normalizeAllowedPrefix(value string) (string, error) {
	trimmed := strings.TrimSuffix(strings.TrimSpace(value), "/")
	if trimmed == "" {
		return "", fmt.Errorf("empty allowed prefix")
	}

	prefixRef, err := parseImageReference(trimmed + "/placeholder")
	if err != nil {
		return "", fmt.Errorf("normalize allowed prefix %q: %w", value, err)
	}

	return strings.TrimSuffix(prefixRef.repository, "/placeholder") + "/", nil
}
