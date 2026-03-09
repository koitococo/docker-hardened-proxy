package audit

import (
	"net/url"
	"strings"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
)

// RegistryAuditResult contains the result of a registry audit check.
type RegistryAuditResult struct {
	Denied bool
	Reason string
}

// AuditAuth checks if registry authentication is allowed.
// The serveraddress parameter contains the registry URL.
func AuditAuth(query url.Values, cfg *config.Config) RegistryAuditResult {
	policy := cfg.Audit.Registry.Auth
	serverAddress := query.Get("serveraddress")

	switch policy {
	case "allow":
		return RegistryAuditResult{Denied: false}
	case "deny":
		return RegistryAuditResult{
			Denied: true,
			Reason: "registry authentication is denied by policy (audit.registry.auth)",
		}
	case "list":
		if serverAddress == "" {
			return RegistryAuditResult{
				Denied: true,
				Reason: "registry authentication denied: serveraddress parameter is required",
			}
		}
		for _, allowed := range cfg.Audit.Registry.AuthAllowed {
			if strings.HasPrefix(serverAddress, allowed) {
				return RegistryAuditResult{Denied: false}
			}
		}
		return RegistryAuditResult{
			Denied: true,
			Reason: "registry authentication denied: serveraddress not in allowed list",
		}
	default:
		return RegistryAuditResult{
			Denied: true,
			Reason: "registry authentication is denied by default",
		}
	}
}

// AuditPush checks if image push is allowed.
// The name parameter contains the image name (from query string).
func AuditPush(query url.Values, cfg *config.Config) RegistryAuditResult {
	policy := cfg.Audit.Registry.Push
	imageName := query.Get("name")

	switch policy {
	case "allow":
		return RegistryAuditResult{Denied: false}
	case "deny":
		return RegistryAuditResult{
			Denied: true,
			Reason: "image push is denied by policy (audit.registry.push)",
		}
	case "list":
		if imageName == "" {
			return RegistryAuditResult{
				Denied: true,
				Reason: "image push denied: name parameter is required",
			}
		}
		for _, allowed := range cfg.Audit.Registry.PushAllowed {
			if strings.HasPrefix(imageName, allowed) {
				return RegistryAuditResult{Denied: false}
			}
		}
		return RegistryAuditResult{
			Denied: true,
			Reason: "image push denied: image name not in allowed list",
		}
	default:
		return RegistryAuditResult{
			Denied: true,
			Reason: "image push is denied by default",
		}
	}
}
