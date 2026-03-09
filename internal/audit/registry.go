package audit

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
)

// RegistryAuditResult contains the result of a registry audit check.
type RegistryAuditResult struct {
	Denied bool
	Reason string
}

// AuthRequest represents the JSON body sent to the /auth endpoint.
type AuthRequest struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	ServerAddress string `json:"serveraddress"`
}

// AuditAuth checks if registry authentication is allowed.
// The serveraddress is extracted from the request body JSON.
func AuditAuth(body []byte, cfg *config.Config) RegistryAuditResult {
	policy := cfg.Audit.Registry.Auth

	var authReq AuthRequest
	if err := json.Unmarshal(body, &authReq); err != nil {
		return RegistryAuditResult{
			Denied: true,
			Reason: fmt.Sprintf("registry authentication denied: invalid JSON body: %v", err),
		}
	}

	switch policy {
	case "allow":
		return RegistryAuditResult{Denied: false}
	case "deny":
		return RegistryAuditResult{
			Denied: true,
			Reason: "registry authentication is denied by policy (audit.registry.auth)",
		}
	case "list":
		if authReq.ServerAddress == "" {
			return RegistryAuditResult{
				Denied: true,
				Reason: "registry authentication denied: serveraddress is required in request body",
			}
		}
		for _, allowed := range cfg.Audit.Registry.AuthAllowed {
			if strings.HasPrefix(authReq.ServerAddress, allowed) {
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
