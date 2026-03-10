package audit

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
)

const buildKitSessionMethodHeader = "X-Docker-Expose-Session-Grpc-Method"

type buildKitSessionPolicy string

const (
	buildKitSessionPolicyFilesync buildKitSessionPolicy = "filesync"
	buildKitSessionPolicyUpload   buildKitSessionPolicy = "upload"
	buildKitSessionPolicySecrets  buildKitSessionPolicy = "secrets"
	buildKitSessionPolicySSH      buildKitSessionPolicy = "ssh"
	buildKitSessionPolicyAuth     buildKitSessionPolicy = "auth"
)

var buildKitSessionMethods = map[string]buildKitSessionPolicy{
	"moby.filesync.v1.FileSync/DiffCopy":         buildKitSessionPolicyFilesync,
	"moby.filesync.v1.FileSync/TarStream":        buildKitSessionPolicyFilesync,
	"moby.filesync.v1.FileSend/DiffCopy":         buildKitSessionPolicyFilesync,
	"moby.upload.v1.Upload/Pull":                 buildKitSessionPolicyUpload,
	"moby.buildkit.secrets.v1.Secrets/GetSecret": buildKitSessionPolicySecrets,
	"moby.sshforward.v1.SSH/CheckAgent":          buildKitSessionPolicySSH,
	"moby.sshforward.v1.SSH/ForwardAgent":        buildKitSessionPolicySSH,
	"moby.filesync.v1.Auth/Credentials":          buildKitSessionPolicyAuth,
	"moby.filesync.v1.Auth/FetchToken":           buildKitSessionPolicyAuth,
	"moby.filesync.v1.Auth/GetTokenAuthority":    buildKitSessionPolicyAuth,
	"moby.filesync.v1.Auth/VerifyTokenAuthority": buildKitSessionPolicyAuth,
}

// BuildKitAuditResult holds the result of auditing a BuildKit request.
type BuildKitAuditResult struct {
	Denied bool
	Reason string
}

// AuditBuildKitSessionHeaders audits advertised BuildKit session methods before h2c upgrade.
func AuditBuildKitSessionHeaders(headers http.Header, cfg *config.Config) *BuildKitAuditResult {
	methods := headers.Values(buildKitSessionMethodHeader)
	if len(methods) == 0 {
		return &BuildKitAuditResult{
			Denied: true,
			Reason: "buildkit session request missing X-Docker-Expose-Session-Grpc-Method header",
		}
	}

	for _, rawMethod := range methods {
		method := normalizeBuildKitSessionMethod(rawMethod)
		if method == "" {
			return &BuildKitAuditResult{
				Denied: true,
				Reason: "buildkit session request contains an empty X-Docker-Expose-Session-Grpc-Method value",
			}
		}
		if reason := denyBuildKitSessionMethod(method, cfg.Audit.BuildKit.Session); reason != "" {
			return &BuildKitAuditResult{Denied: true, Reason: reason}
		}
	}

	return &BuildKitAuditResult{}
}

func normalizeBuildKitSessionMethod(method string) string {
	return strings.TrimPrefix(strings.TrimSpace(method), "/")
}

func denyBuildKitSessionMethod(method string, sessionCfg config.BuildKitSessionConfig) string {
	policy, ok := buildKitSessionMethods[method]
	if !ok {
		return fmt.Sprintf("unknown buildkit session method %q", method)
	}
	if isBuildKitSessionMethodAllowed(policy, sessionCfg) {
		return ""
	}
	return fmt.Sprintf("buildkit session method %q is denied by policy", method)
}

func isBuildKitSessionMethodAllowed(policy buildKitSessionPolicy, sessionCfg config.BuildKitSessionConfig) bool {
	switch policy {
	case buildKitSessionPolicyFilesync:
		return sessionCfg.AllowFilesync
	case buildKitSessionPolicyUpload:
		return sessionCfg.AllowUpload
	case buildKitSessionPolicySecrets:
		return sessionCfg.AllowSecrets
	case buildKitSessionPolicySSH:
		return sessionCfg.AllowSSH
	case buildKitSessionPolicyAuth:
		return sessionCfg.AllowAuth
	default:
		return false
	}
}
