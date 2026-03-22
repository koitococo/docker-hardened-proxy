package audit

import (
	"fmt"
	"net/http"
	"strings"

	control "github.com/moby/buildkit/api/services/control"
	pb "github.com/moby/buildkit/solver/pb"
	"google.golang.org/protobuf/proto"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
)

const buildKitSessionMethodHeader = "X-Docker-Expose-Session-Grpc-Method"

type buildKitSessionPolicy string

const (
	buildKitSessionPolicyFilesync buildKitSessionPolicy = "filesync"
	buildKitSessionPolicyUpload   buildKitSessionPolicy = "upload"
	buildKitSessionPolicyHealth   buildKitSessionPolicy = "health"
	buildKitSessionPolicySecrets  buildKitSessionPolicy = "secrets"
	buildKitSessionPolicySSH      buildKitSessionPolicy = "ssh"
	buildKitSessionPolicyAuth     buildKitSessionPolicy = "auth"
)

var buildKitSessionMethods = map[string]buildKitSessionPolicy{
	"moby.filesync.v1.FileSync/DiffCopy":         buildKitSessionPolicyFilesync,
	"moby.filesync.v1.FileSync/TarStream":        buildKitSessionPolicyFilesync,
	"moby.filesync.v1.FileSend/DiffCopy":         buildKitSessionPolicyFilesync,
	"moby.upload.v1.Upload/Pull":                 buildKitSessionPolicyUpload,
	"grpc.health.v1.Health/Check":                buildKitSessionPolicyHealth,
	"grpc.health.v1.Health/Watch":                buildKitSessionPolicyHealth,
	"grpc.health.v1.Health/List":                 buildKitSessionPolicyHealth,
	"moby.buildkit.secrets.v1.Secrets/GetSecret": buildKitSessionPolicySecrets,
	"moby.sshforward.v1.SSH/CheckAgent":          buildKitSessionPolicySSH,
	"moby.sshforward.v1.SSH/ForwardAgent":        buildKitSessionPolicySSH,
	"moby.filesync.v1.Auth/Credentials":          buildKitSessionPolicyAuth,
	"moby.filesync.v1.Auth/FetchToken":           buildKitSessionPolicyAuth,
	"moby.filesync.v1.Auth/GetTokenAuthority":    buildKitSessionPolicyAuth,
	"moby.filesync.v1.Auth/VerifyTokenAuthority": buildKitSessionPolicyAuth,
}

var deniedBuildKitEntitlements = map[string]bool{
	"network.host":      true,
	"security.insecure": true,
	"device":            true,
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

	seen := make(map[string]struct{}, len(methods))

	for _, rawMethod := range methods {
		method := normalizeBuildKitSessionMethod(rawMethod)
		if method == "" {
			return &BuildKitAuditResult{
				Denied: true,
				Reason: "buildkit session request contains an empty X-Docker-Expose-Session-Grpc-Method value",
			}
		}
		if _, ok := seen[method]; ok {
			return &BuildKitAuditResult{
				Denied: true,
				Reason: fmt.Sprintf("buildkit session request repeats X-Docker-Expose-Session-Grpc-Method value %q", method),
			}
		}
		seen[method] = struct{}{}
		if reason := denyBuildKitSessionMethod(method, cfg.Audit.BuildKit.Session); reason != "" {
			return &BuildKitAuditResult{Denied: true, Reason: reason}
		}
	}

	return &BuildKitAuditResult{}
}

// AuditBuildKitSolve audits a BuildKit Solve request and its embedded LLB definition.
func AuditBuildKitSolve(req *control.SolveRequest, cfg *config.Config) (*BuildKitAuditResult, error) {
	for _, entitlement := range req.Entitlements {
		normalized := strings.TrimSpace(entitlement)
		if deniedBuildKitEntitlements[normalized] {
			return &BuildKitAuditResult{
				Denied: true,
				Reason: fmt.Sprintf("buildkit solve entitlement %q is denied by policy", normalized),
			}, nil
		}
	}

	if req.Definition == nil {
		return &BuildKitAuditResult{}, nil
	}

	for i, rawOp := range req.Definition.Def {
		op, err := decodeBuildKitOp(rawOp)
		if err != nil {
			return nil, fmt.Errorf("decoding buildkit op %d: %w", i, err)
		}
		if reason := denyBuildKitOp(op); reason != "" {
			return &BuildKitAuditResult{Denied: true, Reason: reason}, nil
		}
	}

	return &BuildKitAuditResult{}, nil
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
	case buildKitSessionPolicyHealth:
		return true
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

func decodeBuildKitOp(rawOp []byte) (*pb.Op, error) {
	var op pb.Op
	if err := proto.Unmarshal(rawOp, &op); err != nil {
		return nil, fmt.Errorf("unmarshal buildkit op: %w", err)
	}
	return &op, nil
}

func denyBuildKitOp(op *pb.Op) string {
	execOp := op.GetExec()
	if execOp == nil {
		return ""
	}
	if execOp.Network == pb.NetMode_HOST {
		return "buildkit exec op uses host network mode"
	}
	if execOp.Security == pb.SecurityMode_INSECURE {
		return "buildkit exec op uses insecure security mode"
	}
	if len(execOp.CdiDevices) > 0 {
		return "buildkit exec op requests CDI devices"
	}
	if len(execOp.Secretenv) > 0 {
		return "buildkit exec op exposes secret environment variables"
	}
	for _, mount := range execOp.Mounts {
		switch mount.MountType {
		case pb.MountType_SECRET:
			return "buildkit exec op uses secret mount"
		case pb.MountType_SSH:
			return "buildkit exec op uses SSH mount"
		}
	}
	return ""
}
