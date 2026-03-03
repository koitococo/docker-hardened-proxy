# AUDIT MODULE KNOWLEDGE BASE

**Generated:** 2026-03-03  
**Parent:** ../AGENTS.md  
**Purpose:** Docker API security policy enforcement

## OVERVIEW

Security auditing layer for Docker container operations. Inspects create, exec, build, and pull requests against configurable policies. Can deny, rewrite, or pass-through requests.

**Key Files:**
- `create.go` - Container create auditing (534 lines, most complex)
- `exec.go` - Exec create auditing
- `build.go` - Build request auditing
- `pull.go` - Image pull auditing
- `list.go` - Container list filtering
- `namespace.go` - Container label/namespace checks

## POLICY CHECKS (Container Create)

Auditing happens in `AuditCreate()` in priority order:

1. **Privileged** - Deny `--privileged` containers
2. **Capabilities** - Check `CapAdd` against denied list
3. **Sysctls** - Allowlist/denylist kernel parameters
4. **Bind Mounts** - Path-based allow/deny with rewrite support
5. **SecurityOpt** - Block dangerous options (seccomp=unconfined, etc.)
6. **Devices** - Deny host device access
7. **OomKillDisable** - Block memory OOM killer disable
8. **PidsLimit** - Deny unlimited PIDs
9. **LogConfig** - Block custom log drivers
10. **Namespace Modes** - Deny `host` mode, track `container:{id}` refs
11. **Label Injection** - Auto-inject namespace labels

## BIND MOUNT RULES

Rules use **longest-prefix-match** - more specific rules override general ones.

```yaml
bind_mounts:
  default_action: "deny"
  rules:
    - source_prefix: "/home/ubuntu"
      rewrite_prefix: "/mnt/host/ubuntu"  # Optional path rewrite
      action: "allow"
```

**Security Note:** Paths are string-matched only. Symlinks in allowed directories can escape boundaries. Use `rewrite_prefix` to mitigate - Docker sees the rewritten path.

## NAMESPACE ISOLATION

**Labels Injected:**
- `ltkk.run/namespace` - Configured namespace value
- `ltkk.run/managed-by` - Always `"docker-hardened-proxy"`

**Cross-Namespace Validation:**
When `NetworkMode`, `IpcMode`, `PidMode`, etc. use `container:{id}`, the referenced container must be in the same namespace. Returns `ReferencedContainers` for caller to validate.

## DANGEROUS SECURITY OPTIONS

Blocked SecurityOpt values (case-insensitive):
- `seccomp=unconfined`, `seccomp:unconfined`
- `apparmor=unconfined`, `apparmor:unconfined`
- `label:disable`, `label=disable`
- `no-new-privileges:false`, `no-new-privileges=false`

## BUILD/ACCESS POLICIES

**Build Policy:**
- `deny` (default) - Block all builds
- `allow` - Allow with security enforcement
- `list` - Allow only for image names in `allowed` list

**Pull Policy:**
- `allow` (default) - Allow all pulls
- `deny` - Block all pulls
- `list` - Allow only for registry/image prefixes in `allowed`

List matching: entries ending with `/` are prefix matches, others are exact.

## WHERE TO ADD CHECKS

| Policy Type | Add To | Pattern |
|-------------|--------|---------|
| HostConfig field | `create.go` | Add `checkFieldName()` method, call in `AuditCreate()` |
| New namespace mode | `create.go` | Extend `checkNamespaceModes()` |
| New dangerous option | `create.go` | Add to `dangerousSecurityOpts` slice |
| Exec restrictions | `exec.go` | Modify `AuditExecCreate()` |
| Build restrictions | `build.go` | Modify `AuditBuild()` |
| Pull restrictions | `pull.go` | Modify `AuditPull()` |

## TESTING

Each audit file has corresponding `*_test.go`:
- Test deny/allow cases for each policy
- Test edge cases (empty values, malformed JSON)
- Test rewrite behavior

Run: `go test ./internal/audit/... -v`
