# AGENTS.md

## Repo snapshot
- Go module: `github.com/koitococo/docker-hardened-proxy` (`go 1.25.5` in `go.mod`)
- Single binary entrypoint: `cmd/docker-hardened-proxy/main.go`
- Purpose: security proxy in front of the Docker API; default posture is fail-closed

## Commands that matter
- Build: `just build`
- Run locally: `just run -- -config ./config.yaml`
- Full test suite: `just test` or `go test -v ./...`
- Lint used in CI: `just lint` (`go vet ./...`)
- Focused verification:
  - Single test: `go test -v ./internal/audit -run TestAuditCreatePrivilegedDenied`
  - One package: `go test -v ./internal/audit/...`
  - Other common packages: `go test -v ./internal/proxy/...`, `go test -v ./internal/config/...`

## What is wired where
- `cmd/docker-hardened-proxy/main.go` wires: config load/search -> Docker client -> proxy handler -> server.
- `internal/proxy/proxy.go` is the real request path: `route.Parse(...)` classifies, handler audits/denies/rewrites, then `httputil.ReverseProxy` forwards.
- `internal/route/router.go` is the allow/deny boundary. Unknown routes default to `Denied`, not passthrough.
- `internal/audit/create.go` is the densest policy file; read it first for container create changes.
- BuildKit is split across two flows:
  - `/session` header/service gating
  - `/grpc` per-request control RPC auditing

## Security invariants agents must not break
- Keep fail-closed behavior: new endpoints should not default to passthrough.
- Do not skip namespace label injection on container create: `ltkk.run/namespace` and `ltkk.run/managed-by`.
- `container:{id}` references must stay namespace-validated.
- Bind mount rules are string-prefix based, not symlink-aware; `rewrite_prefix` is the mitigation.
- `audit.denied_response_mode` only changes ordinary HTTP 403 bodies; it does not change hijacked BuildKit deny behavior.

## If you change routing or policy
- Adding a new Docker endpoint usually requires changes in both `internal/route/router.go` and `internal/proxy/proxy.go`.
- Adding/changing audit policy usually belongs in `internal/audit/*`; also read `internal/audit/AGENTS.md` before editing audit logic.
- For create-policy work, preserve check ordering in `AuditCreate()` unless you intentionally want behavior changes.

## Config/runtime gotchas
- If `-config` is omitted, config search order is:
  1. `./config.yaml`
  2. `~/.config/docker-hardened-proxy/config.yaml`
  3. `/etc/docker-hardened-proxy/config.yaml`
  4. `/usr/local/lib/docker-hardened-proxy/config.yaml`
  5. `/usr/lib/docker-hardened-proxy/config.yaml`
- `config.example.yaml` is the executable source of truth for supported policy keys; keep docs aligned with it.
- CI (`.github/workflows/release.yml`) runs `go test -v ./...` and `go vet ./...`, then cross-compiles release binaries.

## High-value files
- `README.md` - user-facing behavior and policy examples
- `docs/configuration-guide.md` - comprehensive configuration documentation with all options explained
- `justfile` - canonical local dev commands
- `config.example.yaml` - supported config surface
- `internal/audit/AGENTS.md` - audit-module-specific rules and check ordering
