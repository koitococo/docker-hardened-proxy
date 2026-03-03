# PROJECT KNOWLEDGE BASE

**Generated:** 2026-03-03  
**Language:** Go 1.25  
**Type:** Docker API Security Proxy

## OVERVIEW

Security-hardened proxy for Docker daemon API calls. Intercepts and audits container operations (create, exec, build, pull) against configurable policies. Uses namespace-based isolation with label injection for multi-tenant environments.

**Key Dependencies:**
- `github.com/docker/docker` - Docker API client
- `gopkg.in/yaml.v3` - Configuration parsing

## STRUCTURE

```
.
├── cmd/docker-hardened-proxy/    # Application entry point
├── internal/
│   ├── audit/                    # Security policy enforcement (see internal/audit/AGENTS.md)
│   ├── config/                   # YAML config parsing and validation
│   ├── docker/                   # Docker daemon client wrapper
│   ├── proxy/                    # HTTP proxy and request routing
│   ├── route/                    # URL path classification
│   └── server/                   # TCP/Unix socket listeners
├── config.example.yaml           # Configuration template
├── Dockerfile                    # Multi-stage build (alpine runtime)
└── justfile                      # Build commands
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Add audit policy | `internal/audit/` | Container/exec/build/pull auditing |
| Change config format | `internal/config/config.go` | Update structs + validation |
| Add API endpoint | `internal/route/` + `internal/proxy/proxy.go` | Route classification + handler |
| Modify proxy behavior | `internal/proxy/proxy.go` | Request forwarding logic |
| Change logging | `cmd/docker-hardened-proxy/main.go` | setupLogger function |

## CODE MAP

| Symbol | Type | Location | Purpose |
|--------|------|----------|---------|
| `audit.AuditCreate` | func | audit/create.go | Container create auditing |
| `audit.AuditExecCreate` | func | audit/exec.go | Exec create auditing |
| `proxy.Handler` | struct | proxy/proxy.go | Main HTTP handler |
| `route.Parse` | func | route/router.go | URL path classification |
| `config.Config` | struct | config/config.go | Configuration schema |
| `server.Server` | struct | server/server.go | Listener management |

## CONVENTIONS

**Go Style:**
- Standard Go project layout (`cmd/`, `internal/`)
- Use `log/slog` for structured logging (JSON default)
- Error wrapping with `fmt.Errorf("...: %w", err)`
- Context propagation for cancellation

**Security-First Defaults:**
- All audit policies default to "deny" (opt-in to allow)
- Bind mounts: deny by default, explicit allowlist required
- Capabilities: case-insensitive matching
- Namespace isolation enforced via labels (`ltkk.run/namespace`)

**Configuration:**
- YAML config with search path: `./config.yaml` → `~/.config/...` → `/etc/...`
- Validation in `Config.validate()` - fail fast on bad config
- Default namespace: `"default"`

**Docker API Handling:**
- Route classification strips `/v{version}/` prefix
- Unknown endpoints return `Denied` (fail-closed)
- Passthrough endpoints: `_ping`, `version`
- Body size limit: 10MB for create/exec requests

## ANTI-PATTERNS (THIS PROJECT)

**Security:**
- Never use `passthrough` for new endpoints without security review
- Don't add `container:` namespace modes without cross-namespace validation
- Never skip label injection on container create

**Code:**
- Don't use `panic()` - return errors for graceful handling
- Don't ignore `json.Unmarshal` errors in audit logic
- Don't add endpoints to `safePassthroughPaths` without auditing implications

## COMMANDS

```bash
# Development
just run                    # Run with default config
just run -- -config ./my.yaml
just test                   # Run tests
just test-v                 # Verbose tests
just lint                   # go vet

# Build
just build                  # Build binary
./docker-hardened-proxy -config config.yaml

# Docker
docker build -t docker-hardened-proxy .
docker run -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/config.yaml:/etc/docker-hardened-proxy/config.yaml \
  docker-hardened-proxy
```

## NOTES

**Bind Mount Security:**
`matchBindRule()` uses string path matching (does NOT resolve symlinks). Users with write access to allowed directories can create symlinks to escape boundaries. Use `rewrite_prefix` to mitigate - Docker receives the rewritten path.

**Namespace Isolation:**
- Containers are labeled with `ltkk.run/namespace` and `ltkk.run/managed-by`
- All operations check container labels against configured namespace
- `container:{id}` namespace modes require cross-namespace validation

**Request Flow:**
1. `server` accepts connection (TCP or Unix socket)
2. `proxy.Handler.ServeHTTP` receives request
3. `route.Parse` classifies endpoint
4. Audit functions inspect/modify request body
5. `httputil.ReverseProxy` forwards to upstream Docker daemon

**No CI/CD:** No GitHub Actions or other CI configured. Tests run locally via `just`.
