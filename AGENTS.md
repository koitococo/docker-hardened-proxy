# AGENTS.md - Developer Guide

**Project:** docker-hardened-proxy  
**Language:** Go 1.25  
**Type:** Docker API Security Proxy  
**Last Updated:** 2026-03-09

## Quick Start

```bash
# Build the binary
just build

# Run tests
just test

# Run with config
just run -- -config ./config.yaml
```

## Build Commands

```bash
# Build binary (default output: ./docker-hardened-proxy)
just build
# Or: go build -o docker-hardened-proxy ./cmd/docker-hardened-proxy

# Production build (stripped binary, no debug info)
CGO_ENABLED=0 go build -ldflags="-s -w" -o docker-hardened-proxy ./cmd/docker-hardened-proxy

# Cross-compile (examples)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o docker-hardened-proxy-linux-amd64 ./cmd/docker-hardened-proxy
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o docker-hardened-proxy-darwin-arm64 ./cmd/docker-hardened-proxy

# Clean build artifacts
just clean
```

## Test Commands

```bash
# Run all tests
just test
# Or: go test ./...

# Run tests with verbose output
just test-v
# Or: go test -v ./...

# Run a single test function
go test -v ./internal/audit -run TestAuditCreatePrivilegedDenied

# Run tests for a specific package
go test -v ./internal/audit/...
go test -v ./internal/proxy/...
go test -v ./internal/config/...

# Run tests with coverage
go test -cover ./...
go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out

# Race detection
go test -race ./...
```

## Lint Commands

```bash
# Run go vet
just lint
# Or: go vet ./...

# Install and run golangci-lint (if available)
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
golangci-lint run

# Format code
go fmt ./...

# Check formatting
gofmt -l .
```

## Docker Commands

```bash
# Build Docker image
docker build -t docker-hardened-proxy .

# Run container
docker run -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/config.yaml:/etc/docker-hardened-proxy/config.yaml \
  -p 2375:2375 \
  docker-hardened-proxy
```

## Code Style Guidelines

### Imports

Group imports in this order:
1. Standard library imports
2. Third-party imports (blank line separator)
3. Internal project imports (blank line separator)

```go
import (
    "context"
    "fmt"
    "net/http"

    "github.com/docker/docker"

    "github.com/koitococo/docker-hardened-proxy/internal/config"
)
```

Use `goimports` or ensure `go fmt` maintains this ordering.

### Formatting

- Use `go fmt` for all Go code
- Max line length: ~100 characters (soft limit)
- No trailing whitespace
- Files end with a single newline

### Naming Conventions

**Types:**
- Exported: `PascalCase` (e.g., `Handler`, `AuditResult`)
- Unexported: `camelCase` (e.g., `createRequest`, `hostConfig`)

**Functions:**
- Exported: `PascalCase` (e.g., `AuditCreate`, `New`)
- Unexported: `camelCase` (e.g., `checkPrivileged`, `matchBindRule`)
- Constructor pattern: `New` or `New<Type>` (e.g., `New`, `NewClient`)

**Variables:**
- `camelCase` for both exported and unexported
- Acronyms in uppercase: `ID`, `URL`, `HTTP`, `JSON` (e.g., `containerID`, `rawURL`)

**Constants:**
- `PascalCase` for exported: `LabelNamespace`, `ManagedByValue`
- `camelCase` for unexported when appropriate

**Interfaces:**
- Single-method: Method name + `er` (e.g., `Reader`, `Handler`)
- Multi-method: Descriptive noun (e.g., `Client`)

### Error Handling

Always wrap errors with context using `fmt.Errorf` and `%w`:

```go
// Good
result, err := json.Unmarshal(data, &obj)
if err != nil {
    return nil, fmt.Errorf("parsing config: %w", err)
}

// Bad - loses context
if err != nil {
    return nil, err
}

// Bad - uses string formatting instead of wrapping
if err != nil {
    return nil, fmt.Errorf("parsing config: %v", err)
}
```

**Never use `panic()`** - return errors for graceful handling.

### Types

**Structs:**
- Use field tags for JSON/YAML marshaling
- Document exported fields

```go
type AuditResult struct {
    Denied  bool
    Reason  string
    Warning string
    Body    []byte
    // ReferencedContainers holds container IDs from "container:{id}" namespace
    ReferencedContainers []string
}
```

**Constants:**
Group related constants:

```go
const (
    LabelNamespace = "ltkk.run/namespace"
    LabelManagedBy = "ltkk.run/managed-by"
    ManagedByValue = "docker-hardened-proxy"
)
```

### Comments

- All exported types, functions, and constants must have doc comments
- Start with the name of the item being documented
- Use complete sentences

```go
// Handler is the core HTTP handler that routes, audits, and forwards Docker API requests.
type Handler struct { ... }

// AuditCreate audits a container create request against the config policy.
func AuditCreate(body []byte, cfg *config.Config) (*AuditResult, error) { ... }
```

### Logging

Use `log/slog` with structured logging:

```go
// Good - structured fields
logger.Info("container created",
    "id", containerID,
    "namespace", cfg.Namespace,
    "image", imageName,
)

// Bad - string interpolation
logger.Info(fmt.Sprintf("container %s created", containerID))
```

### Context Usage

Always propagate `context.Context` for cancellation:

```go
func (c *Client) DoSomething(ctx context.Context, id string) error {
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    // ...
}
```

## Security Guidelines

### Security-First Defaults

- All audit policies default to "deny" (opt-in to allow)
- Unknown endpoints return `Denied` (fail-closed)
- Never use `passthrough` for new endpoints without security review

### Never Skip

- Label injection on container create (`ltkk.run/namespace`, `ltkk.run/managed-by`)
- Cross-namespace validation for `container:{id}` references
- JSON unmarshal error checking in audit logic

### Sensitive Patterns

```go
// Block dangerous security options
dangerousSecurityOpts = []string{
    "seccomp=unconfined",
    "apparmor=unconfined",
    "label:disable",
    "no-new-privileges:false",
}
```

## Testing Guidelines

### Test Structure

```go
func Test<FunctionName><Scenario>(t *testing.T) {
    // Arrange
    cfg := testConfig()
    body := []byte(`{"Image":"alpine"}`)
    
    // Act
    result, err := AuditCreate(body, cfg)
    
    // Assert
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if result.Denied {
        t.Fatal("expected allow")
    }
}
```

### Table-Driven Tests

Use for multiple similar test cases:

```go
func TestAuditCreateCapabilities(t *testing.T) {
    tests := []struct {
        name     string
        caps     []string
        wantDeny bool
    }{
        {"SYS_ADMIN denied", []string{"SYS_ADMIN"}, true},
        {"SYS_PTRACE allowed", []string{"SYS_PTRACE"}, false},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // test logic
        })
    }
}
```

## Project Structure

```
.
├── cmd/docker-hardened-proxy/    # Application entry point
├── internal/
│   ├── audit/                    # Security policy enforcement
│   ├── config/                   # YAML config parsing
│   ├── docker/                   # Docker client wrapper
│   ├── proxy/                    # HTTP proxy and routing
│   ├── route/                    # URL path classification
│   └── server/                   # TCP/Unix socket listeners
├── config.example.yaml           # Configuration template
├── Dockerfile
└── justfile                      # Build commands
```

## CI/CD

GitHub Actions workflow (`.github/workflows/release.yml`):
- Runs on Go 1.25
- Executes `go test -v ./...`
- Executes `go vet ./...`
- Builds multi-platform binaries on tag push

No local CI required - tests run via `just`.

## Key Dependencies

- `github.com/docker/docker` - Docker API client
- `gopkg.in/yaml.v3` - Configuration parsing
- Standard library: `log/slog`, `net/http`, `encoding/json`

## Notes

**Bind Mount Security:** `matchBindRule()` uses string path matching (does NOT resolve symlinks). Use `rewrite_prefix` to mitigate symlink attacks.

**Namespace Isolation:** Containers are labeled with `ltkk.run/namespace`. All operations check labels against configured namespace.

**BuildKit Auditing:** BuildKit is denied by default via `audit.deny_buildkit`. Fine-grained policy lives in `internal/config/config.go` and `config.example.yaml`; session method checks live in `internal/audit/buildkit.go`; per-request `/grpc` control auditing lives in `internal/proxy/buildkit_hijack.go`; route dispatch is split in `internal/route/router.go` and `internal/proxy/proxy.go`.

**Request Flow:**
1. `server` accepts connection
2. `proxy.Handler.ServeHTTP` receives request
3. `route.Parse` classifies endpoint
4. Audit functions inspect/modify request body
5. `httputil.ReverseProxy` forwards to Docker daemon
