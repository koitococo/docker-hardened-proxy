# Docker Hardened Proxy

Security-hardened proxy for Docker daemon API. Intercepts container operations against configurable policies with namespace-based isolation.

## Quick Start

```bash
# Build
docker build -t docker-hardened-proxy .

# Run with config
docker run -d \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/config.yaml:/etc/docker-hardened-proxy/config.yaml \
  -p 2375:2375 \
  docker-hardened-proxy

# Use proxy
docker -H tcp://localhost:2375 ps
```

## Configuration

```yaml
listeners:
  tcp:
    address: ["0.0.0.0:2375"]

upstream:
  url: "unix:///var/run/docker.sock"

namespace: "default"

audit:
  deny_privileged: true
  
  build:
    policy: "list"
    allowed: ["myregistry.com/"]
  
  pull:
    policy: "list"
    allowed: ["alpine", "ubuntu"]
  
  registry:
    auth: "list"
    auth_allowed: ["https://myregistry.com"]
    push: "list"
    push_allowed: ["myregistry.com/"]

logging:
  level: "info"
  format: "json"
```

## Policies

All policies support three modes:
- `deny` - block all (default for most)
- `allow` - allow all
- `list` - allow only items in allowed list

**Endpoints:**
- `/containers/create` - audited for privileged, capabilities, bind mounts
- `/containers/{id}/exec` - audited for security options
- `/build` - controlled by `audit.build.policy`
- `/images/create` (pull) - controlled by `audit.pull.policy`
- `/auth` - controlled by `audit.registry.auth`
- `/images/{name}/push` - controlled by `audit.registry.push`

## Namespace Isolation

Containers are labeled with `ltkk.run/namespace`. All operations check container labels match the configured namespace. Cross-namespace operations are denied.

```yaml
namespace: "team-a"
```

## Development

```bash
just test      # Run tests
just lint      # Run linter
just build     # Build binary
just run       # Run with default config
```

## Security Defaults

- Bind mounts: denied unless explicitly allowed
- Privileged containers: denied
- Dangerous capabilities (SYS_ADMIN, etc.): denied
- BuildKit: denied (bypasses audits)
- Unknown endpoints: denied (fail-closed)
