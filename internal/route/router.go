package route

import (
	"strings"
)

// RouteInfo holds the parsed information about a Docker API request.
type RouteInfo struct {
	Kind EndpointKind
	// ID is the container or exec ID extracted from the path.
	ID string
	// StrippedPath is the path with the API version prefix removed.
	StrippedPath string
}

// Parse analyzes a Docker API URL path and returns routing information.
// It strips the optional /v{version}/ prefix for classification but
// the original path is preserved for forwarding.
func Parse(path string) RouteInfo {
	stripped := stripVersion(path)

	info := RouteInfo{
		StrippedPath: stripped,
		Kind:         Passthrough,
	}

	// Strip query string for route matching
	routePath := stripped
	if idx := strings.IndexByte(routePath, '?'); idx >= 0 {
		routePath = routePath[:idx]
	}

	// Split path into segments: /containers/json -> ["", "containers", "json"]
	parts := strings.Split(routePath, "/")
	// Remove empty leading segment
	if len(parts) > 0 && parts[0] == "" {
		parts = parts[1:]
	}

	if len(parts) == 0 || parts[0] == "" {
		return info // root path is passthrough
	}

	switch parts[0] {
	case "containers":
		return parseContainerRoute(parts[1:], info)
	case "exec":
		return parseExecRoute(parts[1:], info)
	default:
		return classifyTopLevel(parts, info)
	}
}

func parseContainerRoute(parts []string, info RouteInfo) RouteInfo {
	if len(parts) == 0 {
		return info
	}

	// /containers/create
	if parts[0] == "create" {
		info.Kind = ContainerCreate
		return info
	}

	// /containers/json — list
	if parts[0] == "json" {
		info.Kind = ContainerList
		return info
	}

	// /containers/{id}/...
	info.ID = parts[0]

	if len(parts) == 1 {
		// /containers/{id} — inspect (GET) or remove (DELETE)
		info.Kind = ContainerOp
		return info
	}

	action := parts[1]
	switch action {
	case "exec":
		// /containers/{id}/exec
		info.Kind = ExecCreate
	case "json":
		// /containers/{id}/json — inspect
		info.Kind = ContainerOp
	default:
		// /containers/{id}/start, stop, kill, restart, etc.
		info.Kind = ContainerOp
	}

	return info
}

func parseExecRoute(parts []string, info RouteInfo) RouteInfo {
	if len(parts) == 0 {
		return info
	}

	// /exec/{id}/...
	info.ID = parts[0]
	info.Kind = ExecOp
	return info
}

// safePassthroughPaths is the allowlist of top-level Docker API paths that are
// safe to forward without auditing. All other paths default to Denied.
var safePassthroughPaths = map[string]bool{
	"_ping":   true,
	"version": true,
	"info":    true,
}

// safePassthroughPrefixes covers paths like /images/json, /images/{id}/json, /images/{id}/tag, /images/create.
var safeImageActions = map[string]bool{
	"json":   true,
	"create": true,
}

var safeImageIDActions = map[string]bool{
	"json": true,
	"tag":  true,
}

func classifyTopLevel(parts []string, info RouteInfo) RouteInfo {
	// Single-segment paths: /_ping, /version, /info
	if len(parts) == 1 {
		if safePassthroughPaths[parts[0]] {
			return info // Kind remains Passthrough
		}
		info.Kind = Denied
		return info
	}

	// /images/* allowlist
	if parts[0] == "images" {
		if len(parts) == 2 {
			// /images/json (list), /images/create (pull)
			if safeImageActions[parts[1]] {
				return info
			}
		}
		if len(parts) == 3 {
			// /images/{id}/json (inspect), /images/{id}/tag
			if safeImageIDActions[parts[2]] {
				return info
			}
		}
		info.Kind = Denied
		return info
	}

	// Everything else is denied
	info.Kind = Denied
	return info
}

// stripVersion removes the /v{major}.{minor} prefix from a Docker API path.
func stripVersion(path string) string {
	if len(path) < 2 {
		return path
	}
	// Check for /v prefix
	if path[0] != '/' || path[1] != 'v' {
		return path
	}
	// Find the next / after /v...
	rest := path[2:]
	idx := strings.IndexByte(rest, '/')
	if idx < 0 {
		// Just /v1.41 with nothing after — keep as is
		return path
	}
	// Check that the part between /v and / looks like a version (contains digits/dots)
	version := rest[:idx]
	if !isVersionString(version) {
		return path
	}
	return rest[idx:]
}

func isVersionString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
