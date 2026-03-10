package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	"github.com/koitococo/docker-hardened-proxy/internal/audit"
	"github.com/koitococo/docker-hardened-proxy/internal/config"
	"github.com/koitococo/docker-hardened-proxy/internal/docker"
	"github.com/koitococo/docker-hardened-proxy/internal/route"
)

// Handler is the core HTTP handler that routes, audits, and forwards Docker API requests.
type Handler struct {
	cfg     *config.Config
	reverse *httputil.ReverseProxy
	docker  docker.Client
	logger  *slog.Logger
}

// New creates a new proxy Handler.
func New(cfg *config.Config, dockerClient docker.Client, logger *slog.Logger) *Handler {
	transport := NewUpstreamTransport(cfg.Upstream.Network, cfg.Upstream.Address, cfg.Upstream.TLSConfig)

	scheme := "http"
	if cfg.Upstream.TLSConfig != nil {
		scheme = "https"
	}

	director := func(req *http.Request) {
		req.URL.Scheme = scheme
		req.URL.Host = "docker"
	}

	rp := &httputil.ReverseProxy{
		Director:  director,
		Transport: transport,
	}

	return &Handler{
		cfg:     cfg,
		reverse: rp,
		docker:  dockerClient,
		logger:  logger,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info := route.Parse(r.URL.Path)

	h.logger.Info("request",
		"method", r.Method,
		"path", r.URL.Path,
		"endpoint", info.Kind.String(),
		"id", info.ID,
	)

	switch info.Kind {
	case route.ContainerCreate:
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleContainerCreate(w, r)
		return
	case route.ContainerList:
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleContainerList(w, r)
		return
	case route.ExecCreate:
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := h.checkNamespace(r, info); err != nil {
			h.logger.Warn("denied",
				"endpoint", info.Kind.String(),
				"id", info.ID,
				"reason", err.Error(),
			)
			http.Error(w, "denied: "+err.Error(), http.StatusForbidden)
			return
		}
		h.handleExecCreate(w, r)
		return
	case route.ContainerOp:
		if err := h.checkNamespace(r, info); err != nil {
			h.logger.Warn("denied",
				"endpoint", info.Kind.String(),
				"id", info.ID,
				"reason", err.Error(),
			)
			http.Error(w, "denied: "+err.Error(), http.StatusForbidden)
			return
		}
	case route.ExecOp:
		if err := h.checkExecNamespace(r, info); err != nil {
			h.logger.Warn("denied",
				"endpoint", info.Kind.String(),
				"id", info.ID,
				"reason", err.Error(),
			)
			http.Error(w, "denied: "+err.Error(), http.StatusForbidden)
			return
		}
	case route.SystemInfo:
		if h.cfg.Audit.DenyInfo {
			h.logger.Warn("denied",
				"endpoint", info.Kind.String(),
				"reason", "system info is denied by policy",
			)
			http.Error(w, "denied: system info is denied by policy", http.StatusForbidden)
			return
		}
	case route.ImagePull:
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleImagePull(w, r)
		return
	case route.Build:
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleBuild(w, r)
		return
	case route.BuildKitControl:
		h.handleBuildKitControl(w, r)
		return
	case route.BuildKitSession:
		h.handleBuildKitSession(w, r)
		return
	case route.Auth:
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleAuth(w, r)
		return
	case route.ImagePush:
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleImagePush(w, r)
		return
	case route.Denied:
		h.logger.Warn("denied",
			"endpoint", info.Kind.String(),
			"path", r.URL.Path,
			"reason", "endpoint not allowed",
		)
		http.Error(w, "denied: endpoint not allowed", http.StatusForbidden)
		return
	}

	h.logger.Debug("forwarding",
		"method", r.Method,
		"path", r.URL.Path,
		"endpoint", info.Kind.String(),
	)

	h.forward(w, r)
}

func (h *Handler) forward(w http.ResponseWriter, r *http.Request) {
	if isUpgradeRequest(r) {
		h.logger.Debug("hijacking connection", "path", r.URL.Path)
		h.hijackProxy(w, r)
		return
	}
	h.reverse.ServeHTTP(w, r)
}

func (h *Handler) checkNamespace(r *http.Request, info route.RouteInfo) error {
	if info.ID == "" {
		return nil
	}
	return audit.CheckContainer(r.Context(), h.docker, info.ID, h.cfg.Namespace)
}

func (h *Handler) checkExecNamespace(r *http.Request, info route.RouteInfo) error {
	if info.ID == "" {
		return nil
	}
	return audit.CheckExec(r.Context(), h.docker, info.ID, h.cfg.Namespace)
}

func (h *Handler) handleContainerList(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("injecting namespace filter", "namespace", h.cfg.Namespace)
	query, warning := audit.InjectNamespaceFilter(r.URL.Query(), h.cfg.Namespace)
	if warning != "" {
		h.logger.Warn("filter warning", "warning", warning)
	}
	r.URL.RawQuery = query.Encode()
	h.forward(w, r)
}

// maxCreateBodySize is the maximum allowed request body size for container/exec create (10MB).
const maxCreateBodySize = 10 << 20

func (h *Handler) handleExecCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxCreateBodySize)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}

	result, err := audit.AuditExecCreate(body, h.cfg)
	if err != nil {
		h.logger.Error("exec audit error", "error", err)
		http.Error(w, "audit error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if result.Denied {
		h.logger.Warn("denied",
			"endpoint", "exec_create",
			"reason", result.Reason,
		)
		http.Error(w, "denied: "+result.Reason, http.StatusForbidden)
		return
	}

	// Restore body for forwarding
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))

	h.forward(w, r)
}

func (h *Handler) handleImagePull(w http.ResponseWriter, r *http.Request) {
	result := audit.AuditPull(r.URL.Query(), h.cfg)
	if result.Denied {
		h.logger.Warn("denied",
			"endpoint", "image_pull",
			"reason", result.Reason,
		)
		http.Error(w, "denied: "+result.Reason, http.StatusForbidden)
		return
	}

	h.logger.Info("image pull allowed")
	h.forward(w, r)
}

func (h *Handler) handleBuild(w http.ResponseWriter, r *http.Request) {
	result := audit.AuditBuild(r.URL.Query(), h.cfg)
	if result.Denied {
		h.logger.Warn("denied",
			"endpoint", "build",
			"reason", result.Reason,
		)
		http.Error(w, "denied: "+result.Reason, http.StatusForbidden)
		return
	}

	r.URL.RawQuery = result.Query.Encode()

	h.logger.Info("build allowed")
	h.forward(w, r)
}

func (h *Handler) handleBuildKit(w http.ResponseWriter, r *http.Request) {
	if h.cfg.Audit.DenyBuildkit {
		h.logger.Warn("denied",
			"endpoint", "buildkit",
			"reason", "buildkit is denied by policy (audit.deny_buildkit)",
		)
		http.Error(w, "denied: buildkit is disabled by policy", http.StatusForbidden)
		return
	}

	h.logger.Warn("buildkit allowed - security warning: buildkit bypasses container creation audits",
		"path", r.URL.Path,
	)
	h.forward(w, r)
}

func (h *Handler) handleBuildKitSession(w http.ResponseWriter, r *http.Request) {
	if h.cfg.Audit.DenyBuildkit {
		h.logger.Warn("denied",
			"endpoint", "buildkit_session",
			"reason", "buildkit is denied by policy (audit.deny_buildkit)",
		)
		http.Error(w, "denied: buildkit is disabled by policy", http.StatusForbidden)
		return
	}

	result := audit.AuditBuildKitSessionHeaders(r.Header, h.cfg)
	if result.Denied {
		h.logger.Warn("denied",
			"endpoint", "buildkit_session",
			"reason", result.Reason,
		)
		http.Error(w, "denied: "+result.Reason, http.StatusForbidden)
		return
	}

	h.forward(w, r)
}

func (h *Handler) handleBuildKitControl(w http.ResponseWriter, r *http.Request) {
	if h.cfg.Audit.DenyBuildkit {
		h.logger.Warn("denied",
			"endpoint", "buildkit_control",
			"reason", "buildkit is denied by policy (audit.deny_buildkit)",
		)
		http.Error(w, "denied: buildkit is disabled by policy", http.StatusForbidden)
		return
	}
	if !isUpgradeRequest(r) {
		http.Error(w, "buildkit control requires h2c upgrade", http.StatusBadRequest)
		return
	}

	h.hijackBuildKitControl(w, r)
}

func (h *Handler) handleAuth(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxCreateBodySize)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}

	result := audit.AuditAuth(body, h.cfg)
	if result.Denied {
		h.logger.Warn("denied",
			"endpoint", "auth",
			"reason", result.Reason,
		)
		http.Error(w, "denied: "+result.Reason, http.StatusForbidden)
		return
	}

	// Restore body for forwarding
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))

	h.logger.Info("registry authentication allowed")
	h.forward(w, r)
}

func (h *Handler) handleImagePush(w http.ResponseWriter, r *http.Request) {
	// Extract image name from path: /v1.52/images/{name}/push -> {name}
	imageName := extractImageNameFromPushPath(r.URL.Path)

	result := audit.AuditPush(imageName, h.cfg)
	if result.Denied {
		h.logger.Warn("denied",
			"endpoint", "image_push",
			"reason", result.Reason,
		)
		http.Error(w, "denied: "+result.Reason, http.StatusForbidden)
		return
	}

	h.logger.Info("image push allowed")
	h.forward(w, r)
}

// extractImageNameFromPushPath extracts the image name from a push endpoint path.
// Path format: /[v{version}/]images/{name}/push
func extractImageNameFromPushPath(path string) string {
	// Strip query string if present
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}

	// Split path into segments
	parts := strings.Split(path, "/")

	// Remove empty leading segment and version prefix if present
	if len(parts) > 0 && parts[0] == "" {
		parts = parts[1:]
	}

	// Check if first part is a version (starts with 'v' followed by digits/dots)
	if len(parts) > 0 && len(parts[0]) > 1 && parts[0][0] == 'v' {
		isVersion := true
		for i := 1; i < len(parts[0]); i++ {
			c := parts[0][i]
			if c != '.' && (c < '0' || c > '9') {
				isVersion = false
				break
			}
		}
		if isVersion {
			parts = parts[1:]
		}
	}

	// Now should be: ["images", {name parts...}, "push"]
	if len(parts) < 3 || parts[0] != "images" || parts[len(parts)-1] != "push" {
		return ""
	}

	// Join the middle parts as the image name
	return strings.Join(parts[1:len(parts)-1], "/")
}

func (h *Handler) handleContainerCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxCreateBodySize)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}

	h.logger.Debug("auditing container create", "body_size", len(body))

	result, err := audit.AuditCreate(body, h.cfg)
	if err != nil {
		h.logger.Error("audit error", "error", err)
		http.Error(w, "audit error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if result.Denied {
		h.logger.Warn("denied",
			"endpoint", "container_create",
			"reason", result.Reason,
		)
		http.Error(w, "denied: "+result.Reason, http.StatusForbidden)
		return
	}

	// Validate container: namespace mode references belong to the same namespace
	for _, refID := range result.ReferencedContainers {
		if err := audit.CheckContainer(r.Context(), h.docker, refID, h.cfg.Namespace); err != nil {
			h.logger.Warn("denied",
				"endpoint", "container_create",
				"reason", "namespace mode references foreign container",
				"ref_container", refID,
			)
			http.Error(w, "denied: namespace mode container:"+refID+" references a container outside this namespace", http.StatusForbidden)
			return
		}
	}

	if result.Warning != "" {
		h.logger.Warn("audit warning", "warning", result.Warning)
	}

	h.logger.Info("container create allowed",
		"rewritten", result.Rewrite,
	)

	// Replace body with audited version
	r.Body = io.NopCloser(bytes.NewReader(result.Body))
	r.ContentLength = int64(len(result.Body))
	r.Header.Set("Content-Length", strconv.Itoa(len(result.Body)))

	h.forward(w, r)
}
