package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strconv"

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
		h.handleContainerCreate(w, r)
		return
	case route.ContainerList:
		h.handleContainerList(w, r)
		return
	case route.ContainerOp, route.ExecCreate:
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
	r.URL.RawQuery = audit.InjectNamespaceFilter(r.URL.Query(), h.cfg.Namespace).Encode()
	h.forward(w, r)
}

// maxCreateBodySize is the maximum allowed request body size for container create (10MB).
const maxCreateBodySize = 10 << 20

func (h *Handler) handleContainerCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxCreateBodySize)
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
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

	h.logger.Info("container create allowed",
		"rewritten", result.Rewrite,
	)

	// Replace body with audited version
	r.Body = io.NopCloser(bytes.NewReader(result.Body))
	r.ContentLength = int64(len(result.Body))
	r.Header.Set("Content-Length", strconv.Itoa(len(result.Body)))

	h.forward(w, r)
}
