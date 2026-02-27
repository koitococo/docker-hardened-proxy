package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httputil"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
)

// Handler is the core HTTP handler that routes, audits, and forwards Docker API requests.
type Handler struct {
	cfg     *config.Config
	reverse *httputil.ReverseProxy
	logger  *slog.Logger
}

// New creates a new proxy Handler.
func New(cfg *config.Config, logger *slog.Logger) *Handler {
	transport := NewUnixTransport(cfg.Upstream.Socket)

	director := func(req *http.Request) {
		req.URL.Scheme = "http"
		req.URL.Host = "docker"
	}

	rp := &httputil.ReverseProxy{
		Director:  director,
		Transport: transport,
	}

	return &Handler{
		cfg:     cfg,
		reverse: rp,
		logger:  logger,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.reverse.ServeHTTP(w, r)
}
