package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// isUpgradeRequest checks if the request is a connection upgrade (e.g., attach, exec start).
func isUpgradeRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "tcp") ||
		strings.EqualFold(r.Header.Get("Connection"), "Upgrade")
}

// hijackProxy handles bidirectional streaming for Docker attach/exec/logs.
// It hijacks both the client connection and the upstream connection, then
// copies data bidirectionally.
func (h *Handler) hijackProxy(w http.ResponseWriter, r *http.Request) {
	// Dial upstream Docker daemon
	rawConn, err := net.Dial(h.cfg.Upstream.Network, h.cfg.Upstream.Address)
	if err != nil {
		h.logger.Error("failed to dial upstream for hijack", "error", err)
		http.Error(w, "upstream connection failed", http.StatusBadGateway)
		return
	}

	// Wrap with TLS if configured
	var upstreamConn net.Conn = rawConn
	if h.cfg.Upstream.TLSConfig != nil {
		cfg := h.cfg.Upstream.TLSConfig.Clone()
		if cfg.ServerName == "" {
			host, _, _ := net.SplitHostPort(h.cfg.Upstream.Address)
			if host != "" {
				cfg.ServerName = host
			}
		}
		tlsConn := tls.Client(rawConn, cfg)
		if err := tlsConn.Handshake(); err != nil {
			rawConn.Close()
			h.logger.Error("TLS handshake failed for hijack", "error", err)
			http.Error(w, "upstream TLS handshake failed", http.StatusBadGateway)
			return
		}
		upstreamConn = tlsConn
	}
	defer upstreamConn.Close()

	// Write the original request to upstream
	if err := r.Write(upstreamConn); err != nil {
		h.logger.Error("failed to write request to upstream", "error", err)
		http.Error(w, "upstream write failed", http.StatusBadGateway)
		return
	}

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		h.logger.Error("response writer does not support hijacking")
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		h.logger.Error("failed to hijack client connection", "error", err)
		return
	}
	defer clientConn.Close()

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(upstreamConn, clientConn)
		closeWrite(upstreamConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, upstreamConn)
		closeWrite(clientConn)
	}()

	wg.Wait()
}

// closeWrite signals half-close on connections that support it.
func closeWrite(c net.Conn) {
	type halfCloser interface {
		CloseWrite() error
	}
	if hc, ok := c.(halfCloser); ok {
		hc.CloseWrite()
	}
}
