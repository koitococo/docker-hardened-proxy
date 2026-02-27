package proxy

import (
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
	upstreamConn, err := net.Dial(h.cfg.Upstream.Network, h.cfg.Upstream.Address)
	if err != nil {
		h.logger.Error("failed to dial upstream for hijack", "error", err)
		http.Error(w, "upstream connection failed", http.StatusBadGateway)
		return
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
		// Signal upstream that client is done writing
		if tc, ok := upstreamConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		} else if uc, ok := upstreamConn.(*net.UnixConn); ok {
			uc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, upstreamConn)
		// Signal client that upstream is done writing
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		if uc, ok := clientConn.(*net.UnixConn); ok {
			uc.CloseWrite()
		}
	}()

	wg.Wait()
}
