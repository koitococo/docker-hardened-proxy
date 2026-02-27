package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
)

// Server manages TCP and Unix socket listeners for the proxy.
type Server struct {
	cfg       *config.Config
	handler   http.Handler
	logger    *slog.Logger
	listeners []net.Listener
}

// New creates a new Server.
func New(cfg *config.Config, handler http.Handler, logger *slog.Logger) *Server {
	return &Server{
		cfg:     cfg,
		handler: handler,
		logger:  logger,
	}
}

// ListenAndServe starts all configured listeners and blocks until ctx is done.
func (s *Server) ListenAndServe(ctx context.Context) error {
	var wg sync.WaitGroup
	var servers []*http.Server

	// cleanup shuts down all started servers on setup failure.
	cleanup := func() {
		for _, srv := range servers {
			srv.Close()
		}
	}

	if s.cfg.Listeners.TCP != nil {
		ln, err := net.Listen("tcp", s.cfg.Listeners.TCP.Address)
		if err != nil {
			return fmt.Errorf("tcp listen: %w", err)
		}
		s.listeners = append(s.listeners, ln)
		s.logger.Info("listening on TCP", "address", s.cfg.Listeners.TCP.Address)

		srv := &http.Server{Handler: s.handler}
		servers = append(servers, srv)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				s.logger.Error("tcp serve error", "error", err)
			}
		}()
	}

	if s.cfg.Listeners.Unix != nil {
		socketPath := s.cfg.Listeners.Unix.Path
		// Remove existing socket file
		os.Remove(socketPath)

		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			cleanup()
			return fmt.Errorf("unix listen: %w", err)
		}
		s.listeners = append(s.listeners, ln)

		if s.cfg.Listeners.Unix.Mode != 0 {
			if err := os.Chmod(socketPath, s.cfg.Listeners.Unix.Mode); err != nil {
				ln.Close()
				cleanup()
				return fmt.Errorf("chmod socket: %w", err)
			}
		}
		s.logger.Info("listening on Unix socket", "path", socketPath)

		srv := &http.Server{Handler: s.handler}
		servers = append(servers, srv)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				s.logger.Error("unix serve error", "error", err)
			}
		}()
	}

	// Wait for context cancellation, then shut down all servers gracefully.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, srv := range servers {
			srv.Shutdown(shutdownCtx)
		}
		// Clean up Unix socket file
		if s.cfg.Listeners.Unix != nil {
			os.Remove(s.cfg.Listeners.Unix.Path)
		}
	}()

	wg.Wait()
	return nil
}
