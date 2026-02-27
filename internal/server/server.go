package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"

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

	if s.cfg.Listeners.TCP != nil {
		ln, err := net.Listen("tcp", s.cfg.Listeners.TCP.Address)
		if err != nil {
			return fmt.Errorf("tcp listen: %w", err)
		}
		s.listeners = append(s.listeners, ln)
		s.logger.Info("listening on TCP", "address", s.cfg.Listeners.TCP.Address)

		srv := &http.Server{Handler: s.handler}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				s.logger.Error("tcp serve error", "error", err)
			}
		}()
		go func() {
			<-ctx.Done()
			srv.Close()
		}()
	}

	if s.cfg.Listeners.Unix != nil {
		socketPath := s.cfg.Listeners.Unix.Path
		// Remove existing socket file
		os.Remove(socketPath)

		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			return fmt.Errorf("unix listen: %w", err)
		}
		s.listeners = append(s.listeners, ln)

		if s.cfg.Listeners.Unix.Mode != 0 {
			if err := os.Chmod(socketPath, s.cfg.Listeners.Unix.Mode); err != nil {
				ln.Close()
				return fmt.Errorf("chmod socket: %w", err)
			}
		}
		s.logger.Info("listening on Unix socket", "path", socketPath)

		srv := &http.Server{Handler: s.handler}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				s.logger.Error("unix serve error", "error", err)
			}
		}()
		go func() {
			<-ctx.Done()
			srv.Close()
			os.Remove(socketPath)
		}()
	}

	wg.Wait()
	return nil
}
