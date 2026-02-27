package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
	"github.com/koitococo/docker-hardened-proxy/internal/docker"
	"github.com/koitococo/docker-hardened-proxy/internal/proxy"
	"github.com/koitococo/docker-hardened-proxy/internal/server"
)

func main() {
	configPath := flag.String("config", "", "path to config file")
	flag.Parse()

	path := *configPath
	if path == "" {
		path = config.Search()
		if path == "" {
			slog.Error("no config file found", "search_paths", config.SearchPaths)
			os.Exit(1)
		}
	}

	cfg, err := config.Load(path)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	logger := setupLogger(cfg)

	dockerClient, err := docker.NewClient(cfg.Upstream.URL, cfg.Upstream.TLSConfig)
	if err != nil {
		logger.Error("failed to create docker client", "error", err)
		os.Exit(1)
	}

	handler := proxy.New(cfg, dockerClient, logger)
	srv := server.New(cfg, handler, logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Info("starting docker-hardened-proxy", "namespace", cfg.Namespace)

	if err := srv.ListenAndServe(ctx); err != nil {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}

func setupLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	switch cfg.Logging.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if cfg.Logging.Format == "text" {
		handler = slog.NewTextHandler(os.Stderr, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}

	return slog.New(handler)
}
