package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// Set via -ldflags "-X main.agentVersion=v1.0.0" at build time.
var agentVersion = "dev"

func main() {
	configPath := flag.String("config", "agent.toml", "path to agent bootstrap config")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := NewAgent(cfg, agentVersion)

	slog.Info("agent starting",
		"agent_version", agentVersion,
		"panel", cfg.PanelAddr)

	if err := a.Run(ctx); err != nil {
		slog.Error("agent exited with error", "error", err)
		os.Exit(1)
	}
	slog.Info("agent stopped")
}
