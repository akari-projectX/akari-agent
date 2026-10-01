package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

// Set at build time (see the Makefile): -ldflags "-X main.agentVersion=v1.0.0
// -X main.gitSHA=abc123def456".
var (
	agentVersion = "dev"
	gitSHA       = "unknown"
)

// versionString is what `agent -version` prints.
func versionString() string {
	return fmt.Sprintf("akari-agent %s (%s) %s %s/%s",
		agentVersion, gitSHA, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func main() {
	configPath := flag.String("config", "agent.toml", "path to agent bootstrap config")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(versionString())
		return
	}

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
		"git_sha", gitSHA,
		"panel", cfg.PanelAddr)

	if err := a.Run(ctx); err != nil {
		slog.Error("agent exited with error", "error", err)
		os.Exit(1)
	}
	slog.Info("agent stopped")
}
