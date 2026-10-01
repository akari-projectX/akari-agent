package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
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
	stateDir := flag.String("state-dir", "", "directory for the agent's key and certificates "+
		"(default: $STATE_DIRECTORY when run by systemd, else the config file's directory)")
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

	dir := *stateDir
	if dir == "" {
		dir = defaultStateDir(*configPath)
	}
	ids, err := loadIdentities(dir, cfg)
	if err != nil {
		slog.Error("failed to load identity", "error", err, "state_dir", dir)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := NewAgent(cfg, agentVersion, ids)

	slog.Info("agent starting",
		"agent_version", agentVersion,
		"git_sha", gitSHA,
		"panel", cfg.PanelAddr,
		"state_dir", dir)

	if err := a.Run(ctx); err != nil {
		slog.Error("agent exited with error", "error", err)
		os.Exit(1)
	}
	slog.Info("agent stopped")
}

// defaultStateDir: systemd's StateDirectory= ($STATE_DIRECTORY, first entry)
// or the config file's directory.
func defaultStateDir(configPath string) string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		return strings.SplitN(d, ":", 2)[0]
	}
	return filepath.Dir(configPath)
}
