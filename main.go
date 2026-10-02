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
	"time"

	"akari/agent/release"
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
	showKeys := flag.Bool("release-keys", false, "print the pinned self-update release keys and exit")
	selfCheck := flag.Duration("update-self-check", defaultSelfCheck,
		"after a self-update: how long the new binary has to connect and apply the panel's state before it is rolled back")
	maxBoots := flag.Int("update-max-boots", defaultMaxBoots,
		"after a self-update: starts the new binary gets to pass its self-check before the launcher rolls it back")
	heartbeat := flag.Duration("heartbeat-interval", 15*time.Second,
		"how often the agent reports its machine status (heartbeat), 1s..5m")
	acmeRoots := flag.String("acme-roots", "", "PEM file of extra CA roots trusted for the ACME directory (tests; default: system roots)")
	acmeHTTPPort := flag.Int("acme-http-port", 80, "TCP port the HTTP-01 challenge is answered on (the CA always connects to 80; tests only)")
	acmeTLSPort := flag.Int("acme-tls-port", 443, "TCP port the TLS-ALPN-01 challenge is answered on (the CA always connects to 443; tests only)")
	flag.Parse()
	if *showVersion {
		fmt.Println(versionString())
		return
	}
	keys, keyErr := pinnedReleaseKeys()
	if *showKeys {
		if keyErr != nil {
			fmt.Fprintln(os.Stderr, keyErr)
			os.Exit(1)
		}
		if len(keys) == 0 {
			fmt.Println("no release keys pinned: self-update disabled")
		}
		for _, k := range keys {
			fmt.Printf("%s %s %s\n", k.ID, release.FormatPublicKey(k.Key), k.Label)
		}
		return
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	dir := *stateDir
	if dir == "" {
		dir = defaultStateDir(*configPath)
	}

	// Self-update launcher (M6): before anything else, so a fresh start of
	// the installed binary hands over to the newest staged one. A broken
	// update directory never stops the agent; it only disables updates.
	upd, trial := startUpdater(dir, keys, keyErr, *selfCheck, *maxBoots)

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	ids, err := loadIdentities(dir, cfg)
	if err != nil {
		slog.Error("failed to load identity", "error", err, "state_dir", dir)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := NewAgent(cfg, agentVersion, ids)
	a.heartbeatEvery = min(max(*heartbeat, time.Second), 5*time.Minute)
	a.certs = newCertManager(dir)
	a.certs.ua = "akari-agent/" + agentVersion
	a.certs.httpPort, a.certs.tlsPort = *acmeHTTPPort, *acmeTLSPort
	if *acmeRoots != "" {
		roots, err := loadRoots(*acmeRoots)
		if err != nil {
			slog.Error("failed to load -acme-roots", "error", err)
			os.Exit(1)
		}
		a.certs.roots = roots
	}
	a.upd = upd
	a.trial = newTrialState(trial)
	a.finalsStore = &finalsStore{dir: dir}
	// Final counters a previous process persisted when it stopped (SIGTERM
	// or a self-update restart); they go out first on the next stream.
	if finals := a.finalsStore.load(); len(finals) > 0 {
		for _, r := range finals {
			a.finals.add(r)
		}
		a.finalsPersisted.Store(true)
		slog.Info("resending final traffic counters from before the restart", "reports", len(finals))
	} else {
		a.finalsStore.drop()
	}

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

func startUpdater(dir string, keys []release.PublicKey, keyErr error, selfCheck time.Duration, maxBoots int) (*updater, *trialRec) {
	if keyErr != nil {
		slog.Error("self-update disabled", "error", keyErr)
		return nil, nil
	}
	upd, err := newUpdater(dir, agentVersion, keys)
	if err != nil {
		slog.Error("self-update disabled", "error", err)
		return nil, nil
	}
	upd.selfCheck = max(selfCheck, 10*time.Second)
	upd.maxBoots = max(maxBoots, 1)
	trial, err := upd.launch(os.Getenv(envLaunched) != "")
	if err != nil {
		slog.Error("update state", "error", err)
	}
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, k.ID)
	}
	slog.Info("self-update", "release_keys", ids, "on_probation", trial != nil)
	return upd, trial
}

// defaultStateDir: systemd's StateDirectory= ($STATE_DIRECTORY, first entry)
// or the config file's directory.
func defaultStateDir(configPath string) string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		return strings.SplitN(d, ":", 2)[0]
	}
	return filepath.Dir(configPath)
}
