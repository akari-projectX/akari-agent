package main

import (
	"fmt"
	"net"
	"os"

	"github.com/BurntSushi/toml"
)

// Config mirrors the bootstrap file produced by `akari node add`.
//
// It holds panel_addr, server_name, identity.ca_pem and a one-time
// enrollment_token; the agent generates its key locally and enrolls (the
// certificate and key then live in the state directory, identity.go).
// The agent never talks to any port other than the panel's outbound gRPC
// endpoint.
type Config struct {
	PanelAddr       string         `toml:"panel_addr"`
	ServerName      string         `toml:"server_name"`
	EnrollmentToken string         `toml:"enrollment_token"`
	Identity        IdentityConfig `toml:"identity"`
}

// IdentityConfig is the bootstrap file's [identity] table: the CA to trust.
type IdentityConfig struct {
	CAPEM string `toml:"ca_pem"`
}

// LoadConfig reads and strictly parses the bootstrap file at path (unknown
// keys are an error).
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	md, err := toml.Decode(string(b), &cfg)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if un := md.Undecoded(); len(un) > 0 {
		return nil, fmt.Errorf("unknown config keys: %v", un)
	}
	if cfg.PanelAddr == "" {
		return nil, fmt.Errorf("panel_addr is required")
	}
	if cfg.Identity.CAPEM == "" {
		return nil, fmt.Errorf("identity.ca_pem is required")
	}
	if cfg.ServerName == "" {
		cfg.ServerName = defaultServerName(cfg.PanelAddr)
	}
	return &cfg, nil
}

// defaultServerName is the TLS server name for a panel_addr without an
// explicit server_name: the host part of "host:port" (a TLS server name never
// carries a port), or addr itself when it has no host to extract.
func defaultServerName(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil && host != "" {
		return host
	}
	return addr
}
