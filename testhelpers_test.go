package main

// Helpers that only the tests use: thin wrappers over the production entry
// points (kept out of the non-test build so the unused-code checks stay
// meaningful).

import (
	"encoding/json"

	"github.com/xtls/xray-core/core"
)

// Connections returns how many proxied dispatches the gate tracks right
// now (0 when no instance runs). Heartbeat.connections.
func (m *CoreManager) Connections() uint64 {
	g := m.liveGate.Load()
	if g == nil {
		return 0
	}
	return uint64(g.LiveTotal())
}

func newInstance(inboundsJSON string) (*built, error) {
	return newInstanceWith(inboundsJSON, nil)
}

// buildConfig turns the inbounds into xray's config (gate in place of the
// dispatcher), with node certificate entries pointed at cert (if set).
func buildConfig(inbounds []json.RawMessage, cert *certFiles) (*core.Config, map[string]inboundKind, []string, error) {
	b, err := buildConfigFor(inbounds, cert, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	return b.config, b.kinds, b.acmeTags, nil
}

func newInstanceWith(inboundsJSON string, cert *certFiles) (*built, error) {
	return newInstanceFor(inboundsJSON, cert, nil)
}

// kernelVersion: the xray-core version the manifest was verified against.
func (m *protocolManifest) kernelVersion(id string) string {
	for _, k := range m.Kernel {
		if k.ID == id {
			return k.Version
		}
	}
	return ""
}

// embeddedUnits: the files this release carries for s.
func (s *initSys) embeddedUnits() map[string][]byte {
	out := make(map[string][]byte, len(s.units))
	for _, n := range s.units {
		b, _ := embeddedUnit(n)
		out[n] = b
	}
	return out
}
