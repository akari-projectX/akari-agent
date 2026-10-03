package main

// W26: the protocol capability manifest (proto/protocols.toml), a
// byte-identical copy of akari-panel's canonical file (`make sync-proto`,
// `make check-proto`). The agent takes from it what it enforces: the
// managed protocols (wire names), the credential rules (VLESS flows,
// Shadowsocks 2022 methods and key lengths, minimum lengths), which
// protocols are shrink-unsafe (tombstones), and the canary scenarios
// (rt_matrix_test.go). Per-protocol behaviour lives in the protocol
// modules (proto_*.go); everything kernel-specific (xray types and field
// names) stays there.
//
// The file is compiled in (go:embed) and parsed once at start-up; a broken
// file cannot reach a release (TestManifest*), so a parse failure panics.

import (
	_ "embed"
	"fmt"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed proto/protocols.toml
var manifestTOML string

type manifestField struct {
	Name          string   `toml:"name"`
	LabelZh       string   `toml:"label_zh"`
	Type          string   `toml:"type"`
	Values        []string `toml:"values"`
	ValueLabelsZh []string `toml:"value_labels_zh"`
	KeyLen        []int    `toml:"key_len"`
	KeyLenFrom    string   `toml:"key_len_from"`
	Default       *string  `toml:"default"`
	Required      bool     `toml:"required"`
	Generated     bool     `toml:"generated"`
	HelpZh        string   `toml:"help_zh"`
}

type manifestCredential struct {
	Field      string `toml:"field"`
	Kind       string `toml:"kind"`
	From       string `toml:"from"`
	Bytes      int    `toml:"bytes"`
	KeyLenFrom string `toml:"key_len_from"`
	MinLen     int    `toml:"min_len"`
}

type manifestProtocol struct {
	ID                  string               `toml:"id"`
	Wire                string               `toml:"wire"`
	Label               string               `toml:"label"`
	LabelZh             string               `toml:"label_zh"`
	Transports          []string             `toml:"transports"`
	Security            []string             `toml:"security"`
	L4                  string               `toml:"l4"`
	TemplateRequiresTLS bool                 `toml:"template_requires_tls"`
	ShrinkUnsafe        bool                 `toml:"shrink_unsafe"`
	ALPN                []string             `toml:"alpn"`
	Credential          []manifestCredential `toml:"credential"`
	Option              []manifestField      `toml:"option"`
}

type manifestLayer struct {
	ID               string          `toml:"id"`
	Label            string          `toml:"label"`
	LabelZh          string          `toml:"label_zh"`
	NeedsCertificate bool            `toml:"needs_certificate"`
	ALPN             []string        `toml:"alpn"`
	Field            []manifestField `toml:"field"`
}

type manifestRule struct {
	ID           string              `toml:"id"`
	TemplateOnly bool                `toml:"template_only"`
	When         map[string][]string `toml:"when"`
	Require      map[string][]string `toml:"require"`
	Doc          string              `toml:"doc"`
}

type manifestScenario struct {
	Name      string            `toml:"name"`
	Protocol  string            `toml:"protocol"`
	Transport string            `toml:"transport"`
	Security  string            `toml:"security"`
	Options   map[string]string `toml:"options"`
}

type manifestFormat struct {
	ID          string            `toml:"id"`
	Label       string            `toml:"label"`
	Notes       map[string]string `toml:"notes"`
	Unsupported []struct {
		Protocol    []string `toml:"protocol"`
		ProtocolNot []string `toml:"protocol_not"`
		Transport   []string `toml:"transport"`
		Security    []string `toml:"security"`
		Reason      string   `toml:"reason"`
	} `toml:"unsupported"`
}

type protocolManifest struct {
	Schema int `toml:"schema"`
	Kernel []struct {
		ID      string `toml:"id"`
		Label   string `toml:"label"`
		Version string `toml:"version"`
	} `toml:"kernel"`
	Security  []manifestLayer    `toml:"security"`
	Transport []manifestLayer    `toml:"transport"`
	Protocol  []manifestProtocol `toml:"protocol"`
	Rule      []manifestRule     `toml:"rule"`
	Format    []manifestFormat   `toml:"format"`
	Scenario  []manifestScenario `toml:"scenario"`
}

// manifest is the compiled-in manifest.
var manifest = mustParseManifest(manifestTOML)

func mustParseManifest(src string) *protocolManifest {
	m, err := parseManifest(src)
	if err != nil {
		panic("proto/protocols.toml: " + err.Error())
	}
	return m
}

// parseManifest decodes strictly (unknown keys are errors, like the
// panel's parser) and checks what the agent relies on. The panel's
// validator (manifest_def.rs) is the complete one; both read the same file.
func parseManifest(src string) (*protocolManifest, error) {
	var m protocolManifest
	md, err := toml.Decode(src, &m)
	if err != nil {
		return nil, err
	}
	if und := md.Undecoded(); len(und) > 0 {
		return nil, fmt.Errorf("unknown keys %v", und)
	}
	if m.Schema != 1 {
		return nil, fmt.Errorf("schema %d (this agent reads schema 1)", m.Schema)
	}
	transports := map[string]bool{}
	for _, t := range m.Transport {
		transports[t.ID] = true
	}
	securities := map[string]bool{}
	for _, s := range m.Security {
		securities[s.ID] = true
	}
	wires := map[string]bool{}
	for _, p := range m.Protocol {
		if p.ID == "" || p.Wire == "" || wires[p.Wire] {
			return nil, fmt.Errorf("protocol %q: empty or duplicate wire name %q", p.ID, p.Wire)
		}
		wires[p.Wire] = true
		for _, t := range p.Transports {
			if !transports[t] {
				return nil, fmt.Errorf("protocol %q: unknown transport %q", p.ID, t)
			}
		}
		for _, s := range p.Security {
			if !securities[s] {
				return nil, fmt.Errorf("protocol %q: unknown security %q", p.ID, s)
			}
		}
		for _, o := range p.Option {
			if len(o.KeyLen) > 0 && len(o.KeyLen) != len(o.Values) {
				return nil, fmt.Errorf("protocol %q option %q: key_len does not match values", p.ID, o.Name)
			}
		}
	}
	if len(m.Protocol) == 0 {
		return nil, fmt.Errorf("no protocols")
	}
	for _, s := range m.Scenario {
		p := m.protocolByID(s.Protocol)
		if p == nil || !slices.Contains(p.Transports, s.Transport) || !slices.Contains(p.Security, s.Security) {
			return nil, fmt.Errorf("scenario %q: not a combination its protocol accepts", s.Name)
		}
	}
	return &m, nil
}

func (m *protocolManifest) protocolByID(id string) *manifestProtocol {
	for i := range m.Protocol {
		if m.Protocol[i].ID == id {
			return &m.Protocol[i]
		}
	}
	return nil
}

// protocolByWire: the manifest protocol of an agent-contract name
// (InboundUser.protocol).
func (m *protocolManifest) protocolByWire(wire string) *manifestProtocol {
	for i := range m.Protocol {
		if m.Protocol[i].Wire == wire {
			return &m.Protocol[i]
		}
	}
	return nil
}

func (p *manifestProtocol) option(name string) *manifestField {
	for i := range p.Option {
		if p.Option[i].Name == name {
			return &p.Option[i]
		}
	}
	return nil
}

func (p *manifestProtocol) credential(field string) *manifestCredential {
	for i := range p.Credential {
		if p.Credential[i].Field == field {
			return &p.Credential[i]
		}
	}
	return nil
}

// keyLens: value -> key length of an enum option carrying key_len.
func (f *manifestField) keyLens() map[string]int {
	out := make(map[string]int, len(f.Values))
	for i, v := range f.Values {
		if i < len(f.KeyLen) {
			out[v] = f.KeyLen[i]
		}
	}
	return out
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

func (s manifestScenario) String() string {
	var opts []string
	for k, v := range s.Options {
		opts = append(opts, k+"="+v)
	}
	return fmt.Sprintf("%s (%s/%s/%s %s)", s.Name, s.Protocol, s.Transport, s.Security, strings.Join(opts, ","))
}
