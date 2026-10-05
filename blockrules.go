package main

// W29: node block rules (面板「审计规则」, capability "block-rules").
//
// The panel compiles the rules; the agent only installs them into xray
// routing. PanelDown.block_policy carries the whole policy (never part of a
// Snapshot: no config_version, no state hash). Three pieces:
//
//   - blockRouter wraps the instance's routing.Router (xray's DefaultRouter:
//     the agent's config has no routing section) inside the gate. A policy
//     is compiled into a fresh, immutable xray *router.Router (xray's own
//     matchers: succinct domain matcher, CIDR tries, sniffed protocol) and
//     published with one atomic pointer store. In-place rule edits through
//     xray's RoutingService (Router.AddRule/RemoveRule/ReloadRules) are not
//     used: they reassign the rule slice while PickRoute iterates it without
//     the router's lock (a data race in v26.3.27). A rule CONTENT change is
//     therefore a pointer swap: no rebuild, no handler change, no dropped
//     connection. With no policy the pointer is nil and PickRoute costs one
//     atomic load before the base router answers exactly as before.
//   - every match routes to the "akari-block" blackhole outbound, added to
//     the outbound manager at runtime while a policy is in force and removed
//     after it: the xray config of a node without block rules is
//     byte-identical to one built by an agent without the feature.
//   - the audited inbounds sniff (routeOnly: sniffed names feed routing only,
//     never the destination; inbounds whose own config already sniffs are
//     left as they are). Sniffing is fixed in an inbound handler, so a change
//     of the audited set (the per-node switch) re-creates only the handlers
//     of the inbounds whose sniffing changes (CoreManager.reloadInboundsLocked,
//     users re-added with their existing *MemoryUser: gate identities, the
//     session and the counters stay).
//
// Hits are counted per rule in the router wrapper (one atomic add per
// blocked dispatch) and reported cumulatively per agent process (epoch) in
// Heartbeat.block: aggregate counts only, nothing per user or destination.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	commonserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/blackhole"

	"akari/agent/pb"
)

// blockOutboundTag: the blackhole outbound every rule targets. The "akari-"
// prefix is reserved by the panel (no admin inbound/outbound may use it).
const blockOutboundTag = "akari-block"

// Bounds on panel input (the panel allows 3 built-ins + 32 custom rules of
// at most 1000 entries each; the built-in tracker list is ~450 entries).
const (
	maxBlockRules       = 64
	maxBlockEntries     = 4096 // per rule and kind
	maxBlockTags        = 256
	maxBlockVersionLen  = 64
	maxBlockDomainLen   = 253
	maxBlockErrorReport = 256
)

// blockSniffOverride: what audited inbounds sniff names from. xray runs
// every sniffer once sniffing is on (protocol detection, BitTorrent
// included, does not depend on this list); the list only selects which
// sniffed names feed routing (routeOnly).
var blockSniffOverride = []string{"http", "tls", "quic"}

// blockProtocols: the sniffed protocol names a rule may match.
var blockProtocols = []string{"bittorrent", "http", "tls", "quic"}

// blockSet is one compiled policy: an xray router that is never mutated
// after Init, and the hit counter of each of its rule tags.
type blockSet struct {
	router  *router.Router
	counter map[string]*atomic.Uint64
}

// blockRouter is the routing.Router the gate's inner dispatcher uses.
type blockRouter struct {
	base routing.Router
	set  atomic.Pointer[blockSet]
}

var _ routing.Router = (*blockRouter)(nil)

func newBlockRouter(base routing.Router) *blockRouter { return &blockRouter{base: base} }

func (*blockRouter) Type() interface{} { return routing.RouterType() }
func (*blockRouter) Start() error      { return nil }
func (*blockRouter) Close() error      { return nil }

// PickRoute: the block rules first (when a policy is in force), then the
// base router — unchanged behaviour for everything the rules do not match.
func (b *blockRouter) PickRoute(ctx routing.Context) (routing.Route, error) {
	if s := b.set.Load(); s != nil {
		if r, err := s.router.PickRoute(ctx); err == nil {
			if c := s.counter[r.GetRuleTag()]; c != nil {
				c.Add(1)
			}
			return r, nil
		}
	}
	return b.base.PickRoute(ctx)
}

// The RoutingService mutators are not supported (see the file comment).
func (*blockRouter) AddRule(*commonserial.TypedMessage, bool) error {
	return fmt.Errorf("akari: routing rules are managed by the panel")
}
func (*blockRouter) RemoveRule(string) error {
	return fmt.Errorf("akari: routing rules are managed by the panel")
}
func (b *blockRouter) ListRule() []routing.Route {
	if s := b.set.Load(); s != nil {
		return s.router.ListRule()
	}
	return b.base.ListRule()
}

// blockState is the agent's policy and counters, kept across instances
// (a Rebuild installs the current policy into the new instance).
type blockState struct {
	mu      sync.Mutex
	policy  *pb.BlockPolicy // last received (nil = none yet, i.e. off)
	applied string          // version in force on the running instance
	lastErr string
	epoch   string
	hits    map[uint64]*atomic.Uint64
}

func newBlockState() *blockState {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return &blockState{epoch: hex.EncodeToString(b[:]), hits: make(map[uint64]*atomic.Uint64)}
}

// counter returns the process-lifetime counter of rule id (never removed:
// a rule switched off and on again keeps counting from where it was, so the
// panel's cumulative baseline stays valid).
func (s *blockState) counter(id uint64) *atomic.Uint64 {
	c := s.hits[id]
	if c == nil {
		c = new(atomic.Uint64)
		s.hits[id] = c
	}
	return c
}

// stats: Heartbeat.block (nil until the panel sent a policy and nothing was
// ever counted: an old panel never sees the field).
func (s *blockState) stats() *pb.BlockStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.policy == nil && len(s.hits) == 0 {
		return nil
	}
	out := &pb.BlockStats{Epoch: s.epoch, Applied: s.applied, Error: s.lastErr}
	for id, c := range s.hits {
		if n := c.Load(); n > 0 {
			out.Hits = append(out.Hits, &pb.BlockHits{RuleId: id, Hits: n})
		}
	}
	slices.SortFunc(out.Hits, func(a, b *pb.BlockHits) int {
		switch {
		case a.RuleId < b.RuleId:
			return -1
		case a.RuleId > b.RuleId:
			return 1
		}
		return 0
	})
	return out
}

func (s *blockState) setError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastErr = shortErr(err)
}

// setApplied records the version in force ("" = off) and clears the error.
func (s *blockState) setApplied(version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied = version
	s.lastErr = ""
}

// sniffTags: the inbounds that must sniff under the current policy.
func (s *blockState) sniffTags() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return policySniffTags(s.policy)
}

func policySniffTags(p *pb.BlockPolicy) map[string]bool {
	if p == nil || len(p.InboundTags) == 0 {
		return nil
	}
	out := make(map[string]bool, len(p.InboundTags))
	for _, t := range p.InboundTags {
		out[t] = true
	}
	return out
}

// validateBlockPolicy checks panel input before anything is touched.
func validateBlockPolicy(p *pb.BlockPolicy) error {
	if len(p.InboundTags) > maxBlockTags || len(p.Rules) > maxBlockRules {
		return fmt.Errorf("block policy too large")
	}
	if len(p.Version) > maxBlockVersionLen {
		return fmt.Errorf("block policy version too long")
	}
	if len(p.InboundTags) == 0 {
		return nil
	}
	seen := make(map[uint64]bool, len(p.Rules))
	for _, t := range p.InboundTags {
		if t == "" {
			return fmt.Errorf("empty inbound tag")
		}
	}
	for _, r := range p.Rules {
		if seen[r.Id] {
			return fmt.Errorf("duplicate rule id %d", r.Id)
		}
		seen[r.Id] = true
		if len(r.Domains) > maxBlockEntries || len(r.Cidrs) > maxBlockEntries || len(r.Protocols) > len(blockProtocols) {
			return fmt.Errorf("rule %d: too many entries", r.Id)
		}
		if len(r.Domains)+len(r.Cidrs)+len(r.Protocols) == 0 {
			return fmt.Errorf("rule %d: no entries", r.Id)
		}
	}
	return nil
}

// blockDomain: "domain:"/"full:"/"keyword:" entries only (never regexp,
// geosite or ext: — no file is ever read on behalf of the panel).
func blockDomain(s string) (*router.Domain, error) {
	kind, value, ok := strings.Cut(s, ":")
	if !ok || value == "" || len(value) > maxBlockDomainLen {
		return nil, fmt.Errorf("bad domain entry %q", s)
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return nil, fmt.Errorf("bad domain entry %q", s)
		}
	}
	switch kind {
	case "domain":
		return &router.Domain{Type: router.Domain_Domain, Value: value}, nil
	case "full":
		return &router.Domain{Type: router.Domain_Full, Value: value}, nil
	case "keyword":
		return &router.Domain{Type: router.Domain_Plain, Value: value}, nil
	}
	return nil, fmt.Errorf("bad domain entry %q", s)
}

func blockCIDR(s string) (*router.CIDR, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return nil, fmt.Errorf("bad network %q", s)
	}
	p = p.Masked()
	return &router.CIDR{Ip: p.Addr().AsSlice(), Prefix: uint32(p.Bits())}, nil
}

// blockRuleTag names one compiled xray rule: a panel rule becomes up to
// three (domains, networks, protocols: conditions within one xray rule are
// ANDed, a panel rule's entries are ORed).
func blockRuleTag(id uint64, part string) string {
	return "akari-block-" + strconv.FormatUint(id, 10) + "-" + part
}

// compileBlockRules turns a validated policy into xray's router config and
// the rule-tag -> panel rule id map.
func compileBlockRules(p *pb.BlockPolicy) (*router.Config, map[string]uint64, error) {
	cfg := &router.Config{DomainStrategy: router.Config_AsIs}
	ids := make(map[string]uint64)
	tags := slices.Clone(p.InboundTags)
	target := &router.RoutingRule_Tag{Tag: blockOutboundTag}
	add := func(id uint64, part string, fill func(*router.RoutingRule)) {
		r := &router.RoutingRule{RuleTag: blockRuleTag(id, part), TargetTag: target, InboundTag: tags}
		fill(r)
		cfg.Rule = append(cfg.Rule, r)
		ids[r.RuleTag] = id
	}
	for _, r := range p.Rules {
		if len(r.Domains) > 0 {
			domains := make([]*router.Domain, 0, len(r.Domains))
			for _, d := range r.Domains {
				dd, err := blockDomain(d)
				if err != nil {
					return nil, nil, fmt.Errorf("rule %d: %w", r.Id, err)
				}
				domains = append(domains, dd)
			}
			add(r.Id, "d", func(x *router.RoutingRule) { x.Domain = domains })
		}
		if len(r.Cidrs) > 0 {
			cidrs := make([]*router.CIDR, 0, len(r.Cidrs))
			for _, c := range r.Cidrs {
				cc, err := blockCIDR(c)
				if err != nil {
					return nil, nil, fmt.Errorf("rule %d: %w", r.Id, err)
				}
				cidrs = append(cidrs, cc)
			}
			add(r.Id, "i", func(x *router.RoutingRule) { x.Geoip = []*router.GeoIP{{Cidr: cidrs}} })
		}
		if len(r.Protocols) > 0 {
			for _, proto := range r.Protocols {
				if !slices.Contains(blockProtocols, proto) {
					return nil, nil, fmt.Errorf("rule %d: unknown protocol %q", r.Id, proto)
				}
			}
			protos := slices.Clone(r.Protocols)
			add(r.Id, "p", func(x *router.RoutingRule) { x.Protocol = protos })
		}
	}
	return cfg, ids, nil
}

// newBlockSet builds the immutable router for a policy on an instance.
func newBlockSet(inst *core.Instance, gate *gateDispatcher, p *pb.BlockPolicy, counter func(uint64) *atomic.Uint64) (*blockSet, error) {
	cfg, ids, err := compileBlockRules(p)
	if err != nil {
		return nil, err
	}
	ohm, ok := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok {
		return nil, fmt.Errorf("outbound manager missing")
	}
	dnsClient, _ := inst.GetFeature(dns.ClientType()).(dns.Client)
	r := new(router.Router)
	if err := r.Init(context.Background(), cfg, dnsClient, ohm, gate); err != nil {
		return nil, fmt.Errorf("build routing rules: %w", err)
	}
	set := &blockSet{router: r, counter: make(map[string]*atomic.Uint64, len(ids))}
	for tag, id := range ids {
		set.counter[tag] = counter(id)
	}
	return set, nil
}

// ensureBlockOutbound adds the blackhole outbound if missing.
func ensureBlockOutbound(inst *core.Instance) error {
	ohm, ok := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok {
		return fmt.Errorf("outbound manager missing")
	}
	if ohm.GetHandler(blockOutboundTag) != nil {
		return nil
	}
	return core.AddOutboundHandler(inst, &core.OutboundHandlerConfig{
		Tag:           blockOutboundTag,
		ProxySettings: commonserial.ToTypedMessage(&blackhole.Config{}),
	})
}

// removeBlockOutbound drops the blackhole outbound (after the rules that
// target it were unpublished).
func removeBlockOutbound(inst *core.Instance) {
	ohm, ok := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok || ohm.GetHandler(blockOutboundTag) == nil {
		return
	}
	_ = ohm.RemoveHandler(context.Background(), blockOutboundTag)
}

// addBlockSniffing turns on routeOnly sniffing in the receiver settings of
// the listed inbounds whose own config does not sniff. Returns the tags it
// changed. Inbounds not listed are untouched (byte-identical config).
func addBlockSniffing(cfg *core.Config, sniff map[string]bool) ([]string, error) {
	if len(sniff) == 0 {
		return nil, nil
	}
	var changed []string
	for _, in := range cfg.Inbound {
		if !sniff[in.Tag] || in.ReceiverSettings == nil {
			continue
		}
		msg, err := in.ReceiverSettings.GetInstance()
		if err != nil {
			return nil, fmt.Errorf("inbound %q: receiver settings: %w", in.Tag, err)
		}
		rc, ok := msg.(*proxyman.ReceiverConfig)
		if !ok {
			continue
		}
		if rc.SniffingSettings != nil && rc.SniffingSettings.Enabled {
			continue
		}
		rc.SniffingSettings = &proxyman.SniffingConfig{
			Enabled:             true,
			DestinationOverride: slices.Clone(blockSniffOverride),
			RouteOnly:           true,
		}
		in.ReceiverSettings = commonserial.ToTypedMessage(rc)
		changed = append(changed, in.Tag)
	}
	return changed, nil
}

// shortErr bounds an error for the heartbeat.
func shortErr(err error) string {
	s := err.Error()
	if len(s) > maxBlockErrorReport {
		s = s[:maxBlockErrorReport]
	}
	return s
}
