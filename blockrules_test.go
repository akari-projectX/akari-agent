package main

// W29 block rules: policy validation and compilation, the config of a node
// without block rules (byte-identical), and live behaviour on a real xray
// instance — blocked by name, by network and by sniffed protocol, counted,
// content swapped without a rebuild or a dropped connection, the per-node
// switch re-creating only the audited inbound.

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	routingsession "github.com/xtls/xray-core/features/routing/session"
	"google.golang.org/protobuf/proto"

	"akari/agent/pb"
)

// vlessDialName: a raw VLESS connection to a destination given by name.
func vlessDialName(inboundPort int, id, host string, destPort int) (*vlessConn, error) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", inboundPort), 2*time.Second)
	if err != nil {
		return nil, err
	}
	u, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}
	hdr := []byte{0}
	hdr = append(hdr, u[:]...)
	hdr = append(hdr, 0, 1)
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(destPort))
	hdr = append(hdr, 2, byte(len(host)))
	hdr = append(hdr, host...)
	if _, err := c.Write(hdr); err != nil {
		c.Close()
		return nil, err
	}
	return &vlessConn{Conn: c, r: bufio.NewReader(c)}, nil
}

// blocked: the proxy refuses to relay (the blackhole closes the link).
func blocked(c *vlessConn, err error, payload string) bool {
	if err != nil {
		return true
	}
	defer c.Close()
	return c.echo(payload) != nil
}

func blockPol(tags []string, rules ...*pb.BlockRule) *pb.BlockPolicy {
	return &pb.BlockPolicy{InboundTags: tags, Rules: rules, Version: fmt.Sprintf("v-%d-%d", len(tags), len(rules))}
}

func hitsOf(s *pb.BlockStats, id uint64) uint64 {
	for _, h := range s.GetHits() {
		if h.RuleId == id {
			return h.Hits
		}
	}
	return 0
}

func TestBlockPolicyValidation(t *testing.T) {
	ok := blockPol([]string{"in-a"}, &pb.BlockRule{Id: 1, Domains: []string{"domain:a.example", "full:b.example", "keyword:torrent"}},
		&pb.BlockRule{Id: 2, Cidrs: []string{"192.0.2.77/24", "2001:db8::/32", "198.51.100.1/32"}},
		&pb.BlockRule{Id: 3, Protocols: []string{"bittorrent"}})
	if err := validateBlockPolicy(ok); err != nil {
		t.Fatal(err)
	}
	cfg, ids, err := compileBlockRules(ok)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rule) != 3 || ids["akari-block-2-i"] != 2 || ids["akari-block-3-p"] != 3 {
		t.Fatalf("rules %v ids %v", cfg.Rule, ids)
	}
	if got := cfg.Rule[1].Geoip[0].Cidr[0]; got.Prefix != 24 || net.IP(got.Ip).String() != "192.0.2.0" {
		t.Fatalf("network not masked: %v", got)
	}
	for _, r := range cfg.Rule {
		if !slices.Equal(r.InboundTag, []string{"in-a"}) || r.GetTag() != blockOutboundTag {
			t.Fatalf("rule %v", r)
		}
	}
	// A mixed panel rule becomes one xray rule per kind (ORed, not ANDed).
	mixed := blockPol([]string{"x"}, &pb.BlockRule{Id: 9, Domains: []string{"full:a.example"}, Cidrs: []string{"10.0.0.0/8"}})
	if cfg, _, err := compileBlockRules(mixed); err != nil || len(cfg.Rule) != 2 {
		t.Fatalf("mixed rule: %v %v", cfg, err)
	}

	for name, bad := range map[string]*pb.BlockPolicy{
		"geosite":   blockPol([]string{"x"}, &pb.BlockRule{Id: 1, Domains: []string{"geosite:cn"}}),
		"ext file":  blockPol([]string{"x"}, &pb.BlockRule{Id: 1, Domains: []string{"ext:/etc/passwd:x"}}),
		"regexp":    blockPol([]string{"x"}, &pb.BlockRule{Id: 1, Domains: []string{"regexp:.*"}}),
		"bare name": blockPol([]string{"x"}, &pb.BlockRule{Id: 1, Domains: []string{"a.example"}}),
		"upper":     blockPol([]string{"x"}, &pb.BlockRule{Id: 1, Domains: []string{"full:A.example"}}),
		"geoip":     blockPol([]string{"x"}, &pb.BlockRule{Id: 1, Cidrs: []string{"geoip:cn"}}),
		"cidr":      blockPol([]string{"x"}, &pb.BlockRule{Id: 1, Cidrs: []string{"10.0.0.0/33"}}),
		"protocol":  blockPol([]string{"x"}, &pb.BlockRule{Id: 1, Protocols: []string{"ssh"}}),
	} {
		if err := validateBlockPolicy(bad); err == nil {
			if _, _, err := compileBlockRules(bad); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
	}
	for name, bad := range map[string]*pb.BlockPolicy{
		"empty rule":   blockPol([]string{"x"}, &pb.BlockRule{Id: 1}),
		"duplicate id": blockPol([]string{"x"}, &pb.BlockRule{Id: 1, Protocols: []string{"quic"}}, &pb.BlockRule{Id: 1, Protocols: []string{"tls"}}),
		"empty tag":    blockPol([]string{""}, &pb.BlockRule{Id: 1, Protocols: []string{"quic"}}),
		"long version": {InboundTags: []string{"x"}, Version: strings.Repeat("v", 65)},
		"many entries": blockPol([]string{"x"}, &pb.BlockRule{Id: 1, Cidrs: make([]string, maxBlockEntries+1)}),
	} {
		if validateBlockPolicy(bad) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	tooMany := &pb.BlockPolicy{InboundTags: []string{"x"}}
	for i := 0; i <= maxBlockRules; i++ {
		tooMany.Rules = append(tooMany.Rules, &pb.BlockRule{Id: uint64(i), Protocols: []string{"quic"}})
	}
	if validateBlockPolicy(tooMany) == nil {
		t.Error("too many rules accepted")
	}
	// Off: no tags, nothing else is looked at.
	if err := validateBlockPolicy(&pb.BlockPolicy{}); err != nil {
		t.Fatal(err)
	}
}

// Without block rules the config is byte-identical to the pre-W29 one;
// sniffing changes only the listed inbounds, and never an inbound that
// sniffs on its own.
func TestBlockSniffingConfig(t *testing.T) {
	inbounds := []json.RawMessage{
		json.RawMessage(`{"tag":"in-a","listen":"127.0.0.1","port":1,"protocol":"vless","settings":{"clients":[],"decryption":"none"}}`),
		json.RawMessage(`{"tag":"in-b","listen":"127.0.0.1","port":2,"protocol":"vless","settings":{"clients":[],"decryption":"none"}}`),
		json.RawMessage(`{"tag":"in-c","listen":"127.0.0.1","port":3,"protocol":"vless","settings":{"clients":[],"decryption":"none"},` +
			`"sniffing":{"enabled":true,"destOverride":["tls"]}}`),
	}
	base, _, _, err := buildConfig(inbounds, nil)
	if err != nil {
		t.Fatal(err)
	}
	marshal := func(m proto.Message) []byte {
		b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, sniff := range []map[string]bool{nil, {}, {"absent": true}} {
		off, err := buildConfigFor(inbounds, nil, sniff)
		if err != nil {
			t.Fatal(err)
		}
		if string(marshal(off.config)) != string(marshal(base)) || len(off.sniffed) != 0 {
			t.Fatalf("config without block rules differs (sniff %v)", sniff)
		}
	}
	on, err := buildConfigFor(inbounds, nil, map[string]bool{"in-a": true, "in-c": true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(on.sniffed, []string{"in-a"}) {
		t.Fatalf("sniffed %v", on.sniffed)
	}
	for i, in := range on.config.Inbound {
		changed := string(marshal(in)) != string(marshal(base.Inbound[i]))
		if changed != (in.Tag == "in-a") {
			t.Fatalf("inbound %s changed=%v", in.Tag, changed)
		}
	}
	msg, err := on.config.Inbound[0].ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	s := msg.(*proxyman.ReceiverConfig).SniffingSettings
	if !s.Enabled || !s.RouteOnly || s.MetadataOnly || !slices.Equal(s.DestinationOverride, blockSniffOverride) {
		t.Fatalf("sniffing %+v", s)
	}
}

// Live: rules block by name, network and sniffed protocol on the audited
// inbound only, count per rule, and swap without a rebuild; the switch
// re-creates the audited inbound's handler only (an accepted raw TCP
// connection keeps running); off removes everything.
func TestBlockRulesLive(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	echo := echoServer(t)
	pa, pb2 := freePort(t), freePort(t)
	users := []*pb.UserOp{{Op: pb.UserOp_ADD, UserId: userA, InboundUsers: []*pb.InboundUser{
		{InboundTag: "in-a", Protocol: "vless", AccountJson: fmt.Sprintf(`{"flow":"","id":%q}`, idA)},
		{InboundTag: "in-b", Protocol: "vless", AccountJson: fmt.Sprintf(`{"flow":"","id":%q}`, idA)},
	}}}
	if _, err := m.Rebuild(twoInbounds(pa, pb2), users); err != nil {
		t.Fatal(err)
	}
	session := m.SessionID()
	if st := m.BlockStats(); st != nil {
		t.Fatalf("stats before any policy: %v", st)
	}
	// Established before the switch, on both inbounds.
	ca, err := vlessDial(pa, idA, echo)
	mustEcho(t, ca, err, "a-before")
	defer ca.Close()
	cb, err := vlessDial(pb2, idA, echo)
	mustEcho(t, cb, err, "b-before")
	defer cb.Close()

	byName := &pb.BlockRule{Id: 7, Domains: []string{"full:localhost"}}
	if err := m.SetBlockPolicy(blockPol([]string{"in-a"}, byName)); err != nil {
		t.Fatal(err)
	}
	if !m.sniffed["in-a"] || m.sniffed["in-b"] {
		t.Fatalf("sniffed %v", m.sniffed)
	}
	if err := ca.echo("a-after-switch"); err != nil {
		t.Fatalf("raw TCP connection on the re-created inbound dropped: %v", err)
	}
	if err := cb.echo("b-after-switch"); err != nil {
		t.Fatalf("other inbound disturbed: %v", err)
	}
	if c, err := vlessDialName(pa, idA, "localhost", echo); !blocked(c, err, "x") {
		t.Fatal("blocked name relayed on the audited inbound")
	}
	if c, err := vlessDialName(pb2, idA, "localhost", echo); blocked(c, err, "x") {
		t.Fatal("name blocked on an inbound without block rules")
	}
	if c, err := vlessDial(pa, idA, echo); blocked(c, err, "x") {
		t.Fatal("unmatched destination blocked")
	}
	st := m.BlockStats()
	if hitsOf(st, 7) != 1 || st.Applied != "v-1-1" || st.Error != "" || st.Epoch == "" {
		t.Fatalf("stats %v", st)
	}

	// BitTorrent by sniffing (the payload, not the destination).
	bt := &pb.BlockRule{Id: 8, Protocols: []string{"bittorrent"}}
	if err := m.SetBlockPolicy(blockPol([]string{"in-a"}, byName, bt)); err != nil {
		t.Fatal(err)
	}
	if c, err := vlessDial(pa, idA, echo); !blocked(c, err, "\x13BitTorrent protocol"+strings.Repeat("\x00", 48)) {
		t.Fatal("BitTorrent handshake relayed")
	}
	if hitsOf(m.BlockStats(), 8) != 1 {
		t.Fatalf("stats %v", m.BlockStats())
	}

	// Content change: a network rule replaces the name rule. Same audited
	// set: no handler change, the connections stay, the counters continue.
	handlerBefore := inboundHandler(t, m, "in-a")
	byNet := &pb.BlockRule{Id: 9, Cidrs: []string{"127.0.0.1/32"}}
	if err := m.SetBlockPolicy(blockPol([]string{"in-a"}, byNet)); err != nil {
		t.Fatal(err)
	}
	if inboundHandler(t, m, "in-a") != handlerBefore {
		t.Fatal("a content change re-created the inbound")
	}
	if err := ca.echo("a-after-content"); err != nil {
		t.Fatalf("connection dropped by a content change: %v", err)
	}
	if c, err := vlessDial(pa, idA, echo); !blocked(c, err, "x") {
		t.Fatal("blocked network relayed")
	}
	if c, err := vlessDialName(pa, idA, "localhost", echo); blocked(c, err, "x") {
		t.Fatal("name request matched a network rule (no DNS for block rules)")
	}
	st = m.BlockStats()
	if hitsOf(st, 7) != 1 || hitsOf(st, 8) != 1 || hitsOf(st, 9) != 1 {
		t.Fatalf("stats %v", st)
	}

	// Off: sniffing and rules removed, the blackhole outbound too.
	if err := m.SetBlockPolicy(&pb.BlockPolicy{}); err != nil {
		t.Fatal(err)
	}
	if len(m.sniffed) != 0 || m.gate.blocks.set.Load() != nil {
		t.Fatalf("still on: sniffed %v", m.sniffed)
	}
	if m.instance.GetFeature(outbound.ManagerType()).(outbound.Manager).GetHandler(blockOutboundTag) != nil {
		t.Fatal("blackhole outbound left behind")
	}
	if c, err := vlessDial(pa, idA, echo); blocked(c, err, "x") {
		t.Fatal("blocked after the switch went off")
	}
	if err := ca.echo("a-after-off"); err != nil {
		t.Fatalf("raw TCP connection dropped by switching off: %v", err)
	}
	if st := m.BlockStats(); st.Applied != "" || hitsOf(st, 9) != 1 {
		t.Fatalf("stats after off %v", st)
	}
	if m.SessionID() != session {
		t.Fatal("block policy rebuilt the instance")
	}
}

// A Rebuild (Snapshot) installs the current policy into the new instance;
// a policy that does not compile changes nothing and is reported.
func TestBlockPolicySurvivesRebuildAndRejectsBadInput(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	echo := echoServer(t)
	pa := freePort(t)
	// Received before any instance: kept for the next Rebuild.
	if err := m.SetBlockPolicy(blockPol([]string{"in-a"}, &pb.BlockRule{Id: 1, Domains: []string{"full:localhost"}})); err != nil {
		t.Fatal(err)
	}
	if st := m.BlockStats(); st.Applied != "" {
		t.Fatalf("applied without an instance: %v", st)
	}
	if _, err := m.Rebuild(twoInbounds(pa, freePort(t)), []*pb.UserOp{vlessUser(userA, "in-a", idA)}); err != nil {
		t.Fatal(err)
	}
	if !m.sniffed["in-a"] || m.BlockStats().Applied != "v-1-1" {
		t.Fatalf("policy not installed by the rebuild: %v %v", m.sniffed, m.BlockStats())
	}
	if c, err := vlessDialName(pa, idA, "localhost", echo); !blocked(c, err, "x") {
		t.Fatal("not blocked after the rebuild")
	}
	bad := blockPol([]string{"in-a"}, &pb.BlockRule{Id: 2, Domains: []string{"geosite:cn"}})
	if err := m.SetBlockPolicy(bad); err != nil {
		t.Fatal(err)
	}
	st := m.BlockStats()
	if st.Applied != "v-1-1" || !strings.Contains(st.Error, "geosite") {
		t.Fatalf("bad policy: %v", st)
	}
	if c, err := vlessDialName(pa, idA, "localhost", echo); !blocked(c, err, "x") {
		t.Fatal("a rejected policy replaced the one in force")
	}
}

func inboundHandler(t *testing.T, m *CoreManager, tag string) any {
	t.Helper()
	im, err := m.manager()
	if err != nil {
		t.Fatal(err)
	}
	h, err := im.GetHandler(context.Background(), tag)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// The router wrapper: concurrent dispatches against concurrent swaps (the
// race detector checks there is no unsynchronised access; xray's own
// AddRule/RemoveRule would be flagged here).
func TestBlockRouterSwapIsRaceFree(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	if _, err := m.Rebuild(twoInbounds(freePort(t), freePort(t)), nil); err != nil {
		t.Fatal(err)
	}
	r := m.gate.blocks
	ctx := routingCtxFor("localhost", "in-a")
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = r.PickRoute(ctx)
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		p := blockPol([]string{"in-a"}, &pb.BlockRule{Id: uint64(i%3 + 1), Domains: []string{"full:localhost"}})
		if i%5 == 4 {
			p = &pb.BlockPolicy{}
		}
		if err := m.SetBlockPolicy(p); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	if err := r.AddRule(nil, true); err == nil {
		t.Fatal("RoutingService AddRule accepted")
	}
	if err := r.RemoveRule("x"); err == nil {
		t.Fatal("RoutingService RemoveRule accepted")
	}
	var _ routing.Router = r
}

// routingCtxFor is the routing context of a TCP dispatch to host:443 from
// the inbound tag.
func routingCtxFor(host, tag string) routing.Context {
	return &routingsession.Context{
		Inbound:  &session.Inbound{Tag: tag},
		Outbound: &session.Outbound{Target: xnet.TCPDestination(xnet.DomainAddress(host), 443)},
	}
}
