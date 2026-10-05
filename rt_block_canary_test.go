//go:build canary

// W29 audit rules over every manifest scenario, with a real xray client:
// which established connections survive the per-node switch (the only
// change that re-creates inbound handlers), that a rule-content change never
// touches an established connection, and that a rule blocks new connections
// of every protocol and counts them. Run WITHOUT -race: `make test-canary`.

package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"akari/agent/pb"
)

// switchOutcome: whether a scenario's established connection survives the
// per-node switch (which re-creates its inbound handler).
type switchOutcome int

const (
	switchKeeps switchOutcome = iota // always survives
	switchDrops                      // always cut; the client redials
	switchMay                        // timing-dependent: either is correct
)

func (o switchOutcome) String() string {
	return [...]string{"keeps", "drops", "may drop"}[o]
}

// blockSwitchOutcome: the scenarios whose established connections do not
// reliably survive the per-node switch (measured by this canary); every
// other scenario keeps them. Re-creating a handler closes its listener:
// connections on a raw TCP stream (TCP, TLS, REALITY, WebSocket,
// HTTPUpgrade, Shadowsocks 2022) and XHTTP over TLS/REALITY (one long
// HTTP/2 request per connection) belong to their own goroutines and keep
// relaying; gRPC (streams of a listener-owned HTTP/2 server) and Hysteria 2
// (QUIC connections owned by the listener) are cut and redialled by the
// client. Plain-HTTP XHTTP (the client's packet-up mode: every upload is a
// new request) survives only while the client sends its uploads over
// keep-alive connections the old handler still serves (xray's XHTTP
// listener Close closes only the listener); an upload on a fresh connection
// reaches the new handler, which does not know the session, and the client
// redials. Documented in the panel's DEPLOY §3h.
var blockSwitchOutcome = map[string]switchOutcome{
	"VLESS-XHTTP":        switchMay,
	"VLESS-gRPC-TLS":     switchDrops,
	"VLESS-REALITY-gRPC": switchDrops,
	"Trojan-gRPC-TLS":    switchDrops,
	"Hysteria2":          switchDrops,
}

func TestRT_BlockRulesMatrix(t *testing.T) {
	e := newMatrixEnv(t)
	realityDest := tlsEcho(t, e.cert)
	seen := map[string]bool{}
	for _, sc := range manifest.Scenario {
		tc, err := scenarioCase(e, realityDest, sc)
		if err != nil {
			t.Fatalf("%v: %v", sc, err)
		}
		seen[tc.name] = true
		want := blockSwitchOutcome[tc.name] // zero value: switchKeeps
		t.Run(tc.name, func(t *testing.T) { runBlockCase(t, e, tc, want) })
	}
	for name := range blockSwitchOutcome {
		if !seen[name] {
			t.Errorf("blockSwitchOutcome names %q, which is not a manifest scenario", name)
		}
	}
}

func runBlockCase(t *testing.T, e *matrixEnv, tc matrixCase, want switchOutcome) {
	m := NewCoreManager()
	defer m.Teardown()
	sp := freePort(t)
	inb := fmt.Sprintf(`[{"tag":"in","listen":"127.0.0.1","port":%d,%s}]`, sp, tc.inbound(sp))
	op := &pb.UserOp{Op: pb.UserOp_ADD, UserId: userA, InboundUsers: []*pb.InboundUser{{InboundTag: "in", Protocol: tc.protocol, AccountJson: tc.account}}}
	if _, err := m.Rebuild(inb, []*pb.UserOp{op}); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	echo := echoServer(t)
	if tc.innerTLS {
		echo = tlsEcho(t, e.cert)
	}
	cp := freePort(t)
	clientInstance(t, map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": cp, "protocol": "dokodemo-door",
			"settings": map[string]any{"address": "127.0.0.1", "port": echo, "network": "tcp"}}},
		"outbounds": []any{tc.outbound(sp)},
	})
	dial := func() (net.Conn, error) {
		raw, err := dialRetry(cp)
		if err != nil || !tc.innerTLS {
			return raw, err
		}
		return tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}), nil
	}
	// connect: a relaying connection (listeners of some transports come up
	// asynchronously, and clients redial sessions the server closed).
	connect := func(phase string) net.Conn {
		t.Helper()
		var err error
		for i := 0; i < 30; i++ {
			var c net.Conn
			if c, err = dial(); err == nil {
				if err = echoOnce(c, phase+strings.Repeat("x", 2000)); err == nil {
					return c
				}
				c.Close()
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("%s: %s: %v", tc.name, phase, err)
		return nil
	}
	// refused: a new connection does not relay.
	// switched: the established connection's fate matches want.
	switched := func(c net.Conn, phase string) {
		t.Helper()
		survived := echoOnce(c, phase) == nil
		if want != switchMay && survived != (want == switchKeeps) {
			t.Fatalf("%s: connection survived the switch turning %s = %v, documented: %v", tc.name, phase, survived, want)
		}
	}
	refused := func() bool {
		for i := 0; i < 3; i++ {
			c, err := dial()
			if err != nil {
				return true
			}
			err = echoOnce(c, "probe")
			c.Close()
			if err == nil {
				return false
			}
		}
		return true
	}

	before := connect("before")
	defer before.Close()

	// Switch on with a rule that matches nothing here.
	miss := &pb.BlockRule{Id: 1, Cidrs: []string{"192.0.2.0/24"}}
	if err := m.SetBlockPolicy(&pb.BlockPolicy{InboundTags: []string{"in"}, Rules: []*pb.BlockRule{miss}, Version: "on"}); err != nil {
		t.Fatal(err)
	}
	switched(before, "on")
	on := connect("on")
	defer on.Close()

	// A content change (another non-matching rule) keeps every connection.
	miss2 := &pb.BlockRule{Id: 2, Domains: []string{"full:blocked.example"}}
	if err := m.SetBlockPolicy(&pb.BlockPolicy{InboundTags: []string{"in"}, Rules: []*pb.BlockRule{miss, miss2}, Version: "content"}); err != nil {
		t.Fatal(err)
	}
	if err := echoOnce(on, "after-content"); err != nil {
		t.Fatalf("%s: a rule-content change dropped a connection: %v", tc.name, err)
	}
	// A rule matching the echo server: established connections keep
	// relaying (routing is decided per dispatch), new ones are blocked and
	// counted.
	hit := &pb.BlockRule{Id: 3, Cidrs: []string{"127.0.0.1/32"}}
	if err := m.SetBlockPolicy(&pb.BlockPolicy{InboundTags: []string{"in"}, Rules: []*pb.BlockRule{miss, hit}, Version: "hit"}); err != nil {
		t.Fatal(err)
	}
	if err := echoOnce(on, "after-hit"); err != nil {
		t.Fatalf("%s: a new rule dropped an established connection: %v", tc.name, err)
	}
	if !refused() {
		t.Fatalf("%s: a blocked destination relayed", tc.name)
	}
	if n := hitsOf(m.BlockStats(), 3); n == 0 {
		t.Fatalf("%s: the blocked dispatch was not counted", tc.name)
	}

	// Switch off: the rule no longer applies; the same survival rule.
	if err := m.SetBlockPolicy(&pb.BlockPolicy{Version: "off"}); err != nil {
		t.Fatal(err)
	}
	switched(on, "off")
	connect("off").Close()
	t.Logf("RT-%s-BLOCK: blocked+counted, content change kept connections, switch %v", tc.name, want)
}
