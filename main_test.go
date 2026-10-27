package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// The tests relay to loopback echo servers, which xray's freedom outbound
// refuses by default (see allowPrivateDestinations).
func TestMain(m *testing.M) {
	allowPrivateDestinations = true
	os.Exit(m.Run())
}

// Production keeps xray's default final rules (no private destinations for
// users); only the operator's setting (or the test hook) adds an allow-all
// rule in front of them.
func TestFreedomOutboundDefaultRules(t *testing.T) {
	defer func(old bool) { allowPrivateDestinations = old }(allowPrivateDestinations)

	allowPrivateDestinations = false
	if out := freedomOutbound(false); out["protocol"] != "freedom" || out["settings"] != nil {
		t.Fatalf("default outbound %v carries settings: xray's safe default rules would be bypassed", out)
	}
	want := `{"protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}}`
	for name, tc := range map[string]struct{ setting, hook bool }{
		"setting": {true, false}, "hook": {false, true}, "both": {true, true},
	} {
		allowPrivateDestinations = tc.hook
		b, err := json.Marshal(freedomOutbound(tc.setting))
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != want {
			t.Fatalf("%s: outbound %s, want %s", name, b, want)
		}
	}
}

// ConfigSnapshot.allow_private_destinations decides whether a user reaches
// a loopback service through the node: refused by default, reachable once
// the setting arrives with a Snapshot.
func TestSnapshotSettingControlsPrivateDestinations(t *testing.T) {
	defer func(old bool) { allowPrivateDestinations = old }(allowPrivateDestinations)
	allowPrivateDestinations = false

	echo := echoServer(t)
	m := NewCoreManager()
	defer m.Teardown()
	inb, users := testSnapshot(freePort(t))
	var port int
	if _, err := fmt.Sscanf(inb[strings.Index(inb, `"port":`):], `"port":%d`, &port); err != nil {
		t.Fatal(err)
	}
	const id = "22222222-2222-2222-2222-222222222222"

	m.SetAllowPrivateDestinations(false)
	if _, err := m.Rebuild(inb, users); err != nil {
		t.Fatal(err)
	}
	c, err := vlessDial(port, id, echo)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.echo("blocked"); err == nil {
		t.Fatal("a user reached a loopback service with the setting off")
	}
	c.Close()

	m.SetAllowPrivateDestinations(true)
	if _, err := m.Rebuild(inb, users); err != nil {
		t.Fatal(err)
	}
	c, err = vlessDial(port, id, echo)
	mustEcho(t, c, err, "allowed")
	c.Close()
}
