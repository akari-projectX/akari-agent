package main

import (
	"encoding/json"
	"os"
	"testing"
)

// The tests relay to loopback echo servers, which xray's freedom outbound
// refuses by default (see allowPrivateDestinations).
func TestMain(m *testing.M) {
	allowPrivateDestinations = true
	os.Exit(m.Run())
}

// Production keeps xray's default final rules (no private destinations for
// users); only the opt-in adds an allow-all rule in front of them.
func TestFreedomOutboundDefaultRules(t *testing.T) {
	defer func(old bool) { allowPrivateDestinations = old }(allowPrivateDestinations)

	allowPrivateDestinations = false
	if out := freedomOutbound(); out["protocol"] != "freedom" || out["settings"] != nil {
		t.Fatalf("default outbound %v carries settings: xray's safe default rules would be bypassed", out)
	}
	allowPrivateDestinations = true
	b, err := json.Marshal(freedomOutbound())
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}}`; string(b) != want {
		t.Fatalf("opt-in outbound %s, want %s", b, want)
	}
}
