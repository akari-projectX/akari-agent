package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"akari/agent/pb"
)

// W28-a: the nftables transaction for the relay entrances' allowlists.
func TestNftScript(t *testing.T) {
	got, err := nftScript(specsOf([]*pb.SourceFilter{
		{Port: 20443, Tcp: true, Cidrs: []string{"203.0.113.7/32", "198.51.100.9/24", "2001:db8::1/48"}},
		{Port: 30443, Tcp: true, Udp: true, Cidrs: []string{"192.0.2.0/24"}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := `table inet akari_sources
delete table inet akari_sources
table inet akari_sources {
  set s0_4 {
    type ipv4_addr
    flags interval
    auto-merge
    elements = { 203.0.113.7/32, 198.51.100.0/24 }
  }
  set s0_6 {
    type ipv6_addr
    flags interval
    auto-merge
    elements = { 2001:db8::/48 }
  }
  set s1_4 {
    type ipv4_addr
    flags interval
    auto-merge
    elements = { 192.0.2.0/24 }
  }
  chain input {
    type filter hook input priority filter; policy accept;
    meta nfproto ipv4 tcp dport 20443 ct state new ip saddr != @s0_4 drop
    meta nfproto ipv6 tcp dport 20443 ct state new ip6 saddr != @s0_6 drop
    meta nfproto ipv4 tcp dport 30443 ct state new ip saddr != @s1_4 drop
    meta nfproto ipv6 tcp dport 30443 ct state new drop
    meta nfproto ipv4 udp dport 30443 ct state new ip saddr != @s1_4 drop
    meta nfproto ipv6 udp dport 30443 ct state new drop
  }
}
`
	if got != want {
		t.Fatalf("script:\n%s\nwant:\n%s", got, want)
	}
	// No filters: only the removal.
	got, err = nftScript(nil)
	if err != nil || got != "table inet akari_sources\ndelete table inet akari_sources\n" {
		t.Fatalf("empty: %q %v", got, err)
	}
	for _, bad := range []*pb.SourceFilter{
		{Port: 0, Tcp: true, Cidrs: []string{"192.0.2.1/32"}},
		{Port: 70000, Tcp: true, Cidrs: []string{"192.0.2.1/32"}},
		{Port: 1, Cidrs: []string{"192.0.2.1/32"}},
		{Port: 1, Tcp: true},
		{Port: 1, Tcp: true, Cidrs: []string{"192.0.2.1"}},
		{Port: 1, Tcp: true, Cidrs: []string{"192.0.2.1/32 } ; flush ruleset"}},
		{Port: 1, Tcp: true, Cidrs: []string{"192.0.2.1/32\nflush ruleset"}},
		{Port: 1, Tcp: true, Cidrs: make([]string, maxFilterCIDRs+1)},
	} {
		if s, err := nftScript(specsOf([]*pb.SourceFilter{bad})); err == nil {
			t.Fatalf("accepted %v:\n%s", bad, s)
		}
	}
}

// The agent side (R44): Apply writes the normalized request for the root
// updater and the heartbeat follows the updater's answer; unchanged
// filters are not requested again (except after a failure), nothing is
// requested while there never were filters, an updater that never answers
// is reported.
func TestSourceFiltersRequest(t *testing.T) {
	state := t.TempDir()
	s := newSourceFilters(state)
	clock := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }
	req := func() *filterRequest {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(s.dir, filterRequestName))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		var r filterRequest
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		return &r
	}
	// answer plays the root updater: consume the request, write a result.
	answer := func(applied bool, msg string) {
		t.Helper()
		r := req()
		if r == nil {
			t.Fatal("no request")
		}
		_ = os.Remove(filepath.Join(s.dir, filterRequestName))
		b, _ := json.Marshal(&filterResult{Schema: filterSchema, ID: r.ID, Applied: applied, Ports: len(r.Filters), Error: msg})
		if err := os.WriteFile(filepath.Join(s.dir, filterResultName), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f := []*pb.SourceFilter{{Port: 20443, Tcp: true, Cidrs: []string{"203.0.113.7/24"}}}

	// Nothing asked for, never applied: no request, nothing to report.
	s.Apply(nil)
	if req() != nil || s.Status() != nil {
		t.Fatal("request without filters")
	}
	s.Apply(f)
	r := req()
	if r == nil || r.Schema != filterSchema || len(r.Filters) != 1 || r.Filters[0].CIDRs[0] != "203.0.113.0/24" {
		t.Fatalf("request %+v", r)
	}
	if st := s.Status(); st.GetApplied() || st.GetError() != errFilterPending {
		t.Fatalf("pending status %v", st)
	}
	answer(true, "")
	if st := s.Status(); !st.GetApplied() || st.GetError() != "" {
		t.Fatalf("applied status %v", st)
	}
	s.Apply(f) // unchanged: no new request
	if req() != nil {
		t.Fatal("unchanged filters requested again")
	}
	// A failure is reported and retried on the next Snapshot.
	f2 := []*pb.SourceFilter{{Port: 20444, Tcp: true, Cidrs: []string{"203.0.113.7/32"}}}
	s.Apply(f2)
	answer(false, "nft: Operation not permitted")
	if st := s.Status(); st.GetApplied() || !strings.Contains(st.GetError(), "not permitted") {
		t.Fatalf("failure status %v", st)
	}
	s.Apply(f2)
	if req() == nil {
		t.Fatal("failure not retried")
	}
	answer(true, "")
	// Relays gone: removal requested; once done there is nothing to report.
	s.Apply(nil)
	if r := req(); r == nil || len(r.Filters) != 0 {
		t.Fatalf("removal request %+v", r)
	}
	answer(true, "")
	if st := s.Status(); st != nil {
		t.Fatalf("status after removal %v", st)
	}
	// A failed removal is reported as such.
	s.Apply(f)
	answer(true, "")
	s.Apply(nil)
	answer(false, "nft: gone")
	if st := s.Status(); st.GetApplied() || !strings.HasPrefix(st.GetError(), "remove: ") {
		t.Fatalf("failed removal status %v", st)
	}
	// No updater: pending, then reported missing; a late answer still lands.
	s.Apply(f2)
	clock = clock.Add(filterResultWait + time.Second)
	if st := s.Status(); st.GetError() != errFilterNoReply {
		t.Fatalf("no updater status %v", st)
	}
	answer(true, "")
	if st := s.Status(); !st.GetApplied() {
		t.Fatalf("late answer %v", st)
	}
	// A bad filter (never from a correct panel): reported, no request.
	_ = os.Remove(filepath.Join(s.dir, filterRequestName))
	s.Apply([]*pb.SourceFilter{{Port: 0, Tcp: true, Cidrs: []string{"203.0.113.7/32"}}})
	if req() != nil || s.Status().GetApplied() || !strings.Contains(s.Status().GetError(), "bad port") {
		t.Fatalf("bad filter: %v", s.Status())
	}

	// A new process after one that had filters applied: an empty set
	// removes the table it may have left.
	s2 := newSourceFilters(state)
	s2.Apply(nil)
	if r := req(); r == nil || len(r.Filters) != 0 {
		t.Fatalf("restart: no removal request %+v", r)
	}
}
