package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"akari/agent/pb"
)

// W28-a: the nftables transaction for the relay entrances' allowlists.
func TestNftScript(t *testing.T) {
	got, err := nftScript([]*pb.SourceFilter{
		{Port: 20443, Tcp: true, Cidrs: []string{"203.0.113.7/32", "198.51.100.9/24", "2001:db8::1/48"}},
		{Port: 30443, Tcp: true, Udp: true, Cidrs: []string{"192.0.2.0/24"}},
	})
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
	} {
		if s, err := nftScript([]*pb.SourceFilter{bad}); err == nil {
			t.Fatalf("accepted %v:\n%s", bad, s)
		}
	}
}

// Apply runs nft only when the filters change (or after a failure),
// reports the outcome, and cleans up quietly when nothing was asked for.
func TestSourceFiltersApply(t *testing.T) {
	var runs []string
	fail := error(nil)
	s := &sourceFilters{run: func(_ context.Context, script string) error {
		runs = append(runs, script)
		return fail
	}}
	ctx := context.Background()
	f := []*pb.SourceFilter{{Port: 20443, Tcp: true, Cidrs: []string{"203.0.113.7/32"}}}

	// Nothing asked for: one quiet cleanup, no status, not repeated.
	s.Apply(ctx, nil)
	s.Apply(ctx, nil)
	if len(runs) != 1 || s.Status() != nil {
		t.Fatalf("runs %d status %v", len(runs), s.Status())
	}
	s.Apply(ctx, f)
	if st := s.Status(); len(runs) != 2 || !st.GetApplied() || st.GetError() != "" {
		t.Fatalf("apply: runs %d status %v", len(runs), st)
	}
	s.Apply(ctx, f) // unchanged: not re-applied
	if len(runs) != 2 {
		t.Fatalf("re-applied unchanged filters")
	}
	// A failure is reported and retried on the next Snapshot.
	fail = errors.New("nft: Operation not permitted")
	f2 := []*pb.SourceFilter{{Port: 20444, Tcp: true, Cidrs: []string{"203.0.113.7/32"}}}
	s.Apply(ctx, f2)
	if st := s.Status(); st.GetApplied() || !strings.Contains(st.GetError(), "not permitted") {
		t.Fatalf("failure status %v", st)
	}
	fail = nil
	s.Apply(ctx, f2)
	if st := s.Status(); len(runs) != 4 || !st.GetApplied() {
		t.Fatalf("retry: runs %d status %v", len(runs), st)
	}
	// Relays gone: the table is removed, nothing more to report.
	s.Apply(ctx, nil)
	if len(runs) != 5 || s.Status() != nil || !strings.HasSuffix(runs[4], "delete table inet akari_sources\n") {
		t.Fatalf("remove: runs %d status %v", len(runs), s.Status())
	}
	// A removal that fails is reported too.
	s.Apply(ctx, f)
	fail = errors.New("nft: gone")
	s.Apply(ctx, nil)
	if st := s.Status(); st.GetApplied() || !strings.HasPrefix(st.GetError(), "remove: ") {
		t.Fatalf("failed removal status %v", st)
	}
	// A bad filter (never from a correct panel) is reported, nft untouched.
	n := len(runs)
	s.Apply(ctx, []*pb.SourceFilter{{Port: 0, Tcp: true, Cidrs: []string{"203.0.113.7/32"}}})
	if len(runs) != n || s.Status().GetApplied() {
		t.Fatal("bad filter")
	}
}

// runNft reports a missing binary / failing run with its output.
func TestRunNftErrors(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if err := runNft(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "nft") {
		t.Fatalf("missing nft: %v", err)
	}
}
