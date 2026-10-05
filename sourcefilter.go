package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"akari/agent/pb"
)

// W28-a source allowlists (capability "source-filter"): a relay entrance's
// derived inbound accepts new connections only from the relay's egress
// networks (ConfigSnapshot.source_filters). They are enforced in the
// kernel with nftables: one table of the agent's own, `inet
// akari_sources`, replaced as a whole (one atomic `nft -f` transaction)
// whenever the Snapshot's filters change, and deleted when there are none.
// Only new connections are checked (ct state new): established ones keep
// running, nothing is evaluated per packet beyond that match.
//
// Needs the nft binary and CAP_NET_ADMIN (the unit grants it). Without
// them the filters are not enforced: the agent says so in
// Heartbeat.source_filter and keeps serving (per-entrance credentials still
// isolate the entrances); the panel warns on the node page.

// nftTable is the agent's table (family inet: IPv4 and IPv6).
const nftTable = "inet akari_sources"

// nftTimeout bounds one nft run.
const nftTimeout = 10 * time.Second

// nftScript renders the filters as one nft transaction that replaces the
// agent's table (or, with no filters, removes it). Everything the panel
// sent is re-rendered from parsed values (ports as numbers, networks as
// netip.Prefix): no panel text reaches nft verbatim.
func nftScript(filters []*pb.SourceFilter) (string, error) {
	var b strings.Builder
	// Creating then deleting the table makes the delete valid whether or not
	// it existed; the new table (if any) follows in the same transaction.
	fmt.Fprintf(&b, "table %s\ndelete table %s\n", nftTable, nftTable)
	if len(filters) == 0 {
		return b.String(), nil
	}
	var sets, rules strings.Builder
	for i, f := range filters {
		if f.GetPort() < 1 || f.GetPort() > 65535 {
			return "", fmt.Errorf("source filter %d: bad port %d", i, f.GetPort())
		}
		if !f.GetTcp() && !f.GetUdp() {
			return "", fmt.Errorf("source filter %d: neither tcp nor udp", i)
		}
		if len(f.GetCidrs()) == 0 {
			return "", fmt.Errorf("source filter %d: no networks", i)
		}
		var v4, v6 []string
		for _, c := range f.GetCidrs() {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return "", fmt.Errorf("source filter %d: %w", i, err)
			}
			p = p.Masked()
			if p.Addr().Is4() {
				v4 = append(v4, p.String())
			} else {
				v6 = append(v6, p.String())
			}
		}
		for _, set := range []struct {
			fam, typ string
			nets     []string
		}{{"4", "ipv4_addr", v4}, {"6", "ipv6_addr", v6}} {
			if len(set.nets) == 0 {
				continue
			}
			fmt.Fprintf(&sets, "  set s%d_%s {\n    type %s\n    flags interval\n    auto-merge\n    elements = { %s }\n  }\n",
				i, set.fam, set.typ, strings.Join(set.nets, ", "))
		}
		for _, l4 := range []struct {
			on   bool
			name string
		}{{f.GetTcp(), "tcp"}, {f.GetUdp(), "udp"}} {
			if !l4.on {
				continue
			}
			// IPv4 / IPv6: from outside the allowlist (or any address of a
			// family the relay has none in) a new connection is dropped.
			if len(v4) > 0 {
				fmt.Fprintf(&rules, "    meta nfproto ipv4 %s dport %d ct state new ip saddr != @s%d_4 drop\n", l4.name, f.GetPort(), i)
			} else {
				fmt.Fprintf(&rules, "    meta nfproto ipv4 %s dport %d ct state new drop\n", l4.name, f.GetPort())
			}
			if len(v6) > 0 {
				fmt.Fprintf(&rules, "    meta nfproto ipv6 %s dport %d ct state new ip6 saddr != @s%d_6 drop\n", l4.name, f.GetPort(), i)
			} else {
				fmt.Fprintf(&rules, "    meta nfproto ipv6 %s dport %d ct state new drop\n", l4.name, f.GetPort())
			}
		}
	}
	fmt.Fprintf(&b, "table %s {\n%s  chain input {\n    type filter hook input priority filter; policy accept;\n%s  }\n}\n",
		nftTable, sets.String(), rules.String())
	return b.String(), nil
}

// sourceFilters applies the Snapshot's filters and remembers the outcome
// for the heartbeat.
type sourceFilters struct {
	// run executes one nft script (tests replace it).
	run func(ctx context.Context, script string) error

	mu sync.Mutex
	// applied: the script the kernel holds ("" = none applied by this
	// process; a table left by an earlier run is replaced by the first
	// Apply that has filters, or removed by one without).
	applied string
	// status: the last outcome; nil while no filters were asked for.
	status *pb.SourceFilterStatus
}

func newSourceFilters() *sourceFilters {
	return &sourceFilters{run: runNft}
}

// runNft feeds the script to `nft -f -` (no shell).
func runNft(ctx context.Context, script string) error {
	ctx, cancel := context.WithTimeout(ctx, nftTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if msg != "" {
			return fmt.Errorf("nft: %w: %s", err, msg)
		}
		return fmt.Errorf("nft: %w", err)
	}
	return nil
}

// Apply installs filters (the complete set). Unchanged filters are not
// re-applied, except after a failure. A failure is logged and reported;
// it never blocks the Snapshot.
func (s *sourceFilters) Apply(ctx context.Context, filters []*pb.SourceFilter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	script, err := nftScript(filters)
	if err == nil && script == s.applied && (s.status == nil || s.status.Applied) {
		return
	}
	if err == nil {
		if len(filters) == 0 && s.applied == "" && s.status == nil {
			// Nothing asked for, nothing installed by us: only clean up a
			// table an earlier process may have left, best effort, quietly.
			if s.run(ctx, script) == nil {
				s.applied = script
			}
			return
		}
		err = s.run(ctx, script)
	}
	switch {
	case err == nil && len(filters) == 0:
		s.applied, s.status = script, nil
		slog.Info("source filters removed")
	case err == nil:
		s.applied = script
		s.status = &pb.SourceFilterStatus{Applied: true}
		slog.Info("source filters applied", "ports", len(filters))
	default:
		s.applied = ""
		if len(filters) == 0 {
			// Could not remove ours: report it like a failed install.
			err = fmt.Errorf("remove: %w", err)
		}
		msg := err.Error()
		if len(msg) > 512 {
			msg = msg[:512]
		}
		s.status = &pb.SourceFilterStatus{Applied: false, Error: msg}
		slog.Warn("source filters NOT enforced; relay entrances rely on their credentials only", "error", err)
	}
}

// Status is Heartbeat.source_filter (nil = nothing to report).
func (s *sourceFilters) Status() *pb.SourceFilterStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status == nil {
		return nil
	}
	return &pb.SourceFilterStatus{Applied: s.status.Applied, Error: s.status.Error}
}
