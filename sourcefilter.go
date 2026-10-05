package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"akari/agent/pb"
)

// W28-a source allowlists (capability "source-filter"): a relay entrance's
// derived inbound accepts new connections only from the relay's egress
// networks (ConfigSnapshot.source_filters). They are enforced in the
// kernel with nftables: one table of their own, `inet akari_sources`,
// replaced as a whole (one atomic `nft -f` transaction) whenever the
// Snapshot's filters change, and deleted when there are none. Only new
// connections are checked (ct state new): established ones keep running,
// nothing is evaluated per packet beyond that match.
//
// R44: the agent has no CAP_NET_ADMIN. It writes the parsed, normalized
// filters to update/source-filter-request.json in its state directory; the
// root updater (akari-agent-update.path + .service on systemd, the
// akari-agent-update loop on OpenRC) re-validates the request as untrusted
// input, applies it with `nft -f -` and writes the outcome back
// (update/source-filter-result.json, sourcefilter_root_linux.go), which
// the agent reports in Heartbeat.source_filter. Apply latency: about a
// second (longer only while the updater watches a self-update). Without
// nft or the updater the filters are not enforced: the agent says so and
// keeps serving (per-entrance credentials still isolate the entrances);
// the panel warns on the node page.

const (
	// nftTable is the filters' table (family inet: IPv4 and IPv6).
	nftTable = "inet akari_sources"
	// Files in the update directory (the updater's hand-over directory).
	filterRequestName = "source-filter-request.json"
	filterResultName  = "source-filter-result.json"
	filterSchema      = 1
	// Bounds of a request (the panel allows 1-64 networks per relay).
	maxFilters           = 1024
	maxFilterCIDRs       = 64
	maxFilterRequestSize = 1 << 20
	maxFilterResultSize  = 4 << 10
	maxFilterIDLen       = 64
	// filterResultWait: how long the agent waits for the updater's answer
	// before it reports the updater as missing.
	filterResultWait = time.Minute
	errFilterPending = "pending: waiting for the root updater (akari-agent-update) to apply them"
	errFilterNoReply = "the root updater did not apply them within a minute (akari-agent-update missing or older " +
		"than this agent, or nftables not installed): run the panel's install command (重装命令) once on this node"
)

// filterSpec is one port's allowlist as the agent hands it to the updater
// (normalized: networks masked and printed by netip).
type filterSpec struct {
	Port  uint32   `json:"port"`
	TCP   bool     `json:"tcp,omitempty"`
	UDP   bool     `json:"udp,omitempty"`
	CIDRs []string `json:"cidrs"`
}

// filterRequest is the agent's request (untrusted on the updater's side).
type filterRequest struct {
	Schema  int          `json:"schema"`
	ID      string       `json:"id"`
	Filters []filterSpec `json:"filters"`
}

// filterResult is the updater's answer to the request with that ID.
type filterResult struct {
	Schema  int    `json:"schema"`
	ID      string `json:"id"`
	Applied bool   `json:"applied"`
	Ports   int    `json:"ports"`
	Error   string `json:"error,omitempty"`
}

// specsOf converts the Snapshot's filters.
func specsOf(filters []*pb.SourceFilter) []filterSpec {
	out := make([]filterSpec, 0, len(filters))
	for _, f := range filters {
		out = append(out, filterSpec{Port: f.GetPort(), TCP: f.GetTcp(), UDP: f.GetUdp(), CIDRs: f.GetCidrs()})
	}
	return out
}

// normalizeFilters validates filters and returns them normalized: every
// network parsed by netip and printed back masked, so no panel (or
// agent-directory) text ever reaches nft verbatim.
func normalizeFilters(filters []filterSpec) ([]filterSpec, error) {
	if len(filters) > maxFilters {
		return nil, fmt.Errorf("%d source filters (at most %d)", len(filters), maxFilters)
	}
	out := make([]filterSpec, 0, len(filters))
	for i, f := range filters {
		switch {
		case f.Port < 1 || f.Port > 65535:
			return nil, fmt.Errorf("source filter %d: bad port %d", i, f.Port)
		case !f.TCP && !f.UDP:
			return nil, fmt.Errorf("source filter %d: neither tcp nor udp", i)
		case len(f.CIDRs) == 0:
			return nil, fmt.Errorf("source filter %d: no networks", i)
		case len(f.CIDRs) > maxFilterCIDRs:
			return nil, fmt.Errorf("source filter %d: %d networks (at most %d)", i, len(f.CIDRs), maxFilterCIDRs)
		}
		n := filterSpec{Port: f.Port, TCP: f.TCP, UDP: f.UDP, CIDRs: make([]string, 0, len(f.CIDRs))}
		for _, c := range f.CIDRs {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return nil, fmt.Errorf("source filter %d: %w", i, err)
			}
			n.CIDRs = append(n.CIDRs, p.Masked().String())
		}
		out = append(out, n)
	}
	return out, nil
}

// filterID identifies normalized filters (the updater echoes it).
func filterID(filters []filterSpec) string {
	b, err := json.Marshal(filters)
	if err != nil {
		// []filterSpec always marshals; a distinct ID keeps it harmless.
		return "unmarshalable"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

// nftScript renders the filters as one nft transaction that replaces the
// table (or, with no filters, removes it). Everything is re-rendered from
// parsed values (ports as numbers, networks as netip.Prefix).
func nftScript(filters []filterSpec) (string, error) {
	filters, err := normalizeFilters(filters)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	// Creating then deleting the table makes the delete valid whether or not
	// it existed; the new table (if any) follows in the same transaction.
	fmt.Fprintf(&b, "table %s\ndelete table %s\n", nftTable, nftTable)
	if len(filters) == 0 {
		return b.String(), nil
	}
	var sets, rules strings.Builder
	for i, f := range filters {
		var v4, v6 []string
		for _, c := range f.CIDRs {
			if netip.MustParsePrefix(c).Addr().Is4() {
				v4 = append(v4, c)
			} else {
				v6 = append(v6, c)
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
		}{{f.TCP, "tcp"}, {f.UDP, "udp"}} {
			if !l4.on {
				continue
			}
			// IPv4 / IPv6: from outside the allowlist (or any address of a
			// family the relay has none in) a new connection is dropped.
			if len(v4) > 0 {
				fmt.Fprintf(&rules, "    meta nfproto ipv4 %s dport %d ct state new ip saddr != @s%d_4 drop\n", l4.name, f.Port, i)
			} else {
				fmt.Fprintf(&rules, "    meta nfproto ipv4 %s dport %d ct state new drop\n", l4.name, f.Port)
			}
			if len(v6) > 0 {
				fmt.Fprintf(&rules, "    meta nfproto ipv6 %s dport %d ct state new ip6 saddr != @s%d_6 drop\n", l4.name, f.Port, i)
			} else {
				fmt.Fprintf(&rules, "    meta nfproto ipv6 %s dport %d ct state new drop\n", l4.name, f.Port)
			}
		}
	}
	fmt.Fprintf(&b, "table %s {\n%s  chain input {\n    type filter hook input priority filter; policy accept;\n%s  }\n}\n",
		nftTable, sets.String(), rules.String())
	return b.String(), nil
}

// sourceFilters hands the Snapshot's filters to the root updater and
// tracks its answer for the heartbeat.
type sourceFilters struct {
	dir  string // <state>/update
	now  func() time.Time
	wait time.Duration

	mu sync.Mutex
	// requested: the ID of the last request this process wrote ("" =
	// none); ports: its number of filters; at: when.
	requested string
	ports     int
	at        time.Time
	// resolved: the updater answered the request.
	resolved bool
	// status: what the heartbeat reports (nil = nothing).
	status *pb.SourceFilterStatus
}

func newSourceFilters(stateDir string) *sourceFilters {
	return &sourceFilters{dir: filepath.Join(stateDir, updateDirName), now: time.Now, wait: filterResultWait}
}

// Apply hands the complete set of filters to the updater. Unchanged
// filters are not requested again, except after a failure (the next
// Snapshot retries). It never blocks the Snapshot: the updater applies
// them within about a second.
func (s *sourceFilters) Apply(filters []*pb.SourceFilter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	specs, err := normalizeFilters(specsOf(filters))
	if err != nil {
		// Never from a correct panel: reported, the kernel left as it is.
		s.requested, s.resolved = "", true
		s.status = &pb.SourceFilterStatus{Error: truncate("bad source filters from the panel: "+err.Error(), 512)}
		slog.Warn("source filters NOT enforced; relay entrances rely on their credentials only", "error", err)
		return
	}
	id := filterID(specs)
	if id == s.requested && (!s.resolved || s.status == nil || s.status.Applied) {
		return
	}
	if len(specs) == 0 && s.requested == "" && !s.tableMayExist() {
		return
	}
	if err := s.writeRequest(filterRequest{Schema: filterSchema, ID: id, Filters: specs}); err != nil {
		s.requested, s.resolved = "", true
		s.status = &pb.SourceFilterStatus{Error: truncate("source filter request: "+err.Error(), 512)}
		slog.Warn("source filters NOT enforced; relay entrances rely on their credentials only", "error", err)
		return
	}
	s.requested, s.ports, s.at, s.resolved = id, len(specs), s.now(), false
	s.status = &pb.SourceFilterStatus{Error: errFilterPending}
	slog.Info("source filters handed to the root updater", "ports", len(specs), "id", id)
}

// tableMayExist: an earlier process had filters applied (a result with
// ports): an empty set must then remove the table.
func (s *sourceFilters) tableMayExist() bool {
	r, err := s.readResult()
	return err == nil && r != nil && r.Ports > 0
}

func (s *sourceFilters) writeRequest(r filterRequest) error {
	b, err := json.Marshal(&r)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	return writeSecret(filepath.Join(s.dir, filterRequestName), b)
}

func (s *sourceFilters) readResult() (*filterResult, error) {
	b, err := readSmall(filepath.Join(s.dir, filterResultName), maxFilterResultSize)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r filterResult
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Status is Heartbeat.source_filter (nil = nothing to report). While the
// request is unanswered it reads the updater's result (one small file).
func (s *sourceFilters) Status() *pb.SourceFilterStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.requested != "" && !s.resolved {
		s.poll()
	}
	if s.status == nil {
		return nil
	}
	return &pb.SourceFilterStatus{Applied: s.status.Applied, Error: s.status.Error}
}

func (s *sourceFilters) poll() {
	r, err := s.readResult()
	if err == nil && r != nil && r.ID == s.requested {
		s.resolved = true
		switch {
		case r.Applied && s.ports == 0:
			s.status = nil
			slog.Info("source filters removed")
		case r.Applied:
			s.status = &pb.SourceFilterStatus{Applied: true}
			slog.Info("source filters applied", "ports", s.ports)
		default:
			msg := r.Error
			if s.ports == 0 {
				msg = "remove: " + msg
			}
			s.status = &pb.SourceFilterStatus{Error: truncate(msg, 512)}
			slog.Warn("source filters NOT enforced; relay entrances rely on their credentials only", "error", msg)
		}
		return
	}
	if s.now().Sub(s.at) > s.wait && s.status.GetError() == errFilterPending {
		// Still unresolved: a late answer replaces this.
		s.status = &pb.SourceFilterStatus{Error: errFilterNoReply}
		slog.Warn("source filters NOT enforced; relay entrances rely on their credentials only", "error", errFilterNoReply)
	}
}
