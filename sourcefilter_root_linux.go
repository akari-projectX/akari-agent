//go:build linux

package main

// R44: the root half of the source allowlists (sourcefilter.go). The
// privileged updater (`-apply-update`, root) applies the agent's
// source-filter request: the agent has no CAP_NET_ADMIN. The request comes
// from the agent's directory, so it is untrusted input like an apply
// request: opened with the same rules (no symlink, regular, one link,
// owned by the agent, bounded), consumed first (the path unit cannot loop
// on it), decoded strictly and re-validated, and the nft transaction is
// rendered from the parsed values by this (installed, trusted) binary. The
// only thing it can change is the table `inet akari_sources` (the script
// creates, deletes and refills that table and nothing else). The outcome
// goes back as source-filter-result.json (created O_EXCL|O_NOFOLLOW,
// chowned to the agent, renamed into place).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// nftTimeout bounds one nft run.
const nftTimeout = 10 * time.Second

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

// netTables are the files readNetSockets merges, per protocol.
var netTables = map[bool][]string{
	false: {"/proc/net/tcp", "/proc/net/tcp6"},
	true:  {"/proc/net/udp", "/proc/net/udp6"},
}

// readNetSockets reads the host's bound sockets of one protocol. The
// updater runs in the host's network namespace (it needs it for nft). A
// table that does not exist (IPv6 disabled) is empty; any other failure is
// an error: not knowing who holds a port means not filtering it.
func readNetSockets(udp bool) ([]netSocket, error) {
	var out []netSocket
	for _, name := range netTables[udp] {
		f, err := os.Open(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		socks, err := parseNetSockets(f, udp)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out = append(out, socks...)
	}
	return out, nil
}

// allowedFilters splits filters (audit 2026-10 P2-1): the request comes
// from the agent's directory, and a compromised agent could otherwise
// have the root updater drop new connections to any port of the host (SSH,
// monitoring). A filter is applied only if no socket of another user than
// the agent (uid) is bound to its port for any of its protocols; an
// unbound port is fine (the agent binds it right after asking), so are the
// agent's own. The skipped ports are returned in request order.
func allowedFilters(filters []filterSpec, uid uint32, tcp, udp []netSocket) (kept []filterSpec, skipped []uint32) {
	for _, f := range filters {
		_, byTCP := foreignHolder(tcp, uint16(f.Port), uid)
		_, byUDP := foreignHolder(udp, uint16(f.Port), uid)
		if (f.TCP && byTCP) || (f.UDP && byUDP) {
			skipped = append(skipped, f.Port)
			continue
		}
		kept = append(kept, f)
	}
	return kept, skipped
}

// restrictFilters applies allowedFilters with the host's sockets.
func (p *applier) restrictFilters(filters []filterSpec, uid uint32) ([]filterSpec, []uint32, error) {
	var tcp, udp []netSocket
	var needTCP, needUDP bool
	for _, f := range filters {
		needTCP = needTCP || f.TCP
		needUDP = needUDP || f.UDP
	}
	var err error
	if needTCP {
		if tcp, err = p.sockets(false); err != nil {
			return nil, nil, fmt.Errorf("cannot tell which ports other users hold: %w", err)
		}
	}
	if needUDP {
		if udp, err = p.sockets(true); err != nil {
			return nil, nil, fmt.Errorf("cannot tell which ports other users hold: %w", err)
		}
	}
	kept, skipped := allowedFilters(filters, uid, tcp, udp)
	return kept, skipped, nil
}

// parseFilterRequest decodes a source-filter request strictly (unknown
// fields, trailing data, a bad ID or a filter outside the bounds are
// errors) and returns it with its filters normalized.
func parseFilterRequest(b []byte) (*filterRequest, error) {
	if len(b) > maxFilterRequestSize {
		return nil, errors.New("source filter request too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r filterRequest
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("source filter request: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("source filter request: trailing data")
	}
	if r.Schema != filterSchema {
		return nil, fmt.Errorf("source filter request: schema %d", r.Schema)
	}
	if !validFilterID(r.ID) {
		return nil, errors.New("source filter request: bad id")
	}
	filters, err := normalizeFilters(r.Filters)
	if err != nil {
		return &filterRequest{Schema: r.Schema, ID: r.ID}, fmt.Errorf("source filter request: %w", err)
	}
	r.Filters = filters
	return &r, nil
}

// validFilterID: lowercase hex, 1..maxFilterIDLen (echoed to the agent).
func validFilterID(id string) bool {
	if id == "" || len(id) > maxFilterIDLen {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// applySourceFilters consumes and applies the agent's source-filter
// request, if there is one. Errors go to the agent (and the log); they
// never stop the updater's other work.
func (p *applier) applySourceFilters(d *agentDir) {
	f, _, err := d.open(filterRequestName, maxFilterRequestSize)
	_ = d.remove(filterRequestName)
	if errors.Is(err, unix.ENOENT) {
		return
	}
	res := filterResult{Schema: filterSchema}
	var req *filterRequest
	if err == nil {
		var b []byte
		b, err = io.ReadAll(io.LimitReader(f, maxFilterRequestSize))
		f.Close()
		if err == nil {
			req, err = parseFilterRequest(b)
		}
	}
	if req != nil {
		res.ID = req.ID
	}
	if err == nil {
		var kept []filterSpec
		kept, res.Skipped, err = p.restrictFilters(req.Filters, d.uid)
		res.Ports = len(kept)
		if len(res.Skipped) > 0 {
			res.Note = fmt.Sprintf("source filters not applied to port(s) %s: held by another user's process, "+
				"which the updater never filters (the rest is applied)", portList(res.Skipped))
		}
		var script string
		if err == nil {
			script, err = nftScript(kept)
		}
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), nftTimeout)
			err = p.nft(ctx, script)
			cancel()
		}
	}
	if err != nil {
		res.Error = truncate(err.Error(), 512)
		res.Skipped, res.Note = nil, ""
		slog.Error("source filters NOT applied", "id", res.ID, "ports", res.Ports, "error", err)
	} else {
		res.Applied = true
		slog.Info("source filters applied", "id", res.ID, "ports", res.Ports, "skipped", res.Skipped)
	}
	b, err := json.Marshal(&res)
	if err == nil {
		err = d.writeFile(filterResultName, b)
	}
	if err != nil {
		slog.Error("cannot hand the source filter result to the agent", "error", err)
	}
}

// portList renders ports as "22, 80" (at most 8; a request has at most
// maxFilters, and the note is bounded anyway).
func portList(ports []uint32) string {
	const most = 8
	var b strings.Builder
	for i, p := range ports {
		if i == most {
			fmt.Fprintf(&b, ", … (%d more)", len(ports)-most)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(strconv.FormatUint(uint64(p), 10))
	}
	return b.String()
}
