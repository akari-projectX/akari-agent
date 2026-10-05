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
	"os/exec"
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
		res.Ports = len(req.Filters)
		var script string
		if script, err = nftScript(req.Filters); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), nftTimeout)
			err = p.nft(ctx, script)
			cancel()
		}
	}
	if err != nil {
		res.Error = truncate(err.Error(), 512)
		slog.Error("source filters NOT applied", "id", res.ID, "ports", res.Ports, "error", err)
	} else {
		res.Applied = true
		slog.Info("source filters applied", "id", res.ID, "ports", res.Ports)
	}
	b, err := json.Marshal(&res)
	if err == nil {
		err = d.writeFile(filterResultName, b)
	}
	if err != nil {
		slog.Error("cannot hand the source filter result to the agent", "error", err)
	}
}
