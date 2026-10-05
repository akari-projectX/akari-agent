//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"akari/agent/pb"
)

// R44 end to end without a kernel: the agent's request, the root
// updater's run (strict parse, re-render, nft), the agent's status.
func TestSourceFiltersThroughTheUpdater(t *testing.T) {
	e := newUpdaterEnv(t)
	var scripts []string
	var nftErr error
	e.p.nft = func(_ context.Context, script string) error {
		scripts = append(scripts, script)
		return nftErr
	}
	s := newSourceFilters(filepath.Dir(e.agentDir))
	run := func() {
		t.Helper()
		if err := e.p.run(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(e.agentDir, filterRequestName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("request not consumed")
		}
	}
	f := []*pb.SourceFilter{{Port: 20443, Tcp: true, Cidrs: []string{"203.0.113.7/32", "2001:db8::1/48"}}}
	s.Apply(f)
	run()
	want, _ := nftScript(specsOf(f))
	if len(scripts) != 1 || scripts[0] != want {
		t.Fatalf("nft scripts %q", scripts)
	}
	if st := s.Status(); !st.GetApplied() {
		t.Fatalf("status %v", st)
	}
	// The result belongs to the agent like an apply result.
	if fi, err := os.Lstat(filepath.Join(e.agentDir, filterResultName)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("result file %v %v", fi, err)
	}
	// nft fails: reported with its message.
	nftErr = errors.New("nft: exit status 1: Error: Could not process rule: Operation not permitted")
	s.Apply([]*pb.SourceFilter{{Port: 20444, Udp: true, Cidrs: []string{"192.0.2.0/24"}}})
	run()
	if st := s.Status(); st.GetApplied() || !strings.Contains(st.GetError(), "Operation not permitted") {
		t.Fatalf("failure status %v", st)
	}
	// Removal: the table is deleted, nothing left to report.
	nftErr = nil
	s.Apply(nil)
	run()
	if got := scripts[len(scripts)-1]; got != "table inet akari_sources\ndelete table inet akari_sources\n" || s.Status() != nil {
		t.Fatalf("removal: %q %v", got, s.Status())
	}
	// No request: nft is not run.
	n := len(scripts)
	run()
	if len(scripts) != n {
		t.Fatal("nft ran without a request")
	}
}

// The request is untrusted: planted links, foreign files, unknown fields,
// bad IDs and filters the agent would never send are refused without
// running nft.
func TestUpdaterRefusesBadSourceFilterRequests(t *testing.T) {
	e := newUpdaterEnv(t)
	ran := 0
	e.p.nft = func(context.Context, string) error { ran++; return nil }
	reqPath := filepath.Join(e.agentDir, filterRequestName)
	result := func() filterResult {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(e.agentDir, filterResultName))
		if err != nil {
			t.Fatal(err)
		}
		var r filterResult
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	for name, body := range map[string]string{
		"unknown field":   `{"schema":1,"id":"ab","filters":[],"x":1}`,
		"schema":          `{"schema":2,"id":"ab","filters":[]}`,
		"bad id":          `{"schema":1,"id":"AB/..","filters":[]}`,
		"trailing":        `{"schema":1,"id":"ab","filters":[]} {}`,
		"bad port":        `{"schema":1,"id":"ab","filters":[{"port":0,"tcp":true,"cidrs":["192.0.2.0/24"]}]}`,
		"injection":       `{"schema":1,"id":"ab","filters":[{"port":1,"tcp":true,"cidrs":["192.0.2.0/24 } ; flush ruleset"]}]}`,
		"not json":        `flush ruleset`,
		"neither tcp/udp": `{"schema":1,"id":"ab","filters":[{"port":1,"cidrs":["192.0.2.0/24"]}]}`,
	} {
		if err := os.WriteFile(reqPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := e.p.run(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r := result(); r.Applied || r.Error == "" {
			t.Fatalf("%s: accepted: %+v", name, r)
		}
	}
	// A symlink planted as the request is not followed.
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{"schema":1,"id":"ab","filters":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, reqPath); err != nil {
		t.Fatal(err)
	}
	if err := e.p.run(); err != nil {
		t.Fatal(err)
	}
	if r := result(); r.Applied || r.ID != "" {
		t.Fatalf("symlink: %+v", r)
	}
	if _, err := os.Lstat(reqPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("planted link not removed")
	}
	if ran != 0 {
		t.Fatalf("nft ran %d times on refused requests", ran)
	}
}

// runNft reports a missing binary with a clear error.
func TestRunNftErrors(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if err := runNft(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "nft") {
		t.Fatalf("missing nft: %v", err)
	}
}

// W13-style fuzz of the root side's untrusted input: whatever the agent's
// directory holds, an accepted request renders only the fixed nft shapes
// and its ID is safe to echo.
var nftShapes = regexp.MustCompile(`^(table inet akari_sources( \{)?|delete table inet akari_sources|` +
	`  set s[0-9]+_[46] \{|    type ipv[46]_addr|    flags interval|    auto-merge|` +
	`    elements = \{ [0-9a-f.:/, ]+ \}|  \}|\}|  chain input \{|` +
	`    type filter hook input priority filter; policy accept;|` +
	`    meta nfproto ipv[46] (tcp|udp) dport [0-9]{1,5} ct state new( ip6? saddr != @s[0-9]+_[46])? drop)$`)

func FuzzFilterRequest(f *testing.F) {
	f.Add([]byte(`{"schema":1,"id":"ab","filters":[{"port":20443,"tcp":true,"cidrs":["203.0.113.7/32","2001:db8::/48"]}]}`))
	f.Add([]byte(`{"schema":1,"id":"0f","filters":[]}`))
	f.Add([]byte(`{"schema":1,"id":"ab","filters":[{"port":1,"udp":true,"cidrs":["0.0.0.0/0 } ; flush ruleset"]}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseFilterRequest(b)
		if err != nil {
			return
		}
		if !validFilterID(r.ID) {
			t.Fatalf("id %q", r.ID)
		}
		script, err := nftScript(r.Filters)
		if err != nil {
			t.Fatalf("normalized filters not renderable: %v", err)
		}
		for _, line := range strings.Split(strings.TrimSuffix(script, "\n"), "\n") {
			if !nftShapes.MatchString(line) {
				t.Fatalf("unexpected line %q in\n%s", line, script)
			}
		}
	})
}
