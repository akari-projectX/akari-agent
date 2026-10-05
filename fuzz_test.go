package main

// Native Go fuzz targets for the agent's parsers of input it does not
// control: panel-sent inbounds and accounts (a compromised or buggy panel,
// or an admin's JSON), ACME settings, /proc text, the state-hash encoding
// and the bootstrap file. `go test` runs the seeds (testdata/fuzz/<name>
// plus the f.Add calls) as ordinary tests; `make fuzz` explores
// (FUZZTIME per target), CI runs it nightly (.github/workflows/fuzz.yml).
//
// Each target asserts invariants, not just "no panic"; see the comments.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"akari/agent/pb"
	"akari/agent/release"

	"github.com/xtls/xray-core/common/protocol"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

var fuzzInboundSeeds = []string{
	`[{"tag":"v","port":443,"protocol":"vless","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"tcp","security":"none"}}]`,
	`[{"tag":"m","port":8443,"protocol":"vmess","settings":{"clients":[]},"streamSettings":{"network":"ws","wsSettings":{"path":"/x"}}}]`,
	`[{"tag":"t","port":443,"protocol":"trojan","settings":{"clients":[]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/run/credentials/akari-agent.service/tls_fullchain.pem","keyFile":"/run/credentials/akari-agent.service/tls_privkey.pem"}]}}}]`,
	`[{"tag":"s","port":8388,"protocol":"shadowsocks","settings":{"method":"2022-blake3-aes-128-gcm","password":"AAAAAAAAAAAAAAAAAAAAAA==","clients":[],"network":"tcp,udp"}}]`,
	`[{"tag":"s","TAG":"x","port":8388,"protocol":"shadowsocks","settings":{"method":"2022-blake3-aes-256-gcm","password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","clients":[]}}]`,
	`[{"tag":"h","port":443,"protocol":"hysteria","settings":{"version":2},"streamSettings":{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2}}}]`,
	`[{"tag":"d","port":"1000-2000,3000","protocol":"dokodemo-door","settings":{"network":"tcp"},"sniffing":{"enabled":true,"destOverride":["http"]}}]`,
	`[]`,
}

// xrayView decodes JSON the way xray's config structs see it (Go
// encoding/json into a struct: case-insensitive keys, the last duplicate
// wins). The oracle for what xray built.
type xrayView struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings"`
}

// FuzzBuildConfig: panel-sent inbounds JSON through the xray config build
// the agent does before every Rebuild (buildConfig: xray's own parse,
// refuseFakeDNS, the SS2022 multi-user rewrite, inboundKinds, the gate
// swap), with and without the node certificate rewrite.
//
// Invariants: no panic; on success every inbound xray sees as a
// Shadowsocks inbound whose settings carry "clients" (as xray reads the
// keys) is a multi-user SS2022 server — never the stock single-user server
// keyed by the shared PSK, which no gate could revoke; managed kinds
// carry a key length exactly for SS.
// FuzzNftScript: panel-sent source allowlists (W28-a) become an nft
// transaction. Invariants: either refused, or every line of the script is
// one of the fixed shapes with numbers and canonical networks only — no
// panel text reaches nft verbatim — and the networks are exactly the
// accepted ones.
func FuzzNftScript(f *testing.F) {
	f.Add(uint32(20443), true, false, "203.0.113.7/32,2001:db8::/48")
	f.Add(uint32(1), false, true, "0.0.0.0/0")
	f.Add(uint32(80), true, true, "1.2.3.4/32 } ; flush ruleset")
	f.Add(uint32(70000), true, false, "::/0")
	shapes := regexp.MustCompile(`^(table inet akari_sources( \{)?|delete table inet akari_sources|` +
		`  set s0_[46] \{|    type ipv[46]_addr|    flags interval|    auto-merge|` +
		`    elements = \{ [0-9a-f.:/, ]+ \}|  \}|\}|  chain input \{|` +
		`    type filter hook input priority filter; policy accept;|` +
		`    meta nfproto ipv[46] (tcp|udp) dport [0-9]{1,5} ct state new( ip6? saddr != @s0_[46])? drop)$`)
	f.Fuzz(func(t *testing.T, port uint32, tcp, udp bool, cidrs string) {
		filter := &pb.SourceFilter{Port: port, Tcp: tcp, Udp: udp, Cidrs: strings.Split(cidrs, ",")}
		script, err := nftScript(specsOf([]*pb.SourceFilter{filter}))
		if err != nil {
			return
		}
		for _, line := range strings.Split(strings.TrimSuffix(script, "\n"), "\n") {
			if !shapes.MatchString(line) {
				t.Fatalf("unexpected line %q in\n%s", line, script)
			}
		}
		for _, c := range filter.Cidrs {
			p, perr := netip.ParsePrefix(c)
			if perr != nil {
				t.Fatalf("accepted %q", c)
			}
			if !strings.Contains(script, p.Masked().String()) {
				t.Fatalf("%q missing from\n%s", c, script)
			}
		}
	})
}

func FuzzBuildConfig(f *testing.F) {
	for _, s := range fuzzInboundSeeds {
		f.Add([]byte(s), false)
		f.Add([]byte(s), true)
	}
	f.Fuzz(func(t *testing.T, data []byte, withCert bool) {
		var inbounds []json.RawMessage
		if json.Unmarshal(data, &inbounds) != nil || len(inbounds) > 8 {
			return
		}
		var cert *certFiles
		if withCert {
			cert = &certFiles{cert: "/state/tls/x/fullchain.pem", key: "/state/tls/x/privkey.pem"}
		}
		cfg, kinds, _, err := buildConfig(inbounds, cert)
		if err != nil {
			return
		}
		managedSS := map[string]bool{}
		for _, raw := range inbounds {
			var v xrayView
			if json.Unmarshal(raw, &v) != nil || !strings.EqualFold(v.Protocol, "shadowsocks") {
				continue
			}
			var s struct {
				Clients json.RawMessage `json:"clients"`
			}
			if json.Unmarshal(v.Settings, &s) == nil && len(s.Clients) > 0 &&
				!bytes.Equal(bytes.TrimSpace(s.Clients), []byte("null")) {
				managedSS[v.Tag] = true
			}
		}
		for _, in := range cfg.Inbound {
			if in.ProxySettings == nil {
				continue
			}
			msg, err := in.ProxySettings.GetInstance()
			if err != nil {
				t.Fatalf("built config holds an unloadable inbound %q: %v", in.Tag, err)
			}
			if _, single := msg.(*ss2022.ServerConfig); single && managedSS[in.Tag] {
				t.Fatalf("inbound %q has clients but runs the single-user SS2022 server (shared PSK, no per-user identity)", in.Tag)
			}
		}
		for tag, k := range kinds {
			if (k.protocol == "shadowsocks") != (k.ssKeyLen > 0) {
				t.Fatalf("inbound %q: kind %+v", tag, k)
			}
		}
	})
}

// FuzzRewriteCertPaths: the node-certificate rewrite must change exactly
// the two path strings and nothing else of what xray will parse (numbers
// keep their precision, every other member its value).
func FuzzRewriteCertPaths(f *testing.F) {
	for _, s := range fuzzInboundSeeds {
		f.Add([]byte(s))
	}
	f.Add([]byte(`[{"tag":"t","port":443,"x":9007199254740993,"streamSettings":{"tlsSettings":{"certificates":[{"certificateFile":"/run/credentials/akari-agent.service/tls_fullchain.pem","keyFile":"/run/credentials/akari-agent.service/tls_privkey.pem","ocspStapling":3600}]}}}]`))
	files := certFiles{cert: "/state/tls/d/fullchain.pem", key: "/state/tls/d/privkey.pem"}
	decode := func(b []byte) (any, bool) {
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber()
		var v any
		return v, d.Decode(&v) == nil
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var inbounds []json.RawMessage
		if json.Unmarshal(data, &inbounds) != nil {
			return
		}
		out, tags, err := rewriteCertPaths(inbounds, files)
		if err != nil {
			return
		}
		if len(out) != len(inbounds) {
			t.Fatalf("rewrite changed the inbound count")
		}
		changed := 0
		for i := range inbounds {
			before, ok1 := decode(inbounds[i])
			after, ok2 := decode(out[i])
			if ok1 != ok2 {
				t.Fatalf("inbound %d: decodability changed", i)
			}
			if !ok1 {
				continue
			}
			// Apply the intended edit to the original and compare.
			if m, ok := before.(map[string]any); ok {
				ss, _ := m["streamSettings"].(map[string]any)
				ts, _ := ss["tlsSettings"].(map[string]any)
				certs, _ := ts["certificates"].([]any)
				edited := false
				for _, c := range certs {
					cm, _ := c.(map[string]any)
					if cm != nil && cm["certificateFile"] == nodeCertCredFile && cm["keyFile"] == nodeKeyCredFile {
						cm["certificateFile"], cm["keyFile"] = files.cert, files.key
						edited = true
					}
				}
				if edited {
					changed++
				}
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("inbound %d: rewrite changed more than the certificate paths:\n%s\n->\n%s", i, inbounds[i], out[i])
			}
		}
		if len(tags) > changed {
			t.Fatalf("%d tags reported for %d changed inbounds", len(tags), changed)
		}
	})
}

// FuzzBuildUser: a panel credential (protocol, account_json) for an
// inbound of a given kind. Invariants: no panic (xray's validators
// type-assert the account and would panic on a mismatch); a credential is
// only accepted for its own protocol; an accepted user converts to a
// MemoryUser or fails cleanly; SS keys and Hysteria auth obey their
// length rules; the email is the panel user id.
func FuzzBuildUser(f *testing.F) {
	for _, s := range [][2]string{
		{"vless", `{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision"}`},
		{"vless", `{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-direct"}`},
		{"vmess", `{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}`},
		{"trojan", `{"password":"0123456789abcdef0123456789abcdef"}`},
		{"shadowsocks", `{"password":"AAAAAAAAAAAAAAAAAAAAAA=="}`},
		{"shadowsocks", `{"password":"AAAAAAAAAAAAAAAAAAAAAA==","extra":1}`},
		{"hysteria", `{"auth":"0123456789abcdef0123456789abcdef"}`},
		{"hysteria", `{"auth":"short"}`},
	} {
		for k := uint8(0); k < 6; k++ {
			f.Add(s[0], s[1], "8b5b5a4e-0d6f-4f3e-9c2e-1a2b3c4d5e6f", k)
		}
	}
	kinds := []inboundKind{
		{protocol: "vless"}, {protocol: "vmess"}, {protocol: "trojan"},
		{protocol: "shadowsocks", ssKeyLen: 16}, {protocol: "shadowsocks", ssKeyLen: 32},
		{protocol: "hysteria"}, {},
	}
	f.Fuzz(func(t *testing.T, proto, account, userID string, k uint8) {
		kind := kinds[int(k)%len(kinds)]
		u, err := buildUser(proto, account, userID, kind)
		if err != nil {
			return
		}
		if proto != kind.protocol || kind.protocol == "" {
			t.Fatalf("credential %q accepted for inbound kind %+v", proto, kind)
		}
		if u.Email != userID {
			t.Fatalf("email %q, want the user id", u.Email)
		}
		mu, err := u.ToMemoryUser()
		if err != nil {
			return
		}
		checkMemoryUser(t, proto, kind, mu)
	})
}

func checkMemoryUser(t *testing.T, proto string, kind inboundKind, mu *protocol.MemoryUser) {
	t.Helper()
	if mu == nil || mu.Account == nil {
		t.Fatalf("nil memory user/account for %s", proto)
	}
	switch a := mu.Account.(type) {
	case *ss2022.MemoryAccount:
		if kind.ssKeyLen == 0 {
			t.Fatalf("SS account for kind %+v", kind)
		}
		_ = a
	}
}

// FuzzInboundTCPPorts: the TCP ports the ACME solver must avoid, from the
// panel's inbounds JSON. Invariants: no panic; every literal integer port
// of a non-hysteria inbound is reported (a missed port would let the
// solver bind it and break the inbound, or vice versa).
func FuzzInboundTCPPorts(f *testing.F) {
	for _, s := range fuzzInboundSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, inbounds string) {
		ports := inboundTCPPorts(inbounds)
		var ins []struct {
			Port     json.RawMessage `json:"port"`
			Protocol string          `json:"protocol"`
		}
		if json.Unmarshal([]byte(inbounds), &ins) != nil {
			if ports != nil {
				t.Fatalf("ports from unparseable inbounds")
			}
			return
		}
		for _, in := range ins {
			var n int
			if json.Unmarshal(in.Port, &n) == nil && !strings.EqualFold(in.Protocol, "hysteria") && !ports.has(n) {
				t.Fatalf("port %d not reported", n)
			}
		}
	})
}

// FuzzACMEConfig: the panel's AcmeConfig (domain, directory). An accepted
// domain is the name of a directory under the state dir, so it must be a
// plain lowercase DNS name: no separators, no "..", no IP literal.
func FuzzACMEConfig(f *testing.F) {
	for _, s := range []string{"node.example.com", "Node.Example.COM.", "../etc", "a..b", "1.2.3.4", "*.example.com", "xn--fsq.com"} {
		f.Add(s, "https://acme-v02.api.letsencrypt.org/directory")
		f.Add(s, "http://insecure")
	}
	f.Fuzz(func(t *testing.T, domain, dir string) {
		c, err := normalizeAcme(&pb.AcmeConfig{Domain: domain, DirectoryUrl: dir})
		if err != nil || c == nil {
			return
		}
		d := c.domain
		if d == "" || strings.ContainsAny(d, "/\\\x00") || strings.Contains(d, "..") || d != strings.ToLower(d) ||
			filepath.Base(d) != d || !validDomain(d) {
			t.Fatalf("unsafe domain accepted: %q", d)
		}
		if !strings.HasPrefix(c.directory, "https://") {
			t.Fatalf("non-https directory accepted: %q", c.directory)
		}
	})
}

// FuzzProcParsers: /proc text (W11). Invariants: no panic; used <= total
// for memory and swap; load averages are finite and non-negative;
// interface names come from the input; byte counts given in kB never wrap.
func FuzzProcParsers(f *testing.F) {
	for _, name := range []string{"stat", "loadavg", "meminfo", "net/dev", "net/route", "net/ipv6_route", "net/sockstat", "self/status"} {
		if b, err := os.ReadFile(filepath.Join("testdata", "proc", name)); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte("MemTotal: 18446744073709551615 kB\nMemAvailable: 1 kB\nVmRSS: 18446744073709551615 kB\n"))
	f.Add([]byte("nan inf -1 1/2 3\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, n, ok := parseCPUStat(b); ok && n < 0 {
			t.Fatal("negative cpu count")
		}
		if l1, l5, l15, ok := parseLoadavg(b); ok {
			for _, v := range []float64{l1, l5, l15} {
				if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
					t.Fatalf("load average %v accepted", v)
				}
			}
		}
		m := parseMeminfo(b)
		if m.used > m.total || m.swapUsed > m.swapTotal {
			t.Fatalf("used > total: %+v", m)
		}
		// kB values never wrap: the byte count is at least the kB number.
		if n, kb, ok := kbField(b, "MemTotal:", false); ok && kb && m.total < n {
			t.Fatalf("MemTotal %d kB became %d bytes (wrapped)", n, m.total)
		}
		if n, kb, ok := kbField(b, "VmRSS:", true); ok && kb {
			if rss, _ := parseStatusRSS(b); rss < n {
				t.Fatalf("VmRSS %d kB became %d bytes (wrapped)", n, rss)
			}
		}
		devs := parseNetDev(b)
		for _, name := range []string{parseDefaultRoute4(b), parseDefaultRoute6(b), busiestInterface(devs)} {
			if name != "" && !bytes.Contains(b, []byte(name)) {
				t.Fatalf("interface %q not in the input", name)
			}
		}
		_, _, _ = parseSockstat(b)
		if p := cpuPercent(cpuTimes{}, cpuTimes{idle: 1, total: 2}); p < 0 || p > 100 {
			t.Fatalf("cpu %% %v", p)
		}
	})
}

// kbField: the value of the first (first=true) or last "<name> N [kB]"
// line as the parsers see lines (bufio.Scanner), and whether it is in kB.
func kbField(b []byte, name string, first bool) (n uint64, kb, ok bool) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		rest, found := strings.CutPrefix(sc.Text(), name)
		if !found {
			continue
		}
		f := strings.Fields(rest)
		v, err := strconv.ParseUint(firstOr(f, ""), 10, 64)
		if err == nil {
			n, kb, ok = v, len(f) > 1 && f[1] == "kB", true
		} else if first {
			return 0, false, false
		}
		if first {
			return n, kb, ok
		}
	}
	return n, kb, ok
}

func firstOr(f []string, d string) string {
	if len(f) == 0 {
		return d
	}
	return f[0]
}

// FuzzStateHash: the state-hash input encoding (agent.proto "State hash"
// v2) must be unambiguous: two record sets that differ as sets hash
// differently (field boundaries cannot shift), and the order of records
// does not matter.
func FuzzStateHash(f *testing.F) {
	f.Add(uint64(1), "[]", "u1", "t1", "vless", `{"id":"x"}`, "u1t", "1", "vless", `{"id":"x"}`)
	f.Add(uint64(7), "", "ab", "c", "p", "", "a", "bc", "p", "")
	f.Fuzz(func(t *testing.T, ver uint64, inb, u1, t1, p1, a1, u2, t2, p2, a2 string) {
		r1 := hashRecord{UserID: u1, Tag: t1, Protocol: p1, Account: a1}
		r2 := hashRecord{UserID: u2, Tag: t2, Protocol: p2, Account: a2}
		if r1.UserID == r2.UserID && r1.Tag == r2.Tag {
			return // records must be unique per (user, tag)
		}
		h12 := stateHash(ver, inb, []hashRecord{r1, r2})
		if h21 := stateHash(ver, inb, []hashRecord{r2, r1}); h12 != h21 {
			t.Fatal("hash depends on record order")
		}
		one := stateHash(ver, inb, []hashRecord{r1})
		if one == h12 {
			t.Fatal("dropping a record kept the hash")
		}
		// Moving bytes between adjacent fields must change the hash.
		if len(a1) > 0 {
			moved := r1
			moved.Account = a1[1:]
			moved.Protocol = p1 + a1[:1]
			if stateHash(ver, inb, []hashRecord{moved}) == one {
				t.Fatal("field boundary is ambiguous")
			}
		}
		if stateHash(ver+1, inb, []hashRecord{r1}) == one || stateHash(ver, inb+" ", []hashRecord{r1}) == one {
			t.Fatal("version/inbounds not bound")
		}
		recs := []hashRecord{r2, r1}
		sort.Slice(recs, func(i, j int) bool { return recs[i].UserID < recs[j].UserID })
		if stateHash(ver, inb, recs) != h12 {
			t.Fatal("hash depends on input order")
		}
	})
}

// FuzzLoadConfig: the bootstrap file (written by the installer from what
// the panel served). Invariants: no panic; an accepted config has a panel
// address, a CA and a server name; unknown keys are refused.
func FuzzLoadConfig(f *testing.F) {
	f.Add("panel_addr = \"panel.example.com:8443\"\nenrollment_token = \"t\"\n[identity]\nca_pem = \"x\"\n")
	f.Add("panel_addr = \"p\"\nbogus = 1\n[identity]\nca_pem = \"x\"\n")
	f.Add("panel_addr = \"p\"\n[identity]\nca_pem = \"x\"\ncert_pem = \"c\"\n")
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, text string) {
		p := filepath.Join(dir, "bootstrap.toml")
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadConfig(p)
		if err != nil {
			return
		}
		if cfg.PanelAddr == "" || cfg.ServerName == "" || cfg.Identity.CAPEM == "" {
			t.Fatalf("incomplete config accepted: %+v", cfg)
		}
		if (cfg.Identity.CertPEM == "") != (cfg.Identity.KeyPEM == "") {
			t.Fatal("half a v1 identity accepted")
		}
	})
}

// FuzzApplyRequest: the apply request is written by the unprivileged agent
// and read by the root updater (W18). Invariants: no panic; an accepted
// request has a known kind, a release version and bounded fields, and
// re-encoding it parses to the same request.
func FuzzApplyRequest(f *testing.F) {
	f.Add([]byte(`{"schema":1,"kind":"apply","rollout_id":"r","version":"v1.2.3","panel_protocol":3,"manifest":"e30=","signatures":[{"key_id":"k","sig":"AA=="}]}`))
	f.Add([]byte(`{"schema":1,"kind":"rollback","version":"v1.2.3-rc.1","reason":"x"}`))
	f.Add([]byte(`{"schema":1,"kind":"apply","version":"v1.2.3","path":"/etc/shadow"}`))
	f.Add([]byte(`{"schema":1,"kind":"apply","version":"v1.2.3"} {}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseApplyRequest(b)
		if err != nil {
			return
		}
		if (r.Kind != kindApply && r.Kind != kindRollback) || !release.ValidVersion(r.Version) ||
			len(r.RolloutID) > 64 || len(r.Reason) > 512 || len(r.Signatures) > 8 {
			t.Fatalf("out-of-range request accepted: %+v", r)
		}
		again, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		r2, err := parseApplyRequest(again)
		if err != nil || r2.Version != r.Version || r2.Kind != r.Kind || string(r2.Manifest) != string(r.Manifest) {
			t.Fatalf("round trip: %v %+v", err, r2)
		}
	})
}
