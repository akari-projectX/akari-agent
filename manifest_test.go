package main

// W26: the agent's protocol modules agree with proto/protocols.toml (the
// panel's canonical manifest, synced byte for byte), and the credential
// rules they enforce are the manifest's.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/xtls/xray-core/proxy/vless"

	"akari/agent/pb"
)

func TestManifestParses(t *testing.T) {
	m, err := parseManifest(manifestTOML)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Protocol) == 0 || len(m.Scenario) == 0 {
		t.Fatalf("empty manifest: %+v", m)
	}
	for _, bad := range []struct{ from, to string }{
		{"schema = 1", "schema = 2"},
		{"label = \"VLESS\"\n", "label = \"VLESS\"\nunknown_key = 1\n"},
		{"wire = \"vmess\"", "wire = \"vless\""},
		{"transports = [\"tcp\", \"ws\"", "transports = [\"tcp\", \"kcp\""},
		{"key_len = [16, 32]", "key_len = [16]"},
	} {
		if !strings.Contains(manifestTOML, bad.from) {
			t.Fatalf("fixture %q not in the manifest", bad.from)
		}
		if _, err := parseManifest(strings.Replace(manifestTOML, bad.from, bad.to, 1)); err == nil {
			t.Fatalf("accepted %q -> %q", bad.from, bad.to)
		}
	}
}

// The embedded file is the vendored copy in proto/ (the one check-proto
// compares with the panel's).
func TestManifestIsTheVendoredFile(t *testing.T) {
	b, err := os.ReadFile("proto/protocols.toml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, []byte(manifestTOML)) {
		t.Fatal("embedded manifest differs from proto/protocols.toml")
	}
}

// Every manifest protocol has exactly one module, in manifest order.
func TestModulesMatchManifest(t *testing.T) {
	if len(protocolModules) != len(manifest.Protocol) {
		t.Fatalf("%d modules, %d manifest protocols", len(protocolModules), len(manifest.Protocol))
	}
	for i, p := range manifest.Protocol {
		if got := protocolModules[i].wire(); got != p.Wire {
			t.Fatalf("module %d is %q, manifest protocol %q has wire %q", i, got, p.ID, p.Wire)
		}
		if modulesByWire[p.Wire] == nil {
			t.Fatalf("no module for %q", p.Wire)
		}
	}
}

// The kernel version the manifest was verified against is the xray-core
// this agent links (v1.YYMMDD.P = vYY.M.D): an xray bump must re-verify the
// matrix (`make test-canary`) and update the panel's manifest.
func TestManifestKernelIsLinkedXray(t *testing.T) {
	mod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`github\.com/xtls/xray-core v1\.(\d\d)(\d\d)(\d\d)\.(\d+)`).FindSubmatch(mod)
	if m == nil {
		t.Fatal("xray-core not found in go.mod")
	}
	var yy, mm, dd int
	fmt.Sscanf(string(m[1])+" "+string(m[2])+" "+string(m[3]), "%d %d %d", &yy, &mm, &dd)
	want := fmt.Sprintf("v%d.%d.%d", yy, mm, dd)
	if got := manifest.kernelVersion("xray"); got != want {
		t.Fatalf("manifest kernel xray %q, go.mod links %s (%s)", got, want, m[0])
	}
}

// Every flow the manifest allows is one xray implements.
func TestManifestFlowsAreXrayFlows(t *testing.T) {
	o := protocolSpec("vless").option("flow")
	if o == nil || len(o.Values) == 0 {
		t.Fatal("no vless flow option")
	}
	for _, f := range o.Values {
		if f != "" && f != vless.XRV {
			t.Fatalf("manifest flow %q is not an xray flow", f)
		}
	}
}

// A fresh account built from the manifest's credential spec, for a kind.
func manifestAccount(t *testing.T, p *manifestProtocol, kind inboundKind, flow string) string {
	t.Helper()
	var parts []string
	for _, c := range p.Credential {
		var v string
		switch c.Kind {
		case "uuid":
			v = idA
		case "hex":
			b := make([]byte, c.Bytes)
			rand.Read(b)
			v = hex.EncodeToString(b)
		case "base64_key":
			v = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, kind.ssKeyLen))
		case "option":
			v = flow
		default:
			t.Fatalf("credential kind %q has no test generator", c.Kind)
		}
		parts = append(parts, fmt.Sprintf("%q:%q", c.Field, v))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// Credential rules, table-driven from the manifest: every account the
// manifest describes is accepted for its protocol and refused for every
// other; option values outside the manifest, keys of the wrong length and
// auths under min_len are refused.
func TestCredentialRulesFollowManifest(t *testing.T) {
	kinds := map[string][]inboundKind{}
	for _, p := range manifest.Protocol {
		k := []inboundKind{{protocol: p.Wire}}
		if o := p.option("method"); o != nil && len(o.KeyLen) > 0 {
			k = nil
			for _, v := range o.Values {
				k = append(k, inboundKind{protocol: p.Wire, ssKeyLen: o.keyLens()[v]})
			}
		}
		kinds[p.Wire] = k
	}
	for i := range manifest.Protocol {
		p := &manifest.Protocol[i]
		flows := []string{""}
		if o := p.option("flow"); o != nil {
			flows = o.Values
		}
		for _, kind := range kinds[p.Wire] {
			for _, flow := range flows {
				acc := manifestAccount(t, p, kind, flow)
				if _, err := buildUser(p.Wire, acc, userA, kind); err != nil {
					t.Fatalf("%s %+v: manifest account %s refused: %v", p.ID, kind, acc, err)
				}
				for other, oks := range kinds {
					if other == p.Wire {
						continue
					}
					if _, err := buildUser(p.Wire, acc, userA, oks[0]); err == nil {
						t.Fatalf("%s credential accepted on a %s inbound", p.Wire, other)
					}
				}
			}
			if p.option("flow") != nil {
				if _, err := buildUser(p.Wire, manifestAccount(t, p, kind, "xtls-rprx-direct"), userA, kind); err == nil {
					t.Fatalf("%s: flow outside the manifest accepted", p.ID)
				}
			}
			if kind.ssKeyLen > 0 {
				acc := strings.Replace(manifestAccount(t, p, kind, ""),
					base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, kind.ssKeyLen)),
					base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, kind.ssKeyLen+1)), 1)
				if _, err := buildUser(p.Wire, acc, userA, kind); err == nil {
					t.Fatalf("%s: key of the wrong length accepted", p.ID)
				}
			}
			for _, c := range p.Credential {
				if c.MinLen <= 1 {
					continue
				}
				short := fmt.Sprintf(`{%q:%q}`, c.Field, strings.Repeat("a", c.MinLen-1))
				if _, err := buildUser(p.Wire, short, userA, kind); err == nil {
					t.Fatalf("%s: %s shorter than %d accepted", p.ID, c.Field, c.MinLen)
				}
				ok := fmt.Sprintf(`{%q:%q}`, c.Field, strings.Repeat("a", c.MinLen))
				if len(p.Credential) == 1 {
					if _, err := buildUser(p.Wire, ok, userA, kind); err != nil {
						t.Fatalf("%s: %s of exactly %d refused: %v", p.ID, c.Field, c.MinLen, err)
					}
				}
			}
		}
	}
}

// Every manifest Shadowsocks 2022 method builds xray's multi-user server
// with the manifest's key length; only shrink_unsafe protocols tombstone.
func TestManifestMethodsAndShrinkRules(t *testing.T) {
	ss := protocolSpec("shadowsocks")
	methods := ss.option("method")
	if methods == nil || len(methods.Values) == 0 {
		t.Fatal("no shadowsocks methods")
	}
	for _, method := range methods.Values {
		n := methods.keyLens()[method]
		m := NewCoreManager()
		inb := "[" + ssInbound("ss", freePort(t), method, b64key(n, 1), true) + "]"
		if _, err := m.Rebuild(inb, []*pb.UserOp{ssOp(userA, "ss", b64key(n, 2))}); err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		if k := m.kinds["ss"]; k.ssKeyLen != n || !shrinkUnsafe(k) {
			t.Fatalf("%s: kind %+v shrinkUnsafe=%v", method, k, shrinkUnsafe(k))
		}
		m.Teardown()
	}
	for _, p := range manifest.Protocol {
		if got := shrinkUnsafe(inboundKind{protocol: p.Wire}); got != p.ShrinkUnsafe {
			t.Fatalf("%s: shrinkUnsafe %v, manifest %v", p.ID, got, p.ShrinkUnsafe)
		}
	}
	if shrinkUnsafe(inboundKind{}) {
		t.Fatal("an unmanaged inbound is shrink-unsafe")
	}
}
