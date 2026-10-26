package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T) (ed25519.PrivateKey, PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, PublicKey{ID: KeyID(pub), Key: pub}
}

func manifest(t *testing.T, version string, rollback bool) []byte {
	t.Helper()
	m := &Manifest{Schema: SchemaForward, Version: version, OS: "linux", Arch: "amd64",
		SHA256: strings.Repeat("ab", 32), Size: 1234, MinPanelProtocol: 3,
		CreatedAt: "2026-10-02T00:00:00Z", Rollback: rollback}
	if rollback {
		m.Schema, m.RollbackFrom, m.ExpiresAt = SchemaRollback, "v1.2.3", "2026-10-09T00:00:00Z"
		if c, _ := CompareVersions(version, "v1.2.3"); c >= 0 {
			m.RollbackFrom = "v9.0.0" // a manifest must name a newer version; Check then refuses it on other grounds
		}
	}
	b, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyGoodWrongKeyTampered(t *testing.T) {
	priv, pub := newKey(t)
	_, other := newKey(t)
	b := manifest(t, "v1.2.3", false)
	sig := Sign(b, priv)
	if id, err := Verify(b, []Signature{sig}, []PublicKey{pub}); err != nil || id != pub.ID {
		t.Fatalf("valid signature refused: %v", err)
	}
	if _, err := Verify(b, []Signature{sig}, []PublicKey{other}); err == nil {
		t.Fatal("signature by an unpinned key accepted")
	}
	// Same key id claimed by a different key: still refused.
	forged := Signature{KeyID: other.ID, Sig: sig.Sig}
	if _, err := Verify(b, []Signature{forged}, []PublicKey{other}); err == nil {
		t.Fatal("relabelled signature accepted")
	}
	tampered := []byte(strings.Replace(string(b), "v1.2.3", "v1.2.4", 1))
	if _, err := Verify(tampered, []Signature{sig}, []PublicKey{pub}); err == nil {
		t.Fatal("tampered manifest accepted")
	}
	// Domain separation: a bare signature over the manifest bytes is not a
	// release signature.
	bare := Signature{KeyID: pub.ID, Sig: ed25519.Sign(priv, b)}
	if _, err := Verify(b, []Signature{bare}, []PublicKey{pub}); err == nil {
		t.Fatal("signature without the context prefix accepted")
	}
	if _, err := Verify(b, []Signature{sig}, nil); err == nil {
		t.Fatal("verified with no pinned keys")
	}
	if _, err := Verify(b, []Signature{{KeyID: pub.ID, Sig: []byte("short")}}, []PublicKey{pub}); err == nil {
		t.Fatal("short signature accepted")
	}
}

// Rotation: a release signed by both the old and the next key verifies on
// agents pinning either; one signed only by the next key needs an agent
// that already pins it.
func TestKeyRotation(t *testing.T) {
	oldPriv, oldPub := newKey(t)
	nextPriv, nextPub := newKey(t)
	b := manifest(t, "v2.0.0", false)
	both := []Signature{Sign(b, oldPriv), Sign(b, nextPriv)}
	for _, pinned := range [][]PublicKey{{oldPub}, {nextPub}, {oldPub, nextPub}} {
		if _, err := Verify(b, both, pinned); err != nil {
			t.Fatalf("dual-signed release refused by %v: %v", pinned, err)
		}
	}
	onlyNext := []Signature{Sign(b, nextPriv)}
	if _, err := Verify(b, onlyNext, []PublicKey{oldPub}); err == nil {
		t.Fatal("next-key-only release accepted by an agent pinning only the old key")
	}
	if id, err := Verify(b, onlyNext, []PublicKey{oldPub, nextPub}); err != nil || id != nextPub.ID {
		t.Fatalf("next-key-only release refused after rotation: %v", err)
	}
}

func TestParseManifestStrict(t *testing.T) {
	good := string(manifest(t, "v1.0.0", false))
	if _, err := ParseManifest([]byte(good)); err != nil {
		t.Fatal(err)
	}
	bad := []string{
		strings.Replace(good, `"schema":1`, `"schema":2`, 1),
		strings.Replace(good, `"v1.0.0"`, `"1.0.0"`, 1),
		strings.Replace(good, `"v1.0.0"`, `"v1.0"`, 1),
		strings.Replace(good, `"linux"`, `"Linux"`, 1),
		strings.Replace(good, strings.Repeat("ab", 32), strings.Repeat("AB", 32), 1),
		strings.Replace(good, `"size":1234`, `"size":0`, 1),
		strings.Replace(good, `"size":1234`, `"size":268435457`, 1),
		strings.Replace(good, `"2026-10-02T00:00:00Z"`, `"yesterday"`, 1),
		strings.Replace(good, `{`, `{"extra":1,`, 1),
		good + `{}`,
		"",
	}
	for _, b := range bad {
		if _, err := ParseManifest([]byte(b)); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
}

func TestPolicy(t *testing.T) {
	m := func(v string, rb bool) *Manifest {
		x, err := ParseManifest(manifest(t, v, rb))
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	p := Policy{Running: "v1.2.3", OS: "linux", Arch: "amd64", PanelProtocol: 3,
		RolledBack: func(v string) bool { return v == "v1.3.0" },
		Ran:        func(string) bool { return true },
		Now:        func() time.Time { return time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC) }}
	ok := []*Manifest{m("v1.2.4", false), m("v2.0.0", false), m("v1.2.4-rc.1", false), m("v1.0.0", true)}
	for _, x := range ok {
		if err := p.Check(x); err != nil {
			t.Errorf("%s (rollback=%v) refused: %v", x.Version, x.Rollback, err)
		}
	}
	refused := []*Manifest{
		m("v1.2.3", false),      // same
		m("v1.2.2", false),      // downgrade
		m("v1.2.3-rc.9", false), // pre-release of the running version sorts below it
		m("v1.3.0", false),      // rolled back from before
		m("v1.3.0", true),       // even as a signed rollback target (and it is no downgrade)
	}
	for _, x := range refused {
		if err := p.Check(x); err == nil {
			t.Errorf("%s (rollback=%v) accepted", x.Version, x.Rollback)
		}
	}
	other := m("v9.0.0", false)
	other.Arch = "arm64"
	if p.Check(other) == nil {
		t.Error("foreign arch accepted")
	}
	high := m("v9.0.0", false)
	high.MinPanelProtocol = 4
	if p.Check(high) == nil {
		t.Error("release needing a newer panel accepted")
	}
	dev := p
	dev.Running = "dev"
	if dev.Check(m("v9.0.0", false)) == nil {
		t.Error("update accepted by a non-release build")
	}
}

func TestCompareVersions(t *testing.T) {
	// Ascending per semver 2.0 §11.
	order := []string{"v1.0.0-alpha", "v1.0.0-alpha.1", "v1.0.0-alpha.beta", "v1.0.0-beta",
		"v1.0.0-beta.2", "v1.0.0-beta.11", "v1.0.0-rc.1", "v1.0.0", "v1.0.1", "v1.1.0", "v2.0.0", "v10.0.0"}
	for i := range order {
		for j := range order {
			c, err := CompareVersions(order[i], order[j])
			if err != nil {
				t.Fatal(err)
			}
			want := cmpU(uint64(i), uint64(j))
			if c != want {
				t.Errorf("compare(%s,%s)=%d want %d", order[i], order[j], c, want)
			}
		}
	}
	if c, _ := CompareVersions("v1.0.0+build.1", "v1.0.0"); c != 0 {
		t.Error("build metadata affects precedence")
	}
	for _, v := range []string{"dev", "1.0.0", "v01.0.0", "v1.0", "v1.0.0-", "v1.0.0-01", "v0.1.0-3-gabcdef-dirty "} {
		if ValidVersion(v) {
			t.Errorf("%q accepted", v)
		}
	}
}

func TestKeysAndPrivateKeyFormat(t *testing.T) {
	priv, pub := newKey(t)
	text := "# pinned keys\n\n" + FormatPublicKey(pub.Key) + " release-2026 (offline)\n"
	keys, err := ParseKeys(text)
	if err != nil || len(keys) != 1 || keys[0].ID != pub.ID || keys[0].Label != "release-2026 (offline)" {
		t.Fatalf("keys %+v err %v", keys, err)
	}
	if _, err := ParseKeys(text + text); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if _, err := ParseKeys("not-a-key\n"); err == nil {
		t.Fatal("junk accepted")
	}
	back, err := ParsePrivateKey(" " + FormatPrivateKey(priv) + "\n")
	if err != nil || !back.Equal(priv) {
		t.Fatalf("private key round trip: %v", err)
	}
	if _, err := ParsePrivateKey(FormatPublicKey(pub.Key)); err == nil {
		t.Fatal("public key parsed as private")
	}
}

// The shared vector (akari-panel proto/testdata/update_vector.json, vendored
// as proto/update_vector.json): what the panel verifies, the agent verifies.
func TestSharedVector(t *testing.T) {
	raw, err := os.ReadFile("../proto/update_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		PublicKey string  `json:"public_key"`
		Manifest  string  `json:"manifest"`
		Sig       SigFile `json:"sig"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	keys, err := ParseKeys(v.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManifest([]byte(v.Manifest)); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify([]byte(v.Manifest), v.Sig.Signatures, keys); err != nil {
		t.Fatal(err)
	}
}

// The rollback cases of the shared vector (audit P2-2): the panel's
// updates.rs reads the same cases.
func TestSharedVectorRollbackCases(t *testing.T) {
	raw, err := os.ReadFile("../proto/update_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		PublicKey string `json:"public_key"`
		Cases     []struct {
			Name     string  `json:"name"`
			Manifest string  `json:"manifest"`
			Sig      SigFile `json:"sig"`
			Running  string  `json:"running"`
			Now      string  `json:"now"`
			Ran      bool    `json:"ran"`
			ParseOK  bool    `json:"parse_ok"`
			Verdict  string  `json:"verdict"`
		} `json:"rollback_cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	keys, err := ParseKeys(v.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) < 10 {
		t.Fatalf("vector lost its rollback cases (%d)", len(v.Cases))
	}
	for _, c := range v.Cases {
		if _, err := Verify([]byte(c.Manifest), c.Sig.Signatures, keys); err != nil {
			t.Errorf("%s: signature: %v", c.Name, err)
			continue
		}
		m, perr := ParseManifest([]byte(c.Manifest))
		if (perr == nil) != c.ParseOK {
			t.Errorf("%s: parse error %v, want ok=%v", c.Name, perr, c.ParseOK)
			continue
		}
		if perr != nil {
			if c.Verdict != "refused" {
				t.Errorf("%s: unparseable but verdict %q", c.Name, c.Verdict)
			}
			continue
		}
		now, err := time.Parse(time.RFC3339, c.Now)
		if err != nil {
			t.Fatal(err)
		}
		p := Policy{Running: c.Running, OS: "linux", Arch: "amd64", PanelProtocol: 3,
			Ran: func(string) bool { return c.Ran }, Now: func() time.Time { return now }}
		err = p.Check(m)
		want := map[string]string{"wrong_from": "replaces", "expired": "expired", "unknown_target": "never ran"}[c.Verdict]
		switch {
		case c.Verdict == "ok" && err != nil:
			t.Errorf("%s: refused: %v", c.Name, err)
		case c.Verdict != "ok" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: verdict %s, got %v", c.Name, c.Verdict, err)
		}
	}
}

// W13 fuzz regression: numeric pre-release identifiers beyond uint64 are
// still numeric (semver; the panel's updates.rs agrees).
func TestCompareVersionsHugeNumericIdentifiers(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"v1.0.0-rc.99999999999999999999", "v1.0.0-rc.100000000000000000000", -1},
		{"v1.0.0-99999999999999999999", "v1.0.0--x", -1},
		{"v1.0.0-18446744073709551616", "v1.0.0-18446744073709551615", 1},
		{"v1.0.0-1", "v1.0.0-18446744073709551616", -1},
	} {
		if got, err := CompareVersions(c.a, c.b); err != nil || got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, %v; want %d", c.a, c.b, got, err, c.want)
		}
	}
}

// Audit P2-2: a signed rollback is bound to the version it replaces, to its
// expiry, and to a version the node ran.
func TestRollbackPolicy(t *testing.T) {
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	rb := func(mod func(*Manifest)) *Manifest {
		m := &Manifest{Schema: SchemaRollback, Version: "v1.2.3", OS: "linux", Arch: "amd64",
			SHA256: strings.Repeat("ab", 32), Size: 1, MinPanelProtocol: 3, CreatedAt: "2026-10-01T00:00:00Z",
			Rollback: true, RollbackFrom: "v1.3.0", ExpiresAt: "2026-10-08T00:00:00Z"}
		if mod != nil {
			mod(m)
		}
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseManifest(b)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	p := Policy{Running: "v1.3.0", OS: "linux", Arch: "amd64", PanelProtocol: 3,
		Ran: func(v string) bool { return v == "v1.2.3" }, Now: func() time.Time { return now }}
	if err := p.Check(rb(nil)); err != nil {
		t.Fatalf("bound rollback refused: %v", err)
	}
	for name, c := range map[string]struct {
		p    Policy
		m    *Manifest
		want string
	}{
		"another running version": {Policy{Running: "v1.4.0"}, rb(nil), "replaces v1.3.0"},
		"expired":                 {Policy{Now: func() time.Time { return time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC) }}, rb(nil), "expired"},
		"never ran":               {Policy{Ran: func(string) bool { return false }}, rb(nil), "never ran"},
		"no history":              {Policy{Ran: func(string) bool { return true }}, rb(func(m *Manifest) { m.Version = "v1.2.2" }), ""},
	} {
		q := p
		if c.p.Running != "" {
			q.Running = c.p.Running
		}
		if c.p.Now != nil {
			q.Now = c.p.Now
		}
		if c.p.Ran != nil {
			q.Ran = c.p.Ran
		}
		err := q.Check(c.m)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	// No Ran function = no history = refused, unless the caller is not the
	// authority on it (the agent defers to the updater).
	q := p
	q.Ran = nil
	if err := q.Check(rb(nil)); err == nil || !strings.Contains(err.Error(), "never ran") {
		t.Errorf("rollback without a history accepted: %v", err)
	}
	q.DeferRan = true
	if err := q.Check(rb(nil)); err != nil {
		t.Errorf("deferred history: %v", err)
	}
	// Forward releases are not affected by any of it.
	fwd := &Manifest{Schema: 1, Version: "v1.4.0", OS: "linux", Arch: "amd64", SHA256: strings.Repeat("ab", 32),
		Size: 1, CreatedAt: "2026-10-01T00:00:00Z"}
	q.Ran, q.DeferRan = nil, false
	if err := q.Check(fwd); err != nil {
		t.Errorf("forward release: %v", err)
	}
}

func TestManifestRollbackFields(t *testing.T) {
	const base = `{"schema":2,"version":"v1.2.3","os":"linux","arch":"amd64","sha256":"` +
		"abababababababababababababababababababababababababababababababab" +
		`","size":5,"min_panel_protocol":3,"created_at":"2026-10-01T00:00:00Z","rollback":true,` +
		`"rollback_from":"v1.3.0","expires_at":"2026-10-08T00:00:00Z"}`
	if _, err := ParseManifest([]byte(base)); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"schema 1 rollback":      strings.Replace(base, `"schema":2`, `"schema":1`, 1),
		"schema 3":               strings.Replace(base, `"schema":2`, `"schema":3`, 1),
		"no rollback_from":       strings.Replace(base, `"rollback_from":"v1.3.0",`, "", 1),
		"no expires_at":          strings.Replace(base, `,"expires_at":"2026-10-08T00:00:00Z"`, "", 1),
		"from == version":        strings.Replace(base, `"rollback_from":"v1.3.0"`, `"rollback_from":"v1.2.3"`, 1),
		"from older":             strings.Replace(base, `"rollback_from":"v1.3.0"`, `"rollback_from":"v1.0.0"`, 1),
		"from not a version":     strings.Replace(base, `"rollback_from":"v1.3.0"`, `"rollback_from":"latest"`, 1),
		"expires before created": strings.Replace(base, `2026-10-08T00:00:00Z`, `2026-09-30T00:00:00Z`, 1),
		"expires == created":     strings.Replace(base, `2026-10-08T00:00:00Z`, `2026-10-01T00:00:00Z`, 1),
		"over 30 days":           strings.Replace(base, `2026-10-08T00:00:00Z`, `2026-11-01T00:00:01Z`, 1),
		"expires not a time":     strings.Replace(base, `2026-10-08T00:00:00Z`, `soon`, 1),
		"schema 2 forward":       strings.Replace(base, `"rollback":true`, `"rollback":false`, 1),
	} {
		if _, err := ParseManifest([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	fwd := strings.Replace(strings.Replace(base, `"schema":2`, `"schema":1`, 1), `"rollback":true`, `"rollback":false`, 1)
	if _, err := ParseManifest([]byte(fwd)); err == nil {
		t.Error("rollback_from on a forward release accepted")
	}
	if _, err := ParseManifest([]byte(strings.Replace(base, `2026-10-08T00:00:00Z`, `2026-10-31T00:00:00Z`, 1))); err != nil {
		t.Errorf("30 days exactly refused: %v", err)
	}
}
