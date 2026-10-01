package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"strings"
	"testing"
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
	m := &Manifest{Schema: 1, Version: version, OS: "linux", Arch: "amd64",
		SHA256: strings.Repeat("ab", 32), Size: 1234, MinPanelProtocol: 3,
		CreatedAt: "2026-10-02T00:00:00Z", Rollback: rollback}
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
		RolledBack: func(v string) bool { return v == "v1.3.0" }}
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
		m("v1.3.0", true),       // even as a signed rollback target
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
