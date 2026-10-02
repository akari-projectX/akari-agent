package release

// Fuzz targets for the self-update trust path: manifest bytes and
// signature files (from the panel's offer), the pinned key list, and the
// version order that decides upgrade vs. downgrade. Seeds run as tests;
// `make fuzz` explores.

import (
	"crypto/ed25519"
	"math/big"
	"regexp"
	"strings"
	"testing"
)

// FuzzParseManifest: an accepted manifest re-encodes (Encode, the bytes
// that get signed) to a manifest that parses back equal.
func FuzzParseManifest(f *testing.F) {
	f.Add([]byte(`{"schema":1,"version":"v1.2.3","os":"linux","arch":"amd64","sha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824","size":5,"min_panel_protocol":3,"created_at":"2026-10-02T00:00:00Z","rollback":false}`))
	f.Add([]byte(`{"schema":1,"VERSION":"v1.2.3-rc.1+b.7","os":"linux","arch":"arm64","sha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824","size":5,"min_panel_protocol":3,"created_at":"2026-10-02T00:00:00+08:00"} `))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseManifest(b)
		if err != nil {
			return
		}
		enc, err := m.Encode()
		if err != nil {
			t.Fatalf("accepted manifest does not encode: %v", err)
		}
		m2, err := ParseManifest(enc)
		if err != nil || *m2 != *m {
			t.Fatalf("round trip: %v %+v != %+v", err, m2, m)
		}
	})
}

var numericRE = regexp.MustCompile(`^[0-9]+$`)

// refCompare is semver 2.0.0 precedence written independently: numeric
// identifiers of ANY length compare numerically and sort before
// alphanumeric ones (ASCII order).
func refCompare(a, b string) int {
	core := func(v string) ([]*big.Int, []string) {
		v = strings.TrimPrefix(v, "v")
		v, _, _ = strings.Cut(v, "+")
		c, pre, hasPre := strings.Cut(v, "-")
		var nums []*big.Int
		for _, p := range strings.Split(c, ".") {
			n, _ := new(big.Int).SetString(p, 10)
			nums = append(nums, n)
		}
		if !hasPre {
			return nums, nil
		}
		return nums, strings.Split(pre, ".")
	}
	xa, pa := core(a)
	xb, pb := core(b)
	for i := range xa {
		if c := xa[i].Cmp(xb[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(pa) == 0 && len(pb) == 0:
		return 0
	case len(pa) == 0:
		return 1
	case len(pb) == 0:
		return -1
	}
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, nb := numericRE.MatchString(pa[i]), numericRE.MatchString(pb[i])
		var c int
		switch {
		case na && nb:
			x, _ := new(big.Int).SetString(pa[i], 10)
			y, _ := new(big.Int).SetString(pb[i], 10)
			c = x.Cmp(y)
		case na:
			c = -1
		case nb:
			c = 1
		default:
			c = strings.Compare(pa[i], pb[i])
		}
		if c != 0 {
			return c
		}
	}
	switch {
	case len(pa) < len(pb):
		return -1
	case len(pa) > len(pb):
		return 1
	}
	return 0
}

// FuzzCompareVersions: CompareVersions equals the reference precedence
// (the panel's updates.rs implements the same order: a disagreement means
// the panel offers what the agent calls a downgrade, or the reverse), and
// is antisymmetric.
func FuzzCompareVersions(f *testing.F) {
	for _, p := range [][2]string{
		{"v1.2.3", "v1.2.4"},
		{"v1.0.0-alpha", "v1.0.0-alpha.1"},
		{"v1.0.0-rc.99999999999999999999", "v1.0.0-rc.100000000000000000000"},
		{"v1.0.0-99999999999999999999", "v1.0.0--x"},
		{"v1.0.0-beta.11", "v1.0.0-beta.2"},
		{"v1.0.0+build.1", "v1.0.0+build.2"},
	} {
		f.Add(p[0], p[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		ab, err1 := CompareVersions(a, b)
		ba, err2 := CompareVersions(b, a)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("error asymmetry %v / %v", err1, err2)
		}
		if err1 != nil {
			return
		}
		if ab != -ba {
			t.Fatalf("not antisymmetric: %q %q -> %d %d", a, b, ab, ba)
		}
		if want := refCompare(a, b); ab != want {
			t.Fatalf("CompareVersions(%q, %q) = %d, semver says %d", a, b, ab, want)
		}
	})
}

// FuzzVerify: a signature verifies for its exact manifest bytes under
// the pinned key only; key ids that do not match are ignored.
func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{"schema":1}`), []byte{1, 2, 3})
	seed := make([]byte, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	pub, _ := priv.Public().(ed25519.PublicKey)
	key := PublicKey{ID: KeyID(pub), Key: pub}
	f.Fuzz(func(t *testing.T, manifest, junk []byte) {
		s := Sign(manifest, priv)
		if id, err := Verify(manifest, []Signature{s}, []PublicKey{key}); err != nil || id != key.ID {
			t.Fatalf("genuine signature refused: %v", err)
		}
		if _, err := Verify(append(append([]byte{}, manifest...), 'x'), []Signature{s}, []PublicKey{key}); err == nil {
			t.Fatal("signature verified for other bytes")
		}
		if _, err := Verify(manifest, []Signature{{KeyID: "x", Sig: s.Sig}}, []PublicKey{key}); err == nil {
			t.Fatal("signature under a foreign key id accepted")
		}
		if _, err := Verify(manifest, []Signature{{KeyID: key.ID, Sig: junk}}, []PublicKey{key}); err == nil {
			// Only the real signature could verify; junk equal to it is fine.
			if string(junk) != string(s.Sig) {
				t.Fatal("junk signature verified")
			}
		}
		if _, err := Verify(manifest, []Signature{s}, nil); err == nil {
			t.Fatal("verified without pinned keys")
		}
	})
}

// FuzzParseKeys: the pinned key list. Every key is 32 bytes with its
// derived id, ids are unique.
func FuzzParseKeys(f *testing.F) {
	f.Add("vRaBp2ipakKPUi8YJg00NXCsSqhxLSMgE5UusAbaCuM= test key\n# comment\n\n")
	f.Add("vRaBp2ipakKPUi8YJg00NXCsSqhxLSMgE5UusAbaCuM=\nvRaBp2ipakKPUi8YJg00NXCsSqhxLSMgE5UusAbaCuM=\n")
	f.Fuzz(func(t *testing.T, text string) {
		keys, err := ParseKeys(text)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, k := range keys {
			if len(k.Key) != ed25519.PublicKeySize || k.ID != KeyID(k.Key) || seen[k.ID] {
				t.Fatalf("bad key %+v", k)
			}
			seen[k.ID] = true
		}
	})
}
