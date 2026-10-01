// Package release is the agent self-update trust format (M6): signed
// release manifests, the Ed25519 release keys that sign them, and the
// version policy. It is shared by the agent (verification) and the offline
// signing tool cmd/akari-sign. The format is part of the control contract;
// see "Agent self-update" in akari-panel/proto/agent.proto.
package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SigContext is prepended to the manifest bytes before signing (domain
// separation: a release signature can never be mistaken for anything else
// the key might sign).
const SigContext = "akari-agent-manifest-v1\n"

// MaxArtifactSize bounds a release binary (download, disk, panel storage).
const MaxArtifactSize = 256 << 20

// MaxManifestSize bounds the manifest bytes.
const MaxManifestSize = 4096

// Schema is the only manifest schema this code understands.
const Schema = 1

// PrivateKeyPrefix tags a release private key (the 32-byte Ed25519 seed,
// standard base64).
const PrivateKeyPrefix = "akari-release-key-v1:"

// Manifest describes one release binary for one platform.
type Manifest struct {
	Schema           int    `json:"schema"`
	Version          string `json:"version"`
	OS               string `json:"os"`
	Arch             string `json:"arch"`
	SHA256           string `json:"sha256"`
	Size             int64  `json:"size"`
	MinPanelProtocol uint32 `json:"min_panel_protocol"`
	CreatedAt        string `json:"created_at"`
	// Rollback: an explicitly signed downgrade target. Only such a manifest
	// may carry a version below the running one.
	Rollback bool `json:"rollback"`
}

var (
	platformRE = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
	sha256RE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Encode renders a manifest as the bytes to sign (compact JSON, fixed
// field order).
func (m *Manifest) Encode() ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// ParseManifest decodes and validates signed manifest bytes. Unknown
// fields, trailing data and out-of-range values are errors.
func ParseManifest(b []byte) (*Manifest, error) {
	if len(b) == 0 || len(b) > MaxManifestSize {
		return nil, fmt.Errorf("manifest: size %d out of range", len(b))
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("manifest: trailing data")
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	switch {
	case m.Schema != Schema:
		return fmt.Errorf("manifest: unsupported schema %d", m.Schema)
	case !ValidVersion(m.Version):
		return fmt.Errorf("manifest: invalid version %q", m.Version)
	case !platformRE.MatchString(m.OS) || !platformRE.MatchString(m.Arch):
		return fmt.Errorf("manifest: invalid platform %q/%q", m.OS, m.Arch)
	case !sha256RE.MatchString(m.SHA256):
		return errors.New("manifest: sha256 must be 64 lowercase hex digits")
	case m.Size <= 0 || m.Size > MaxArtifactSize:
		return fmt.Errorf("manifest: size %d out of range", m.Size)
	}
	if _, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil {
		return fmt.Errorf("manifest: created_at: %w", err)
	}
	return nil
}

// Signature is one release-key signature over a manifest.
type Signature struct {
	KeyID string `json:"key_id"`
	Sig   []byte `json:"sig"` // JSON: standard base64
}

// SigFile is the on-disk form of a manifest's signatures (<binary>.sig).
type SigFile struct {
	Signatures []Signature `json:"signatures"`
}

// PublicKey is a pinned release key.
type PublicKey struct {
	ID    string
	Key   ed25519.PublicKey
	Label string
}

// KeyID is the first 8 bytes of SHA-256(public key), lowercase hex.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// ParseKeys reads a key list: one "<base64 public key> [label]" per line;
// blank lines and lines starting with '#' are ignored. Duplicates are
// errors.
func ParseKeys(text string) ([]PublicKey, error) {
	var keys []PublicKey
	seen := map[string]bool{}
	for n, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		raw, err := base64.StdEncoding.DecodeString(f[0])
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("release keys line %d: not a base64 Ed25519 public key", n+1)
		}
		pub := ed25519.PublicKey(raw)
		id := KeyID(pub)
		if seen[id] {
			return nil, fmt.Errorf("release keys line %d: duplicate key %s", n+1, id)
		}
		seen[id] = true
		keys = append(keys, PublicKey{ID: id, Key: pub, Label: strings.Join(f[1:], " ")})
	}
	return keys, nil
}

// FormatPublicKey is the key-list form of a public key.
func FormatPublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// FormatPrivateKey encodes a private key (its seed) for custody.
func FormatPrivateKey(priv ed25519.PrivateKey) string {
	return PrivateKeyPrefix + base64.StdEncoding.EncodeToString(priv.Seed())
}

// ParsePrivateKey decodes FormatPrivateKey's output (surrounding
// whitespace ignored).
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(s, PrivateKeyPrefix)
	if !ok {
		return nil, errors.New("not an akari release private key")
	}
	seed, err := base64.StdEncoding.DecodeString(rest)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("malformed akari release private key")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Sign signs manifest bytes.
func Sign(manifest []byte, priv ed25519.PrivateKey) Signature {
	msg := append([]byte(SigContext), manifest...)
	pub, _ := priv.Public().(ed25519.PublicKey)
	return Signature{KeyID: KeyID(pub), Sig: ed25519.Sign(priv, msg)}
}

// ErrNoValidSignature: no signature verifies under any pinned key.
var ErrNoValidSignature = errors.New("no valid signature by a pinned release key")

// Verify returns the id of a pinned key with a valid signature over the
// manifest bytes. Signatures by unknown keys are skipped (a release may be
// signed by the old and the next key during a rotation).
func Verify(manifest []byte, sigs []Signature, keys []PublicKey) (string, error) {
	if len(keys) == 0 {
		return "", errors.New("no release keys pinned in this build: self-update disabled")
	}
	msg := append([]byte(SigContext), manifest...)
	for _, s := range sigs {
		if len(s.Sig) != ed25519.SignatureSize {
			continue
		}
		for _, k := range keys {
			if k.ID == s.KeyID && ed25519.Verify(k.Key, msg, s.Sig) {
				return k.ID, nil
			}
		}
	}
	return "", ErrNoValidSignature
}

// Policy is what the running agent knows when it judges an offer.
type Policy struct {
	Running       string // running version
	OS, Arch      string
	PanelProtocol uint32
	// RolledBack reports whether the agent already rolled back from this
	// version (it is never accepted again).
	RolledBack func(version string) bool
}

// Check applies the version policy to a verified manifest.
func (p Policy) Check(m *Manifest) error {
	if m.OS != p.OS || m.Arch != p.Arch {
		return fmt.Errorf("manifest is for %s/%s, this agent is %s/%s", m.OS, m.Arch, p.OS, p.Arch)
	}
	if m.MinPanelProtocol > p.PanelProtocol {
		return fmt.Errorf("release needs panel protocol >= %d, panel speaks %d", m.MinPanelProtocol, p.PanelProtocol)
	}
	if p.RolledBack != nil && p.RolledBack(m.Version) {
		return fmt.Errorf("version %s already failed its self-check here (rolled back)", m.Version)
	}
	c, err := CompareVersions(m.Version, p.Running)
	if err != nil {
		return fmt.Errorf("running version %q is not a release version: %w", p.Running, err)
	}
	switch {
	case c == 0:
		return fmt.Errorf("already running %s", m.Version)
	case c < 0 && !m.Rollback:
		return fmt.Errorf("refusing downgrade %s -> %s (manifest is not a signed rollback target)", p.Running, m.Version)
	}
	return nil
}

// --- semver ----------------------------------------------------------------

type semver struct {
	major, minor, patch uint64
	pre                 []string
}

var semverRE = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)` +
	`(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?` +
	`(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

func parseSemver(v string) (semver, error) {
	m := semverRE.FindStringSubmatch(v)
	if m == nil || len(v) > 128 {
		return semver{}, fmt.Errorf("%q is not a semantic version (vMAJOR.MINOR.PATCH[-pre][+build])", v)
	}
	var s semver
	var err error
	if s.major, err = strconv.ParseUint(m[1], 10, 64); err != nil {
		return semver{}, err
	}
	if s.minor, err = strconv.ParseUint(m[2], 10, 64); err != nil {
		return semver{}, err
	}
	if s.patch, err = strconv.ParseUint(m[3], 10, 64); err != nil {
		return semver{}, err
	}
	if m[4] != "" {
		s.pre = strings.Split(m[4], ".")
	}
	return s, nil
}

// ValidVersion reports whether v is "v" + a semantic version.
func ValidVersion(v string) bool {
	_, err := parseSemver(v)
	return err == nil
}

// CompareVersions orders two versions by semver precedence (build
// metadata ignored): -1, 0 or 1.
func CompareVersions(a, b string) (int, error) {
	x, err := parseSemver(a)
	if err != nil {
		return 0, err
	}
	y, err := parseSemver(b)
	if err != nil {
		return 0, err
	}
	for _, d := range [][2]uint64{{x.major, y.major}, {x.minor, y.minor}, {x.patch, y.patch}} {
		if d[0] != d[1] {
			return cmpU(d[0], d[1]), nil
		}
	}
	// A pre-release sorts before the release.
	switch {
	case len(x.pre) == 0 && len(y.pre) == 0:
		return 0, nil
	case len(x.pre) == 0:
		return 1, nil
	case len(y.pre) == 0:
		return -1, nil
	}
	for i := 0; i < len(x.pre) && i < len(y.pre); i++ {
		if c := cmpIdent(x.pre[i], y.pre[i]); c != 0 {
			return c, nil
		}
	}
	return cmpU(uint64(len(x.pre)), uint64(len(y.pre))), nil
}

func cmpU(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// cmpIdent: numeric identifiers compare numerically and sort before
// alphanumeric ones, which compare in ASCII order.
func cmpIdent(a, b string) int {
	na, ea := strconv.ParseUint(a, 10, 64)
	nb, eb := strconv.ParseUint(b, 10, 64)
	switch {
	case ea == nil && eb == nil:
		return cmpU(na, nb)
	case ea == nil:
		return -1
	case eb == nil:
		return 1
	}
	return strings.Compare(a, b)
}
