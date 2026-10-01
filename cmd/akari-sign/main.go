// Command akari-sign is the offline release-signing tool (M6): it creates
// release keys and signs/verifies agent self-update manifests. The format
// lives in package release; see README "Release signing keys".
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"akari/agent/release"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "akari-sign:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: akari-sign keygen|pubkey|sign|countersign|verify [flags] (see -h of each)")
	}
	switch args[0] {
	case "keygen":
		return keygen(args[1:])
	case "pubkey":
		return pubkey(args[1:])
	case "sign":
		return sign(args[1:])
	case "countersign":
		return countersign(args[1:])
	case "verify":
		return verify(args[1:])
	}
	return fmt.Errorf("unknown command %q (keygen|pubkey|sign|countersign|verify)", args[0])
}

type keyFlags struct{ file, env string }

func (k *keyFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&k.file, "key", "", "private key file")
	fs.StringVar(&k.env, "key-env", "", "environment variable holding the private key (instead of -key)")
}

func (k *keyFlags) load() (ed25519.PrivateKey, error) {
	var text string
	switch {
	case k.file != "" && k.env != "":
		return nil, errors.New("-key and -key-env are mutually exclusive")
	case k.file != "":
		b, err := os.ReadFile(k.file)
		if err != nil {
			return nil, err
		}
		text = string(b)
	case k.env != "":
		text = os.Getenv(k.env)
		if strings.TrimSpace(text) == "" {
			return nil, fmt.Errorf("environment variable %s is empty", k.env)
		}
	default:
		return nil, errors.New("-key <file> or -key-env <variable> required")
	}
	return release.ParsePrivateKey(text)
}

func pubLine(priv ed25519.PrivateKey) (string, string) {
	pub, _ := priv.Public().(ed25519.PublicKey)
	id := release.KeyID(pub)
	return release.FormatPublicKey(pub) + " key-" + id, id
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	var kf keyFlags
	kf.register(fs)
	out := fs.String("out", "", "where to write the new private key (0600; must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("keygen: -out is required")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(release.FormatPrivateKey(priv) + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	line, _ := pubLine(priv)
	fmt.Println(line)
	return nil
}

func pubkey(args []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	var kf keyFlags
	kf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	priv, err := kf.load()
	if err != nil {
		return err
	}
	line, _ := pubLine(priv)
	fmt.Println(line)
	return nil
}

var fileRE = regexp.MustCompile(`(?:^|[/-])akari-agent-([a-z0-9]+)-([a-z0-9]+)(?:\.|$)`)

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	var kf keyFlags
	kf.register(fs)
	binary := fs.String("binary", "", "release binary")
	version := fs.String("version", "", "release version (vX.Y.Z[-pre])")
	osName := fs.String("os", "", "target OS (default: from the akari-agent-<os>-<arch> file name)")
	arch := fs.String("arch", "", "target arch (default: from the file name)")
	minProto := fs.Uint("min-panel-protocol", 3, "lowest panel control-protocol revision this release works with")
	createdAt := fs.String("created-at", "", "RFC 3339 timestamp (default: $SOURCE_DATE_EPOCH or now)")
	outM := fs.String("out-manifest", "", "default: <binary>.manifest.json")
	outS := fs.String("out-sig", "", "default: <binary>.manifest.sig")
	rollback := fs.Bool("rollback", false, "mark as an explicit rollback target (may be installed over newer versions)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *binary == "" || *version == "" {
		return errors.New("sign: -binary and -version are required")
	}
	if *minProto > 1<<32-1 {
		return errors.New("sign: -min-panel-protocol out of range")
	}
	priv, err := kf.load()
	if err != nil {
		return err
	}
	if m := fileRE.FindStringSubmatch(filepath.Base(*binary)); m != nil {
		if *osName == "" {
			*osName = m[1]
		}
		if *arch == "" {
			*arch = m[2]
		}
	}
	if *osName == "" || *arch == "" {
		return errors.New("sign: -os and -arch required (cannot be derived from the file name)")
	}
	ts := *createdAt
	if ts == "" {
		now := time.Now().UTC()
		if sde := os.Getenv("SOURCE_DATE_EPOCH"); sde != "" {
			sec, err := strconv.ParseInt(sde, 10, 64)
			if err != nil {
				return fmt.Errorf("SOURCE_DATE_EPOCH: %w", err)
			}
			now = time.Unix(sec, 0).UTC()
		}
		ts = now.Format(time.RFC3339)
	}
	sum, size, err := hashFile(*binary)
	if err != nil {
		return err
	}
	m := &release.Manifest{
		Schema: release.Schema, Version: *version, OS: *osName, Arch: *arch,
		SHA256: sum, Size: size, MinPanelProtocol: uint32(*minProto), //nolint:gosec // range checked above
		CreatedAt: ts, Rollback: *rollback,
	}
	body, err := m.Encode()
	if err != nil {
		return err
	}
	sig := release.Sign(body, priv)
	if *outM == "" {
		*outM = *binary + ".manifest.json"
	}
	if *outS == "" {
		*outS = *binary + ".manifest.sig"
	}
	sf, err := json.Marshal(release.SigFile{Signatures: []release.Signature{sig}})
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outM, body, 0o644); err != nil { //nolint:gosec // public artifact
		return err
	}
	if err := os.WriteFile(*outS, sf, 0o644); err != nil { //nolint:gosec // public artifact
		return err
	}
	fmt.Printf("signed %s %s/%s sha256=%s size=%d key=%s\n  %s\n  %s\n",
		m.Version, m.OS, m.Arch, m.SHA256, m.Size, sig.KeyID, *outM, *outS)
	return nil
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func readSigs(path string) (*release.SigFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sf release.SigFile
	if err := json.Unmarshal(b, &sf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &sf, nil
}

func countersign(args []string) error {
	fs := flag.NewFlagSet("countersign", flag.ContinueOnError)
	var kf keyFlags
	kf.register(fs)
	manifest := fs.String("manifest", "", "manifest file")
	sigPath := fs.String("sig", "", "signature file to add to")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifest == "" || *sigPath == "" {
		return errors.New("countersign: -manifest and -sig are required")
	}
	priv, err := kf.load()
	if err != nil {
		return err
	}
	body, err := os.ReadFile(*manifest)
	if err != nil {
		return err
	}
	if _, err := release.ParseManifest(body); err != nil {
		return err
	}
	sf, err := readSigs(*sigPath)
	if err != nil {
		return err
	}
	sig := release.Sign(body, priv)
	for _, s := range sf.Signatures {
		if s.KeyID == sig.KeyID {
			return fmt.Errorf("already signed by key %s", sig.KeyID)
		}
	}
	sf.Signatures = append(sf.Signatures, sig)
	out, err := json.Marshal(sf)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*sigPath, out, 0o644); err != nil { //nolint:gosec // public artifact
		return err
	}
	fmt.Printf("countersigned with key %s (%d signatures)\n", sig.KeyID, len(sf.Signatures))
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	var kf keyFlags
	kf.register(fs)
	keys := fs.String("keys", "", "public key list (release-keys.txt format)")
	manifest := fs.String("manifest", "", "manifest file")
	sigPath := fs.String("sig", "", "signature file")
	binary := fs.String("binary", "", "optional: also check the binary's size and SHA-256")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keys == "" || *manifest == "" || *sigPath == "" {
		return errors.New("verify: -keys, -manifest and -sig are required")
	}
	kt, err := os.ReadFile(*keys)
	if err != nil {
		return err
	}
	pubs, err := release.ParseKeys(string(kt))
	if err != nil {
		return err
	}
	body, err := os.ReadFile(*manifest)
	if err != nil {
		return err
	}
	m, err := release.ParseManifest(body)
	if err != nil {
		return err
	}
	sf, err := readSigs(*sigPath)
	if err != nil {
		return err
	}
	id, err := release.Verify(body, sf.Signatures, pubs)
	if err != nil {
		return err
	}
	if *binary != "" {
		sum, size, err := hashFile(*binary)
		if err != nil {
			return err
		}
		if sum != m.SHA256 || size != m.Size {
			return fmt.Errorf("binary does not match the manifest (sha256 %s, size %d)", sum, size)
		}
	}
	fmt.Printf("ok: %s %s/%s signed by %s\n", m.Version, m.OS, m.Arch, id)
	return nil
}
