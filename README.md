# akari-agent

Node-side agent for the Akari control plane. Embeds **xray-core**
(`v1.260327.0`, the Go-module form of release v26.3.27) and keeps one
outbound-only mTLS gRPC stream to the panel. There is no management port on
the node and no protocol credentials — the TLS client certificate (issued by
the panel CA) is the node's identity.

Responsibilities:

- apply panel-pushed `ConfigSnapshot`s (start/rebuild the embedded core) and
  `UserDelta`s (base/target versions, REPLACE semantics; dynamic
  `AddUser`/`RemoveUser`, no rebuild). A gate dispatcher replaces xray's
  default one so removing or rotating a user also closes that user's live
  connections (and refuses new mux sub-streams on them)
- user-less inbounds (dokodemo/socks/http without clients) are neither gated
  nor billed — only vless/vmess/trojan users are panel-managed
- `agent.remove_mode = "rebuild"` on the panel (pushed on every lease grant)
  makes every removal/rotation a full rebuild instead (fallback switch)
- per-protocol revocation canaries: `make test-canary` (part of `make
  test`); bump xray-core only when they are green
- report a state hash of what actually runs (Hello, every Ack) so the panel
  detects divergence
- enforce the panel's fail-closed lease (CLOCK_BOOTTIME; stop xray when the
  panel has not confirmed the desired state for the lease duration)
- report cumulative per-user traffic counters (10s) and heartbeats (15s)
- converge to the panel's desired state after any disconnect

## Build

```bash
make build            # static go build, version + git sha stamped (`./agent -version`)
make dist             # linux amd64/arm64 release binaries + SHA256SUMS in dist/
make proto            # regenerate pb/ from proto/agent.proto
make sync-proto       # pull the contract from the sibling akari-panel checkout
make check-proto      # fail if the vendored contract drifted from akari-panel
make vet fmt-check
```

Releases (tag `v*`) are built, SBOM'd and cosign-signed by `.github/workflows/release.yml`;
install as a hardened systemd service with `akari-panel/deploy/systemd/akari-agent.service`.

Sibling checkout convention: akari-panel and akari-agent live side by side
(`../akari-panel` / `../akari-agent`), same as the panel's smoke test expects.

## Self-update (protocol 3)

The panel can roll out new agent releases (staged waves, health gate, automatic halt; see
`akari-panel/docs/DEPLOY.md`, "Agent updates"). The agent trusts **only** manifests signed by a
release key pinned in this repository (`release-keys.txt`, compiled in); the panel is a relay.
An offer is accepted only if a signature verifies, the platform matches, the version is newer
than the running one (or the signed manifest is an explicit `rollback` target) and the node has
not rolled back from that version before. The binary comes over the existing mTLS connection
(`AgentChannel.FetchArtifact`), is checked for size and SHA-256, staged in
`<state dir>/update/bin/`, and the agent replaces its process image with it after persisting its
final traffic counters. The new binary must connect and get an apply acknowledged within
`-update-self-check` (default 5m) or it returns to the previous binary; one that crashes on start
is rolled back by the installed binary (the launcher) after `-update-max-boots` (default 3)
starts. `./agent -release-keys` lists the pinned keys.

### Release signing keys

Manifests (`akari-agent-linux-<arch>.manifest.json`: version, os, arch, sha256, size,
min_panel_protocol, created_at, rollback) are signed with Ed25519 over
`"akari-agent-manifest-v1\n" || manifest` (`release/`, contract in akari-panel
`proto/agent.proto`). Cosign keyless signatures stay for humans and CI; nodes do not need
Rekor/Fulcio connectivity.

```bash
go run ./cmd/akari-sign keygen -out /offline/release.key   # prints the public line
# add that line to release-keys.txt, commit, release (agents now pin it)
make dist VERSION=v1.2.3
make sign-manifest VERSION=v1.2.3 KEY=/offline/release.key  # dist/*.manifest.{json,sig}
go run ./cmd/akari-sign verify -keys release-keys.txt -manifest dist/akari-agent-linux-amd64.manifest.json \
  -sig dist/akari-agent-linux-amd64.manifest.sig -binary dist/akari-agent-linux-amd64
```

Custody: generate and keep the key offline (encrypted media, two copies); whoever holds it can
update every node. CI signs only if the `AKARI_RELEASE_SIGNING_KEY` repository secret is set
(`.github/workflows/release.yml`; without it the release has no manifests and a warning) and
refuses manifests that do not verify under `release-keys.txt`. Rotation: pin the next key next to
the current one and release; sign with both (`akari-sign countersign`) until every node runs a
build pinning the next key; then drop the old key. `testdata/TEST-ONLY-release.key` is a public
test key used only by builds with the `akari_testkeys` tag (`make build-testkeys`, smoke);
`make dist` refuses binaries that contain it.

## Run

```bash
./agent -config test-node-bootstrap.toml -state-dir /var/lib/akari-agent
```

The bootstrap file is produced by `akari node add <name>` on the panel: panel
address, TLS server name, the panel CA and a **one-time enrollment token** —
no private key. On first start the agent generates an ECDSA P-256 key in its
state directory (`-state-dir`; default `$STATE_DIRECTORY` under systemd, else
the config file's directory; files 0600), enrolls with a CSR (the only call
that works without a client certificate) and stores the issued certificate.
The key never leaves the node and is never logged. Once less than a third of
the certificate's validity is left (protocol 2), it renews over the live mTLS
connection with a new key, reconnects with the new certificate and keeps the
old one until the panel has accepted the new one. A bootstrap file with a new
token re-enrolls the node once. v1 bootstrap files (`identity.cert_pem` +
`identity.key_pem`) still work and move onto a local key at the first
renewal. See `akari-panel/docs/DEPLOY.md`.
