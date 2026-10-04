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
- report cumulative per-user traffic counters (10s) and heartbeats (15s,
  `-heartbeat-interval`) with the machine status (W11: CPU, load,
  memory/swap, disk, default-route interface rates and totals, TCP/UDP
  sockets, online users, RSS, xray version; read from `/proc`, no cgo)
- latency test like Clash's url-test (W11): HTTP GET from the node's own
  egress every 5 h (panel-configurable; "test now" from the panel), median
  of 3, primary URL with a fallback
- converge to the panel's desired state after any disconnect

## Licence

- **Source code**: akari-agent's own code is MIT licensed (`LICENSE`).
- **Binaries**: every agent binary statically links xray-core (MPL-2.0) and,
  through xray-core's Shadowsocks support, `github.com/sagernet/sing` and
  `sing-shadowsocks`, which are **GPL-3.0-or-later**. A released (or
  self-built) agent binary is therefore a combined work distributed under
  **GPL-3.0-or-later** (`LICENSES/GPL-3.0.txt`). The corresponding source is
  this public repository at the tag/commit shown by `akari-agent -version`;
  `make dist` reproduces the release binaries byte for byte. Our own files
  stay MIT; nothing is relicensed. (Decision R19: the binary's status is
  stated here and in the release notes; we do not carry an xray patch that
  drops Shadowsocks to avoid the GPL modules.)
- **Third-party licences**: `THIRD_PARTY_LICENSES.txt` lists every module
  linked into the binary with its licence and carries the licence/notice
  texts verbatim. It is generated (`make third-party`, `cmd/thirdparty`:
  `go list -deps` for linux/amd64+arm64, licence files from the module cache,
  fail-closed allow-list), CI fails when it is stale (`make
  check-third-party`), every release ships it as an asset, and the binary
  embeds it: `akari-agent -licenses` prints it (nodes installed through the
  panel receive only the binary). `THIRD-PARTY-NOTICES.md` is the
  maintainers' assessment behind it.

## Build

```bash
make build            # static go build, version + git sha stamped (`./agent -version`)
make dist             # linux amd64/arm64 release binaries + SHA256SUMS in dist/
make proto            # regenerate pb/ from proto/agent.proto
make sync-proto       # pull the contract from the sibling akari-panel checkout
make check-proto      # fail if the vendored contract drifted from akari-panel
make vet fmt-check
make third-party      # regenerate THIRD_PARTY_LICENSES.txt (after go.mod changes)
./agent -licenses     # licensing of this binary + all third-party licence texts
```

Releases (tag `v*`) are built, SBOM'd and cosign-signed by `.github/workflows/release.yml`;
install as a hardened systemd service with the units in `systemd/` (compiled into the binary:
`./agent -print-unit akari-agent.service`; the panel's installer installs the units of the
release it installs, and every self-update installs the new release's units).

Sibling checkout convention: akari-panel and akari-agent live side by side
(`../akari-panel` / `../akari-agent`), same as the panel's smoke test expects.

## Automatic node certificate (protocol 6)

When the node has a TLS domain in the panel (节点域名) and an inbound reads the
node certificate files, the panel sends `ConfigSnapshot.acme` and the agent
obtains and renews the certificate itself over ACME (Let's Encrypt by default;
library: [acmez](https://github.com/mholt/acmez), Apache-2.0) — no certbot.
`acme.go` has the details:

- **Store**: `<state dir>/tls/<domain>/{fullchain,privkey}.pem` (0600, dir 0700)
  and the ACME account key `<state dir>/tls/accounts/<hash>.key.pem`. The state
  dir is systemd's `StateDirectory` (the agent runs as a dynamic user under
  `ProtectSystem=strict`, so `/etc` is not writable for it). TLS inbounds that
  name `/run/credentials/akari-agent.service/tls_{fullchain,privkey}.pem` are
  pointed at these files before xray is built; the inbounds JSON (and the state
  hash) stay exactly what the panel sent.
- **Challenges**: HTTP-01 on TCP 80 when no inbound uses 80 and it is free;
  else TLS-ALPN-01 on TCP 443 when no inbound uses 443 and it is free; else the
  order fails as "port busy" (free TCP 80). After a connection/DNS failure the
  next order tries the other challenge. DNS-01 is not supported.
- **Before the first certificate** the files hold a self-signed placeholder, so
  xray always builds and other inbounds are never held up; the first CA
  certificate swaps only the TLS inbounds' handlers (other inbounds and their
  connections are untouched; on failure the agent claims (0,0) and the panel
  resends the Snapshot).
- **Renewal** with a third of the validity left (minus up to 1/30 jitter),
  ARI `replaces` set; the files are replaced atomically and xray re-reads
  certificate files every hour by itself (`oneTimeLoading` must stay unset):
  no rebuild, no dropped connection. Failures back off 5 min → 6 h (≥ 1 h after
  a rate-limit answer); restart the agent to retry at once.
- **Status** goes to the panel on every heartbeat (`Heartbeat.cert`: state,
  expiry, next attempt, classified error), shown on the node page.
- Manual certificates still work: without a TLS domain nothing changes.

Tests: `acme_test.go` (in-process pebble CA + DNS: HTTP-01, TLS-ALPN-01, port
busy, DNS/connection errors, backoff, renewal, restart, Snapshot glue) and the
canary `TestACME_TLSInboundsGetAndHotReloadTheCertificate` (real xray clients
over VLESS-WS-TLS, Trojan-TLS and Hysteria 2 trusting only the test CA; the
swap keeps another inbound's connection; the renewal keeps every connection).
No test talks to a real CA. Flags for tests/smoke only: `-acme-roots`,
`-acme-http-port`, `-acme-tls-port`.

## Per-user speed limits (protocol 4)

The panel sends each user's plan speed limit with the user
(`UserOp.speed_limit_bytes_per_sec`, 0 = unlimited). xray-core has no
per-user rate limiting, so the agent's gate dispatcher paces a limited
user's traffic itself (`ratelimit.go`): one token bucket per direction per
user, shared by all of that user's connections and inbounds on the node.
Limited users' connections do not use XTLS Vision's kernel splice (it would
bypass any limiter); Vision itself keeps working. Unlimited users take
exactly the old path. A limit that appears where there was none closes the
user's live connections (clients reconnect throttled); other changes apply
in place. Only the outbound side of a dispatch is wrapped (xray's mux keeps
the inbound-side link and asserts its type). Tests: `ratelimit_test.go`
(real VLESS through xray: throughput
equals the limit), canaries `TestRT_VisionSpeedLimit` (Vision over TLS),
`TestRT_MuxSpeedLimit`, `TestRT_UDPSpeedLimit` and the limit phase of
`TestRT_ProtocolMatrix` (every protocol incl. SS2022 and Hysteria2).

## Self-update (protocol 3)

The panel can roll out new agent releases (staged waves, health gate, automatic halt; see
`akari-panel/docs/DEPLOY.md`, "Agent updates"). The agent trusts **only** manifests signed by a
release key pinned in this repository (`release-keys.txt`, compiled in); the panel is a relay.
An offer is accepted only if a signature verifies, the platform matches, the version is newer
than the running one (or the signed manifest is an explicit `rollback` target) and the node has
not rolled back from that version before. The binary comes over the existing mTLS connection
(`AgentChannel.FetchArtifact`) and is checked for size and SHA-256. The agent never executes
it: its state directory is mounted `noexec` by systemd (DynamicUser), and stays so. It stages the
file and an apply request in `<state dir>/update/`; the **privileged updater**
(`akari-agent-update.path` + `akari-agent-update.service`, in `systemd/` and installed by the
panel's one-line installer) runs the *installed* binary as
`akari-agent -apply-update <state dir>`, which treats that directory as untrusted, copies the
file into a root-only location, re-verifies the copy with its own pinned keys and version policy,
installs it as `/usr/local/bin/akari-agent` (keeping `akari-agent.prev`) together with the
systemd units the new release carries (read from the verified copy with `-print-units`; the
previous units are kept and restored on a rollback) and restarts the agent.
The new binary must connect and get an apply acknowledged within `-update-self-check`
(default 5m); if it does not, or crashes `-update-max-boots` times (default 3), the updater puts
the previous binary back. Agents up to v0.4.0 executed the staged file themselves and fail on
systemd ≥ 256 (`permission denied`): run the panel's install command for such a node once.
Updater units from before W23 cannot replace unit files (their sandbox keeps
`/etc/systemd/system` read-only): the first update to a W23 release installs the binary only,
the agent reports `stale-units`, and one run of the install command fixes it for good.
`./agent -release-keys` lists the pinned keys.

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

Production key: `key-f2ad18a8bb718a1a` (`ciJILGk6W1TnPr56Dncgv0mVQFBzqOrawiOaH0/d5Pg=`, pinned since
v0.2.0). Custody: the private key exists only as an offline file on the lead's machine
(`~/secrets/akari-release-signing.key`, 0600) and as the `AKARI_RELEASE_SIGNING_KEY` repository
secret; whoever holds it can update every node. CI signs only if the `AKARI_RELEASE_SIGNING_KEY` repository secret is set
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

