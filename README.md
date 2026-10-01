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
