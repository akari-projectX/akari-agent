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
- report a state hash of what actually runs (Hello, every Ack) so the panel
  detects divergence
- enforce the panel's fail-closed lease (CLOCK_BOOTTIME; stop xray when the
  panel has not confirmed the desired state for the lease duration)
- report cumulative per-user traffic counters (10s) and heartbeats (15s)
- converge to the panel's desired state after any disconnect

## Build

```bash
make build            # go build (requires protobuf plugins on PATH for proto/)
make proto            # regenerate pb/ from proto/agent.proto
make sync-proto       # pull the contract from the sibling akari-panel checkout
make check-proto      # fail if the vendored contract drifted from akari-panel
make vet fmt-check
```

Sibling checkout convention: akari-panel and akari-agent live side by side
(`../akari-panel` / `../akari-agent`), same as the panel's smoke test expects.

## Run

```bash
./agent -config test-node-bootstrap.toml
```

The bootstrap file is produced by `akari node add <name>` on the panel and
contains the agent's client certificate **and private key** (v1 enrollment —
CSR-based enrollment is planned, see PLAN.md Phase 4). Treat the file as a
secret: transfer securely, delete after provisioning.
