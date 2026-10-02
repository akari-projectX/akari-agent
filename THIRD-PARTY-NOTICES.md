# Third-party notices (akari-agent)

This repository's own code is MIT (see `LICENSE`). It vendors/copies the
contract file `proto/agent.proto` (canonical copy lives in the
`akari-panel` repository of the same organisation) and the released binary
statically links the Go modules below. The list is generated from
`go version -m` of the built agent (41 modules, 2026-10-02 W10, xray-core
`v1.260327.0`); re-check it whenever `go.mod` changes (`go version -m agent`).
License texts are in each module (module cache / upstream repository); the
full dependency graph is `go.mod` / `go.sum`.

## Linked modules

| Component | License | Notes |
|---|---|---|
| [xray-core](https://github.com/XTLS/Xray-core) `v1.260327.0` | MPL-2.0 | embedded core; unmodified |
| [xtls/reality](https://github.com/XTLS/REALITY) | MPL-2.0 | via xray-core |
| [grpc-go](https://github.com/grpc/grpc-go), `genproto/googleapis/rpc` | Apache-2.0 | |
| [mholt/acmez](https://github.com/mholt/acmez) `v3` | Apache-2.0 | ACME client for the automatic node certificate (W10, `acme.go`); its only dependencies are `golang.org/x/{crypto,net}`. Test-only (not linked): [pebble](https://github.com/letsencrypt/pebble) and `challtestsrv` (MPL-2.0), [go-jose](https://github.com/go-jose/go-jose) (Apache-2.0) |
| [protobuf-go](https://github.com/protocolbuffers/protobuf-go) | BSD-3-Clause | generated code in `pb/` |
| [BurntSushi/toml](https://github.com/BurntSushi/toml), [pelletier/go-toml](https://github.com/pelletier/go-toml), [ghodss/yaml](https://github.com/ghodss/yaml) | MIT | config parsing |
| [google/uuid](https://github.com/google/uuid), [gorilla/websocket](https://github.com/gorilla/websocket), [miekg/dns](https://github.com/miekg/dns), [refraction-networking/utls](https://github.com/refraction-networking/utls), [cloudflare/circl](https://github.com/cloudflare/circl), [go4.org/netipx](https://github.com/go4org/netipx) | BSD-3-Clause (or BSD-style) | |
| [klauspost/compress](https://github.com/klauspost/compress) | BSD-3-Clause + Apache-2.0 (parts) | |
| [klauspost/cpuid](https://github.com/klauspost/cpuid), [andybalholm/brotli](https://github.com/andybalholm/brotli), [lukechampine.com/blake3](https://github.com/lukechampine/blake3), [apernet/quic-go](https://github.com/apernet/quic-go), [quic-go/qpack](https://github.com/quic-go/qpack), [wireguard-go](https://git.zx2c4.com/wireguard-go) | MIT | |
| [google/btree](https://github.com/google/btree), [pires/go-proxyproto](https://github.com/pires/go-proxyproto), [vishvananda/netlink](https://github.com/vishvananda/netlink), [vishvananda/netns](https://github.com/vishvananda/netns), [gopkg.in/yaml.v2](https://github.com/go-yaml/yaml), [gvisor](https://github.com/google/gvisor) | Apache-2.0 | |
| `golang.org/x/{crypto,exp,net,sync,sys,text,time}` | BSD-3-Clause | `x/sys` is a direct dependency (`go.mod`) |
| [juju/ratelimit](https://github.com/juju/ratelimit) | LGPL-3.0 with a static-linking exception | the exception permits conveying a combined work that links the library statically or dynamically without providing the Minimal Corresponding Source / installation information (4d/4e), provided the other LGPL-3 terms are met (license text kept with the module) |
| [SagerNet/sing](https://github.com/SagerNet/sing) `v0.5.1`, [sing-shadowsocks](https://github.com/SagerNet/sing-shadowsocks) `v0.2.7` | **GPL-3.0-or-later** | **see below** |

## GPL components linked into the binary (assessment for the maintainers)

`sagernet/sing` and `sagernet/sing-shadowsocks` are GPL-3.0-or-later (module
`LICENSE` is the GPL-3.0 boilerplate; no linking exception). xray-core's
Shadowsocks implementation imports them, and `infra/conf` (needed to parse the
panel's inbound JSON) links every proxy, so they are statically linked into
every released agent binary even though the agent never configures a
Shadowsocks inbound (the panel only hands out vless/vmess/trojan).

Consequences, as far as can be said without legal advice:

- A binary that statically links GPL-3.0 code is a combined work that may be
  conveyed only under GPL-3.0 terms. The MIT license of this repository's own
  code is GPL-compatible, so the combined binary is distributable under
  GPL-3.0-or-later provided the corresponding source is offered. This
  repository is public and tags reproduce the binary (`make dist`, SHA256SUMS),
  so the source offer is satisfiable; the release notes must say the binary
  is a GPL-3.0-or-later combined work.
- Our own source files stay MIT; nothing here is relicensed.
- Removing the exposure instead would need a fork/patch that drops the
  Shadowsocks proxy from xray's `infra/conf` imports; not done (the MPL-2.0
  note below then also applies to that fork).

Open decision (not settled by this file): either state the GPL-3.0-or-later
status of released binaries in README/release notes (cheapest, recommended),
or carry the xray patch. The panel and the client are unaffected by this
(they do not link these modules); the client's own GPL-3.0 position for mihomo
is separate (see `akari-client/CLAUDE.md`).

## MPL-2.0 note

xray-core (and REALITY) are used as unmodified module dependencies; no files
of them are modified in this repository. If you fork this agent and modify
those files, MPL-2.0 obligations apply to the modified files.
