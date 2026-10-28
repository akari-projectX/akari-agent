# Third-party notices (akari-agent)

> The authoritative, generated list of linked modules with their licence
> texts is `THIRD_PARTY_LICENSES.txt` (`make third-party`, CI-checked,
> embedded in the binary as `akari-agent -licenses`, shipped with every
> release). This file is the maintainers' assessment of it.

This repository's own code is MIT (see `LICENSE`). It vendors/copies the
contract file `proto/agent.proto` (canonical copy lives in the
`akari-panel` repository of the same organisation) and the released binary
statically links the Go modules below. The list is generated from
`go list -deps` of the agent (47 modules, 2026-10-26, xray-core
release v26.10.21); `make check-third-party` (CI) fails when go.mod changes the
linked set, so this table is re-checked on every such change.
License texts are in each module (module cache / upstream repository); the
full dependency graph is `go.mod` / `go.sum`.

## Linked modules

| Component | License | Notes |
|---|---|---|
| [xray-core](https://github.com/XTLS/Xray-core) v26.10.21 (`v1.260327.1-0.20261021115930-1b1647cd9ddf`) | MPL-2.0 | embedded core; built from the akari-projectX/xray-core fork carrying one patch to `common/signal/timer.go` (README, "xray-core 分支") |
| [xtls/reality](https://github.com/XTLS/REALITY) | MPL-2.0 | via xray-core |
| [grpc-go](https://github.com/grpc/grpc-go), `genproto/googleapis/rpc` | Apache-2.0 | |
| [mholt/acmez](https://github.com/mholt/acmez) `v3` | Apache-2.0 | ACME client for the automatic node certificate (`acme.go`); its only dependencies are `golang.org/x/{crypto,net}`. Test-only (not linked): [pebble](https://github.com/letsencrypt/pebble) and `challtestsrv` (MPL-2.0), [go-jose](https://github.com/go-jose/go-jose) (Apache-2.0) |
| [protobuf-go](https://github.com/protocolbuffers/protobuf-go) | BSD-3-Clause | generated code in `pb/` |
| [BurntSushi/toml](https://github.com/BurntSushi/toml), [pelletier/go-toml](https://github.com/pelletier/go-toml), [ghodss/yaml](https://github.com/ghodss/yaml) | MIT | config parsing |
| [google/uuid](https://github.com/google/uuid), [gorilla/websocket](https://github.com/gorilla/websocket), [miekg/dns](https://github.com/miekg/dns), [refraction-networking/utls](https://github.com/refraction-networking/utls), [cloudflare/circl](https://github.com/cloudflare/circl), [go4.org/netipx](https://github.com/go4org/netipx) | BSD-3-Clause (or BSD-style) | |
| [klauspost/compress](https://github.com/klauspost/compress) | BSD-3-Clause + Apache-2.0 (parts) | |
| [klauspost/cpuid](https://github.com/klauspost/cpuid), [andybalholm/brotli](https://github.com/andybalholm/brotli), [lukechampine.com/blake3](https://github.com/lukechampine/blake3), [apernet/quic-go](https://github.com/apernet/quic-go), [quic-go/qpack](https://github.com/quic-go/qpack), [wireguard-go](https://git.zx2c4.com/wireguard-go) | MIT | |
| [google/btree](https://github.com/google/btree), [pires/go-proxyproto](https://github.com/pires/go-proxyproto), [vishvananda/netlink](https://github.com/vishvananda/netlink), [vishvananda/netns](https://github.com/vishvananda/netns), [gopkg.in/yaml.v2](https://github.com/go-yaml/yaml), [gvisor](https://github.com/google/gvisor) | Apache-2.0 | |
| `golang.org/x/{crypto,exp,net,sync,sys,text,time}` | BSD-3-Clause | `x/sys` is a direct dependency (`go.mod`) |
| [juju/ratelimit](https://github.com/juju/ratelimit) | LGPL-3.0 with a static-linking exception | the exception permits conveying a combined work that links the library statically or dynamically without providing the Minimal Corresponding Source / installation information (4d/4e), provided the other LGPL-3 terms are met (license text kept with the module) |
| [SagerNet/sing](https://github.com/SagerNet/sing) `v0.5.1`, [sing-shadowsocks](https://github.com/SagerNet/sing-shadowsocks) `v0.2.7` | GPL-3.0-or-later | **test-only since xray-core v26.10.21 (not linked)**; see below |

## GPL components

Since xray-core v26.10.21 the Shadowsocks 2022 implementation no longer depends on
`sagernet/sing*`; `go list -deps` of the agent does not contain them (they remain in
`go.mod` for the SS2022 native-removal test client only). The binary links no GPL
module, `THIRD_PARTY_LICENSES.txt` says so (the generator decides from the linked
set; it adds the combined-work notice automatically if a GPL module is linked again),
and the README licence section matches. Distributing under GPL voluntarily anyway
is for the maintainers to decide.

## MPL-2.0 note

xray-core (and REALITY) are module dependencies. The only modified file is
`common/signal/timer.go` in the fork (published in the akari-projectX/xray-core
repository, so the MPL-2.0 source obligation is met). If you fork this agent and
modify other files of them, MPL-2.0 obligations apply to the modified files.
