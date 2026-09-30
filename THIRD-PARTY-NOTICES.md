# Third-party notices (akari-agent)

This repository vendors/copies the contract file `proto/agent.proto`
(canonical copy lives in the private `akari-panel` repository) and depends on
the following third-party components:

| Component | License | Where |
|---|---|---|
| [xray-core](https://github.com/XTLS/Xray-core) (pinned `v1.260327.0`) | MPL-2.0 | Go module dependency, embedded at runtime |
| [grpc-go](https://github.com/grpc/grpc-go) | Apache-2.0 | Go module dependency |
| [protobuf-go](https://github.com/protocolbuffers/protobuf-go) | BSD-3-Clause | Go module dependency; generated code in `pb/` |
| [protoc-gen-go-grpc output](https://github.com/grpc/grpc-go) | Apache-2.0 | generated code in `pb/` |
| [gopsutil](https://github.com/shirou/gopsutil) | MIT | Go module dependency |
| [google/uuid](https://github.com/google/uuid) | BSD-3-Clause | Go module dependency |
| [BurntSushi/toml](https://github.com/BurntSushi/toml) | MIT | Go module dependency |

License texts of Go module dependencies are included in the module cache and
upstream repositories. The full dependency graph is `go.mod` / `go.sum`.

Note on MPL-2.0: xray-core is used as an unmodified module dependency; no
files of xray-core are modified in this repository. If you fork this agent
and modify xray-core files themselves, MPL-2.0 obligations apply to those
files.
