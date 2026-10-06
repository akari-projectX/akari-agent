# akari-agent

Akari 控制面板的节点端 agent。内嵌 **xray-core**（`v1.260327.0`，即 release v26.3.27 的 Go 模块形式），并与面板保持一条仅出站的 mTLS gRPC 长连接。节点上没有管理端口，也不保存协议凭据——由面板 CA 签发的 TLS 客户端证书就是节点的身份。

职责：

- 应用面板下发的 `ConfigSnapshot`（启动/重建内嵌内核）和 `UserDelta`（基础/目标版本，REPLACE 语义；动态 `AddUser`/`RemoveUser`，无需重建）。用自带的 gate dispatcher 替换 xray 默认的 dispatcher，因此删除或轮换用户时，会同时关闭该用户的存量连接（并拒绝其上新的 mux 子流）。
- 无用户的入站（不带 clients 的 dokodemo/socks/http）既不受 gate 管控，也不计费——只有 vless/vmess/trojan 用户由面板管理。
- 面板的 `agent.remove_mode = "rebuild"`（每次授予租约时下发）会让每次删除/轮换都改为完整重建（回退开关）。
- 按协议的撤销金丝雀（revocation canary）：`make test-canary`（包含在 `make test` 中）；仅在它们全绿时才升级 xray-core。
- 上报实际运行内容的状态哈希（Hello 以及每个 Ack），让面板发现状态分歧。
- 执行面板的 fail-closed 租约（CLOCK_BOOTTIME；面板在租约期内没有确认期望状态，就停止 xray）。
- 上报累计的分用户流量计数（10 秒）和心跳（15 秒，`-heartbeat-interval`），心跳附带机器状态（W11：CPU、负载、内存/swap、磁盘、默认路由网卡的速率与总量、TCP/UDP 连接数、在线用户、RSS、xray 版本；读取 `/proc`，不用 cgo）。
- 类似 Clash url-test 的延迟测试（W11）：每 5 小时（面板可配置；面板可"立即测试"）从节点自身出口发起 HTTP GET，取 3 次中位数，主 URL 失败时使用备用 URL。
- 任何断线之后都收敛到面板的期望状态。

## Licence（许可）

- **源码**：akari-agent 自有代码采用 MIT 许可（`LICENSE`）。
- **二进制**：每个 agent 二进制都静态链接 xray-core（MPL-2.0），并通过 xray-core 的 Shadowsocks 支持链接 `github.com/sagernet/sing` 与 `sing-shadowsocks`，二者为 **GPL-3.0-or-later**。因此发布版（或自行构建）的 agent 二进制是按 **GPL-3.0-or-later**（`LICENSES/GPL-3.0.txt`）分发的组合作品。对应源码即本公开仓库中 `akari-agent -version` 所示的 tag/commit；`make dist` 可逐字节复现发布二进制。我们自己的文件仍为 MIT，不做重新授权。（决策 R19：二进制的许可状态在此处和发布说明中声明；我们不携带为规避 GPL 模块而去掉 Shadowsocks 的 xray 补丁。）
- **第三方许可**：`THIRD_PARTY_LICENSES.txt` 列出链接进二进制的每个模块及其许可，并原样附带许可/声明文本。它是生成物（`make third-party`，`cmd/thirdparty`：对 linux/amd64+arm64 执行 `go list -deps`，许可文件取自模块缓存，白名单 fail-closed）；过期时 CI 失败（`make check-third-party`）；每次发布都作为附件提供，二进制也内嵌了它：`akari-agent -licenses` 会打印（通过面板安装的节点只会收到二进制）。`THIRD-PARTY-NOTICES.md` 是其背后的维护者评估。

## Build（构建）

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

发布（tag `v*`）由 `.github/workflows/release.yml` 构建、生成 SBOM 并用 cosign 签名。以加固的 systemd 服务安装，单元文件在 `systemd/`（已编译进二进制：`./agent -print-unit akari-agent.service`；面板的安装器会安装所装发布版自带的单元，每次自更新也会安装新发布版的单元）。在 Alpine Linux（W32）上，同一个静态二进制通过 OpenRC 运行，脚本在 `openrc/`（同样已编译进二进制：`./agent -print-unit akari-agent`；agent 与 updater 使用 `-init openrc`）；与 systemd 方案的差异及已知缺口见 akari-panel 的 `docs/DEPLOY.md` §3h。

同级检出约定：akari-panel 与 akari-agent 并排放置（`../akari-panel` / `../akari-agent`），与面板 smoke 测试的预期一致。

## Automatic node certificate (protocol 6)（节点证书自动签发）

当节点在面板中配置了 TLS 域名（节点域名），且有入站读取节点证书文件时，面板会下发 `ConfigSnapshot.acme`，agent 自行通过 ACME 获取并续期证书（默认 Let's Encrypt；库：[acmez](https://github.com/mholt/acmez)，Apache-2.0），无需 certbot。细节见 `acme.go`：

- **存储**：`<state dir>/tls/<domain>/{fullchain,privkey}.pem`（0600，目录 0700）以及 ACME 账户密钥 `<state dir>/tls/accounts/<hash>.key.pem`。state dir 是 systemd 的 `StateDirectory`（agent 以 dynamic user 运行在 `ProtectSystem=strict` 下，`/etc` 不可写）。指向 `/run/credentials/akari-agent.service/tls_{fullchain,privkey}.pem` 的 TLS 入站，会在构建 xray 之前被改指向这些文件；入站 JSON（及状态哈希）与面板下发的完全一致。
- **挑战方式**：没有入站占用 TCP 80 且该端口空闲时，用 TCP 80 上的 HTTP-01；否则在没有入站占用 TCP 443 且其空闲时，用 TCP 443 上的 TLS-ALPN-01；再否则申请失败，报 "port busy"（请释放 TCP 80）。连接/DNS 失败后，下一次申请改用另一种挑战。不支持 DNS-01。
- **首张证书之前**，文件内容是自签名占位证书，因此 xray 总能构建，其他入站不会被拖住；首张 CA 证书到位时只替换 TLS 入站的 handler（其他入站及其连接不受影响；失败时 agent 声明 (0,0)，面板重发 Snapshot）。
- **续期**：剩余有效期为三分之一时（再减去最多 1/30 的抖动）发起，并设置 ARI `replaces`；文件原子替换，xray 每小时自行重读证书文件（必须保持 `oneTimeLoading` 未设置）：无需重建，不断连接。失败后退避 5 分钟 → 6 小时（收到限流应答后 ≥ 1 小时）；重启 agent 可立即重试。
- **状态**随每次心跳上报面板（`Heartbeat.cert`：状态、到期时间、下次尝试、分类后的错误），显示在节点页。
- 手动证书仍然有效：没有 TLS 域名时一切照旧。

测试：`acme_test.go`（进程内 pebble CA + DNS：HTTP-01、TLS-ALPN-01、端口被占、DNS/连接错误、退避、续期、重启、Snapshot 衔接）以及金丝雀 `TestACME_TLSInboundsGetAndHotReloadTheCertificate`（真实 xray 客户端经 VLESS-WS-TLS、Trojan-TLS 和 Hysteria 2，仅信任测试 CA；替换时保持另一入站的连接；续期时保持所有连接）。没有任何测试访问真实 CA。仅供测试/smoke 的参数：`-acme-roots`、`-acme-http-port`、`-acme-tls-port`。

## Per-user speed limits (protocol 4)（分用户限速）

面板随用户下发其套餐限速（`UserOp.speed_limit_bytes_per_sec`，0 = 不限速）。xray-core 没有分用户限速，所以 agent 的 gate dispatcher 自行对受限用户的流量整形（`ratelimit.go`）：每用户每方向一个令牌桶，由该用户在本节点上的所有连接和入站共享。受限用户的连接不使用 XTLS Vision 的内核 splice（它会绕过任何限速器），Vision 本身仍然可用。不限速用户走原来的路径，完全不变。限速从无到有时，会关闭该用户的存量连接（客户端重连后即被限速）；其他变更就地生效。只包装 dispatch 的出站一侧（xray 的 mux 保留入站侧 link 并断言其类型）。测试：`ratelimit_test.go`（经 xray 的真实 VLESS：吞吐等于限速值）、金丝雀 `TestRT_VisionSpeedLimit`（TLS 上的 Vision）、`TestRT_MuxSpeedLimit`、`TestRT_UDPSpeedLimit`，以及 `TestRT_ProtocolMatrix` 的限速阶段（所有协议，含 SS2022 和 Hysteria2）。

## Self-update (protocol 3)（自更新）

面板可以分批推出新的 agent 发布版（分波次、健康门、自动中止；见 `akari-panel/docs/DEPLOY.md`，"Agent updates"）。agent **只**信任由本仓库中固定的发布密钥（`release-keys.txt`，编译进二进制）签名的 manifest；面板只是中继。只有在签名校验通过、平台匹配、版本比当前运行的更新（或签名 manifest 是明确的 `rollback` 目标）、且本节点此前没有从该版本回滚过时，才接受更新提议。二进制经已有的 mTLS 连接（`AgentChannel.FetchArtifact`）传来，并校验大小与 SHA-256。agent 从不自己执行它：其 state 目录被 systemd 挂载为 `noexec`（DynamicUser），并且保持如此。它把文件和应用请求暂存到 `<state dir>/update/`；由**特权 updater**（`akari-agent-update.path` + `akari-agent-update.service`，位于 `systemd/`，由面板的一行安装命令安装）以 `akari-agent -apply-update <state dir>` 运行*已安装*的二进制，它把该目录视为不可信，将文件复制到仅 root 可访问的位置，用自己固定的密钥和版本策略重新校验副本，将其安装为 `/usr/local/bin/akari-agent`（保留 `akari-agent.prev`），连同新发布版自带的 systemd 单元一并安装（用 `-print-units` 从已校验的副本读取；旧单元会保留，回滚时恢复），然后重启 agent。新二进制必须在 `-update-self-check`（默认 5m）内连上并得到一次已确认的 apply；否则，或崩溃 `-update-max-boots` 次（默认 3）时，updater 会把旧二进制放回去。v0.4.0 及之前的 agent 自己执行暂存文件，在 systemd ≥ 256 上会失败（`permission denied`）：对此类节点需运行一次面板的安装命令。W23 之前的 updater 单元无法替换单元文件（其沙箱使 `/etc/systemd/system` 只读）：首次更新到 W23 发布版只会安装二进制，agent 上报 `stale-units`，运行一次安装命令即可一劳永逸。`./agent -release-keys` 列出已固定的密钥。

### Release signing keys（发布签名密钥）

Manifest（`akari-agent-linux-<arch>.manifest.json`：version、os、arch、sha256、size、min_panel_protocol、created_at、rollback）使用 Ed25519 对 `"akari-agent-manifest-v1\n" || manifest` 签名（`release/`，契约见 akari-panel 的 `proto/agent.proto`）。Cosign 无密钥签名仍保留，供人工与 CI 使用；节点无需连接 Rekor/Fulcio。

```bash
go run ./cmd/akari-sign keygen -out /offline/release.key   # prints the public line
# add that line to release-keys.txt, commit, release (agents now pin it)
make dist VERSION=v1.2.3
make sign-manifest VERSION=v1.2.3 KEY=/offline/release.key  # dist/*.manifest.{json,sig}
go run ./cmd/akari-sign verify -keys release-keys.txt -manifest dist/akari-agent-linux-amd64.manifest.json \
  -sig dist/akari-agent-linux-amd64.manifest.sig -binary dist/akari-agent-linux-amd64
```

生产密钥：`key-f2ad18a8bb718a1a`（`ciJILGk6W1TnPr56Dncgv0mVQFBzqOrawiOaH0/d5Pg=`，自 v0.2.0 起固定）。保管：私钥仅作为离线文件存在于负责人的机器上（`~/secrets/akari-release-signing.key`，0600），以及作为仓库 secret `AKARI_RELEASE_SIGNING_KEY`；持有者可更新所有节点。CI 仅在设置了仓库 secret `AKARI_RELEASE_SIGNING_KEY` 时才签名（`.github/workflows/release.yml`；未设置则发布版没有 manifest，并给出警告），并拒绝在 `release-keys.txt` 下校验不通过的 manifest。轮换：把下一个密钥与当前密钥并列固定后发布；用两把密钥都签名（`akari-sign countersign`），直到所有节点都运行了固定下一个密钥的构建；然后移除旧密钥。`testdata/TEST-ONLY-release.key` 是仅用于带 `akari_testkeys` tag 的构建（`make build-testkeys`、smoke）的公开测试密钥；`make dist` 会拒绝包含它的二进制。

## Run（运行）

```bash
./agent -config test-node-bootstrap.toml -state-dir /var/lib/akari-agent
```

bootstrap 文件由面板上的 `akari node add <name>` 生成：包含面板地址、TLS server name、面板 CA 和**一次性注册令牌**——不含私钥。首次启动时，agent 在 state 目录（`-state-dir`；systemd 下默认 `$STATE_DIRECTORY`，否则为配置文件所在目录；文件权限 0600）中生成 ECDSA P-256 密钥，用 CSR 注册（唯一无需客户端证书的调用）并保存签发的证书。密钥从不离开节点，也从不写入日志。当证书剩余有效期不足三分之一时（protocol 2），agent 通过存活的 mTLS 连接用新密钥续期，用新证书重连，并保留旧证书直到面板接受新证书。带新令牌的 bootstrap 文件会让节点重新注册一次。v1 bootstrap 文件（`identity.cert_pem` + `identity.key_pem`）仍可使用，并在首次续期时迁移到本地密钥。见 `akari-panel/docs/DEPLOY.md`。
