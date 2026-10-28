# akari-agent

Akari 控制面板的节点端 agent。内嵌 **xray-core**（release v26.10.21，Go 模块形式为其提交的伪版本 `v1.260327.1-0.20261021115930-1b1647cd9ddf`；实际编译的是带一处修复的分支 [akari-projectX/xray-core](https://github.com/akari-projectX/xray-core)，见下文「xray-core 分支」），并与面板保持一条仅出站的 mTLS gRPC 长连接。节点上没有管理端口，也不保存协议凭据——由面板 CA 签发的 TLS 客户端证书就是节点的身份。

职责：

- 应用面板下发的 `ConfigSnapshot`（启动/重建内嵌内核）和 `UserDelta`（基础/目标版本，REPLACE 语义；动态 `AddUser`/`RemoveUser`，无需重建）。用自带的 gate dispatcher 替换 xray 默认的 dispatcher，因此删除或轮换用户时，会同时关闭该用户的存量连接（并拒绝其上新的 mux 子流）。
- 无用户的入站（不带 clients 的 dokodemo/socks/http）既不受 gate 管控，也不计费——只有 vless/vmess/trojan/shadowsocks（2022 多用户）/hysteria（Hysteria 2）用户由面板管理。
- 面板的 系统设置 → 节点通信「撤权方式」= 重建（每次授予租约时下发）会让每次删除/轮换都改为完整重建（回退开关）。
- 按协议的撤销金丝雀（revocation canary）：`make test-canary`（包含在 `make test` 中）；仅在它们全绿时才升级 xray-core。
- 上报实际运行内容的状态哈希（Hello 以及每个 Ack），让面板发现状态分歧。
- 执行面板的 fail-closed 租约（CLOCK_BOOTTIME；面板在租约期内没有确认期望状态，就停止 xray）。
- 上报累计的分用户流量计数（10 秒）和心跳（15 秒，`-heartbeat-interval`），心跳附带机器状态（CPU、负载、内存/swap、磁盘、默认路由网卡的速率与总量、TCP/UDP 连接数、在线用户、RSS、xray 版本；读取 `/proc`，不用 cgo）。
- 类似 Clash url-test 的延迟测试：每 5 小时（面板可配置；面板可"立即测试"）从节点自身出口发起 HTTP GET，取 3 次中位数，主 URL 失败时使用备用 URL。
- 任何断线之后都收敛到面板的期望状态。

## Licence（许可）

- **源码**：akari-agent 自有代码采用 MIT 许可（`LICENSE`）。
- **二进制**：每个 agent 二进制静态链接 xray-core（MPL-2.0）等模块，**不含 GPL 模块**——xray-core v26.10.21 起自己实现 Shadowsocks 2022，不再依赖 `github.com/sagernet/sing*`（GPL-3.0-or-later；它们现在只被测试使用，不进二进制）。二进制按 MIT 与第三方声明分发（`THIRD_PARTY_LICENSES.txt`，由 `make third-party` 按实际链接的模块生成，若将来再链接 GPL 模块会自动写入组合作品声明并附 `LICENSES/GPL-3.0.txt`）。对应源码即本公开仓库中 `akari-agent -version` 所示的 tag/commit；`make dist` 可逐字节复现发布二进制。（决策 R19 的前提——二进制链接 GPL 模块——不再成立，见 `THIRD-PARTY-NOTICES.md`。）
- **第三方许可**：`THIRD_PARTY_LICENSES.txt` 列出链接进二进制的每个模块及其许可，并原样附带许可/声明文本。它是生成物（`make third-party`，`cmd/thirdparty`：对 linux/amd64+arm64 执行 `go list -deps`，许可文件取自模块缓存，白名单 fail-closed）；过期时 CI 失败（`make check-third-party`）；每次发布都作为附件提供，二进制也内嵌了它：`akari-agent -licenses` 会打印（通过面板安装的节点只会收到二进制）。`THIRD-PARTY-NOTICES.md` 是其背后的维护者评估。

## Build（构建）

```bash
make build            # static go build, version + git sha stamped (`./agent -version`)
make dist             # linux amd64/arm64 release binaries + SHA256SUMS in dist/
make proto            # regenerate pb/ from proto/agent.proto
make sync-proto       # pull the contract from the sibling akari-panel checkout
make check-proto      # fail if the vendored contract drifted from akari-panel
make vet fmt-check
make test             # race tests + revocation canaries
make soak             # long-running stability soak (SOAK_DURATION, default 60m; not part of CI)
make third-party      # regenerate THIRD_PARTY_LICENSES.txt (after go.mod changes)
./agent -licenses     # licensing of this binary + all third-party licence texts
```

发布（tag `v*`）由 `.github/workflows/release.yml` 构建、生成 SBOM 并用 cosign 签名。以加固的 systemd 服务安装，单元文件在 `systemd/`（已编译进二进制：`./agent -print-unit akari-agent.service`；面板的安装器会安装所装发布版自带的单元，每次自更新也会安装新发布版的单元）。在 Alpine Linux 上，同一个静态二进制通过 OpenRC 运行，脚本在 `openrc/`（同样已编译进二进制：`./agent -print-unit akari-agent`；agent 与 updater 使用 `-init openrc`）；与 systemd 方案的差异及已知缺口见 akari-panel 的 `docs/DEPLOY.md` §3h。

同级检出约定：akari-panel 与 akari-agent 并排放置（`../akari-panel` / `../akari-agent`），与面板 smoke 测试的预期一致。

## xray-core 分支（每次升级 xray 都要手动做）

agent 编译的不是官方 xray-core，而是 [akari-projectX/xray-core](https://github.com/akari-projectX/xray-core) 上的分支：官方版本 + **一处补丁**。`go.mod` 用 `replace` 指过去：

```
require github.com/xtls/xray-core <官方提交的伪版本或 tag>        # 仍写官方版本（manifest_test.go 读它）
replace github.com/xtls/xray-core => github.com/akari-projectX/xray-core <分支提交的伪版本>
```

**为什么**：官方 `common/signal/timer.go` 的 `ActivityTimer.SetTimeout` 有自死锁。它持锁调用 `Periodic.Start`，而 `Start` 会同步执行第一次检查；如果上一个任务的检查恰好抢走了活动令牌，同步检查就会调用 `finish()`，再去锁自己已经持有的锁，这个 goroutine 从此卡死。trojan、VMess、SS2022 与 freedom 在每条连接结束时都调用 `SetTimeout`，卡住的连接永远不释放：goroutine、socket、内核重建后的整个旧 xray 实例都泄漏（2026-10-27 的 60 分钟浸泡测试泄漏了 77 个连接处理器）。补丁让同步的第一次执行只清掉令牌、不做检查（之后的检查由定时器在释放锁之后执行），其余语义不变。

**上游已拒绝这个修复**（2026-10-27，PR 由 mwnydev/Xray-core 提交），所以分支是长期的。`go build -overlay` 不能替换模块缓存里的文件，只能用分支。

**补丁本身**：分支 `akari/v26.10.21` 上的提交 `ce7424b`（在官方 v26.10.21 `1b1647c` 之上），只改 `common/signal/timer.go`；补丁文件与说明另存于 akari-workspace `upstream/xray-activitytimer-deadlock.{patch,md}`。

**每次升级 xray-core 的步骤**（升级 xray 的其他前提见 CLAUDE.md「升级 xray-core 的前提」：撤权金丝雀全绿）：

1. 在 `akari-projectX/xray-core`：从新的官方 tag 开分支 `akari/<版本>`，把补丁提交摘过来（`git cherry-pick ce7424b`，有冲突就按上面的原理手工改），`go test ./common/signal/...` 通过后推送这个分支。
2. 在本仓库：`require` 改为新的官方版本（官方伪版本或 tag，规则见 CLAUDE.md 开头）；`replace` 指向新分支的提交：
   ```
   go mod edit -replace github.com/xtls/xray-core=github.com/akari-projectX/xray-core@<新分支提交>
   go mod tidy
   ```
   需要时更新 `manifest_test.go` 的 `xrayCommitReleases`。
3. `make third-party`（改了 go.mod 必须做并提交）、`make test`（含金丝雀）。
4. **必须单独跑**补丁的回归测试（它是 canary 标签，不在 `make test` 的 -race 套件里）：
   ```
   go test -tags canary -run TestXrayActivityTimerSelfDeadlock .
   ```
   官方版本上它在 8 秒内大约四次有三次挂住，打了补丁必须一次都不挂。
5. 若改动大，再跑一次 `make soak`（默认 60 分钟），确认 `stuck_timers` 为 0、goroutine 与 fd 回到基线。

如果将来官方自己修了这个问题（新版本上第 4 步的测试在**不打补丁**时也通过），就删掉 `replace`、改回官方模块，并删除本节与 CLAUDE.md 的对应说明。

## Automatic node certificate（节点证书自动签发）

当节点在面板中配置了 TLS 域名（节点域名），且有入站读取节点证书文件时，面板会下发 `ConfigSnapshot.acme`，agent 自行通过 ACME 获取并续期证书（默认 Let's Encrypt；库：[acmez](https://github.com/mholt/acmez)，Apache-2.0），无需 certbot。细节见 `acme.go`：

- **存储**：`<state dir>/tls/<domain>/{fullchain,privkey}.pem`（0600，目录 0700）以及 ACME 账户密钥 `<state dir>/tls/accounts/<hash>.key.pem`。state dir 是 systemd 的 `StateDirectory`（agent 以 dynamic user 运行在 `ProtectSystem=strict` 下，`/etc` 不可写）。指向 `/run/credentials/akari-agent.service/tls_{fullchain,privkey}.pem` 的 TLS 入站，会在构建 xray 之前被改指向这些文件；入站 JSON（及状态哈希）与面板下发的完全一致。
- **挑战方式**：没有入站占用 TCP 80 且该端口空闲时，用 TCP 80 上的 HTTP-01；否则在没有入站占用 TCP 443 且其空闲时，用 TCP 443 上的 TLS-ALPN-01；再否则申请失败，报 "port busy"（请释放 TCP 80）。连接/DNS 失败后，下一次申请改用另一种挑战。不支持 DNS-01。
- **首张证书之前**，文件内容是自签名占位证书，因此 xray 总能构建，其他入站不会被拖住；首张 CA 证书到位时只替换 TLS 入站的 handler（其他入站及其连接不受影响；失败时 agent 声明 (0,0)，面板重发 Snapshot）。
- **续期**：剩余有效期为三分之一时（再减去最多 1/30 的抖动）发起，并设置 ARI `replaces`；文件原子替换，xray 每小时自行重读证书文件（必须保持 `oneTimeLoading` 未设置）：无需重建，不断连接。失败后退避 5 分钟 → 6 小时（收到限流应答后 ≥ 1 小时）；重启 agent 可立即重试。
- **状态**随每次心跳上报面板（`Heartbeat.cert`：状态、到期时间、下次尝试、分类后的错误），显示在节点页。
- 手动证书仍然有效：没有 TLS 域名时一切照旧。

测试：`acme_test.go`（进程内 pebble CA + DNS：HTTP-01、TLS-ALPN-01、端口被占、DNS/连接错误、退避、续期、重启、Snapshot 衔接）以及金丝雀 `TestACME_TLSInboundsGetAndHotReloadTheCertificate`（真实 xray 客户端经 VLESS-WS-TLS、Trojan-TLS 和 Hysteria 2，仅信任测试 CA；替换时保持另一入站的连接；续期时保持所有连接）。没有任何测试访问真实 CA。仅供测试/smoke 的参数：`-acme-roots`、`-acme-http-port`、`-acme-tls-port`。

## Per-user speed limits（分用户限速）

面板随用户下发其套餐限速（`UserOp.speed_limit_bytes_per_sec`，0 = 不限速）。xray-core 没有分用户限速，所以 agent 的 gate dispatcher 自行对受限用户的流量整形（`ratelimit.go`）：每用户每方向一个令牌桶，由该用户在本节点上的所有连接和入站共享。受限用户的连接不使用 XTLS Vision 的内核 splice（它会绕过任何限速器），Vision 本身仍然可用。不限速用户走原来的路径，完全不变。限速从无到有时，会关闭该用户的存量连接（客户端重连后即被限速）；其他变更就地生效。只包装 dispatch 的出站一侧（xray 的 mux 保留入站侧 link 并断言其类型）。测试：`ratelimit_test.go`（经 xray 的真实 VLESS：吞吐等于限速值）、金丝雀 `TestRT_VisionSpeedLimit`（TLS 上的 Vision）、`TestRT_MuxSpeedLimit`、`TestRT_UDPSpeedLimit`，以及 `TestRT_ProtocolMatrix` 的限速阶段（所有协议，含 SS2022 和 Hysteria2）。

## Self-update（自更新）

面板可以分批推出新的 agent 发布版（分波次、健康门、自动中止；见 `akari-panel/docs/DEPLOY.md`，"Agent updates"）。agent **只**信任由本仓库中固定的发布密钥（`release-keys.txt`，编译进二进制）签名的 manifest；面板只是中继。只有在签名校验通过、平台匹配、版本比当前运行的更新（或签名 manifest 是明确的 `rollback` 目标：schema 2，带 `rollback_from` 与 `expires_at`，只在正运行的版本恰好是 `rollback_from`、尚未过期、且目标版本是本节点自己运行并确认过的版本时才接受）、且本节点此前没有从该版本回滚过时，才接受更新提议。二进制经已有的 mTLS 连接（`AgentChannel.FetchArtifact`）传来，并校验大小与 SHA-256。agent 从不自己执行它：其 state 目录被 systemd 挂载为 `noexec`（DynamicUser），并且保持如此。它把文件和应用请求暂存到 `<state dir>/update/`；由**特权 updater**（`akari-agent-update.path` + `akari-agent-update.service`，位于 `systemd/`，由面板的一行安装命令安装）以 `akari-agent -apply-update <state dir>` 运行*已安装*的二进制，它把该目录视为不可信，将文件复制到仅 root 可访问的位置，用自己固定的密钥和版本策略重新校验副本，将其安装为 `/usr/local/bin/akari-agent`（保留 `akari-agent.prev`），连同新发布版自带的 systemd 单元一并安装（用 `-print-units` 从已校验的副本读取；旧单元会保留，回滚时恢复），然后重启 agent。新二进制必须在 `-update-self-check`（默认 5m）内连上并得到一次已确认的 apply；否则，或崩溃 `-update-max-boots` 次（默认 3）时，updater 会把旧二进制放回去。`./agent -release-keys` 列出已固定的密钥。

### Release signing keys（发布签名密钥）

Manifest（`akari-agent-linux-<arch>.manifest.json`：version、os、arch、sha256、size、min_panel_protocol、created_at、rollback；rollback manifest 为 schema 2，另有 rollback_from、expires_at（最长 30 天，`akari-sign sign -rollback -rollback-from vX -expires 7d`））使用 Ed25519 对 `"akari-agent-manifest-v1\n" || manifest` 签名（`release/`，契约见 akari-panel 的 `proto/agent.proto`）。Cosign 无密钥签名仍保留，供人工与 CI 使用；节点无需连接 Rekor/Fulcio。

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

bootstrap 文件由面板上的 `akari server add <name>` 生成：包含面板地址、TLS server name、面板 CA 和**一次性注册令牌**——不含私钥。首次启动时，agent 在 state 目录（`-state-dir`；systemd 下默认 `$STATE_DIRECTORY`，否则为配置文件所在目录；文件权限 0600）中生成 ECDSA P-256 密钥，用 CSR 注册（唯一无需客户端证书的调用）并保存签发的证书。密钥从不离开节点，也从不写入日志。当证书剩余有效期不足三分之一时，agent 通过存活的 mTLS 连接用新密钥续期，用新证书重连，并保留旧证书直到面板接受新证书。带新令牌的 bootstrap 文件会让节点重新注册一次。见 `akari-panel/docs/DEPLOY.md`。
