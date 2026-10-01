# akari-agent

Go 1.27 单包（`package main`，模块名 `akari/agent`），内嵌 xray-core `v1.260327.0`（= release v26.3.27；Xray 用 CalVer，更新 tag 多为 prerelease，勿盲升）。
公开仓库，MIT；xray-core 为 MPL-2.0（修改其源码须开源），声明见 `THIRD-PARTY-NOTICES.md`。

## 文件

| 文件 | 职责 |
|---|---|
| `main.go` | flag、slog JSON、SIGINT/SIGTERM |
| `config.go` | 解析 bootstrap.toml（未知键报错）：v2 = panel_addr / server_name / enrollment_token / identity.ca_pem；v1 = 再加 identity.cert_pem + key_pem（仍支持） |
| `identity.go` | 身份存储（`-state-dir`，默认 `$STATE_DIRECTORY` 或配置文件目录，目录 0700）：`identity.pem`（当前：私钥+证书）、`identity.next.pem`（续期得到、面板尚未接受）、`enroll.key.pem`（注册前先落盘的密钥）、`enrolled.token.sha256`；全部 0600 原子写（临时文件+fsync+rename+fsync 目录）。ECDSA P-256、CSR 无任何扩展；存证书前校验 CA 链、ClientAuth、与私钥匹配。state 中的身份优先于配置里的 v1 密钥 |
| `enroll.go` | 注册（`ensureEnrolled`：无身份或配置里是未用过的新 token 时注册；PERMISSION_DENIED/INVALID_ARGUMENT 为永久错误（无身份时退出），其余退避重试）与续期（`renewLoop`：剩余 < 1/3 有效期时在当前 mTLS 连接上 `Renew`，存 next，取消当前流以用新证书重连；新证书在其流上收到第一条面板消息才提升；被拒（UNAUTHENTICATED/TLS 告警）则丢弃并退避，其它失败则下一次改用当前证书交替；当前证书上的流持续 `nextRetryAfter` 后重试 next；续期失败 10s 起翻倍至 10min，Unimplemented（旧面板）1h） |
| `agent.go` | 会话生命周期：指数退避重连（1s→30s，稳定 >1min 重置，计时在睡眠前；`nextBackoff`）、Hello、单写者 goroutine、处理 Snapshot/Delta/LeaseGrant、Ack、最终计数队列 `finalQueue`、租约检查 |
| `core.go` | `CoreManager`：xray 实例构建（`DecodeJSONConfig→Build`，把 dispatcher app 换成 gate →`core.New`）、REPLACE 语义的用户操作、`applied`（实际生效的凭据，喂 state hash）、按 `user>>>{id}>>>traffic>>>*` 读计数（会话内单调保护） |
| `gate.go` | `gateDispatcher`：替换 xray 的 DefaultDispatcher（内部包一个）。每次分发要求 (inbound tag, email) 当前安装的 `*MemoryUser` 指针；撤销/轮换时取消并中断该 key 的所有活连接 |
| `statehash.go` | state hash（定义见 proto，向量 `proto/state_hash_vectors.json`） |
| `lease.go` / `boottime_*.go` | 失联租约：CLOCK_BOOTTIME、0→24h、≥1h、≤30d、50%/90% 预警 |
| `monitor.go` | 心跳 15s（cpu/mem/租约剩余、`connections` = gate 跟踪的分发数（无锁读，不等 Rebuild）、`uptime_seconds`）、流量 10s（累计值） |
| `update.go` | M6 自更新（磁盘侧）：`<state>/update/`（state.json 0600：current/previous 槽位、trial（试用期，boots 计数）、rolled_back 版本表、待发 report；`finals.json` 跨重启的最终计数；`bin/` 暂存二进制 0700）。`launch()` 在 main 最早执行：**全新启动**（非 `AKARI_AGENT_LAUNCHED=1`）的已安装二进制 = 启动器，current 比自己新则 boots+1（试用中）、超过 `-update-max-boots` 即回滚（标记 rolled_back、report ROLLED_BACK、current:=previous），再按 manifest 校验大小/SHA-256 后 `syscall.Exec`；已安装版本 ≥ 暂存版本则丢弃暂存（手工升级优先）；被 exec 的进程从不再 exec（防循环）。签名只在接受 offer 时验（启动器可能早于密钥轮换），暂存文件只做完整性校验 |
| `update_agent.go` | M6 自更新（会话侧）：`UpdateOffer` → 用**编译进来的**公钥验签 + `release.Policy`（平台、单调版本/签名 rollback、已回滚版本、min_panel_protocol）→ 失败回 `REJECTED`；接受后单任务后台经同一 mTLS 连接 `FetchArtifact` 下载（断点续传，6 次退避），校验大小+SHA-256 → 暂存 → 持 `applyMu` 且流仍活：拆 xray、持有版本 (0,0)、最终计数入队并落盘、发 `RESTARTING` 并 `flushStream` → `commit`（trial boots=1）→ exec（失败则 undo 并重发 Hello）。试用期：Snapshot/Delta ok Ack 发出后 `confirmTrialLocked`（发 `CONFIRMED`）；`trialLoop` 超时（`-update-self-check`）则拆 xray、落盘计数、exec previous/installed（exec 失败退出，交给 systemd）。待发 report 在每条新流 Hello 后发送。租约是进程内状态，不跨 exec（新进程在首个 LeaseGrant 前不跑 xray，因为 (0,0) 只能等 Snapshot，而面板总是先发 LeaseGrant） |
| `release/` | 可导入包：manifest（schema 1，严格解码）、Ed25519 签名（上下文前缀 `akari-agent-manifest-v1\n`，key id = SHA-256(pub)[:8]）、`ParseKeys`、`Policy`、semver 比较；面板 `updates.rs` 实现同一规则，向量 `proto/update_vector.json` |
| `cmd/akari-sign` | 离线签名工具：keygen/pubkey/sign/countersign/verify（`-key` 或 `-key-env`） |
| `release-keys.txt` / `releasekeys*.go` | 生产固定公钥集（go:embed；生产密钥 `key-f2ad18a8bb718a1a`，自 v0.2.0 起固定；私钥仅存负责人机器 `~/secrets/akari-release-signing.key`(0600) + 仓库 secret `AKARI_RELEASE_SIGNING_KEY`；轮换 = 新公钥并列固定 + `akari-sign countersign` 双签，全网升级后删旧钥）；`akari_testkeys` 构建标签额外加入**公开的**测试公钥（`testdata/TEST-ONLY-release.*`，仅 smoke），`make dist` 的 `check-release-keys` 拒绝含测试公钥的二进制 |
| `proto/agent.proto` | **vendor 副本**，禁止手改，只能 `make sync-proto`（worktree 中手工 cp + `buf generate proto` + diff） |
| `proto/state_hash_vectors.json` | 面板正本的副本（共享测试向量） |
| `proto/update_vector.json` | 面板正本的副本（M6 签名 manifest 共享向量，`release` 测试读取） |
| `proto/gate.proto` | agent 内部（非契约、不同步）：gate 的 xray app 配置消息类型 |
| `rt_canary_test.go` | red team 撤权金丝雀（Vision/splice over TLS、trojan），`make test-canary` |
| `bench_test.go` | M2-6 开销基准（每节点 10k 用户 × 2 inbound）：Rebuild、实例堆、单用户 delta、流量快照、state hash、gate admit/release、心跳连接数；`make bench`，结果记录在 `akari-panel/docs/PERF.md` |
| `pb/` | buf 生成物（已提交，`buf generate proto`） |

## 命令

```bash
make build        # → ./agent（gitignored）；静态、-trimpath、版本=git describe、提交=短 sha（-ldflags 注入）
./agent -version  # akari-agent <version> (<sha>) <go> <os/arch>
make dist         # dist/akari-agent-linux-{amd64,arm64} + SHA256SUMS（发布同款构建，CI `reproducible` 校验字节一致）
make vet fmt-check
make test         # test-canary + go test -race ./...
make test-canary  # rt_canary_test.go（build tag canary，不带 -race：xray 的 Vision 客户端在 -race 下触发 checkptr）
make sync-proto   # 从 ../akari-panel 拷贝契约并 buf generate
make check-proto  # 契约漂移校验
make bench        # 开销基准（bench_test.go；-run '^$' 只跑基准）
make build-testkeys VERSION=v900.0.0 OUT=/tmp/a   # 仅测试：额外信任测试公钥（smoke 用）
make sign-manifest VERSION=vX.Y.Z KEY=<file>|KEY_ENV=<var>   # dist/*.manifest.{json,sig}
./agent -release-keys   # 列出固定公钥
```

## 发布

tag `v*` 触发 `.github/workflows/release.yml`：fmt-check/vet/test → `make dist`（含 `check-release-keys`）→ 自更新 manifest 签名（仅当仓库 secret `AKARI_RELEASE_SIGNING_KEY` 存在，否则 warning 跳过；签后用 `release-keys.txt` 复验）→ CycloneDX SBOM → SHA256SUMS → cosign 无密钥签名（GitHub OIDC，`*.sigstore.json`）→ GitHub Release。第三方 action 固定 commit SHA。验证方法见 `akari-panel/docs/DEPLOY.md`。systemd 单元在 `akari-panel/deploy/systemd/akari-agent.service`。

## 须知

- xray 动态用户链路：`inbound.Manager.GetHandler(tag)` → 断言 `GetInbound()` → 协议 inbound 的 `AddUser/RemoveUser`。新协议需要 blank-import 对应 inbound 包并在 `buildUser` 加分支。
- 每个 Snapshot 都会 `Rebuild`（关停并重建 xray 实例 → **断开节点上所有连接**；旧实例最终计数会先入队上报）。面板在只有用户集变化时发 `UserDelta`，不重建。
- **UserDelta**：持有 == base 才应用；持有 == target（且不 dirty）→ ok no-op；否则 `BASE_MISMATCH`，不改任何东西。delta 的 config_version 必须等于 base。部分失败：保持 base 版本、置 `dirty`（之后的 delta 一律 `BASE_MISMATCH` 直到 Snapshot），state hash 反映实际生效内容。
- **REPLACE 语义**：ADD 后用户恰好在列出的 inbound 上；未列出或凭据变化的 tag 先在 gate 撤销（断活连接）再从 validator 删除，所有 inbound 都清一遍；完全相同的凭据不动（连接保留）。被移除/凭据变化的用户在 Ack 前上报最终计数（当前 session）。
- **gate 是撤权的关键**：validator 的 RemoveUser 只挡新握手，已认证连接与 mux 新子流都会继续跑。gate 按 `*MemoryUser` 指针准入并跟踪分发（`Dispatch` 走自己的 pipe + 后台 `DispatchLink`，relay 结束即释放条目）。gate 通过 `proto/gate.proto` 的配置类型注册成 xray app，在 app 列表里原位替换 `dispatcher.Config`（vless 在创建时就 `GetFeature(Dispatcher)`，不能事后替换）。已知旁路：VLESS reverse（Rvs 命令）不经 dispatcher，面板生成的账号不含 reverse。
- **升级 xray-core 的前提**：所有按协议的撤权金丝雀（`make test-canary` + `-race` 套件里的 vless/rotation/dispatch-path 测试）全绿才能升级；gate 依赖 xray 内部（app 槽位替换、Dispatch/DispatchLink 语义）。
- **无用户的 inbound**（dokodemo/socks/http 不带 clients）：分发上下文没有 user，gate 直接放行、不计费、不能撤权。面板只给 vless/vmess/trojan 发凭据；这类 inbound 若由管理员配置，等同于开放代理，自负其责。面板拒绝 fakedns（gate 内部的 DefaultDispatcher 没有接 FakeDNS 引擎）；agent 在 xray 自己解析（`jsonConfig.Build()`）之后由 `refuseFakeDNS` 再查一次 `SniffingSettings.DestinationOverride`，含 fakedns → Rebuild 失败（APPLY_FAILED），这是权威检查，面板的 JSON 检查只是提前报错。
- **remove mode（R10 回退开关）**：`LeaseGrant.remove_mode` = REBUILD 时，会删除/轮换活凭据的 delta 一律 `BASE_MISMATCH`（不做任何改动），由面板改发 Snapshot（整体重建）；纯新增仍走 delta。只接受当前流 grant 设置。
- **xray 计数器**：v26.3.27 中 RemoveUser/AddUser 不会注销或重置 `user>>>…` 计数器（没有任何调用 `UnregisterCounter`），同实例内重新添加后累计值连续；`readCounter` 另有单调保护（计数下降则累加偏移）。被移除用户的计数在本 session 内继续上报（尾部流量不丢）。
- session id 归 `CoreManager` 所有，只在 `Rebuild`/`Teardown` 内持锁更换；`TrafficSnapshot` 在同一把锁下返回 (session, 计数)，每个 `TrafficReport` 都带 `session_id`（面板按它记账）。最终计数进 `finalQueue`：每条新流 Hello 后重发，直到某条流发出后又存活 `finalsConfirmAfter`（60s，> keepalive 判死 30s+10s：写入死 socket 也"成功"）（面板记账幂等，重发安全）。**优雅停机（A29）**：SIGTERM → 会话 goroutine 在**仍存活的流**上 `gracefulStop`（Teardown → 最终计数入队并发送 → 有界 flush `shutdownFlush`=5s，期间不再应用面板消息）→ `Run` 返回前 `stopped()` 把未确认队列持久化到 state dir 的 `finals.json`（`finalsStore`，与自更新器无关；自更新重启同用）；下个进程启动时载入并先于其他消息重发，队列排空后删文件。
- **F3**：`session()` 返回前 join 所有子 goroutine（读协程可能正在 Rebuild）→ 任意时刻至多一个 handleDown；`handleDown` 持 `applyMu`，先查流 ctx，流已死则不 Rebuild、不改版本、不发送（Rebuild 期间流死 → 置 dirty）。
- **租约**：首次收到 `LeaseGrant` 才武装（旧面板永不武装）；只接受当前流的 grant；到期（`checkLease`，5s 一次）拆 xray、最终计数入队、持有版本归 (0,0)；若流仍在（面板活着但 DB 挂了）立即发 Hello (0,0)。
- state hash v2 绑定 inbounds：`CoreManager.inboundsJSON` = 当前实例 Snapshot 的 inbounds_json 原文（无实例时为 ""）。
- Hello 带 `protocol_version`（常量 `agentProtocol`，当前 3 = 自更新；2 = 会续期证书）与 state hash；Ack 带 reason、处理后持有版本、state hash。
- **身份（M1c）**：私钥只在节点生成、永不出节点、不进日志；token 也不进日志（只存其 SHA-256 作“已用”标记）。连接时先用待确认的 next 身份（失败为暂时性则下次用当前身份，交替），收到面板第一条消息即提升为 `identity.pem`。面板在新证书首次出现前一直接受旧证书，所以接收后、持久化前崩溃都无害。当前证书过期时每次连接都打错误日志（需 `akari node enroll-token` 发新 token 重新注册）。
- **GO-2026-6443**：`refuseGRPCTransport` 在 xray 解析后拒绝 `streamSettings.network` = grpc 的 inbound（Rebuild 失败 → APPLY_FAILED），与 `refuseFakeDNS` 同为权威检查；grpc-go ≥ 1.85 后可解除。
- 应用失败（Snapshot 的 `Rebuild` 或 Delta 返回错误）时**不**更新持有版本：Hello 继续报旧版本，Ack 携带**尝试的**版本、`ok=false`、reason `APPLY_FAILED`，面板据此记录 `last_error` 并按退避重试。
