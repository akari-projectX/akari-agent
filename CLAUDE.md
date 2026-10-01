# akari-agent

Go 1.27 单包（`package main`，模块名 `akari/agent`），内嵌 xray-core `v1.260327.0`（= release v26.3.27；Xray 用 CalVer，更新 tag 多为 prerelease，勿盲升）。
公开仓库，MIT；xray-core 为 MPL-2.0（修改其源码须开源），声明见 `THIRD-PARTY-NOTICES.md`。

## 文件

| 文件 | 职责 |
|---|---|
| `main.go` | flag、slog JSON、SIGINT/SIGTERM |
| `config.go` | 解析 bootstrap.toml（panel_addr / server_name / identity 三件套 PEM） |
| `agent.go` | 会话生命周期：指数退避重连（1s→30s，稳定 >1min 重置）、Hello、单写者 goroutine、处理 Snapshot/Delta/LeaseGrant、Ack、最终计数队列 `finalQueue`、租约检查 |
| `core.go` | `CoreManager`：xray 实例构建（`DecodeJSONConfig→Build`，把 dispatcher app 换成 gate →`core.New`）、REPLACE 语义的用户操作、`applied`（实际生效的凭据，喂 state hash）、按 `user>>>{id}>>>traffic>>>*` 读计数（会话内单调保护） |
| `gate.go` | `gateDispatcher`：替换 xray 的 DefaultDispatcher（内部包一个）。每次分发要求 (inbound tag, email) 当前安装的 `*MemoryUser` 指针；撤销/轮换时取消并中断该 key 的所有活连接 |
| `statehash.go` | state hash（定义见 proto，向量 `proto/state_hash_vectors.json`） |
| `lease.go` / `boottime_*.go` | 失联租约：CLOCK_BOOTTIME、0→24h、≥1h、≤30d、50%/90% 预警 |
| `monitor.go` | 心跳 15s（cpu/mem/租约剩余）、流量 10s（累计值） |
| `proto/agent.proto` | **vendor 副本**，禁止手改，只能 `make sync-proto`（worktree 中手工 cp + `buf generate proto` + diff） |
| `proto/state_hash_vectors.json` | 面板正本的副本（共享测试向量） |
| `proto/gate.proto` | agent 内部（非契约、不同步）：gate 的 xray app 配置消息类型 |
| `rt_canary_test.go` | red team 撤权金丝雀（Vision/splice over TLS、trojan），`make test-canary` |
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
```

## 发布

tag `v*` 触发 `.github/workflows/release.yml`：fmt-check/vet/test → `make dist` → CycloneDX SBOM → SHA256SUMS → cosign 无密钥签名（GitHub OIDC，`*.sigstore.json`）→ GitHub Release。第三方 action 固定 commit SHA。验证方法见 `akari-panel/docs/DEPLOY.md`。systemd 单元在 `akari-panel/deploy/systemd/akari-agent.service`。

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
- session id 归 `CoreManager` 所有，只在 `Rebuild`/`Teardown` 内持锁更换；`TrafficSnapshot` 在同一把锁下返回 (session, 计数)，每个 `TrafficReport` 都带 `session_id`（面板按它记账）。最终计数进 `finalQueue`：每条新流 Hello 后重发，直到某条流发出后又存活一个流量周期（面板记账幂等，重发安全）。
- **F3**：`session()` 返回前 join 所有子 goroutine（读协程可能正在 Rebuild）→ 任意时刻至多一个 handleDown；`handleDown` 持 `applyMu`，先查流 ctx，流已死则不 Rebuild、不改版本、不发送（Rebuild 期间流死 → 置 dirty）。
- **租约**：首次收到 `LeaseGrant` 才武装（旧面板永不武装）；只接受当前流的 grant；到期（`checkLease`，5s 一次）拆 xray、最终计数入队、持有版本归 (0,0)；若流仍在（面板活着但 DB 挂了）立即发 Hello (0,0)。
- state hash v2 绑定 inbounds：`CoreManager.inboundsJSON` = 当前实例 Snapshot 的 inbounds_json 原文（无实例时为 ""）。
- Hello 带 `protocol_version`（常量 `agentProtocol`，当前 1）与 state hash；Ack 带 reason、处理后持有版本、state hash。
- `tlsConfig()` 在密钥无效时返回错误（会话失败并重试），bootstrap 文件含私钥，权限应为 0600。
- 应用失败（Snapshot 的 `Rebuild` 或 Delta 返回错误）时**不**更新持有版本：Hello 继续报旧版本，Ack 携带**尝试的**版本、`ok=false`、reason `APPLY_FAILED`，面板据此记录 `last_error` 并按退避重试。
