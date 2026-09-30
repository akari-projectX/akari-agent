# akari-agent

Go 1.27 单包（`package main`，模块名 `akari/agent`），内嵌 xray-core `v1.260327.0`（= release v26.3.27；Xray 用 CalVer，更新 tag 多为 prerelease，勿盲升）。
公开仓库，MIT；xray-core 为 MPL-2.0（修改其源码须开源），声明见 `THIRD-PARTY-NOTICES.md`。

## 文件

| 文件 | 职责 |
|---|---|
| `main.go` | flag、slog JSON、SIGINT/SIGTERM |
| `config.go` | 解析 bootstrap.toml（panel_addr / server_name / identity 三件套 PEM） |
| `agent.go` | 会话生命周期：指数退避重连（1s→30s，稳定 >1min 重置）、Hello、单写者 goroutine、处理 Snapshot/Delta、Ack |
| `core.go` | `CoreManager`：xray 实例构建（`DecodeJSONConfig→Build→core.New`）、动态 AddUser/RemoveUser、按 `user>>>{id}>>>traffic>>>*` 读计数 |
| `monitor.go` | 心跳 15s（cpu/mem）、流量 10s（累计值） |
| `proto/agent.proto` | **vendor 副本**，禁止手改，只能 `make sync-proto` |
| `pb/` | buf 生成物（已提交）；`pb/proto/` 是旧布局遗留的重复副本，可删除 |

## 命令

```bash
make build        # → ./agent（gitignored）
make vet fmt-check
make sync-proto   # 从 ../akari-panel 拷贝契约并 buf generate
make check-proto  # 契约漂移校验
```

## 须知

- xray 动态用户链路：`inbound.Manager.GetHandler(tag)` → 断言 `GetInbound()` → 协议 inbound 的 `AddUser/RemoveUser`。新协议需要 blank-import 对应 inbound 包并在 `buildUser` 加分支。
- 每个 Snapshot 都会 `Rebuild`（关停并重建 xray 实例 → **断开节点上所有连接**，未上报的 ≤10s 流量丢失）。面板目前只发 Snapshot，所以每次用户变更都会触发重建。见 REVIEW。
- 重建后会 `resetSession()`，但**不会重发 Hello**，面板仍按旧 session_id 记账。
- `tlsConfig()` 在密钥无效时 panic；bootstrap 文件含私钥，权限应为 0600。
