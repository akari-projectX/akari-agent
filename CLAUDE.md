# akari-agent

Go 1.27 单包（`package main`，模块名 `akari/agent`），内嵌 xray-core `v1.260327.0`（= release v26.3.27；Xray 用 CalVer，更新 tag 多为 prerelease，勿盲升）。
公开仓库。**许可（R19）**：自有源码 MIT；**二进制**静态链接 `sagernet/sing*`（GPL-3.0-or-later，经 xray-core 的 Shadowsocks）→ 按 **GPL-3.0-or-later 组合作品**分发（README「Licence」、发布说明、`LICENSES/GPL-3.0.txt`）；xray-core 为 MPL-2.0（修改其源码须开源）。`THIRD_PARTY_LICENSES.txt` 是生成物（`make third-party`，CI `check-third-party` 校验最新；内嵌进二进制 `-licenses`；`make dist`/发布附带），`THIRD-PARTY-NOTICES.md` 是人工评估。**改 go.mod 后必须 `make third-party` 并提交**。

## 文件

| 文件 | 职责 |
|---|---|
| `main.go` | flag、slog JSON、SIGINT/SIGTERM |
| `config.go` | 解析 bootstrap.toml（未知键报错）：v2 = panel_addr / server_name / enrollment_token / identity.ca_pem；v1 = 再加 identity.cert_pem + key_pem（仍支持） |
| `identity.go` | 身份存储（`-state-dir`，默认 `$STATE_DIRECTORY` 或配置文件目录，目录 0700）：`identity.pem`（当前：私钥+证书）、`identity.next.pem`（续期得到、面板尚未接受）、`enroll.key.pem`（注册前先落盘的密钥）、`enrolled.token.sha256`；全部 0600 原子写（临时文件+fsync+rename+fsync 目录）。ECDSA P-256、CSR 无任何扩展；存证书前校验 CA 链、ClientAuth、与私钥匹配。state 中的身份优先于配置里的 v1 密钥 |
| `enroll.go` | 注册（`ensureEnrolled`：无身份或配置里是未用过的新 token 时注册；PERMISSION_DENIED/INVALID_ARGUMENT 为永久错误（无身份时退出），其余退避重试（full jitter，W6））与续期（`renewLoop`：剩余 < 1/3 有效期时在当前 mTLS 连接上 `Renew`，存 next，取消当前流以用新证书重连；新证书在其流上收到第一条面板消息才提升；被拒（UNAUTHENTICATED/TLS 告警）则丢弃并退避，其它失败则下一次改用当前证书交替；当前证书上的流持续 `nextRetryAfter` 后重试 next；续期失败 10s 起翻倍至 10min，Unimplemented（旧面板）1h） |
| `agent.go` | 会话生命周期：指数退避重连（1s→30s，稳定 >1min 重置，计时在睡眠前；`nextBackoff`；实际等待 full jitter `[0, backoff)`，W6）、Hello、单写者 goroutine（**有界发送**（C2）：队列（256）满持续 `sendStall`=60s（> keepalive 40s）即取消当前流，持 applyMu 者立即返回、重连；收到停机信号后等待中的发送最多再等 `shutdownFlush`，gracefulStop 必能在 TimeoutStopSec 内拿到锁；接收上限 `maxRecvMsg`=64 MiB（C3，grpc 默认 4 MiB ≈ 1.8 万用户的 Snapshot），`channelDialOptions` 与测试共用）、处理 Snapshot/Delta/LeaseGrant、Ack、最终计数队列 `finalQueue`、租约检查 |
| `core.go` | `CoreManager`：xray 实例构建（`DecodeJSONConfig→Build`，把 dispatcher app 换成 gate →`core.New`）、REPLACE 语义的用户操作、`applied`（实际生效的凭据，喂 state hash）、`issued`（W9：本实例每个 tag 上每个用户最后装过的凭据，含已移除的；同凭据重加复用其 `*MemoryUser`；SS2022 tag 上非 live 的即墓碑，`tombs` 计数）、计数器在装用户时注册并解析一次（`counted`：`*userCounters`，W1）；周期上报 `TrafficChanges` 只带上次之后变化的行（每条新流 Hello 后 `ResetSent` → 首报全量），最终计数/移除用户的尾账/`TrafficSnapshot` 为全量；Rebuild 中尚无凭据的用户跳过"所有 inbound 先删一遍"（W8，delta 保留） |
| `protocols.go` | W8 协议矩阵：`inboundKinds`（按 xray 解析后的 proxy 配置类型判定每个 tag 的受管协议，权威）、`multiUserShadowsocks`（JSON `settings` 含 `clients` 键的 SS2022 入站改建为 xray 多用户服务端；校验 method 与 PSK）、`buildUser`（vless/vmess/trojan/shadowsocks/hysteria，凭据协议须与入站一致，SS 密钥长度按 method、hysteria auth ≥16）、`shrinkUnsafe` |
| `gate.go` | `gateDispatcher`：替换 xray 的 DefaultDispatcher（内部包一个）。每次分发要求 (inbound tag, email) 当前安装的 `*MemoryUser` 指针；撤销/轮换时取消并中断该 key 的所有活连接；`admit` 同时取出该用户的限速（W7）；心跳用的分发数/在线用户数是锁内在 key 0↔1 转换时维护的原子量，读取 O(1) 无锁（review W7） |
| `ratelimit.go` | W7 每用户限速（协议 4，`UserOp.speed_limit_bytes_per_sec`）：每用户一对令牌桶（上/下行，虚拟时间 GCRA 式 pacing，burst = max(rate/5, 64 KiB)，每次最多放行 32 KiB 一块——管道一次可交出数百 KiB，整批等待会让请求/响应两个方向串行、只得到约一半速率），该用户在本节点所有 inbound/连接共享；受限用户的分发链路包 `limitedReader`/`limitedWriter`（等待可被分发 ctx 取消，`Interrupt`/`Close` 透传），并置 `session.Inbound.CanSpliceCopy = 3` 关掉 XTLS Vision 的 splice（否则内核直拷绕过一切 reader/writer）；不限速用户不包装（只多一次 map 查找）。`SetLimit`：从无到有 → 断开该用户所有活连接（未包装/可能已 splice，重连后受限）；改值/取消 → 原地生效 |
| `statehash.go` | state hash（定义见 proto，向量 `proto/state_hash_vectors.json`；W2：原地排序 + 复用编码缓冲，常数次分配） |
| `lease.go` / `boottime_*.go` | 失联租约：CLOCK_BOOTTIME、0→24h、≥1h、≤30d、50%/90% 预警 |
| `acme.go` | W10 自动节点证书（协议 6，`ConfigSnapshot.acme`）：acmez（Apache-2.0）ACME 客户端；存储 `<state>/tls/<domain>/{fullchain,privkey}.pem`（0600，目录 0700）+ `tls/accounts/<sha256(目录)[:8]>.key.pem`（账户密钥跨续期保留）；**不用 /etc**（DynamicUser + ProtectSystem=strict 下不可写，StateDirectory 由 systemd 管属主）。挑战决策：TCP 80 不是入站端口且可绑定 → HTTP-01；否则 443 不是入站端口且可绑定 → TLS-ALPN-01；否则 `ERROR_PORT_BUSY`；连接/DNS 类失败后下一单优先另一种（一单一种挑战，配合退避 5min 翻倍至 6h（+0–10%），限流至少 1h，一小时内 < 5 次失败验证 = LE 每主机名限额）；DNS-01 不支持。首张证书前写**自签占位证书**（O=`akari-agent placeholder`），xray 总能构建；`rewriteCertPaths` 只改名为 `/run/credentials/akari-agent.service/tls_{fullchain,privkey}.pem` 的证书条目（精确键名），inbounds_json 原文仍进 state hash。首张 CA 证书 → `onIssued` → `Agent.onCertIssued` 持 applyMu 调 `CoreManager.ReloadInbounds`（只换这些 TLS 入站的 handler，同 `*MemoryUser` 重加，其他入站/连接/session/计数不动；失败 → 持有 (0,0)+dirty+Hello，面板重发 Snapshot）。续期（剩 1/3 有效期，减最多 1/30 抖动；ARI `replaces`）原子替换文件，**靠 xray 自己每小时重读证书文件**（`setupOcspTicker`，入站不得设 `oneTimeLoading`），不重建、不断连。状态（`Heartbeat.cert`）：PENDING/VALID/FAILED + 到期/下次尝试/分类错误（DNS/CONNECTION/RATE_LIMITED/PORT_BUSY/CAA/REJECTED/CA_UNREACHABLE）。测试用 flag：`-acme-roots`、`-acme-http-port`、`-acme-tls-port` |
| `monitor.go` | 心跳 15s（`-heartbeat-interval`，1s–5min；cpu/mem/租约剩余、`connections` = gate 跟踪的分发数（无锁读，不等 Rebuild）、`uptime_seconds`、W11 `metrics`（`NodeMetrics`，`buildHeartbeat`））、流量 10s（累计值，只发变化行：`TrafficChanges`） |
| `sysstat.go` / `statfs_*.go` | W11 机器状态（无 cgo、无子进程，只读 `/proc` 与 `statfs("/")`）：纯解析函数 `parseCPUStat`/`parseLoadavg`/`parseMeminfo`（used = total − MemAvailable）/`parseDefaultRoute4`/`parseDefaultRoute6`/`parseNetDev`/`parseSockstat`/`parseStatusRSS`，`sampler` 保存上次读数算 CPU% 与网卡速率；**W23：读不到的值不设置（proto3 optional，能力 `metrics-presence`），绝不当 0**（文件缺失/被沙箱隐藏/无法解析；首个心跳、计数回绕、换网卡时速率不设置）；启动时 `logMetricsAvailability` 记一行 `machine metrics`（`unavailable` 列表；非空 = WARN，多为旧单元 `ProcSubset=pid`）；网卡 = IPv4 默认路由（最低 metric）→ IPv6 默认路由 → 流量最大的非 lo；在线用户 = gate 里有活分发的不同用户数（`gateDispatcher.LiveStats`）。夹具 `testdata/proc/`，测试 `sysstat_test.go` |
| `latency.go` | W11 延迟测试（能力 `latency`，Clash url-test 语义）：`prober` 进程级循环（启动后 0–60s 内一次，之后 interval ±10%，默认 5h，面板 `LatencyProbeConfig` 可改并夹到 [10min, 7d]）；每次直连（`Proxy: nil`、不复用连接、不跟随重定向）GET，延迟 = 发请求到收到响应头，`attempts`（默认 3）次取中位数，失败按超时计；URL 依次尝试，首个有响应的即止（默认 gstatic → cloudflare）；`run_token` 变化 = 立即测（进程见到的第一个只记录，10s 内合并；合并中的请求不因间隔变化的重排而推迟，W12 修复）；最新结果在每次 Hello 后重发（`latestReport`）。测试 `latency_test.go`（本地 httptest、超时、回退、调度） |
| `update.go` | M6 自更新（agent 侧磁盘，W18 重写）：`<state>/update/`（0700）：`state.json`（rolled_back 版本表、待发 report；旧 launcher 时代字段读入即丢）、`finals.json`、`staged`（下载并校验后的二进制，0600，**从不执行**）、`apply-request.json`（交给特权更新器的请求，最后原子写入 = path 单元触发器）、`apply-result.json`（更新器写、chown 给 agent：installed/confirmed/rolled_back/rejected/rollback_failed）、`confirmed`（新版本自检通过的标记，更新器据此判健康）。`boot()` 在 main 最早执行：删残留请求/暂存、把 rolled_back/rejected 结果变成待发 report、`installed` 且版本 = 自己且未 confirmed → 试用期。`parseApplyRequest` 严格解码（`FuzzApplyRequest`）。`-updater-unit`（默认 `/etc/systemd/system/akari-agent-update.path`）不存在时拒绝 offer：`updater unit missing …（重装命令）` |
| `units.go` / `systemd/` | W23 systemd 单元**正本**（`akari-agent.service`、`akari-agent-update.service`、`akari-agent-update.path`），`go:embed` 进二进制：`-print-unit NAME`（面板安装器用它安装所装版本自带的单元）、`-print-units`（JSON，更新器读取新版本的单元）、`parseUnits`（只认这三个名字，非空、≤64 KiB、文本）、`staleUnits`（作为已安装服务运行时（`INVOCATION_ID` + 单元目录有 akari-agent.service）比较已安装单元与自带的，不同 → Hello 能力加 `stale-units` + WARN 日志）。面板 `deploy/systemd/` 有逐字节相同的副本（安装器对旧 release 的回退）：`make sync-units PANEL_DIR=…` 写入、`make check-units`（CI proto job）校验；改单元 = 先合面板 PR（同契约） |
| `updater_linux.go` | W18 特权更新器 `-apply-update <agent state dir>`（root，`akari-agent-update.service`，只运行**已安装**的可信二进制；`-updater-state` 默认 `$STATE_DIRECTORY`、`-update-target` 默认自身、`-update-service`）：flock；agent 目录全是不可信输入——逐级 `O_NOFOLLOW` 打开、只收属主 = agent 的单链接普通文件、请求先 unlink 再读（path 单元不会循环）；用**自己**编译进的公钥 + `release.Policy` + 自己的 `updater.json`（rolled_back、trial）重验；先把 staged 拷进 `/usr/local/bin/.akari-agent.new`（root 0700）再校验**副本**的大小/SHA-256（TOCTOU）→ **W23**：对校验过的副本执行 `-print-units`（30s、空环境、输出有界）取新版本单元（读不到 = 拒绝）→ 替换单元目录（`-unit-dir`，默认 `/etc/systemd/system`）中**已存在且不同**的三个单元（原子写、root 0644；被替换的存 `<updater state>/units.prev/`，trial 记 `units`；`daemon-reload`；EROFS = W23 前的更新器单元沙箱不可写 → 只装二进制、WARN `systemd units NOT refreshed`）→ 硬链接保留 `.prev` → rename 就位 → 写 result → `systemctl restart` → 监看：`confirmed` = 通过；`NRestarts` 增量 ≥ `-update-max-boots` / 超时（自检 + 1min）/ agent 的 rollback 请求 → 单元从 `units.prev/` 放回并 reload、`.prev` 放回、记 rolled_back、result rolled_back、再重启（后续进程的回滚请求同样恢复单元）。result 以 O_EXCL|O_NOFOLLOW 临时名创建、fchown 给 agent、renameat。`updater_other.go`：非 Linux 报错 |
| `update_agent.go` | M6 自更新（会话侧）：`UpdateOffer` → 更新器单元存在？→ 用**编译进来的**公钥验签 + `release.Policy`（平台、单调版本/签名 rollback、已回滚版本、min_panel_protocol）→ 失败回 `REJECTED`；接受后单任务后台经同一 mTLS 连接 `FetchArtifact` 下载（断点续传，6 次退避），校验大小+SHA-256 → rename 为 `staged` → 持 `applyMu` 且流仍活：拆 xray、持有版本 (0,0)、最终计数入队并落盘、发 `RESTARTING` 并 `flushStream` → 写 apply 请求、等更新器裁决（`applyWait` 90s；等待随流或进程 `procCtx` 结束而结束——gracefulStop 需要 applyMu）：installed → 等更新器重启（`restartWait` 1min 后自行 exit(1)，磁盘上已是新版本）；rejected/无人接单 → 回 FAILED 并重发 Hello。试用期：Snapshot/Delta ok Ack 后 `confirmTrialLocked`（写 `confirmed`、发 `CONFIRMED`）；`trialLoop` 超时写 rollback 请求（更新器只回滚自己记录中仍在试用的版本；覆盖无人监看的情况，如重启后）。待发 report 在每条新流 Hello 后发送 |
| `release/` | 可导入包：manifest（schema 1，严格解码）、Ed25519 签名（上下文前缀 `akari-agent-manifest-v1\n`，key id = SHA-256(pub)[:8]）、`ParseKeys`、`Policy`、semver 比较；面板 `updates.rs` 实现同一规则，向量 `proto/update_vector.json` |
| `cmd/thirdparty` | R19 许可清单生成器（仅标准库）：`go list -deps`（linux amd64+arm64，即 dist 平台）得链接模块 → 模块缓存里的 LICENSE/COPYING/NOTICE/PATENTS 原文 → 按特征短语分类（copyleft 先判；纯 GPL 全文不判 or-later，须人工）→ 白名单（MIT/ISC/BSD-2/3/Apache-2.0/MPL-2.0/GPL-3.0-or-later/LGPL-3.0 链接例外），未识别或不在白名单 = 失败；输出确定性（排序、相同文本去重、无日期） |
| `THIRD_PARTY_LICENSES.txt` / `LICENSES/GPL-3.0.txt` | 生成的许可清单（`go:embed` 进 `main.go`，`-licenses` 原样打印）/ GPL-3.0 原文（gnu.org，sha256 3972dc97…）；有 GPL 模块链接时自动写入组合作品声明 |
| `cmd/akari-sign` | 离线签名工具：keygen/pubkey/sign/countersign/verify（`-key` 或 `-key-env`） |
| `release-keys.txt` / `releasekeys*.go` | 生产固定公钥集（go:embed；生产密钥 `key-f2ad18a8bb718a1a`，自 v0.2.0 起固定；私钥仅存负责人机器 `~/secrets/akari-release-signing.key`(0600) + 仓库 secret `AKARI_RELEASE_SIGNING_KEY`；轮换 = 新公钥并列固定 + `akari-sign countersign` 双签，全网升级后删旧钥）；`akari_testkeys` 构建标签额外加入**公开的**测试公钥（`testdata/TEST-ONLY-release.*`，仅 smoke），`make dist` 的 `check-release-keys` 拒绝含测试公钥的二进制 |
| `proto/agent.proto` | **vendor 副本**，禁止手改，只能 `make sync-proto`（worktree 中 `make sync-proto PANEL_DIR=../<面板 worktree>`） |
| `proto/state_hash_vectors.json` | 面板正本的副本（共享测试向量） |
| `proto/update_vector.json` | 面板正本的副本（M6 签名 manifest 共享向量，`release` 测试读取） |
| `proto/gate.proto` | agent 内部（非契约、不同步）：gate 的 xray app 配置消息类型 |
| `acme_test.go` / `acme_pebble_test.go` | W10：进程内 pebble（Let's Encrypt 测试 CA）+ miekg/dns 小 DNS（pebble VA 用 TCP 查询）：HTTP-01、80 为入站时 TLS-ALPN-01、端口全占、DNS/连接错误分类与退避（交替挑战）、续期（`now` 接缝）、重启保留证书与账户、Snapshot 胶水（占位证书即可构建、无 acme 时仍读凭据路径）、换 handler 失败 → (0,0) |
| `acme_canary_test.go` | W10 金丝雀（canary 标签，不带 -race：xray 证书重读 goroutine 无锁写 GetCertificate 读的槽位，上游数据竞争）：VLESS-WS-TLS、Trojan-TLS、Hysteria2 真实 xray 客户端只信任 pebble 根；首证换 handler 时另一入站的连接存活；续期后（`ocspStapling:1` 让 xray 每秒重读，生产默认 1 小时，同一代码路径）新握手拿到新序列号、所有既有连接存活、未重建 |
| `rt_canary_test.go` | red team 撤权金丝雀（Vision/splice over TLS、trojan、vmess、mux），`make test-canary` |
| `rt_matrix_test.go` | W8 协议矩阵金丝雀（canary 标签）：17 种 协议×传输×安全 组合各用 xray 真实客户端握手、中继、断言用户计数、撤权后旧连接断开且新连接被拒（全部经 delta，SS2022 为墓碑）；W9：移除→同凭据重加（先带限速、再不限速）后**同一个客户端**能再连上（限速 ±5%/不限速），再次移除再被切断 |
| `ss_tombstone_test.go` | W9 SS2022 墓碑（`-race`）：真实 SS2022 握手（sing-shadowsocks 客户端）在固定头之后拖住（服务端已解析出用户下标），期间 delta 移除部分用户 → 被删用户的握手被拒、其余用户以本人身份完成、已建立连接存活、每用户计数精确（无错记）、不重建；同凭据重加复活墓碑；并发版：随机拖延的握手 vs 反复移除/重加。换回 xray `RemoveUser` 时该测试以 index out of range panic 失败 |
| `protocols_test.go` | SS2022 受管入站/拒绝项、`WouldShrinkUnsafe`（含墓碑生命周期、state hash 不含墓碑、Snapshot 压缩）、`TestTombstoneBound`、账号校验、gRPC 无 :authority 请求不致崩溃（R26 回归） |
| `fuzz_test.go` / `release/fuzz_test.go` | W13 原生 Go fuzz（种子随 `make test` 当普通测试跑；`make fuzz FUZZTIME=…` 逐个探索，CI `fuzz.yml`：PR 每目标 15s、夜间 5m，语料存 Actions 缓存；新崩溃输入落在 `testdata/fuzz/<Target>/`，修复时一并提交作回归种子）：`FuzzBuildConfig`（面板下发的 inbounds → `buildConfig`；不变量：xray 视为带 `clients` 的 SS 入站绝不留作单用户服务端）、`FuzzRewriteCertPaths`（只改两条证书路径，数字精度/其他成员不变）、`FuzzBuildUser`、`FuzzInboundTCPPorts`、`FuzzACMEConfig`（域名可安全作目录名）、`FuzzProcParsers`、`FuzzStateHash`（编码无歧义、与顺序无关）、`FuzzLoadConfig`；release：`FuzzParseManifest`、`FuzzCompareVersions`（与独立 semver 参考实现差分）、`FuzzVerify`、`FuzzParseKeys` |
| `fuzz_regress_test.go` | W13 fuzz 发现的回归测试（SS2022 键匹配、证书路径重写无损、/proc 解析拒绝/饱和；release 包的超长数字预发布标识在 `release_test.go`） |
| `gate_unit_test.go` | gate 记账（轮换只断该 key 的活连接、Close、拒绝不触达内层 dispatcher）与限速边界（饱和、包装器错误透传）的单元测试 |
| `scripts/cover-gate.sh` | `make cover`：`go test -tags canary -coverprofile` 后按文件统计 gate.go/ratelimit.go/core.go 语句覆盖率，低于 `COVER_MIN`（85）失败；CI job `coverage` |
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
make sync-proto   # 从 ../akari-panel 拷贝契约并 buf generate（worktree：PANEL_DIR=../<面板 worktree>）
make check-proto  # 契约漂移校验（同上 PANEL_DIR）
make sync-units   # W23：把 systemd/ 的单元正本拷到面板 deploy/systemd/（PANEL_DIR=…）
make check-units  # 面板副本与正本逐字节相同（CI proto job）
make systemd-test # 真 systemd 257 容器：旧单元下指标未知 + 旧更新器单元不刷新单元、重装后指标全可读、单元随更新安装/随回滚恢复、恶意请求（WORK=<dir> 指定临时目录）
./agent -print-unit akari-agent.service   # 本版本自带的单元
make fuzz FUZZTIME=10m   # 每个 fuzz 目标依次探索（默认 30s）
make cover        # 核心文件覆盖率门（gate/ratelimit/core ≥ 85%）
make bench        # 开销基准（bench_test.go；-run '^$' 只跑基准）
make build-testkeys VERSION=v900.0.0 OUT=/tmp/a   # 仅测试：额外信任测试公钥（smoke 用）
make sign-manifest VERSION=vX.Y.Z KEY=<file>|KEY_ENV=<var>   # dist/*.manifest.{json,sig}
./agent -release-keys   # 列出固定公钥
make third-party        # 重新生成 THIRD_PARTY_LICENSES.txt（改 go.mod 后）
make check-third-party  # CI：清单是否最新
./agent -licenses       # 本二进制的许可声明 + 全部第三方许可原文
```

## 契约变更的合并顺序（面板先行）

`proto/agent.proto` 的正本在面板。改契约（新字段/消息/能力）时：

1. 面板 PR 改 `proto/agent.proto` + 面板代码；面板 CI 的 smoke 跑 agent main：依赖新 agent 能力的段落按 `Hello.protocol_version`/`capabilities` 判定后**大声 SKIP**（`SKIP: agent lacks …`），面板侧断言照常执行。
2. agent PR：`make sync-proto PANEL_DIR=../<面板 worktree>` + 实现；此时 agent CI 的 `check-proto (vs akari-panel main)` **预期失败**（面板 main 还没有新契约）。
3. 联调：在面板仓库手动触发 ci（`workflow_dispatch`，`agent_ref=<agent 分支>`），strict 模式下任何 SKIP 都是失败 → 新功能全量验证。
4. **先合面板 PR**，再重跑 agent PR 的 CI（check-proto 变绿）后合并 agent。之后面板 main 的 smoke（push/nightly）自动对新 agent 跑满该段。
5. 新能力：bump `agentProtocol`（行为语义变化）或在 `agentCapabilities` 加一项（可选特性）；面板 smoke 用它判定，且 smoke 会核对 agent 源码声明的协议号/能力与面板 API 所见一致（不一致 = 失败，SKIP 不能掩盖回归）。

## 发布

tag `v*` 触发 `.github/workflows/release.yml`：fmt-check/vet/check-third-party/test → `make dist`（含 `check-release-keys`，附 `THIRD_PARTY_LICENSES.txt`；校验 `-licenses` 与其一致）→ 自更新 manifest 签名（仅当仓库 secret `AKARI_RELEASE_SIGNING_KEY` 存在，否则 warning 跳过；签后用 `release-keys.txt` 复验）→ CycloneDX SBOM → SHA256SUMS → cosign 无密钥签名（GitHub OIDC，`*.sigstore.json`）→ GitHub Release（发布说明开头是 R19 许可声明，`THIRD_PARTY_LICENSES.txt` 作为资产并入 SHA256SUMS 与 cosign 签名）。第三方 action 固定 commit SHA。验证方法见 `akari-panel/docs/DEPLOY.md`。systemd 单元正本在本仓库 `systemd/`（`akari-agent.service` + W18 更新器 `akari-agent-update.{path,service}`），编进二进制（W23）；面板 `deploy/systemd/` 是 `make check-units` 校验的副本。

## 须知

- xray 动态用户链路：`inbound.Manager.GetHandler(tag)` → 断言 `GetInbound()` → 协议 inbound 的 `AddUser/RemoveUser`。新协议需要 blank-import 对应 inbound 包、在 `protocols.go` 的 `inboundKinds` 与 `buildUser` 加分支，并在 `rt_matrix_test.go` 加一行。
- **受管协议（W8）**：vless/vmess/trojan/shadowsocks（仅 2022-blake3-aes-128/256-gcm 多用户；chacha 无多用户服务端）/hysteria（Hysteria 2）。另：xray 的多用户 SS AddUser 忽略用户表更新错误，一个坏密钥会冻结整张表，所以密钥在 AddUser 前严格校验。
- **SS2022 墓碑不变量（W9，协议 5）**：xray `MultiUserInbound.RemoveUser` 交换删除切片，而连接路径在客户端可拖延的握手之后无锁读 `users[index]` → 被删用户的在途握手会以别的用户身份运行（gate 放行、计费错人）或越界 panic 整个 agent。所以对 SS2022 tag **永不调用 RemoveUser**（`applyOpLocked`/`addUserLocked` 都跳过）：移除 = 只在 gate 撤销 + 凭据留在 xray 表里当墓碑，下标永不移动，在途/新握手解析到被删用户**自己的** `*MemoryUser`，gate 拒绝。同凭据重加 = 复活墓碑（gate 重新放行同一指针，不碰 xray）。xray AddUser 拒绝重复 email，所以对表里已有的用户换凭据（轮换、换新密钥重加）不能原地做 → `WouldShrinkUnsafe` 返回 true → `BASE_MISMATCH` → 面板发 Snapshot（重建即压缩）。墓碑上限 `maxTombstones` = max(`tombstoneFloor`=1024, live)：会超限的移除同样 `BASE_MISMATCH`（这就是给面板的压缩信号，无需新消息）。墓碑**不算 applied**：不进 state hash、不进 UserCount；计数器照常（尾部流量）。注意：xray SS 的 AddUser（追加）与握手路径之间本身有数据竞争（无锁读切片头/`uPSKHash`），与墓碑无关，只在新增用户时出现，属上游问题。
- **同凭据重加复用指针（W9，Hysteria2 修复）**：xray 的 Hysteria 2 每条 QUIC 连接只认证一次（`httpHandler.user` 缓存），其后所有流都带那次握手的 `*MemoryUser`；gate 撤权只断分发，不关 QUIC 连接，客户端保留连接。以前重加时新建 `*MemoryUser` → 该客户端所有新流都被 gate 拒（指针不等）→ 在重建前一直连不上（套餐到期→续费的真实案例）。现在 `issued` 记住本实例每 (tag, 用户) 最后装过的凭据，协议+account 完全相同则复用原指针（同一主体，安全）；凭据不同（轮换）才新建指针，旧会话照旧被拒。实例重建时清空。
- **不开每入站统计**：`policy.system.statsInbound*` 已去掉（无人读取）。开启时 proxyman 用 `stat.CounterConnection` 包装连接，xray 的 Hysteria 入站以 `conn.(interface{ User() })` 取用户会失败 → 所有 Hysteria 客户端匿名运行：不计费、gate 不能撤权（W8 矩阵金丝雀发现）。勿恢复。
- 每个 Snapshot 都会 `Rebuild`（关停并重建 xray 实例 → **断开节点上所有连接**；旧实例最终计数会先入队上报）。面板在只有用户集变化时发 `UserDelta`，不重建。
- **UserDelta**：持有 == base 才应用；持有 == target（且不 dirty）→ ok no-op；否则 `BASE_MISMATCH`，不改任何东西。delta 的 config_version 必须等于 base。部分失败：保持 base 版本、置 `dirty`（之后的 delta 一律 `BASE_MISMATCH` 直到 Snapshot），state hash 反映实际生效内容。
- **REPLACE 语义**：ADD 后用户恰好在列出的 inbound 上；未列出或凭据变化的 tag 先在 gate 撤销（断活连接）再从 validator 删除（SS2022 tag 除外：留作墓碑），所有 inbound 都清一遍；完全相同的凭据不动（连接保留）。被移除/凭据变化的用户在 Ack 前上报最终计数（当前 session）。
- **gate 是撤权的关键**：validator 的 RemoveUser 只挡新握手，已认证连接与 mux 新子流都会继续跑。gate 按 `*MemoryUser` 指针准入并跟踪分发（`Dispatch` 走自己的 pipe + 后台 `DispatchLink`，relay 结束即释放条目）。gate 通过 `proto/gate.proto` 的配置类型注册成 xray app，在 app 列表里原位替换 `dispatcher.Config`（vless 在创建时就 `GetFeature(Dispatcher)`，不能事后替换）。已知旁路：VLESS reverse（Rvs 命令）不经 dispatcher，面板生成的账号不含 reverse。
- **单元随版本走（W23，勿推翻）**：单元只来自已验签的二进制（`-print-units`），绝不来自 agent 可写目录；更新器只替换三个已知名字、只替换已存在的文件，drop-in 不动（本地修改放 drop-in）。W23 之前的更新器单元（`ProtectSystem=strict`，未放行 `/etc/systemd/system`）无法刷新单元：第一次升到 W23 版本后需在节点上执行一次重装命令（面板依 `stale-units` 提示）；这一步绕不开（写入被旧单元自身的沙箱禁止）。agent 单元**不得**再加 `ProcSubset=pid`（隐藏 /proc/stat、meminfo、loadavg、net/*，机器状态全为 0）；`ProtectProc=invisible` 保留。
- **W^X（W18，勿推翻）**：state dir 在 systemd ≥256 下 noexec（DynamicUser idmapped 挂载），这是需求：**不要**给 agent 单元加 ExecPaths 或在 state dir 执行任何东西。自更新只经特权更新器安装到 `/usr/local/bin`。v0.3.0/v0.4.0 的 exec 启动器在这类主机上 `permission denied`，需在节点上运行一次重装命令。复现：容器里 `--tmpfs /var/lib/private`（overlayfs 不能 idmap，不会 noexec）。
- **升级 xray-core 的前提**：所有按协议的撤权金丝雀（`make test-canary` + `-race` 套件里的 vless/rotation/dispatch-path 测试）全绿才能升级；gate 依赖 xray 内部（app 槽位替换、Dispatch/DispatchLink 语义）。
- **无用户的 inbound**（dokodemo/socks/http 不带 clients）：分发上下文没有 user，gate 直接放行、不计费、不能撤权。面板只给受管协议发凭据；这类 inbound 若由管理员配置，等同于开放代理，自负其责。面板拒绝 fakedns（gate 内部的 DefaultDispatcher 没有接 FakeDNS 引擎）；agent 在 xray 自己解析（`jsonConfig.Build()`）之后由 `refuseFakeDNS` 再查一次 `SniffingSettings.DestinationOverride`，含 fakedns → Rebuild 失败（APPLY_FAILED），这是权威检查，面板的 JSON 检查只是提前报错。
- **remove mode（R10 回退开关）**：`LeaseGrant.remove_mode` = REBUILD 时，会删除/轮换活凭据的 delta 一律 `BASE_MISMATCH`（不做任何改动），由面板改发 Snapshot（整体重建）；纯新增仍走 delta。只接受当前流 grant 设置。
- **xray 计数器**：v26.3.27 中 RemoveUser/AddUser 不会注销或重置 `user>>>…` 计数器（没有任何调用 `UnregisterCounter`），同实例内重新添加后累计值连续；agent 持有装用户时解析出的计数器指针（W1，`monoCounter` 已删除；若将来 xray 会重置计数，正确做法是换 session id，`TestCountersSurviveRemoveAndReAdd` 校验读到的就是 xray 计数的那个计数器）。被移除用户的计数在本 session 内继续上报（尾部流量不丢）。
- session id 归 `CoreManager` 所有，只在 `Rebuild`/`Teardown` 内持锁更换；`TrafficSnapshot` 在同一把锁下返回 (session, 计数)，每个 `TrafficReport` 都带 `session_id`（面板按它记账）。最终计数进 `finalQueue`：每条新流 Hello 后重发，直到某条流发出后又存活 `finalsConfirmAfter`（60s，> keepalive 判死 30s+10s：写入死 socket 也"成功"）（面板记账幂等，重发安全）。**优雅停机（A29）**：SIGTERM → 会话 goroutine 在**仍存活的流**上 `gracefulStop`（Teardown → 最终计数入队并发送 → 有界 flush `shutdownFlush`=5s，期间不再应用面板消息）→ `Run` 返回前 `stopped()` 把未确认队列持久化到 state dir 的 `finals.json`（`finalsStore`，与自更新器无关；自更新重启同用）；下个进程启动时载入并先于其他消息重发，队列排空后删文件。
- **F3**：`session()` 返回前 join 所有子 goroutine（读协程可能正在 Rebuild）→ 任意时刻至多一个 handleDown；`handleDown` 持 `applyMu`，先查流 ctx，流已死则不 Rebuild、不改版本、不发送（Rebuild 期间流死 → 置 dirty）。
- **租约**：首次收到 `LeaseGrant` 才武装（旧面板永不武装）；只接受当前流的 grant；到期（`checkLease`，5s 一次）拆 xray、最终计数入队、持有版本归 (0,0)；若流仍在（面板活着但 DB 挂了）立即发 Hello (0,0)。
- state hash v2 绑定 inbounds：`CoreManager.inboundsJSON` = 当前实例 Snapshot 的 inbounds_json 原文（无实例时为 ""）。
- **能力（W11）**：`Hello.capabilities` = `agentCapabilities`（`metrics`、`latency`、W18 `updater`、W23 `metrics-presence`；单元过期时另加状态标志 `stale-units`，`Agent.capabilities`），与协议号无关（不 bump `agentProtocol`）；`PanelDown.latency_probe` 只更新 prober 设置（不持 applyMu 做网络 I/O，不回 Ack）；旧面板不发，prober 用默认值照常测、结果在 Hello 后发出（旧面板忽略未知消息）。
- Hello 带 `protocol_version`（常量 `agentProtocol`，当前 6 = 自动节点证书（`ConfigSnapshot.acme` / `Heartbeat.cert`，W10）；5 = SS2022 移除走墓碑（面板对 SS 节点的移除改发 delta）；4 = 每用户限速；3 = 自更新；2 = 会续期证书）与 state hash；Ack 带 reason、处理后持有版本、state hash。
- **限速（W7，`ratelimit.go`）**：`applyOpLocked` 在安装凭据**之前**设置用户限速（REMOVE / 未装上任何凭据 → 清除），所以新凭据不会先放进一个未受限的连接；限速不进 state hash（与凭据同属持有版本，设置本身不会失败）。xray v26.3.27 没有按用户限速的能力（policy 只有 buffer/超时），所以在 gate 里做；升级 xray 时 `make test-canary` 里的 `TestRT_VisionSpeedLimit` 、`TestRT_MuxSpeedLimit`（mux 子流共享预算）、`TestRT_UDPSpeedLimit`（VLESS UDP）与 `TestRT_ProtocolMatrix`（每个协议：只改限速的 delta 切断未受限的转发，新连接经真实客户端按限速 ±5% 双向回显）必须仍然通过。
- **身份（M1c）**：私钥只在节点生成、永不出节点、不进日志；token 也不进日志（只存其 SHA-256 作“已用”标记）。连接时先用待确认的 next 身份（失败为暂时性则下次用当前身份，交替），收到面板第一条消息即提升为 `identity.pem`。面板在新证书首次出现前一直接受旧证书，所以接收后、持久化前崩溃都无害。当前证书过期时每次连接都打错误日志（需 `akari node enroll-token` 发新 token 重新注册）。
- **GO-2026-6443（更正，R26）**：`refuseGRPCTransport` 已删除，gRPC 传输恢复。grpc-go 钉在上游修复提交 `v1.85.0-dev.0.20260825072537-93e31b48545e`（v1.85.0 发布后改用 tag）；`VULN_ALLOW` 为空且空列表 fail closed。该公告实为 xDS 服务端路径，xray 普通 gRPC 服务端不受影响（`TestGRPCMissingAuthorityDoesNotPanic` 在旧版本上同样通过）。
- 应用失败（Snapshot 的 `Rebuild` 或 Delta 返回错误）时**不**更新持有版本：Hello 继续报旧版本，Ack 携带**尝试的**版本、`ok=false`、reason `APPLY_FAILED`，面板据此记录 `last_error` 并按退避重试。
- **W13 fuzz 发现（已修）**：①`multiUserShadowsocks` 曾用"精确键优先"的 map 查找取 tag/settings，而 xray 按 Go struct 语义（大小写不敏感、**最后一个**同名成员胜出）读取：`{"tag":"a","TAG":"b",...}` 的 SS2022 入站在 xray 里叫 "b"，却按 "a" 判定 → "b" 留作**单用户**服务端（共享 PSK、无用户身份、gate 无法撤权）。现用与 xray 相同的 struct 解码（`inboundJSON`）。②`rewriteCertPaths` 经 `map[string]any` 重编码把 > 2^53 的整数改成 float64 近似值；现 `UseNumber`，且路径上的对象若有大小写折叠后同名的键则拒绝（重编码会改变 xray 取哪一个）。③`release.cmpIdent` 把超出 uint64 的数字预发布标识当字母串比较（与 semver 和面板 `updates.rs` 不一致：面板认为更新的版本 agent 可能视为降级）；现按长度+字典序比较数字标识。④`parseLoadavg` 接受 NaN/Inf/负数，kB 换算与 MemFree+Buffers+Cached 求和可回绕；现拒绝/饱和。
