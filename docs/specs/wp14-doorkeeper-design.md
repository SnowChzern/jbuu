# 锦书 [jbuu][WP-14] 门卫 doorkeeper 设计书（SSH 过渡兼容垫）

| 项 | 内容 |
|---|---|
| 任务 | 论坛任务 #49 · [jbuu][WP-14] 锦书门卫 doorkeeper 设计书（SSH 过渡兼容垫） |
| 设计依据 | 任务卡 #49 内芥末拍板版方案定案（五条已定决策，本文不得偏离）；RFC 4253 §4.2（协议版本交换前置文本行机制）；项目更名通知（论坛 #82：新工作包用 [jbuu] 前缀，二进制名 jbuu）；otp-term workspace 现状（Cargo.toml 依赖基线：无任何异步运行时） |
| 作者 | 斗拱（designer） |
| 状态 | 待评审；评审冻结后据此开实现卡（本文不含实现代码） |
| 范围内 | ①并发模型选型 ②警告行字节级规格 ③客户端兼容矩阵与降级策略 ④资源与健壮性 ⑤进程形态与 systemd ⑥部署 runbook 草案 ⑦测试清单——任务卡要求的全部七项 |
| 范围外 | 实现代码与测试代码（评审通过后另开实现卡）；锦书协议本体（WP-12 transport 等）；sshd 自身配置除"收缩到回环+Banner 可见性互补"外的行为 |
| 修订 | v1.0（本次，任务 #49）：初版。§0 含本机实证记录（OpenSSH 10.0p2 真机透传实测） |

> **编号说明**：本文 WP-14 属 [jbuu] 新系列编号，与 otp-term 实现规划书旧 WP-14（重放/乱序/截断代理与 fuzz）无关，勿混淆。

---

## ⚠️ 安全边界声明（任务卡已定决策 5，评审与实现不得弱化）

**门卫不增强 SSH 会话安全。门卫模式下，SSH 会话的安全上限 = SSH 自身（host key + 用户密钥 + SSH 加密）。**

门卫的全部价值 = 三件事：**暴露面收缩**（公网只能到达门卫，sshd 仅回环可达）+ **迁移期兼容**（存量 SSH 链路不断）+ **可观测性**（连接日志 = 迁移仪表盘数据源）。

推论（实现与运维约束）：

- 门卫**不得**宣称或暗示提供任何认证、加密、防重放能力；README/帮助文本首段必须复述本声明。
- 门卫**不得**做任何 SSH 协议解析与判定（唯一例外：§3.5 客户端版本串**旁路观察**，只看不改不拦，系任务卡已定决策 4 所需）。
- 门卫**不得**成为长期组件：出生即带日落条件（§7.7），过期退役。

---

## 0. 本机实证记录（设计输入之一，2026-09-13，OpenSSH_10.0p2 Debian-7+deb13u2）

设计前用 Python 原型（`workspace/doorkeeper_proto.py`，一次性验证工具，**不入仓、非交付物**）在本机对真 sshd（127.0.0.1:22）做了机制实测，原始回显存 `workspace/evidence-wp14-doorkeeper-proto.log`：

| # | 实测项 | 结果 | 对设计的影响 |
|---|---|---|---|
| E1 | OpenSSH 10.0 客户端经垫片（警告行+双向 pipe）连真 sshd | 完整走通版本交换→KEX→认证（`Permission denied (publickey,password)` 系真实 sshd 应答，证明整条协议路径无损） | 机制成立，定案 1 可行 |
| E2 | 警告行（101B UTF-8，CRLF 结尾）在客户端默认输出 | **默认不可见，仅 `-v` 下以 `debug1: kex_exchange_identification: banner line 0: ...` 显示**（UTF-8 八进制转义形式） | ⚠️ 对定案 1 的事实勘误：OpenSSH 客户端是"忽略（debug 级可见）"而非"显示并忽略"。机制不受影响，但**可见性弱于任务卡预期**，处置见 §3.6 与 §7.4 |
| E3 | 30 并发连接，逐连接字节级校验 | 30/30 收到逐字节精确的警告行（md5 `aecf98908984d17e97343cafb25dfa59`）；超额连接收到 sshd 预版本行 `Not allowed at this time\r\n` | ①sshd `MaxStartups`（默认 10:30:100）本来就用预版本行拒流——**服务端预版本行是生态既有常态**，进一步佐证机制安全性；②门卫并发上限须与 MaxStartups 联动（§5.1） |
| E4 | 上游不可达（指向死端口） | 5s 连接超时内关闭，客户端侧表现为 connection reset | §5.3 上游故障路径规格 |
| E5 | 双栈监听 `[::]:port` + `IPV6_V6ONLY=0` | IPv4-mapped 连接正常接入（日志见 `::ffff:127.0.0.1`） | §1.2 单套接字双栈方案 |
| E6 | 原型日志多线程交错写 | 出现 `[proto] close close` 等交错行——多线程日志**必须**单次 write 原子落盘 | §5.5 日志原子性规格（实证教训直接入规格） |

---

## 1. 总体形态与部署拓扑

### 1.1 拓扑（目标态）

```
公网客户端 ──TCP──> [::]:22  doorkeeper（jbuu-doorkeeper 进程）
                        │ accept → 写警告行 → connect 上游
                        ▼
                  127.0.0.1:2222  sshd（ListenAddress 仅回环，改用高位端口）
```

### 1.2 端口与地址裁决（含一个必须避开的陷阱）

- **陷阱**：若 sshd 仅收缩为 `ListenAddress 127.0.0.1` 且仍用 22 端口，则 doorkeeper 的 `[::]:22`（或 `0.0.0.0:22`）**绑定必然失败**（EADDRINUSE：0.0.0.0/[::] 双栈套接字覆盖 127.0.0.1）。定案 3 的"收缩到 127.0.0.1"必须连带**端口迁移**。
- **裁决（D10）**：sshd 收缩为两条显式监听：`ListenAddress 127.0.0.1:2222` 与 `ListenAddress [::1]:2222`（sshd_config 语法支持 address:port 逐条指定；原有 `Port`/无端口的 `ListenAddress` 行全部注释，避免 sshd 的 Port×ListenAddress 组合语义再生旁支绑定）。doorkeeper 默认 `--upstream 127.0.0.1:2222`。
- doorkeeper 默认监听 `[::]:22` 并在代码内显式设置 `IPV6_V6ONLY=0`（不依赖 sysctl `net.ipv6.bindv6only`），单套接字同时服务 IPv4 与 IPv6（E5 实证）；若部署环境禁用 IPv6，退回 `0.0.0.0:22` 并在 runbook 中同步处理 DNS AAAA 记录（§7.5 步骤 8）。
- doorkeeper 上游连接采用顺序尝试 `127.0.0.1:2222` → `[::1]:2222`（本地回环，无需并行竞速）。

### 1.3 数据面行为总述（一句话规格）

accept → 向客户端写一行警告（可选关闭）→ 连接上游（5s 超时）→ 双向原样 pipe（各方向独立线程、16 KiB 缓冲、半关闭传播）→ 任一方向 EOF/错误后按 §5.4 收尾。全程不改写、不缓存判定、不注入任何字节（警告行除外）。

---

## 2. ① 转发实现选型：OS 线程每连接 + std::net（D1）

### 2.1 候选对比

| 方案 | 说明 | 优点 | 缺点 | 判定 |
|---|---|---|---|---|
| A. thread-per-conn（std::net） | accept 线程 + 每连接 2 个 OS 线程（每方向一个，`try_clone` 句柄） | 零新依赖；代码量最小；阻塞语义天然承载 TCP 背压；与栈内既有同步 I/O 风格（rustix/同步文件 I/O）一致 | 每连接 2 线程；极端并发受线程数约束 | **采纳** |
| B. tokio 异步 | 单（或多）线程 runtime，任务每连接 | 万级并发友好 | 引入 tokio+mio 大依赖树（当前 workspace **零异步依赖**，Cargo.toml 佐证）；"几百行/攻击面=仅此文件"的定案 2 直接破产；过渡垫不配此复杂度 | 否决 |
| C. 手写 epoll（rustix） | 自管事件循环 | 无依赖且省线程 | 自制 runtime 正是 bug 温床；几百行预算内做不完正确性（半关闭/错误分类/背压交互） | 否决 |
| D. 复用锦书栈 runtime | 挂到 jbuu 主进程或共享 transport 层 | 部署面合一 | 锦书栈目前无 runtime 可复用（同步栈）；进程耦合扩大爆炸半径：门卫崩溃/重启域 ≠ 锦书主进程；与 §6 独立进程裁决冲突 | 否决（不可行） |

### 2.2 容量论证（A 方案是否够用）

- 负载剖面：迁移期 SSH 并发 = 存量运维/自动化链路，单机量级典型 < 100 并发（E3 中 30 并发已属压测形态）。
- 资源核算：上限 128 并发（§5.1，D8）→ ≤ 256 线程 + 每连接 2×16 KiB 用户态缓冲 + 2 fd/连接 ≈ 4 MiB 缓冲 + ~300 fd，对任何目标主机均为噪声级。
- 线程栈：实现时以 `Builder::new().stack_size(256 KiB)` 显式设定（pipe 线程调用深度浅，256 KiB 充裕），虚拟内存占用可控。
- 结论：thread-per-conn 在目标负载与资源预算内无短板；并发数不是本组件的风险项，**fd 泄漏与线程清理**才是（§8 测试 9/12 覆盖）。

### 2.3 依赖预算（定案 2"攻击面=仅此文件"的落法）

- 生产依赖仅 `std` + `clap`（workspace 已有基线依赖，derive 解析 CLI）；**禁止**引入：任何异步 runtime、任何 SSH 协议 crate、任何 otp-* 内部 crate（门卫不得链接锦书协议代码——耦合即攻击面）。
- 模块视图（实现卡的建议骨架，目标总量 ≤ ~700 行含错误处理，与"几百行"定案相符）：

```
crates/otp-doorkeeper/
  src/main.rs    # CLI/clap、配置校验、监听生命周期、SIGHUP/信号处理
  src/proxy.rs   # accept 循环、连接计数、每连接双向 pipe + 半关闭
  src/warn.rs    # 警告行常量与配置校验（§3 全部不变式）
  src/obs.rs     # 客户端版本串旁路观察器（§3.5，无状态扫描窗）
  src/log.rs     # JSONL 追加写、单 write 原子性、SIGHUP reopen
```

- 命名：crate 名暂用 `otp-doorkeeper`（仓库命名空间改名未执行，跟随 #82"统一改名另发通知"一波处理）；**二进制名即 `jbuu-doorkeeper`**（新工作包已定 jbuu 前缀，用户可见名一步到位）。

---

## 3. ② 警告行字节级规格

### 3.1 默认警告行（冻结，golden）

```
NOTICE: SSH endpoint deprecated, migrating to jbuu (锦书). 本通道仅过渡，请迁移 jbuu。\r\n
```

- 长度 **101 字节**（含 CRLF；实测 md5 `aecf98908984d17e97343cafb25dfa59`，完整 hex 见 §3.2 表下）。
- 结构 = ASCII 主干（保证在剥蚀终端/仅 ASCII 通道上仍可读）+ 任务卡要求的中文短语「本通道仅过渡，请迁移 jbuu」+ 协议名「锦书」。UTF-8 编码（RFC 4253 §4.2：前置行 SHOULD be ISO-10646 UTF-8）。

### 3.2 字节级不变式（MUST，配置自定义行时同样强制）

| # | 不变式 | 依据 |
|---|---|---|
| W1 | 行以 `\r\n`（0x0D 0x0A）结尾 | RFC 4253 §4.2 "Each line SHOULD be terminated by a CRLF"；OpenSSH 10.0 实测接受（E1）。CRLF 同时满足任务卡"以 \n 结尾"要求 |
| W2 | 行首 4 字节 ≠ `"SSH-"` | RFC 4253 §4.2 "Such lines MUST NOT begin with 'SSH-'"（任务卡点名规避项） |
| W3 | 单行，行内不得含 CR/LF/NUL 及 C0 控制符 | 前置行语义是"文本行"；控制符制造歧义解析面 |
| W4 | 总长（含 CRLF）≤ **200 字节** | 保守预算：已知 Go x/crypto/ssh 对版本交换前读入设有小预算（`maxVersionStringBytes` = 255B，含版本行本身），预算 = 255 − sshd 版本行(~30B) − 冗余；默认行 101B 满足。**实现期须以 §4 矩阵实测复核此预算** |
| W5 | UTF-8 有效编码 | RFC 4253 §4.2 SHOULD |
| W6 | 配置值语义：`--warn-line` 传入**不含终止符**的行内容，doorkeeper 自行追加 `\r\n`；启动时逐条校验 W1–W5，**任一不满足即拒绝启动并输出明确错误**（把误配挡在部署前，而非运行中） | 设计裁决 D4：消灭"忘 CRLF/超长/SSH- 前缀"整类事故 |

默认行完整 hex（101 字节，golden 向量，实现测试逐字节断言）：

```
4e4f544943453a2053534820656e64706f696e7420646570726563617465642c
206d6967726174696e6720746f206a6275752028e994a6e4b9a6292e20e69cac
e9809ae98193e4bb85e8bf87e6b8a1efbc8ce8afb7e8bf81e7a7bb206a627575
e380820d0a
```
（由 `workspace/verify_wp14.py` 程序化生成并复核——首 48 字节另经 §0 E3 真机探针独立核对；教训对齐 #31：golden 一律程序生成，禁手抄。）

### 3.3 发送时机（D3：accept 后立即，不预读客户端任何字节）

- 时序：`accept()` 返回 → 立即 `write(warn_bytes)` → 然后才发起上游连接 → 进入 pipe。
- 依据：RFC 4253 §4.2 "The server MAY send other lines of data **before sending the version string**"。服务端先行发送前置行合法且是生态常态（E3：sshd 自身的 `Not allowed at this time` 即此类行）。客户端的版本串在内核收包缓冲中等门卫进入 pipe 阶段后照常转发，TCP 全双工保证无死锁。
- 明确否决"延迟到读到客户端版本串再发"：那需要**先读后发**，引入对客户端节奏的依赖（慢客户端/不发版本串的扫描器会占住时序），且与"识别逻辑趋近于零"的定案 1 相悖。警告行的全部意义在"尽早、无条件"，发送前不读 = 零识别逻辑。

### 3.4 上游不可达提示行（D11，默认开启，`--failure-line off` 可关）

上游连接失败（连接拒绝/超时）时，在关闭客户端连接前补发一行：

```
NOTICE: upstream sshd unreachable via doorkeeper, try later\r\n
```

同样满足 W1–W5（30 字节）。理由：多一行诊断信息，对忽略前置行的客户端零影响（E4 实测客户端只报 reset），对显示前置行的客户端则把"门卫活着、sshd 死了"这一关键区分暴露出来。随后正常关闭连接并记 `conn_close{reason: upstream_unavailable}`。

### 3.5 客户端版本串旁路观察（定案 4 所需，唯一"看"数据面的地方）

- 目的：连接日志须含客户端版本串（迁移仪表盘数据源）。做法是**观察**不是解析：
  - 仅在 c2s 方向 pipe 循环内，对**首块数据**做一次行扫描：取首个以 `\n` 结尾且以 `SSH-` 开头的行记录原文（截断至 128B）；首块无完整行则看次块，累计扫描窗 **8 KiB**，超窗或未见即放弃（记 `version: null`），**绝不缓存、绝不等待、绝不改写**——扫描在转发同一循环内进行，转发零延迟零滞留。
  - 实测佐证：E1/E3 中 OpenSSH 客户端首块即含完整版本行 `SSH-2.0-OpenSSH_10.0p2 Debian-7-13u2\r\n`。
- 红线（评审检查项）：除该无状态扫描窗外，门卫对数据面字节**零知识**；crate 依赖清单（§2.3）从根上排除 SSH 协议库。

### 3.6 可见性勘误与互补通道（对定案 1 事实层的诚实修正）

- 实测（E2）：OpenSSH 客户端**默认不显示**前置行（RFC 允许"silently ignored"，OpenSSH 选择 debug 级显示）。任务卡表述"显示并忽略"与真机行为不符——机制与安全性不受影响，但"警告用户"的触达率低于预期。
- 处置（已写入 §7 runbook）：
  1. 警告行保留（零成本，对显示型客户端/PuTTY 类仍有触达）；
  2. **可见性主通道改用 sshd 自身 `Banner` 配置**（runbook 步骤 5）：`Banner /etc/ssh/jbuu-migration-banner.txt`，认证阶段由 OpenSSH 客户端在终端原生显示（sshd 行为，门卫零参与、零协议解析，不违定案 1）。
  3. 仪表盘（连接日志聚合，§5.5）承担自动化链路的"告知"：对无人看的会话，警告本就只能靠日志与下线日程触达。

---

## 4. ③ 客户端兼容矩阵与降级策略

### 4.1 矩阵（v1，标注证据等级；实现卡须把"待实测"行跑完回填）

| 客户端 | 对前置行的预期行为 | 证据等级 | 风险与备注 |
|---|---|---|---|
| OpenSSH ≥ 7.x（含 Windows Win32-OpenSSH，同源） | 忽略（`-v` 下 debug 显示），版本交换照常 | **实测**（E1/E2/E3，10.0p2） | 主流人群（运维/CI/git over ssh）；无兼容风险 |
| OpenSSH 老版本（≤6.x） | 同上（该行为自早期即有） | 文献预期，待实测 | 建议实现卡用容器内老 ssh 抽测 5.x/6.x |
| dropbear 客户端（嵌入式/路由器主力） | 跳过非 `SSH-` 行直至版本行 | 文献预期（代码行为），待实测 | 嵌入式设备升级困难，是降级开关的主要保护对象 |
| PuTTY | 事件日志记录，终端可能显示 | 待实测 | 显示型客户端，警告触达率高 |
| libssh2（git/libgit2 链路） | 循环读行直至 `SSH-` | 文献预期，待实测 | — |
| paramiko（Ansible/自动化） | 忽略前置行（有读行预算），超预算报 "Error reading SSH protocol banner" | 文献预期，待实测；老版本（<1.17）预算较紧 | 101B 默认行远低于已知预算；矩阵实测覆盖 2.x 最新与 1.17 |
| Go x/crypto/ssh（Terraform/现代 CI 工具） | 接受前置行但**总读入预算 255B**（含版本行） | 已知实现约束（`maxVersionStringBytes`），待实测 | W4 的 200B 预算即为此设；实测必须包含"默认行+真实 sshd 版本行"总长 |
| JSch（Java） | 预期跳过；老版本有严格首行假设的报道 | 待实测（低优先级：Jenkins git 多走 CLI ssh） | 若实测失败 → 走 §4.2 降级 |

### 4.2 降级策略（D6）

- `--warn-mode off`：完全关闭警告行（纯透传，行为退化为 TCP 中继）。**默认 on**（定案 1 默认发警告）。
- 运行纪律：矩阵中任何客户端实测 FAIL 且无法通过缩短行解决时，才对该链路目标机组关闭警告（配置粒度=每主机实例，不做按客户端 UA 判定——那需要解析，违定案 1）。
- 降级不关闭的东西：连接日志、上限、超时（观测与健壮性与警告行解耦）。

### 4.3 反向兼容（服务端侧，备忘）

doorkeeper 对上游 sshd 是普通 TCP 客户端，无版本交换参与；sshd 侧唯一新增行为是收到"先有前置行"的连接吗？否——前置行由 doorkeeper 发给**客户端**方向，sshd 收到的首字节仍是客户端原始版本串。唯一注意点：sshd 的 `MaxStartups` 行为（E3）在门卫后不变，见 §5.1。

---

## 5. ④ 资源与健壮性

### 5.1 连接数上限（D8）

- 默认 `--max-conns 128`（同时活跃连接），达到上限时：accept 后**立即关闭**该连接（不写警告行——上限保护优先于告知）并记 `conn_refused_over_limit`。backlog 由 listen(256) 承接。
- 与 sshd `MaxStartups`（默认 10:30:100）联动说明：MaxStartups 限的是 sshd 侧**未完成认证**的并发，与门卫总并发（含已建立长会话）不同层。E3 实测：瞬时未认证风暴下 sshd 自己以 `Not allowed at this time` 预版本行拒流——这是 sshd 既有保护，门卫不重复造。结论：门卫上限只管自身资源；若迁移仪表盘显示高频握手风暴，运维侧调 sshd MaxStartups，不在门卫加码。

### 5.2 超时策略（D7：只给门卫自有阶段设超时，pipe 阶段显式不设）

| 阶段 | 超时 | 理由 |
|---|---|---|
| 上游 connect | 5s | 回环连接，5s 已极端宽裕；超时→ §3.4 失败路径 |
| 警告行/失败行 write | 10s（SO_SNDTIMEO） | 防不发不读的恶意端占住首个 write；超时→关闭记 `reason: warn_write_timeout` |
| pipe 数据面 | **无应用层超时** | SSH 会话合法空闲可达小时级，门卫无法区分"认证前挂死"与"认证后空闲"（不解析即不可知）。应用层空闲超时=误杀合法会话，明确不做 |
| 死端检测 | TCP keepalive：两端套接字 SO_KEEPALIVE，`TCP_KEEPIDLE=600s, TCP_KEEPINTVL=60s, TCP_KEEPCNT=5` | keepalive 只杀**真死**对端（网卡消失/断电），对健康空闲会话透明；配合上限，半开连接积累问题被界定（§8 测试 12） |
| 生命周期上限 | 无（不设 max-lifetime） | 过渡垫不终止用户会话；日落靠下线流程不靠杀连接 |

### 5.3 backpressure 与上游未就绪

- 背压模型：阻塞式 copy 循环 + 16 KiB 用户态缓冲，窗口满即阻塞在读/写上，由内核 TCP 流控端到端传导（classic TCP proxy，无需显式水线）。每连接内存上界 = 2×16 KiB + 线程栈。
- 上游未就绪：connect 超时/拒绝 → §3.4 失败行 + 关闭 + 日志。**不重试**（客户端的 SSH 自带重连与用户重试语义；门卫重试只会放大风暴）。

### 5.4 连接收尾语义

- 每方向独立线程；一侧 read 返回 0（EOF）→ 对另一侧 `shutdown(SHUT_WR)` 传播半关闭（SSH 正常会话结束依赖此语义）；一侧硬错误（ECONNRESET/EPIPE）→ 关闭双向、另一方向线程因 fd 关闭自然退出。
- 收尾必记 `conn_close`：`{conn_id, reason ∈ normal|client_reset|upstream_reset|warn_write_timeout|upstream_unavailable|over_limit, bytes_c2s, bytes_s2c, duration_ms}`。
- 资源归还红线：连接计数严格减一、两 fd 必关、线程必 join/detach 有据——泄漏测试见 §8（测试 9/12）。

### 5.5 日志（格式、原子性、轮转）

- **格式**：JSONL，每行一事件。事件集（§3.3/§3.4/§5.1/§5.4 + 启动）：

| 事件 | 字段（ts/level 公共字段之外） |
|---|---|
| `listen_start` | listen, upstream, warn_mode, max_conns, pid, version |
| `conn_accept` | conn_id, src_ip, src_port, family(v4/v4mapped/v6) |
| `warn_sent` | conn_id, bytes |
| `upstream_connect` | conn_id, ok, elapsed_ms, err? |
| `client_version` | conn_id, version(string\|null), truncated(bool) |
| `conn_close` | conn_id, reason, bytes_c2s, bytes_s2c, duration_ms |
| `conn_refused_over_limit` | src_ip, src_port, cur_conns |
| `log_reopened` | path |

- `ts`：RFC 3339 UTC 毫秒。`conn_id`：进程内单调 u64，join key。
- **原子性（E6 实证教训）**：一条日志**一次 `write()` 系统调用**写完（O_APPEND；单行 ≤ PIPE_BUF 量级时 append 原子性由内核保证），跨线程共享一个 fd，不引入锁亦不出现交错行；实现卡测试 7 覆盖（并发压测后日志行 JSON 可解析率 100%）。
- **不做进程内聚合**：仪表盘指标全部由离线分析 doorkeeper.log 得出（runbook §7.6 附 jq 模板：按日连接数、唯一来源 IP、客户端版本分布）——门卫保持哑的。
- **轮转**：logrotate 外置 + `SIGHUP` 触发 reopen（systemd `ExecReload=/bin/kill -HUP $MAINPID`，runbook 给 logrotate 配置：weekly + rotate 8 + compress + postrotate 发 HUP）。无进程内轮转逻辑。

### 5.6 fd/内存预算表（部署核算）

| 项 | 公式 | 默认值 |
|---|---|---|
| fd | 1(listen) + 2×活跃连接 + 1(日志) | ≤ 258 @128 连接；systemd `LimitNOFILE=1024` |
| 线程 | 1(accept) + 2×活跃连接 + 1(信号) | ≤ 258 |
| 用户态内存 | 连接×(2×16 KiB) + 栈×256 KiB | ≤ 4 MiB + 64 MiB 虚拟（RSS 远小） |

---

## 6. ⑤ 与锦书主进程的关系：独立进程（D2）

### 6.1 裁决与理由

- **独立二进制 `jbuu-doorkeeper`，独立 systemd 单元**；不做 `jbuu doorkeeper` 子命令。理由：
  1. **重启域隔离**：过渡垫频繁改配置/升级（警告文案、上限），不能连带主进程；
  2. **权限剖面隔离**：门卫需 `CAP_NET_BIND_SERVICE`（绑 :22），锦书主进程不需要——最小权限各自成立；
  3. **崩溃隔离**：门卫 panic 只影响新 SSH 连接（秒级自愈 by systemd），锦书会话零波及；反向亦然；
  4. **日落故事**：退役=停一个 unit，主进程无感（§7.7）。
- 与主套件的联系仅限：同仓同 CI（workspace member）、同一发布流程、README 同页（安全声明复述）。

### 6.2 systemd 单元草案（实现卡随包附 `jbuu-doorkeeper.service`）

```ini
[Unit]
Description=jbuu doorkeeper - SSH transition shim (RFC 4253 4.2 pre-banner + raw pipe)
Documentation=file:/usr/share/doc/jbuu-doorkeeper/SECURITY-NOTES.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/jbuu-doorkeeper --listen [::]:22 --upstream 127.0.0.1:2222 \
  --log-file /var/log/jbuu/doorkeeper.log --max-conns 128
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2s
# 权限：无 root，仅低位端口绑定能力；DynamicUser 下 /var/log/jbuu 由 systemd 属主管理
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
# 文件系统/内核加固
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
LogsDirectory=jbuu
LimitNOFILE=1024

[Install]
WantedBy=multi-user.target
```

配置面全走 CLI flags（无配置文件）：`--listen`、`--upstream`、`--warn-mode on|off`、`--warn-line`、`--failure-line on|off`、`--max-conns`、`--log-file`、`--verbose`。默认值即本文全部裁决值。

---

## 7. ⑥ 部署 runbook 草案（含 sshd 收缩、防火墙、验证、回滚、日落）

> 前提：单主机 Linux，systemd，OpenSSH ≥ 7.x；全程保持带外控制台可用（收缩窗口期禁止唯一依赖 SSH 远程操作）。

1. **Preflight 盘点**：`journalctl _COMM=sshd --since "-30d" | grep -oE 'from [0-9a-fA-F:.]+' | sort | uniq -c | sort -rn` 得存量来源清单；记录当前 `sshd -T | grep -E '^(port|listenaddress|maxstartups)'`。此清单即迁移基线，交仪表盘比对。
2. **sshd 增设回环监听（不收缩，双活期）**：新建 `/etc/ssh/sshd_config.d/10-doorkeeper-transition.conf`，内容仅两行 `ListenAddress 127.0.0.1:2222`、`ListenAddress [::1]:2222`；`sshd -t` 通过后 `systemctl reload sshd`。验证：`ss -tlnp | grep 2222` 两条回环监听在列；本机 `ssh -p 2222 localhost` 可登录。
3. **门卫影子验证**：安装 `jbuu-doorkeeper`，以 `--listen [::]:2223 --upstream 127.0.0.1:2222` 起 service；从**外部**主机 `ssh -p 2223 user@host`：登录成功、`-v` 可见警告行、`/var/log/jbuu/doorkeeper.log` 出现完整事件链（conn_accept→warn_sent→upstream_connect→client_version→conn_close）。同时跑 §4.1 矩阵中可得客户端（PuTTY/dropbear/paramiko/Go 工具）各至少一次。
4. **切换窗口（唯一中断面 = 数秒新连接拒绝）**：
   a. `systemctl stop jbuu-doorkeeper`（影子实例）；
   b. sshd_config.d 内**注释掉既有 `Port 22`/`ListenAddress 0.0.0.0`/`ListenAddress ::` 相关行**（含主配置文件中的），确认生效面只剩步骤 2 的两条回环监听；`sshd -t` → `systemctl reload sshd`（reload 不断存量会话；`systemctl show -p ExecReload sshd` 为空则改用 restart 并提前公告）；
   c. `systemctl start jbuu-doorkeeper`（正式参数 `--listen [::]:22`）。若 bind 失败（说明仍有 22 端口占用者），**立即回滚**（步骤 9），不得留半收缩态。
5. **可见性互补（§3.6）**：`/etc/ssh/sshd_config.d/` 加 `Banner /etc/ssh/jbuu-migration-banner.txt`（文案：SSH 即将下线、迁移 jbuu 指引链接），`sshd -t && systemctl reload sshd`。
6. **防火墙（可选加固，防"绕过门卫直达 sshd"的纵深）**：
   ```
   nft add table inet jbuu
   nft 'add chain inet jbuu input { type filter hook input priority filter; }'
   nft add rule inet jbuu input tcp dport 2222 iif != "lo" drop
   ```
   （sshd 只绑回环时内核已拒绝外部直达；此规则是配置漂移时的保险带。）
7. **验证清单（逐项打勾）**：外部 `ssh -p 22` 端到端登录+`scp` 传文件成功；外部 `ssh -p 2222` **拒绝**（证明收缩生效）；`nmap -p 2222` closed/filtered；`ss -tlnp` 显示 :22 属 jbuu-doorkeeper、2222 仅回环；日志事件齐全；`systemctl stop jbuu-doorkeeper` 后外部 :22 拒绝而本机 `ssh -p 2222` 仍通（证明无旁路）；再 `start` 恢复。
8. **IPv6 备注**：若主机禁 IPv6，`--listen 0.0.0.0:22`；同时检查 DNS AAAA 记录——客户端可能优先 v6，AAAA 须指向同机或删除。
9. **回滚**：`systemctl stop jbuu-doorkeeper` → 恢复 sshd_config.d（取消注释原 Port/ListenAddress、删两条回环监听与 Banner 行）→ `sshd -t && systemctl reload sshd` → 外部 :22 直连 sshd 复验。门卫包保留本机以便再切换。
10. **仪表盘**：cron 每日 `jq` 聚合 doorkeeper.log（当日连接数、唯一 src_ip、client_version 分布）输出 `/var/log/jbuu/dashboard-YYYYMMDD.json`；与步骤 1 基线比对收敛度。
11. **日落（§安全边界声明的"过渡"落点）**：连续 4 周 SSH 连接 < 5 次/周且唯一来源 0 个自动化客户端（仪表盘判定）→ 排期：公告 → 防火墙封 :22 → 观察 1 周 → `systemctl disable --now jbuu-doorkeeper`，sshd 回环监听保留与否由主进程接入方式定。

---

## 8. ⑦ 测试清单（实现卡的验收测试面，功能/并发/恶意简项）

**功能**
1. 警告行 golden：默认行 101 字节逐字节断言（§3.2 hex）+ W1–W5 不变式（含"配置行以 SSH- 开头 → 拒绝启动""含 CR → 拒绝启动"">200B → 拒绝启动"三负例）。
2. 端到端：临时 sshd（测试密钥）+ 门卫 + 本机 ssh 二进制：登录、执行命令、scp 各一；openssh 二进制缺席则 SKIP 并标注。
3. 上游死端口：5s 内关闭 + 失败行字节断言 + `reason: upstream_unavailable`。
4. 透传字节精确性（性质测试）：随机负载双向过 echo 上游，入口/出口 hash 相等；负载含空、1B、>64 KiB、二进制垃圾、伪造 `SSH-` 诱饵行——观察器不得吞字节/错位（诱饵行后仍出现真版本行时取首个 SSH- 行）。
5. 版本串观察：随机前置行 + `SSH-2.0-x\r\n` → 提取精确；>8 KiB 无换行 → 放弃且 `version: null`、吞吐不变。
6. 半关闭：一侧 FIN → 另一侧收到 FIN 传播（socket 测试工装断言）。
7. 日志原子性：并发压测后全文件 JSONL 可解析率 100%（E6 回归）；SIGHUP reopen 后新行落新文件。

**并发/上限**
8. 128 并发全通（echo 上游）；第 129 条立即关闭 + `conn_refused_over_limit`。
9. 循环建立/销毁 10⁴ 连接：fd 数、线程数回到基线（无泄漏）。

**恶意输入/fuzz 简项**
10. 连接后不读不写（慢速占位）：观察器不阻塞他人；keepalive 生效性以配置断言（`TCP_KEEPIDLE` socket option 实测读回）。
11. 首包巨型单行（1 MiB 无换行）直发：透传不崩、观察器按窗放弃。
12. 客户端 RST 在警告 write 中途：EPIPE 干净回收（无 panic/无线程泄漏）。
13. 随机分段切割（1B 粒度发送警告后首 kex 包）：字节精确性性质测试覆盖（同 4）。
14. 重启韧性：压测中 kill 门卫再启动：旧连接干净消亡、新连接正常、无 sshd 侧残留异常。

**负面清单（评审检查项，非测试）**：依赖清单无异步/SSH 协议/otp-* crate；`cargo clippy -D warnings`、unsafe 面积=0 或逐处论证；README 首段含安全边界声明原文。

---

## 9. 决策点汇总（评审逐条确认；任一被否决只改本文，不动定案）

| ID | 决策 | 位置 | 性质 |
|---|---|---|---|
| D1 | 并发模型=thread-per-conn + std::net，禁引入异步/SSH 协议/内部 crate | §2 | 裁决（卡①） |
| D2 | 独立二进制 jbuu-doorkeeper + 独立 systemd 单元，不做子命令 | §6 | 裁决（卡⑤） |
| D3 | 警告行 accept 后立即发送，此前不读客户端任何字节 | §3.3 | 裁决（卡②） |
| D4 | 警告行默认文案+内容不含终止符+启动期校验 W1–W5 拒绝误配 | §3.1/§3.2 | 裁决（卡②） |
| D5 | 上游 127.0.0.1:2222（sshd 显式 ListenAddress 迁移，避 EADDRINUSE） | §1.2 | 裁决（卡⑥前置） |
| D6 | 降级开关 `--warn-mode off`，默认 on；不做按客户端判定 | §4.2 | 裁决（卡③） |
| D7 | 仅自有阶段超时（connect 5s/warn write 10s）；pipe 无应用层超时，靠 keepalive(600/60/5) | §5.2 | 裁决（卡④） |
| D8 | 并发上限默认 128，超限 accept 即关+记日志；不与 MaxStartups 重复限流 | §5.1 | 裁决（卡④） |
| D9 | JSONL 单 write 原子追加 + SIGHUP reopen + logrotate 外置 + 无进程内聚合 | §5.5 | 裁决（卡④） |
| D10 | 监听 `[::]:22` + 显式 IPV6_V6ONLY=0 单套接字双栈 | §1.2 | 裁决 |
| D11 | 上游不可达补发诊断行（默认 on 可关） | §3.4 | 裁决 |
| F1 | 事实勘误：OpenSSH 客户端默认**忽略**前置行（仅 -v 可见），非"显示并忽略"；可见性主通道改由 sshd Banner 承担 | §3.6/§0-E2 | 勘误（需芥末知悉，不改机制） |

**独立校验器**：`workspace/verify_wp14.py` 复算默认警告行 golden hex/md5 并校验 W1–W5 不变式（不入仓）。

---

## 附：术语与引用

- RFC 4253 §4.2（本设计唯一协议依据）原文要点：服务端 MAY 在版本串前发送其它文本行；每行 SHOULD 以 CRLF 结尾；此类行 MUST NOT 以 "SSH-" 开头、SHOULD 为 ISO-10646 UTF-8；客户端 MUST 能处理此类行，MAY 静默忽略或显示。
- "预版本行"=本文对上述机制的简称；sshd 自身即用其做 MaxStartups 拒流（`Not allowed at this time`，E3 实测）。
- 锦书/jbuu：项目更名见论坛 #82；密码本 magic "OTPB" 与格式 v1 不受影响。
