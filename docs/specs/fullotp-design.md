# `--full-otp` 模式协议设计书：数据面 OTP 流直加密

| 项 | 内容 |
|---|---|
| 任务 | 论坛任务 #68（FULLOTP-DESIGN） |
| 状态 | **评审稿；芥末批准前不得实现** |
| 基线 | v0.1/v0.1.1；WP-01/02/03、WP-10 record 层、WP-16 PTY 恢复语义 |
| 目标 | PTY 数据字节以密码本流逐字节 XOR；每个 pad 字节只使用一次；与现有 ChaCha20-Poly1305 数据面共存 |
| 非目标 | 隐藏长度、时序、方向、段号或流量形态；在端点/密码本失陷后保密；兼容第三方 SSH；本卡实现代码 |

> **结论先行。** 推荐注册一个新的、不可静默降级的 `FULL_OTP_POLY1305` 协议模式：终端明文每 1 字节恰好消耗 1 字节 OTP，加上每条记录 32 字节的一次性 Poly1305 密钥。数据不进入 ChaCha20 或任何其他流密码；Poly1305 只做一次性、无条件安全（unconditional / information-theoretic）认证。拒绝注册“裸 XOR、无完整性”配置。密码本仍以 64B 段持久管理，但会话按双向各 4 KiB 的 bundle 预留，记录在 bundle 内按字节切片，**绝不做“一字符一段”**。

---

## 1. 安全主张、依赖与协议分层

### 1.1 可宣称什么

在密码本字节独立均匀、未泄露且绝不复用的前提下，对于长度为 `L` 的 PTY 明文 `P`，数据密文为 `C=P xor Q`，其中 `Q` 是该方向 pad 流中未用过的 `L` 字节。因此 `C` 对 `P` 提供 Shannon 意义的完美保密；攻击者算力不影响此结论。

推荐 profile 的完整性由**每记录独立的一次性 Poly1305 key**提供。其安全性是概率型、信息论型的伪造界，而不是“绝不可能伪造”；每次失败立即关闭，使攻击者不能在同一 key 下反复试验。具体可接受伪造界须由后续密码学评审按最终最大记录长度复核，产品文案不得把它写成零概率。

### 1.2 不可宣称什么

- 长度、方向、发送时刻、bundle/record 序号公开；小包高频的键盘节奏仍可被流量分析。
- 初始共享本认证、指针/锚完整性、实现、OS、存储和端点安全不因本模式自动变成信息论安全。
- v2 的 CONFIRM 可继续作为控制面启动认证，因此“端点认证链完全信息论安全”不是本设计的主张；准确主张是：**PTY 内容保密与本设计的数据记录认证不依赖计算困难假设**。
- 任一端密码本、pad 缓冲、PTY 明文、swap/core dump 泄露都会破坏相应范围安全。

### 1.3 控制面与数据面

保持 WP-01/02 的仲裁、fail-to-waste、双 CONFIRM 和 WP-16 PTY 语义。新模式只替换 `ESTABLISHED` 后承载 PTY 内容的 record 层：

```text
握手/模式绑定：HELLO -> ARBITRATE -> ISSUE -> 双 CONFIRM
                                  |  CONFIRM 明确绑定 mode
                                  v
控制面：PAD_OFFER / PAD_ACK / PAD_NEED / CLOSE（不含 PTY 内容）
数据面：OTP_DATA = 公开头 || (PTY xor 一次性 pad) || 一次性 Poly1305 tag
```

控制面可在首个 64B 会话段拆出的现有 AEAD 控制通道上承载；其序号空间必须与 OTP 数据序号分离。该 AEAD **不得承载任何终端字符、窗口标题、剪贴板或退出输出**。窗口尺寸、心跳、bundle 编号等元数据不属于“终端字符”，但仍应尽量少披露。

---

## 2. 密钥消耗模型与双向段分配（问题①）

### 2.1 精确消耗公式

对每方向独立计费。第 `j` 条记录明文长度为 `L_j`（`1 <= L_j <= 4064`）：

```text
stream slice = MAC_KEY_j[32] || XOR_PAD_j[L_j]
C_j          = P_j xor XOR_PAD_j
TAG_j        = Poly1305(MAC_KEY_j, canonical_header_j || C_j)
secret consumption(record j) = 32 + L_j bytes
```

因此：

- **加密 pad 消耗严格为 PTY 流量 1:1**：`sum(L_j)` 个明文字节消耗同数 OTP 字节；
- 推荐完整性另收固定 `32 * record_count` 字节；tag 和公开头不消耗 pad；
- 总密码本消耗为 `payload_bytes + 32*records + bundle_tail_waste + crash/disconnect_waste`；
- 不允许从 pad 派生更多 keystream，不允许压缩后声称按原流量 1:1，不允许把 tag key 重用到下一记录。

示例：1 个字符立即发送消耗 33B；1024B 粘贴作为一记录消耗 1056B；4064B 满记录消耗 4096B，完整性额外开销约 0.79%。

### 2.2 物理段与逻辑 bundle

密码本物理段仍固定 64B。新增 allocator 原子操作 `reserve_range(n_segments)`，其耐久顺序必须等价于 WP-02 `issue()`：持锁 -> 双锚 INTENT（`next += n`）各自 fsync -> 读取范围 -> COMMIT 双 fsync -> 返回；任何不确定均浪费整个范围，绝不部分回收。

固定 `PAD_HALF = 4096B = 64 segments`，一个 bundle 为连续 128 段（8192B）：

```text
bundle k: base_segment = b
  C2S stream: B[b .. b+64)       # 4096B
  S2C stream: B[b+64 .. b+128)   # 4096B
next after reservation = b + 128
```

方向映射由角色而非发起方决定，任何情况下 C2S 都取前半、S2C 取后半。bundle 基址必须 128 段对齐不是安全前提；接收方以控制面给出的 `base_segment` 和本地已核验指针为准。首个握手段不属于 bundle，也不得作为 OTP 数据字节。

选择成对 bundle 而非奇偶段的理由：一次范围事务即可使两端明确拥有两个独立方向流；方向失衡只浪费该方向尾部，不会把已暴露/不确定字节转交另一方向。代价是短会话最多浪费每方向不足 4096B，容量规划必须按此而非“每连接 64B”估算。

### 2.3 预取策略

- 会话建立后先预留 bundle 0，完成双方 `PAD_OFFER/PAD_ACK` 后才允许首条 OTP_DATA。
- 每方向维护 `(bundle_id, base_segment, cursor)`；`cursor` 是该方向已消耗字节数，范围 `0..=4096`。
- 任一方向可用量低于 `LOW_WATER = 1024B` 时发送 `PAD_NEED`；**服务端是唯一 bundle 协调者**，同一会话最多一个未决 offer。
- 服务端先按 fail-to-waste 预留下一整个 bundle，再发 `PAD_OFFER(bundle_id+1, base_segment)`；客户端只在本地安全指针恰能采纳该范围后执行同样预留并回 `PAD_ACK`。任一侧失败时，已预留范围全浪费并关闭；不得回退。
- 当前 bundle 仍可发送完整记录；记录不得跨 bundle。若剩余不足 `32+L`，发送方可缩短 `L`；若剩余 `<=32`，尾部整体浪费，切到已 ACK 的下一 bundle。
- 若下一 bundle 尚未 ACK 且当前空间不足，数据泵施加 backpressure；不得裸发、不得改回 AEAD 数据模式。预取 I/O/fsync 应在独立受控任务完成，避免卡住 PTY 泵。

该策略不是无限缓存：每会话至多持有“当前 + 已 ACK 下一 bundle”两套材料；切换后旧 bundle 缓冲立即 zeroize。

---

## 3. OTP 数据记录与游标推进

### 3.1 规范头（设计冻结建议）

后续线格式卡应给新协议版本分配独立消息类型。逻辑字段如下，均为大端、canonical、公开：

| 字段 | 宽度 | 约束 |
|---|---:|---|
| `version` | u16 | 新协议主版本（建议 `0x0003`），不得伪装为 v2 DATA |
| `msg_type` | u16 | `OTP_DATA` 独立类型 |
| `mode` | u8 | 固定 `FULL_OTP_POLY1305` |
| `direction` | u8 | `0x01 C2S / 0x02 S2C` |
| `bundle_id` | u64 | 会话内从 0 严格递增 |
| `base_segment` | u64 | bundle 公开基址 |
| `record_seq` | u64 | 每方向从 0 严格 +1，不跨连接恢复 |
| `pad_offset` | u16 | 必须等于本方向期望 cursor；`<=4096` |
| `ciphertext_len` | u16 | `1..=4064` 且 `offset+32+len<=4096` |
| `ciphertext` | `L` | 与明文等长 |
| `tag` | 16B | Poly1305 输出 |

`canonical_header` 必须包含上述全部字段及 ciphertext 长度；MAC 输入使用带长度的固定域分隔，例如 ASCII `otp-term/full-otp/data/v1`、其长度、canonical header、ciphertext。最终逐字节布局和 golden vector 留给协议线格式实现卡，但不得删去 mode、方向、bundle、base、seq、offset、length 中任何一项。

### 3.2 原子消费规则

发送侧在构造记录前便把 `[cursor, cursor+32+L)` 标记为**已消费**；传输短写、取消或崩溃均不得重试这些字节。可以重发已生成的同一 wire record 只会形成重放歧义，故协议直接禁止应用层重发：传输不确定即关闭并浪费 bundle 尾部。

接收侧按以下顺序处理：格式/长度界限 -> 方向与 bundle -> `seq` -> `offset==cursor` -> 取一次性 MAC key 并验 tag -> 验证成功后 XOR 并一次性交付完整明文 -> 推进 cursor。任何失败都不向 PTY 输出字节、立即关闭、当前及预取 bundle 尾部全部浪费。

---

## 4. 流同步、断线与崩溃恢复（问题②）

### 4.1 正常流同步

TCP 只提供有序字节流；协议同步由自定界 frame、每方向 `record_seq`、`bundle_id` 和 `pad_offset` 四重约束。长度决定本记录精确消耗 `32+L`，因此双方无需扫描密文寻找边界。粘包/拆包不改变 cursor；只有完整且 MAC 成功的记录才能交付。

严禁“验签失败后猜下一个 offset”“在密文中搜 magic”“容忍 seq 窗口”。这些恢复会把攻击者控制的插入/删除变成永久 pad 错位并可能导致 pad 重用。

### 4.2 断线与进程崩溃

**不持久化逐字节 cursor，也不原会话续密钥。** 原因是发送方可能已消费但接收方未收到；任何双端恢复协议都无法仅凭本地 offset 证明哪些 pad 字节未暴露。规则是：

1. EOF、RST、超时、进程崩溃、MAC/序号错误后，当前 bundle 和已预取 bundle的全部未用尾部均标为 SPENT/WASTED；
2. 全部 pad/key 缓冲 zeroize；旧 `(session, bundle, offset)` 永不再接受；
3. 重新连接走 WP-02 仲裁和新 CONFIRM，再预留全新 bundle；
4. 锚只记录已预留到的**段级 next**，因此重启自然从全部 bundle 之后继续。崩溃窗口仍遵守 WP-02“取高、宁浪费、不回退”；范围事务使单次故障浪费上限从 1 段扩大为 128 段，这是明确成本变化。

### 4.3 与 WP-16 恢复语义

`connect --recover HANDLE` 只恢复 PTY 对象/上下文，不恢复密码学流。恢复连接必须：新握手段、新 session nonce、新 pad bundle、新 record_seq=0、新 cursor=0，并通过 WP-16 lease/fencing 后才成为 PTY 单主。旧/新连接不得共享 bundle；并发恢复请求各自预留不同范围，只有获 lease 者可输出，失败者的范围也按 fail-to-waste 浪费。

该规则与 WP-16 原语义一致：恢复 token 是索引/句柄，不是密码材料。若锚出现 CLIENT_AHEAD，仍走 WP-02 人工恢复；`--full-otp` 不得放宽为网络自动前推。

---

## 5. 完整性与可塑性边界（问题③）

### 5.1 为什么裸 XOR 不可接受

裸 `C=P xor Q` 可塑：攻击者翻转密文位会在同位置可预测地翻转明文位。对交互终端，现实攻击包括：

- 把待执行命令、确认选项或控制字符改成另一值；
- 注入/修改 ESC、CSI、OSC 序列，造成终端欺骗、剪贴板操作或显示混淆；
- 修改窗口/退出控制消息（若错误地与数据共用裸通道）；
- 插入、删除或改长度使两端 pad cursor 永久错位，造成 DoS，并可能诱发错误实现复用 pad；
- 重放历史密文，让旧按键/输出再次生效。

因此“保密但无完整性”不满足远程终端的最低安全边界。本设计**不注册** `FULL_OTP_RAW_XOR`，也不提供 `--full-otp-no-auth` 调试开关。

### 5.2 推荐：一次性 Poly1305 key 直接取 pad

每记录先从方向流取独立 32B 作为 Poly1305 one-time key，再取 `L` 字节 XOR pad。不得 KDF、哈希、跨记录/跨方向复用 key；Poly1305 的 `r` 规范化/clamp 是算法定义的一部分，不是密钥派生。MAC 覆盖域分隔、完整公开头与密文，接收侧常量时间校验成功前不解密/不输出。

理由：

1. Poly1305 本就是适合一次性独立 key 的通用哈希认证器；在 key 真随机且只用一次时，伪造界来自信息论分析而非攻击者算力；
2. 16B tag 固定、实现成熟，避免自创 Wegman-Carter 构造；
3. 32B/record 的密码本成本可精确计量；批量流量开销低；
4. 与现有 AEAD 的 Poly1305 **不是同一个 key 或同一构造**，不得调用 ChaCha20-Poly1305 再宣称 full OTP。

限制：必须使用经审计、支持独立 one-time key 的 Poly1305 API；不得手写算法；最终实现卡必须给出标准/KAT、最大 4064B 消息下的明确伪造概率上界并经独立密码评审。若可用库/API 无法证明“每次独立 key、无隐式派生”，此路线应阻断，而不是退化成裸 XOR。

---

## 6. 重放、插入、删除与乱序检测（问题④）

段号/bundle 序列是公开元数据，公开并不削弱 OTP 内容保密，反而提供机械的反重放锚：

| 攻击 | 检测 | 处置 |
|---|---|---|
| 原样重放已收记录 | `record_seq < expected` 或 `pad_offset < cursor` | 静默关闭，尾部浪费 |
| 插入伪记录 | seq/offset 不符；即使恰好命中也无新 one-time key，tag 伪造仅以安全界概率成功 | 同上 |
| 删除/跳过记录 | 下一记录 seq 或 offset 大于期望 | 同上，不跳洞恢复 |
| 乱序 | seq/offset 不等期望 | 同上；TCP 上出现即对端/中间层违规 |
| 跨方向搬运 | direction 不符且 MAC 绑定方向 | 同上 |
| 跨 bundle/连接搬运 | bundle/base/mode/session 控制上下文不符，或 tag 不符 | 同上 |
| 篡改长度/头/密文 | canonical 边界检查或 tag 不符 | 同上，零明文输出 |

接收窗口恒为 1。错误类别可在本地审计为 `OTP_REPLAY/OTP_GAP/OTP_TAG_INVALID/OTP_OFFSET`，线上统一表现为关闭，不回传可区分 oracle。审计仍只允许 book_id、段号/generation、结果、错误类别；不得记录 offset 对应的 pad、MAC key、明密文。

---

## 7. CLI 共存、协商与切换语义（问题⑤）

### 7.1 挂载点

建议 CLI：

```text
jbuu serve  ... [--full-otp]     # 显式允许且要求 full-otp 连接
jbuu connect ... [--full-otp]    # 显式发起 full-otp
```

默认不带参数时保持 v0.1/v0.1.1 `AEAD_CHACHA20_POLY1305` 行为、线格式和容量模型。参数挂在 `serve` 与 `connect` 子命令，而不是 `book`、`doctor` 或 PTY 子层；PTY 泵只接收握手已冻结的 `DataPlane` 枚举，不自行切换。

更稳妥的服务端部署是每个 listener 固定一种模式；如未来需同端口多模式，必须在 HELLO 中显式携带 mode 且 CONFIRM 的 AAD/明文副本完整绑定 mode。WP-01 当前“未知 feature 位忽略”不能承担安全协商：**不得仅占一个可忽略 features bit**。

### 7.2 配对矩阵与降级规则

| client | server listener | 结果 |
|---|---|---|
| 默认 AEAD | 默认 AEAD | 现有协议成功 |
| `--full-otp` | `--full-otp` | 新版本/模式成功 |
| `--full-otp` | 默认 AEAD | 握手前期明确 `MODE_MISMATCH` 后关闭；不消耗数据 bundle |
| 默认 AEAD | `--full-otp` | 同上 |
| 任一模式收到未知版本/mode | 任一 | fail closed |

不允许“试 full OTP 失败后自动重连 AEAD”，也不允许会话中切换。模式在 HELLO、双 CONFIRM、控制面 AAD 和每条 OTP_DATA MAC 中绑定；一旦确认，直到连接关闭保持不变。恢复必须由用户再次给出 `--full-otp`（或客户端保存的公开连接配置明确继承），不得由未经认证的恢复 token 决定。

建议新主版本而不是偷偷复用 `version=0x0002`：现有 DATA 对 `data` 的解释是 `AEAD ciphertext || 16B tag`，新记录具有 pad offset 与 one-time MAC 消耗语义，误解析会造成不可逆 pad 浪费。版本号/消息类型的最终注册由后续 WP-01 修订卡完成。

---

## 8. PTY 小包、瓶颈与交互延迟（问题⑥）

### 8.1 不采用“一字符一段”

一字符一 64B 段会把每按键的持久化分配、双 fsync、网络帧和容量成本绑定在一起：100 字符/秒即约 6400B/s 本体消耗且最多每键触发存储延迟；更重要的是段级游标恢复复杂、吞吐极差。本设计一次预留 4KiB 方向流，再在内存中按 `32+L` 切片；单字符记录消耗 33B，但不触发分配事务。

### 8.2 自适应成帧建议

- `TCP_NODELAY`；不得依赖 Nagle 聚合交互字符。
- 每方向聚合上限 `MAX_PLAINTEXT=4064B`。
- 交互输入：首字节到达后最多等待 **1ms** 微批；若读到换行、控制字符、达到上限或 PTY 当前无更多可读字节则立即发。产品可默认零等待以换取最低按键延迟；1ms 只能是有界可配性能项，不能跨协议协商。
- 批量粘贴/命令输出：尽量填充到 1–4KiB 记录，以摊薄 32B MAC key 和系统调用。
- resize/heartbeat 不混入 OTP_DATA，走控制面，避免无 PTY 内容却消耗数据 pad。

在零等待最坏小包下，一个按键新增的密码计算是 1B XOR + 一次短 Poly1305，通常远小于网络/PTY 调度；主要成本变为 32B 密钥消耗和 frame/syscall。1ms 微批将本模式新增交互等待硬封顶约 1ms（不含调度和网络）。

### 8.3 主要瓶颈与容量

1. **密码本容量**：短连接按首 bundle 至少预留 8192B，加握手段；相对旧模式每连接 64B，容量约下降两个数量级。1GiB 本体理论只容纳约 131072 个空/极短 full-OTP bundle（未扣故障、预取及方向尾部浪费）。
2. **范围 fsync**：每双向 8KiB 触发双方范围预留事务；异步低水位预取隐藏延迟，高吞吐若在 1024B 阈值内仍来不及则 backpressure，而非切模式。
3. **小包 MAC key**：单字符 3200% 密钥开销；微批 32 字符时为 100%，1024B 时约 3.125%。
4. **内存/读放大**：每会话最多当前+下一 bundle 共 16KiB pad，加控制密钥；禁止预读整本。高并发需设 full-OTP 会话上限。
5. **流量分析**：微批能略弱化逐键节奏但不消除；固定填充会额外等量消耗 pad，本版不默认启用。

建议 `doctor/status` 公开报告剩余段数、按 8192B/bundle 折算的最坏可开会话数和实际 wasted 段数，但不得读取或输出段正文。

---

## 9. 失败语义、生命周期与不变量

### 9.1 关键不变量

1. 任一 `(book_id, absolute_byte_offset)` 至多进入一次 MAC key 或 XOR pad，且二者用途不重叠。
2. C2S/S2C 的预留范围不重叠；方向不可交换。
3. 记录不跨 bundle；切换只到已 ACK 且更高 base 的 bundle。
4. 先持久预留范围，后读取 pad；不确定即整范围浪费。
5. MAC 成功前不向 PTY/终端输出任何明文。
6. 会话断开后不恢复 cursor；新连接永远新范围。
7. mode 不可在连接内切换，不可静默降级。
8. pad、MAC key、明文类型不可 Clone/Debug/Serialize；Drop/失败/切 bundle 时 zeroize。

### 9.2 失败成本

| 失败点 | 数据是否可交付 | 消耗/恢复 |
|---|---|---|
| range INTENT 前 | 否 | 按 WP-02 CP0；未预留可不耗 |
| 任一 range 写/fsync 不确定 | 否 | 整 128 段保守浪费，allocator 停机/恢复取高 |
| bundle 一端 ACK 失败 | 否/当前 bundle 可终止前已交付完整记录 | 新 bundle 整体浪费，关闭 |
| OTP record 发送不确定 | 否（对端可能收到） | 已切片字节和 bundle 尾部全浪费，关闭 |
| tag/seq/offset 失败 | 否 | 关闭，当前+预取尾部浪费 |
| 正常关闭 | 已认证完整记录可交付 | 所有 bundle 尾部浪费，不回收 |
| PTY recover | 新连接 | 新握手段+新 bundle；旧范围不复用 |

---

## 10. 后续实现前阻断项与验收建议

本稿批准后仍需拆分实现卡；以下任一未完成不得合并生产实现：

- [ ] WP-01 修订：新版本/mode、OTP_DATA 与 PAD_* canonical 线格式、长度上限、错误码、golden vectors；确认旧 decoder 不会误收。
- [ ] WP-02/allocator 修订：`reserve_range(128)` 的双锚 INTENT/COMMIT 布局、每个 write/fsync/pread 崩溃矩阵；明确单故障最大浪费 128 段。
- [ ] 密码评审：独立 Poly1305 one-time-key API、域分隔编码、4064B 上限下伪造概率界、KAT；确认无 ChaCha/KDF 隐式调用。
- [ ] 状态机：PAD_OFFER/ACK/NEED 单协调者、竞态/超时/双向同时低水位、预取 backpressure。
- [ ] 性质测试：任意合法记录序列中 pad 绝不重叠；任意截断/插入/重放/改长不输出明文；崩溃恢复永不复用范围。
- [ ] WP-16 黑盒：单键、控制字符、32KiB 粘贴、大输出、resize、心跳、断线恢复、并发 recover fencing；模式错配绝不降级。
- [ ] 容量/性能：1 字节、32B、1KiB、4064B 分布下消耗与 p50/p99 延迟；预取跨 bundle 不丢不重；慢盘时只 backpressure。
- [ ] 机密数据扫描：日志、panic、core、swap、evidence 中无 pad/MAC key/明文。

### 10.1 待芥末批准的设计决策

| ID | 决策 | 推荐 |
|---|---|---|
| FOD-1 | 是否允许无完整性 raw XOR | **不允许**；仅注册一次性 Poly1305 profile |
| FOD-2 | bundle 大小 | 固定双向各 4KiB（128×64B），低水位 1KiB |
| FOD-3 | 模式标识 | 新协议主版本 + 显式 mode，不复用可忽略 feature bit |
| FOD-4 | 控制面 | 保留现有 AEAD 控制通道；严禁承载 PTY 字节 |
| FOD-5 | 断线恢复 | 整 bundle 尾部浪费；WP-16 只恢复 PTY，新密码学会话/新 bundle |
| FOD-6 | 交互聚合 | bundle 内按字节切片；0–1ms 自适应微批，绝不一字符一段 |

---

## 11. 与现有规格的关系

- **WP-01**：现有 v2 帧不可直接复用为 OTP_DATA；需要显式修订，新旧协议 decoder 分离。
- **WP-02**：只前进、双锚、fail-to-waste、恢复新段原则保持；分配单位扩展为范围，故故障浪费上限改变。
- **WP-03/WP-10**：默认 AEAD 模式完全保持。full-OTP 数据面不使用其 nonce/AAD/ChaCha seal/open；初始 CONFIRM/控制面可复用但必须绑定 mode。
- **WP-16**：PTY lease、handle、fencing 保持；恢复的是终端对象，不是 pad 流。
- **WP-17**：drain 时不再预留新 bundle；已 ACK bundle 可否跑完应沿用“存量会话跑完”的政策，耗尽需 refill 时关闭，避免 drain 后产生新范围事务。

本设计未修改任何 `src` 或生产 crate；仅给出待评审协议设计。
