# OTP 终端协议 v2 — WP-03 96-bit nonce、AAD、方向密钥拆分与密钥材料生命周期规格

| 项 | 内容 |
|---|---|
| 任务 | 论坛任务 #32 · 工作包 WP-03（规划 §4：nonce/AAD/密钥生命周期规格） |
| 设计依据 | `otp_terminal_protocol_v2.md` §1.2（直接拆段、无派生）、§4（确认包 AAD 字段清单）、§9（96-bit nonce 构造、序号溢出立即终止、审计白名单）；实现规划 §0.4/§4 WP-03/WP-10、§7.1 阻断条件；前置定稿：WP-01 v1.1（字段宽度、session_nonce=C⊕S 即 D3、序号空间、错误码注册表）、WP-02 v3（会话状态机 S1–S7、allocator 状态 T1–T13） |
| 作者 | 斗拱（designer） |
| 状态 | 待评审；评审冻结后 WP-10（AEAD record 层）/ WP-19（独立实现）以本文件为唯一 nonce/AAD/拆键依据 |
| 范围内 | 96-bit nonce 逐字节布局与同方向同段唯一性论证；AAD 逐字段定长清单；64B→2×32B 拆分规则与禁派生清单；sequence 溢出语义与终止流程；密钥材料生成/驻留/zeroize 生命周期与敏感数据禁入清单；canonical nonce/AAD 下的正式 golden vectors（兑现 WP-01 决策 D5） |
| 范围外 | 消息线格式与错误码（WP-01）；状态机与恢复（WP-02）；实现与测试代码（WP-10/14）；锚与密码本文件格式（WP-02/WP-06）；PTY/恢复（WP-16） |
| 修订 | v1.0（本次，任务 #32）：初版。全部向量由经 RFC 8439 §2.8.2 KAT 校验的实现计算并独立复算（§6.0） |

**评审重点**：§8 列出 6 个决策点（D1–D6）。它们是对冻结设计书的*构造补全*而非语义修改，请评审逐条确认；任何一条被否决时只需改本文件并重算向量，不触碰设计书。

---

## 0. 输入依赖与冻结引用

本规格不改写任何前置定稿，只在其上做可执行化。凡引用字段宽度、枚举值、错误码，一律以 WP-01 v1.1 为准；凡引用状态与转移，以 WP-02 v3 为准。

| 依赖 | 本规格使用的冻结事实 |
|---|---|
| WP-01 §1.3/§2/§4 | `version=0x0002 (u16)`；`msg_type ∈ {0x0001..0x0006} (u16)`；`book_id` BYTES(16)；`client_nonce`/`server_nonce` 各 BYTES(16)；`segment_index (u64)`；`epoch (u32)`；`seq (u64)`；`direction ∈ {0x01=C2S, 0x02=S2C} (u8)`；大端 |
| WP-01 D3 | `session_nonce := client_nonce ⊕ server_nonce`（16B，双方确定性一致） |
| WP-01 §4.4/§4.5 | CONFIRM（0x0004/0x0005）占 `seq=0`；DATA（0x0006）自 `seq=1` 起，每方向每段内严格 +1；AEAD 密文长度 = 明文 + 16B tag |
| WP-01 §5.2 | 错误码：0x0201 TAG_INVALID、0x0204 SEQ_REPLAY、0x030B SEQ_UNEXPECTED 等；0x030B 覆盖"CONFIRM seq≠0 / DATA 首序号≠1 / 跳号/乱序" |
| WP-01 D5 | WP-01 向量的 sealed/data 用测试夹具 nonce/AAD；本规格冻结后应补正式 KAT——本规格 §6.4 即为兑现 |
| WP-02 §5.1/§5.2 | 会话状态 ST-DATA/ST-CLOSING/ST-CLOSED/ST-ABORTED；S3"seq 溢出（本方向 2^64−1 后还需发送）→ ST-ABORTED"；无 rekey 状态 |
| WP-02 §1.3 | T4 `issue()` 返回 `CommittedSegment`（64B，drop 清零，不 Clone/Debug/序列化）——拆键的唯一输入 |
| v2 §1.2 | `K_c2s=B[i][0:32]`、`K_s2c=B[i][32:64]`，"直接取段，没有派生转换"；分方向避免同密钥双向复用 |

**套件**（本规格范围内唯一套件，v2 §1.2/§9）：IETF ChaCha20-Poly1305（RFC 8439），256-bit key、96-bit nonce、16B tag、AAD 输入。本协议不存在套件协商；单会话内不得切换（v2 §1.2）。

---

## 1. 96-bit nonce 构造（验收点 ①）

### 1.1 布局（冻结）

每条 AEAD record（CONFIRM_C2S、CONFIRM_S2C、DATA）的 nonce 恰为 12 字节：

| nonce 偏移 | 长度 | 字段 | 取值 | 说明 |
|---|---:|---|---|---|
| 0 | 3 | `session_domain` | `session_nonce[0:3]` | 本连接会话域（24 bit）。`session_nonce = client_nonce ⊕ server_nonce`（WP-01 D3），双方一致，逐连接新生 |
| 3 | 1 | `direction` | `0x01`（C2S）/ `0x02`（S2C） | 与 WP-01 §4.4 `confirm_body.direction` 同一编码；取**发送方**方向：CONFIRM_C2S 与客户端 DATA 为 0x01，CONFIRM_S2C 与服务端 DATA 为 0x02 |
| 4 | 8 | `seq` | 该 record 的 `seq`，u64 大端 | 与帧内/AAD 内 seq 同值；**全宽 64 bit，禁止截断** |
| — | **12** | | | |

**构造函数（规范性定义，实现必须逐字节等价）**：

```text
record_nonce(session_nonce, direction, seq):
    d  = session_nonce[0..3]            # 3B，纯切片，无任何变换
    n  = d ‖ enc8(direction) ‖ BE64(seq)   # enc8(0x01)=0x01, enc8(0x02)=0x02
    assert len(n) == 12
    return n
```

`session_nonce` 与 `direction`、`seq` 均非秘密；nonce 唯一性是本构造唯一要满足的密码学前提（RFC 5116 对 AEAD nonce 唯一性要求；RFC 8439 §2.8 同）。

### 1.2 唯一性论证

**记号**：会话由 `(book_id, i, ζ)` 标识，`i` 为已签发段号，`ζ = client_nonce ⊕ server_nonce`。方向密钥 `K_c2s = B[i][0:32]`、`K_s2c = B[i][32:64]`（§3）。

**引理 1（后缀单射）**：`seq ↦ BE64(seq)` 是 `[0, 2^64−1]` 到 8 字节大端编码的单射；固定 `ζ` 与 `direction` 时，`nonce(direction, seq)` 是前缀固定、后缀单射的拼接，故 `seq ↦ nonce(direction, seq)` 单射。

**引理 2（序号严格分配）**：WP-01 §4.4/§4.5 与 WP-02 §5.1 冻结：每方向每段内，seq 自 CONFIRM 的 0 起严格递增分配（CONFIRM=0，DATA=1,2,3,…），**每个值至多被一条 record 使用**（发送方义务，§4.1 MUST）。

**定理（同方向同段唯一）**：同一段 `i`、同一方向 `d` 的全部 AEAD 调用中，nonce 两两不同。
*证*：两次调用 seq 分别为 `s₁ ≠ s₂`（引理 2），由引理 1 其 nonce 在低 8 字节即不同。∎

**推论 1（跨方向）**：同一连接 C2S 与 S2C 的 nonce 在字节 3 处不同（0x01≠0x02）。注意此字节是纵深防御：正常情况下两方向密钥本已不同（段的两半独立随机）；**若缺陷密码本出现两半相同的段（`B[i][0:32]==B[i][32:64]`），nonce 的方向字节成为防止 keystream 复用的唯一防线**——这是禁止去掉/复用方向字节的根本理由（§1.4）。

**推论 2（跨会话/跨段）**：fail-to-waste（v2 §6、WP-02 §3）保证任何段只签发一次，因此不同会话密钥必然不同，"同 key + 同 nonce"复用不可能发生。唯一残余：缺陷密码本含完全重复的段（v2 §9 测试 1 的检测对象）。此时两连接的 `session_domain = ζ[0:3]` 相互独立均匀，相同概率 2^−24/对——**这是纵深防御而非保证**；保证层在签发（CSPRNG 成书 + 段绝不复用）。本规格如实声明该边界，不宣称 24 bit 域消除缺陷本风险。

### 1.3 为什么是这样 12 字节（备选对比，已定稿不再开放）

| 备选 | 否决理由 |
|---|---|
| `book_id` 截断作域 | book_id 对同一密码本恒定，对"同本不同会话"零区分度；book_id 以全宽 16B 进 AAD（§2）已足 |
| `segment_index` 作域 | 顺序值、可预测；其区分能力不高于随机域；且段号已全宽进 AAD |
| ζ 折叠 16B→3B（XOR/哈希） | 域非秘密，混合无安全收益，徒增实现与审计面；纯切片可在 review 中逐字节核对 |
| seq 截断进 nonce（如 3B） | **灾难**：seq 超过 2^24 后 nonce 回绕复用 keystream；seq 必须全宽（§1.4 禁令） |
| 每记录随机 nonce | 破坏唯一性可证明性；随机 nonce 需更宽域且无法机械论证 |

### 1.4 禁止的 nonce 构造（规范性禁令）

以下任一即实现违规（规划 §7.1 阻断合并项"nonce 构造不能机械证明同方向唯一"）：

1. 截断 `seq` 至 64 bit 以下，或以"低 24/32 bit + 高位丢弃"之类方式编码 seq；
2. nonce 与帧内 seq 取不同计数器（各自递增、不同步）；
3. 每记录引入随机性（nonce = 随机数、nonce ⊕ 随机数）；
4. 去掉或改写方向字节（含把 0x01/0x02 改为 0/1、bit 标志位）；
5. 以任何哈希/KDF（SHA、HMAC、HKDF、HChaCha20…）"混合" ζ/book_id/段号生成 nonce；
6. 采用 XChaCha20-Poly1305（192-bit nonce，内部经 HChaCha20 派生子密钥）：既是套件变更（v2 §1.2 注册表外）又含派生，双重违反 §3.2；
7. CONFIRM 与 DATA 使用互不衔接的序号空间（WP-01 已冻结：CONFIRM=0 与 DATA 连续计数）。

---

## 2. AAD 构造（验收点 ②）

### 2.1 布局（冻结，73 字节定长）

v2 §4 要求确认包 AAD"至少包括版本、book_id、段号、双方 nonce、方向、epoch、序号和消息类型"。本节将其冻结为**全部 AEAD record（CONFIRM 与 DATA）共用**的 73B 定长布局；字段序一经冻结不得调整：

| AAD 偏移 | 长度 | 字段 | 类型 | 取值约束 |
|---|---:|---|---|---|
| 0 | 2 | `version` | u16 BE | 恒 `0x0002` |
| 2 | 2 | `msg_type` | u16 BE | `0x0004` / `0x0005` / `0x0006`（该 record 的帧类型） |
| 4 | 1 | `direction` | u8 | `0x01` / `0x02`（同 §1.1：发送方方向） |
| 5 | 16 | `book_id` | BYTES(16) | 会话 book_id |
| 21 | 8 | `segment_index` | u64 BE | 本会话已签发段号 `i` |
| 29 | 16 | `client_nonce` | BYTES(16) | HELLO 的 client_nonce |
| 45 | 16 | `server_nonce` | BYTES(16) | ARBITRATE 的 server_nonce |
| 61 | 4 | `epoch` | u32 BE | 恒 `0x00000000`（v2 仅定义 epoch 0） |
| 65 | 8 | `seq` | u64 BE | 该 record 的 seq（与 nonce 低 8 字节同值） |
| — | **73** | | | 定长：无长度前缀、无填充、无变体分支 |

**构造函数（规范性定义）**：

```text
build_aad(ctx, msg_type, direction, epoch, seq):
    return BE16(0x0002) ‖ BE16(msg_type) ‖ enc8(direction)
         ‖ ctx.book_id ‖ BE64(ctx.segment_index)
         ‖ ctx.client_nonce ‖ ctx.server_nonce
         ‖ BE32(epoch) ‖ BE64(seq)
```

### 2.2 字段取值来源（发送/接收两侧一致）

| AAD 字段 | CONFIRM_C2S / CONFIRM_S2C | DATA | 接收侧校验锚 |
|---|---|---|---|
| version, msg_type | 本帧帧头 | 本帧帧头 | codec（WP-01 §3.2 步 2/3） |
| direction | 由 msg_type 映射：0x0004→0x01、0x0005→0x02 | 发送方角色：客户端 DATA→0x01、服务端→0x02 | 与 `confirm_body.direction` 副本比对（0x0202） |
| book_id | 会话上下文 | 会话上下文 | 与 body 副本比对（0x0202） |
| segment_index | 本帧字段（经 [state] 校验 `== i`，0x0202） | 会话上下文（DATA 帧不含段号字段） | 与 body 副本比对（0x0202） |
| client_nonce, server_nonce | 会话上下文 | 会话上下文 | 与 body 副本 / 帧内回显比对（0x0203/0x0202） |
| epoch | 本帧字段（[state] 校验 `==0`，0x030A） | 本帧字段（0x030A） | 同左 |
| seq | 本帧字段（[state] 校验 `==0`，0x030B） | 本帧字段（接收方序号算法 §4.2） | §4.2 |

接收方以**会话上下文 + 已校验帧字段**重建 AAD 后 open()：AAD 任何字段被替换（跨会话、跨段、跨连接、跨方向、跨类型搬运密文）均使 tag 失败（0x0201）或被前置 [state] 校验拒绝（0x0202/0x0203/0x030A/0x030B）——这正是 v2 §2"MITM 不能把一段的确认用于另一段/另一连接"的机械实现。

### 2.3 每字段的绑定目的（对照 v2 §4"至少"清单）

| 字段 | 阻断的攻击 |
|---|---|
| version | 跨版本降级/拼接 |
| msg_type | CONFIRM↔DATA 类型混淆、确认密文改作数据密文搬运 |
| direction | 跨方向搬运（叠加 §1.1 推论 1 的 nonce 方向字节） |
| book_id | 错本会话（含"伪造同 ID 异正文"负向夹具，v2 §9 测试 2） |
| segment_index | 跨段/跨会话拼接与重放 |
| client_nonce + server_nonce | 跨连接重放：旧报文带旧 nonce 组合，即使段号巧合也在 AAD 处失败（v2 §4 重放论证） |
| epoch | 未来扩展域预绑定（v2 恒 0） |
| seq | 记录位置绑定（与接收方严格序号算法互为冗余） |

### 2.4 明确排除的字段（及理由）

| 排除项 | 理由 |
|---|---|
| `data_len` | 帧一致性（WP-01 §4.5：`16+data_len == payload_len`，codec 强制）+ tag 覆盖密文本身，使截断/延伸密文必败；AAD 保持 CONFIRM/DATA 统一定长布局 |
| 确认 label（"client-confirm"/"server-confirm"） | label 在密文内（confirm_body 末字段）且 msg_type ∈ AAD 已区分 0x0004/0x0005/0x0006 |
| `session_nonce` | 由双 nonce 逐字节决定（D3）；AAD 同时含两者，严格强于含其 XOR |
| 传输层地址（IP/端口） | 传输无关（loopback/TCP 统一），且双方视角地址本不对称 |
| `features` | 仅握手协商提示，无密码语义（WP-01 D4 位语义） |

---

## 3. 64B 段 → 两个 32B 方向密钥的拆分（验收点 ③）

### 3.1 拆分规则（冻结）

```text
K_c2s := B[i][0x00..0x20)      # 32 字节，前半
K_s2c := B[i][0x20..0x40)      # 32 字节，后半
```

- **K_c2s** 加密本会话全部 C2S 方向 record：CONFIRM_C2S 与客户端发出的每条 DATA；
- **K_s2c** 加密本会话全部 S2C 方向 record：CONFIRM_S2C 与服务端发出的每条 DATA；
- 客户端以 K_c2s 发送、K_s2c 接收；服务端对称。两端持有同一密钥对、角色相反；
- 两个半段**按原字节原顺序直接作为 ChaCha20 的 256-bit key**，不经任何变换（v2 §1.2 原文："这仍是直接取段，没有派生转换"）；
- 拆分在 `SessionCtx` 构造时执行**恰好一次**（split-once）：输入是 `CommittedSegment`（WP-02 T4 返回的 64B，按值消耗），输出两个定长数组；64B 原缓冲在拆分返回前清零（§5.1 L2）。此后运行期不再存在 64B 形态的密钥材料。

### 3.2 禁止清单（规范性；任一即阻断合并——规划 §7.1）

对段、半段或"半段的任意函数"做以下任何操作后充当会话密钥，均属违规：

1. **任何 KDF/哈希**：HKDF、HMAC、CMAC、KBKDF、PBKDF、Argon2、SHA-2/SHA-3、BLAKE2/3、MD/任何 CRC 后截断、"哈希后取 32B"；
2. **任何代数重组**：两半 XOR/OR/AND、循环移位、字节反转、交织、交换前后半顺序（`K_c2s` 恒为**前**半）；
3. **双向复用**：以同一半充当两个方向的密钥；以整段 64B 直接充当某单方向密钥（套件 key 定长 32B）；
4. **混入上下文**：把 `session_nonce`、`book_id`、`epoch`、`seq`、日期等任何附加材料混入密钥；
5. **经由会再派生的 API**：libsodium `crypto_kdf_*`、任何 `derive_key/subkey` 接口、以及 XChaCha20-Poly1305（其 HChaCha20 步骤是内部派生，且属套件变更）；
6. **套件替换**：AES-256-GCM 等其他 AEAD——v2 §1.2 允许在协议注册表中注册替代套件，但**本版注册表只含 ChaCha20-Poly1305**；增补属设计变更（走规划 §7.2 流程），单会话内任何情形不得切换。

**实现锚（WP-10）**：RustCrypto `chacha20poly1305` 下 `Key::from_slice(&half)` 即"复制进定长数组"的视图操作，合规；不存在也不得引入其他密钥装配路径。

### 3.3 与签发层的衔接（为什么能"不派生"）

v2 §1.2 的分层论证是本规则的依据：签发层的信息论性质来自"段内容独立均匀 + 一次性使用"，与是否派生无关；会话层安全性由 ChaCha20-Poly1305 承担。直接拆分不损失安全性（256-bit 均匀密钥），而任何"加强型"派生只会增加实现面与审计面。方向分离的意义：同一密钥绝不在两个方向出现，配合 §1.1 的方向字节，nonce 空间天然按方向二分。

---

## 4. sequence 语义与溢出（验收点 ④）

### 4.1 序号空间与发送方义务

- 空间：u64，**每方向每段独立**；CONFIRM 占 seq=0，DATA 自 1 起严格 +1（WP-01/WP-02 冻结，此处为 record 层可执行化）；
- 每方向发送计数器 `next_seq[d]` 初值 0；构造 record 使用当前值，成功移交传输层后 `+1`；
- **MUST**：同一 (段, 方向) 内任一 seq 值至多使用一次；绝不回绕、绝不复用、绝不跳发。发送算法：

```text
send(direction, plaintext):
    s = next_seq[direction]
    n = record_nonce(session_nonce, direction, s)
    a = build_aad(ctx, msg_type, direction, epoch=0, s)
    record = seal(key[direction], n, a, plaintext)
    handoff(record)                      # 移交传输层
    if s == 2^64 - 1:                    # 序号空间耗尽（见 §4.3）
        SESSION_TERMINATE(SEQ_OVERFLOW)
    else:
        next_seq[direction] = s + 1
```

### 4.2 接收方判定算法（细化 WP-01 §4.5 [record] 判定）

每方向维护 `last_accepted[d]`（初值 None；None ⇒ 期望 0，即首条 record 是该方向 CONFIRM）：

```text
on_record(direction, seq):                       # codec 解码成功之后、open() 之前
    last = last_accepted[direction]
    if last is not None and seq == last:  -> 0x0204 SEQ_REPLAY    # 精确重复
    expected = (0 if last is None else last + 1)                  # last==2^64-1 时无后继
    if seq != expected:                   -> 0x030B SEQ_UNEXPECTED  # 跳号/回退/回绕
    open(key, nonce, aad, sealed)         # tag 失败 -> 0x0201
    last_accepted[direction] = seq        # 仅在 open 成功后推进
```

- **先判 seq 后 open**：确定性（同一畸形输入恒同错误码）、省去无效密码学开销；两类失败对外均表现为静默关闭（WP-01 §5.3），无区分 oracle；
- `last_accepted == 2^64−1` 之后任何到达：`seq == 2^64−1` → 0x0204，其余 → 0x030B——接收侧天然无需"溢出"特判（发送侧已保证不存在 seq=2^64 的 record）；
- 窗口/乱序容忍**不存在**：严格按序（WP-01 §4.5 已冻结，本节仅可执行化）。

### 4.3 溢出定义与终止流程

**定义**：某方向已成功移交 `seq = 2^64−1` 的 record 后，该方向还需要发送任何新 record ⇒ **序号空间溢出**。u64 内不存在下一个值；构造 `seq=0`（回绕）即 nonce 复用（§1.1），绝对禁止。

**终止流程（规范性，全部 MUST）**：

1. **立即停止构造/发送**该方向任何后续 record（防回绕复用 keystream）；
2. **整会话双向终止**：任一方向溢出即终止整个会话（不做半开继续——2^64 记录不可达，见下；半开状态徒增复杂度与审计面）。转移 ST-ABORTED（WP-02 S3），flush 已移交传输层的在途字节后关闭连接，不等待对端；
3. **无线上错误通告**：协议无 ERROR 帧（WP-01 §5.3），对端观测到连接关闭/EOF，按 S6 转 ST-ABORTED；溢出与其它认证失败对对端不可区分（避免区分 oracle）；
4. **zeroize** 双方向密钥与全部秘密副本（§5.1 L4）；
5. **审计**：白名单字段（book_id、段号、generation、结果、错误类别）；错误类别记 `0x030B`（WP-01 §4.5 的 0x030B 语义覆盖序号违规，此处为发送侧镜像情形，不新增错误码——申报见 §8-D4）；
6. **段即 SPENT**（WP-02 T8），绝不复用；无 rekey、无 epoch 递增、无同段续期（WP-02 §5.1 明确不存在 ST-REKEY）。续传唯一路径 = 新仲裁 + 新段的新会话（v2 §5 恢复语义）；
7. 触发时点允许二选一（结果唯一）： 已消耗 `2^64−1` 后的下一次发送请求时； 实现选择在消耗 `2^64−1` 后立即终止。两者均满足 WP-02 S3"2^64−1 后还需发送"判据。

**可达性核算（说明溢出是完备性条款而非运行场景）**：每方向记录数上限 2^64−1 ≈ 1.84×10^19；按 10^6 record/s 亦需约 58.5 万年；按最小帧 40B 计流量下限 ≈ 7.4×10^20 B（约 738 EB）单方向。任何实际会话远早于此耗尽于断线/关闭/段耗尽。

### 4.4 关闭路径汇总（对接 WP-02 §5.2）

| 触发 | 本端动作 | WP-02 转移 | 对端观测 | 密钥处置 |
|---|---|---|---|---|
| 正常 close | flush 在途 record，等对端关闭/超时 | S4 → S5（ST-CLOSING→ST-CLOSED） | EOF → ST-CLOSED | zeroize |
| 序号溢出 | 立即终止，flush 已移交字节 | S3（ST-ABORTED） | EOF → S6 | zeroize |
| tag 失败 / 乱序 / 重复 / 截断 | 立即关闭，不输出未认证明文 | S2 | 连接关闭 | zeroize |
| 传输错误 / 对端 RST / 超时 | 关闭 | S6 | — | zeroize |

---

## 5. 密钥材料生命周期（验收点 ⑤）

### 5.1 生命周期表

| # | 阶段/时点 | 存在的材料 | 规定性动作 | 依据/归属 |
|---|---|---|---|---|
| L0 | 离线成书 | 64B 段 ×N | OS CSPRNG 生成、只读校验介质分发；本规格不涉及会话密钥的"生成"——**密钥从不生成，只从段拆出** | v2 §3；WP-06/17 |
| L1 | `issue()`：双锚 COMMIT fsync 后 pread | 64B 段缓冲（**唯一副本**） | 受保护内存持有（zeroize-on-drop；mlock 尽力，§5.4）；读出至拆分前不得复制到第二缓冲 | WP-02 §1.6/T3/T4；WP-07 |
| L2 | `SessionCtx` 构造：拆分（恰一次，§3.1） | K_c2s、K_s2c（各 32B 定长数组） | 按值消耗 `CommittedSegment`；**拆分返回前清零 64B 原缓冲**；此后运行期密钥材料至多以此两数组存在 | 本规格 §3；WP-10 |
| L3 | 会话进行中（ST-DATA） | 两密钥 + 每记录明文缓冲 | 密钥不出 `SessionCtx`；open 成功的明文以零化包装交付应用，任何失败先清缓冲再返回错误 | WP-10 |
| L4 | 任一终止（close/溢出/tag 失败/EOF/IO/上层取消） | 同上 | Drop-zeroize 两密钥及全部秘密副本；审计仅白名单 | WP-02 T7/T8、S2–S6 |
| L5 | 进程崩溃/正常退出 | — | 密钥**从未持久化**，磁盘无物可清；内存边界靠 §5.4 平台措施；崩溃后恢复 = 新会话新段，绝不重试旧段 | v2 §5/§6；WP-02 §3 |
| L6 | 换本 drain / 旧本退役 | 本体介质 | 离线双人流程，销毁不依赖 rm | v2 §7；WP-17（范围外） |

### 5.2 内存驻留规则（"恰两副本"不变量）

1. 运行期秘密密钥材料**至多以 K_c2s、K_s2c 两个定长数组**存在（L1→L2 拆分瞬间的 64B 缓冲是唯一例外，用后即清）。禁止任何派生副本：诊断快照、临时 Vec、缓存、intern 表；
2. 类型义务（WP-10/规划 §2.2）：承载密钥/段/明文的类型**不得** derive 或实现 `Clone`、`Debug`、`Display`、`PartialEq/Eq`、`Serialize`、`Deserialize`；`Drop` = zeroize（`zeroize`+`secrecy`，规划 §1.2）；核心 crate 禁 `unsafe`；
3. 定长数组（`[u8; 32]`），禁止 `Vec<u8>`/`String`/`Box<[u8]>` 持有密钥（realloc 复制产生不可追踪副本）；
4. panic 安全：unwind 路径 Drop 照常清零；panic 消息/负载不得含材料（§5.3 格式化禁令）；
5. 比较禁令：生产代码不比较密钥（无此需求；避免时序与打印泄露面）；tag 校验只用 AEAD 库内常量时间比较（WP-01 §7.2.3）；
6. AEAD 调用形态：必须使用库的整体 `seal/open`（RFC 8439 构造 = 先验签后释放明文），**禁止**手工拼 ChaCha20 + Poly1305 两段流程（防"先解密输出、后验签失败"的明文泄露路径）。

### 5.3 敏感数据禁入清单（对象 × 渠道矩阵）

**秘密对象（S 类）**：

| # | 对象 | 备注 |
|---|---|---|
| S1 | 段正文 `B[i]`：完整 64B、任意切片/前缀/后缀 | 含 pread 缓冲及其任何拷贝 |
| S2 | 方向密钥 K_c2s / K_s2c：及任意前缀、子串、按位组合 | 含 §3.2 禁止的一切变换输出（违规产物同样是秘密） |
| S3 | AEAD 内部状态：ChaCha 状态矩阵、Poly1305 的 r/s 与累加器 | 库内部状态也不得外泄 |
| S4 | keystream 任意前缀 | 等价于明文 |
| S5 | record 明文：应用业务明文、confirm_body | 含 open 成功待交付的明文 |

**禁入渠道（任一 S 对象 × 任一渠道 = 违规，全部级别生效）**：

| 渠道 | 禁令 |
|---|---|
| 日志（trace/debug/info/…全级别） | 白名单外字段一律不落；白名单 = `book_id、段号、generation、结果、错误类别`（v2 §9、WP-01 §5.3） |
| Debug/Display/错误串/panic 载荷/回溯局部变量 | 类型层已禁 trait（§5.2.2）；错误路径 `format!` 不得接秘密对象 |
| serde/JSON/结构化导出/metrics label | 禁为 S 类实现序列化；metrics 只用白名单维度 |
| core dump / crash report | §5.4 启动前检查禁用 |
| swap | §5.4 |
| `/proc/<pid>/{mem,maps…}` 可见面 | 权限与 ptrace 策略（WP-15 doctor） |
| 临时文件 / 交换文件 / 容器层 | v2 §7 |
| 测试断言输出（`assert_eq!` 双边打印等） | 测试对秘密断言用测试夹具值或哈希（WP-01 §6.1 夹具不属秘密）；CI 输出不得出现真段/真钥 |
| evidence 目录（规划 §5） | 证据只含公开元数据；secret 夹具只入 CI 临时加密卷 |
| 文档/示例/README | 示例只允许 `00..3F` 测试段等夹具值 |

**非秘密澄清**：nonce、AAD、seq、epoch、segment_index、book_id、双 nonce、tag、密文均公开（v2 §4"段号、协议版本、密码本 ID、会话随机数都不是秘密"）；`previous_segment_hash` 是锚允许持有的公开元数据（v2 §7）。但**公开 ≠ 可入日志**：审计仍受白名单约束。

### 5.4 平台边界（部署前提，实现归 WP-09/15）

1. 启动前 `RLIMIT_CORE=0` 且进程 non-dumpable（策略化 fail-closed，`doctor` 检查，高风险拒绝启动）；
2. swap 禁用或全盘加密；密钥页 mlock 尽力（不宣称用户态 mlock 消除历史物理副本）；
3. 诚实声明（v2 §7）：用户态 zeroize 不能担保此前的物理副本（寄存器溢出、SSD wear-leveling）消失；本规格的 zeroize 义务是缩小暴露面，不是信息论擦除。

---

## 6. Golden vectors（canonical nonce/AAD）

### 6.0 向量可验证性声明

本节全部向量由与本规格相互独立的校验器逐字节复算：AEAD 实现先通过 RFC 8439 §2.8.2 KAT，再以本规格 §1.1/§2.1 构造 canonical nonce/AAD 重算全部密文与 tag；接收方序号算法（§4.2）与发送方溢出判据（§4.1）亦经穷举性质断言。校验器留存作者 workspace（`verify_wp03.py`），不入仓。任何评审者可用任一 RFC 8439 实现按 §6.1 夹具独立复算。向量均为小写连续 hex。**本节即 WP-01 决策 D5 承诺的"冻结 WP-03 后追加的正式 KAT 向量"**。

### 6.1 测试夹具（沿用 WP-01 §6.1，跨文档可链）

| 夹具 | 值 |
|---|---|
| BOOK_ID | `00112233445566778899AABBCCDDEEFF` |
| CLIENT_NONCE | `101112131415161718191A1B1C1D1E1F` |
| SERVER_NONCE | `202122232425262728292A2B2C2D2E2F` |
| SESSION_NONCE | `3030…30`（16×`30`，= C⊕S，D3） ⇒ `session_domain = 303030` |
| 测试段 0（64B） | `00 01 … 3F` ⇒ K_c2s = `00..1F`，K_s2c = `20..3F`（§3 直接拆分） |
| DATA 明文 | ASCII `"Hello, otp-term!"`（16B） |

### 6.2 nonce 向量（§1.1）

| 向量 | 场景 | hex（12B） |
|---|---|---|
| N-V1 | C2S，seq=0（CONFIRM_C2S） | `303030010000000000000000` |
| N-V2 | S2C，seq=0（CONFIRM_S2C） | `303030020000000000000000` |
| N-V3 | C2S，seq=1（首条 DATA） | `303030010000000000000001` |
| N-V4 | C2S，seq=2^32（跨 32 bit 边界） | `303030010000000100000000` |
| N-V5 | S2C，seq=2^64−1（最后可用序号） | `30303002ffffffffffffffff` |

唯一性抽样校验（13 个不同 seq 的 C2S nonce 互异、同 seq 双方向互异）随校验器运行；证明见 §1.2。

### 6.3 AAD 向量（§2.1，各 73B）

| 向量 | 场景 | hex |
|---|---|---|
| A-V1 | CONFIRM_C2S（msg=0x0004, dir=01, seg=0, epoch=0, seq=0） | `000200040100112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f000000000000000000000000` |
| A-V2 | CONFIRM_S2C（msg=0x0005, dir=02, seq=0） | `000200050200112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f000000000000000000000000` |
| A-V3 | DATA C2S（msg=0x0006, dir=01, seq=1） | `000200060100112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f000000000000000000000001` |

### 6.4 AEAD KAT（正式向量；明文 = WP-01 §6.6 两个 CONFIRM-BODY-POS 定稿向量与 DATA 明文）

| 向量 | 构成 | sealed = ct‖tag（hex，连续） | tag（末 16B） |
|---|---|---|---|
| K-V1 | seal(K_c2s, N-V1, A-V1, CONFIRM-BODY-POS-001[87B])；ct(87B)‖tag(16B) | `2d7bec766d3da3393e54bfc4078c3d32a21276d0268aba2d30632259fce04e58b7b6e5c5610b9a031cb80dac6dedcb4fd9f2dbd37cd07850bb9569d9d0b6de562309b98e7f513cb5c32536a5254accf5e462debf9c4457d96242d7396bc0fb4e2f81cd33ab7fbd` | `d96242d7396bc0fb4e2f81cd33ab7fbd` |
| K-V2 | seal(K_s2c, N-V2, A-V2, CONFIRM-BODY-POS-002[87B]) | `c2578c0aea067ae4d03750f90b7c1bdc7aef0f7a136c731a061fbfe878a29e8672b704704848649dedc6cd922ee6b63403c6c37bb1039e2a206a32b6e3027cd87eaedfc4a7de6005efd0c07fd1e13929b1ea54ec22a773d00aae7a47a5b1da8d168558d823056d` | `d00aae7a47a5b1da8d168558d823056d` |
| K-V3 | seal(K_c2s, N-V3, A-V3, "Hello, otp-term!"[16B])；ct(16B)‖tag(16B) | `6ce1e72949eab99255ba29ecb16e446a1142284a43daab7fda7babf52389bafb` | `1142284a43daab7fda7babf52389bafb` |

KAT 负性质（随校验器验证，供 WP-10 断言）：K-V1 在"AAD 首字节翻转 1 bit / 换 N-V2 / 换 K_s2c / 换 A-V3"四种错误上下文下 open 全部失败。

### 6.5 整帧向量（canonical nonce/AAD 的完整帧，WP-05/10/19 可直接回放）

| 向量 | 说明 | hex（长度） |
|---|---|---|
| FRAME-CONFIRM-C2S-K1 | CONFIRM_C2S 帧（147B）：seg=0、session_nonce、epoch=0、seq=0、sealed=K-V1 | `000200040000008b0000000000000000303030303030303030303030303030300000000000000000000000002d7bec766d3da3393e54bfc4078c3d32a21276d0268aba2d30632259fce04e58b7b6e5c5610b9a031cb80dac6dedcb4fd9f2dbd37cd07850bb9569d9d0b6de562309b98e7f513cb5c32536a5254accf5e462debf9c4457d96242d7396bc0fb4e2f81cd33ab7fbd` |
| FRAME-DATA-K1 | DATA 帧（56B）：epoch=0、seq=1、data_len=32、data=K-V3 | `0002000600000030000000000000000000000001000000206ce1e72949eab99255ba29ecb16e446a1142284a43daab7fda7babf52389bafb` |

### 6.6 记录层负例

| 向量 | 场景 | hex | 期望 |
|---|---|---|---|
| REC-NEG-1 | FRAME-CONFIRM-C2S-K1 篡改 tag 末字节（bd→bc） | `000200040000008b0000000000000000303030303030303030303030303030300000000000000000000000002d7bec766d3da3393e54bfc4078c3d32a21276d0268aba2d30632259fce04e58b7b6e5c5610b9a031cb80dac6dedcb4fd9f2dbd37cd07850bb9569d9d0b6de562309b98e7f513cb5c32536a5254accf5e462debf9c4457d96242d7396bc0fb4e2f81cd33ab7fbc` | codec Ok；[record] 0x0201 |
| REC-NEG-2 | 已收 CONFIRM(0)、DATA(1) 后到达 seq=2 之外的 seq=2 跳号帧（DATA 帧 seq=2） | `0002000600000030000000000000000000000002000000206ce1e72949eab99255ba29ecb16e446a1142284a43daab7fda7babf52389bafb` | [record] 0x030B |
| REC-NEG-3 | FRAME-DATA-K1 原样重放（已收 seq=1 后再收） | `0002000600000030000000000000000000000001000000206ce1e72949eab99255ba29ecb16e446a1142284a43daab7fda7babf52389bafb` | [record] 0x0204 |
| REC-NEG-4 | 把 K-V1 密文拼进 DATA 帧（data_len=103，跨记录类型搬运） | `0002000600000077000000000000000000000001000000672d7bec766d3da3393e54bfc4078c3d32a21276d0268aba2d30632259fce04e58b7b6e5c5610b9a031cb80dac6dedcb4fd9f2dbd37cd07850bb9569d9d0b6de562309b98e7f513cb5c32536a5254accf5e462debf9c4457d96242d7396bc0fb4e2f81cd33ab7fbd` | [record] 0x0201（AAD msg_type 不符） |

行为负例（无固定字节，供 WP-10/14 断言）：发送侧在 seq=2^64−1 后请求发送 ⇒ 必须整会话终止且不产生任何新帧；接收侧 wrap/回退 ⇒ 0x030B（§4.2 算法已穷举）。

### 6.7 向量 → 测试转换表

| 向量组 | WP-10 / WP-14 / WP-19 断言 |
|---|---|
| N-V1..5 | `record_nonce` 逐字节等于表值；任意 (dir, seq) 满足 §1.1 公式（性质测试采样） |
| A-V1..3 | `build_aad` 逐字节等于表值；长度恒 73 |
| K-V1..3 | seal(KAT) 输出逐字节等于表值；四种错误上下文 open 失败 |
| FRAME-* | 与 WP-01 codec 往返一致（decode→再编码恒等）；整帧 open 成功 |
| REC-NEG-* | §4.2 算法给出表中确定错误码；任何失败不输出明文、不 panic |
| 边界（性质测试） | seq ∈ {0, 1, 2^32, 2^63, 2^64−1} 的 nonce 构造无回绕；随机 fuzz record 层无 panic、无 secret 日志 |

---

## 7. WP-10 实现核对清单与 API 草案

### 7.1 核对清单（评审/验收逐项打勾）

- [ ] `record_nonce`：恰 12B；域=ζ[0:3] 纯切片；direction 字节 0x01/0x02；seq 全宽 BE；无任何哈希/随机
- [ ] `build_aad`：恰 73B；9 字段、本规格字段序；CONFIRM 与 DATA 共用
- [ ] 拆键：`B[i][0:32]`/`B[i][32:64]` 直接切片；§3.2 六条禁令逐条无违反（grep 审计点：无 kdf/derive/hash 调用链）
- [ ] 发送：seq 严格 +1、溢出按 §4.3 七步终止；无回绕路径（类型上 `next_seq` 推进用 `checked_add`）
- [ ] 接收：§4.2 算法；先判 seq 后 open；无窗口
- [ ] 密钥类型：无 Clone/Debug/Display/Eq/Serialize；Drop-zeroize；定长数组；恰两副本不变量
- [ ] 明文路径：仅库整体 seal/open；失败先清缓冲
- [ ] §6 全部向量 + 负例通过；CI 日志扫描无 S 类对象

### 7.2 API 草案（`otp-session`，签名示意）

```rust
pub struct SessionNonceDomain([u8; 3]);            // = session_nonce[0:3]，公开值
pub enum Direction { C2s = 0x01, S2c = 0x02 }

pub fn record_nonce(d: &SessionNonceDomain, dir: Direction, seq: u64) -> [u8; 12];

pub struct SessionCtx { /* book_id, client_nonce, server_nonce, segment_index,
                           domain, keys, next_seq/last_accepted per direction */ }
impl SessionCtx {
    pub fn build_aad(&self, mt: MsgType, dir: Direction, epoch: u32, seq: u64) -> [u8; 73];
}

pub struct SessionKeys { c2s: [u8; 32], s2c: [u8; 32] }   // §5.2 类型义务
impl SessionKeys {
    pub fn split(seg: CommittedSegment) -> Self;   // 恰一次；按值消耗，seg.drop 清零 64B
}
```

---

## 8. 决策点与差异申报

### 8.1 决策点（请评审逐条确认；否决则改本文件并重算向量）

| # | 决策 | 理由 | 若否决 |
|---|---|---|---|
| D1 | nonce 域 = `session_nonce[0:3]`（纯切片） | 设计书 §9"由 book_id/session_nonce 域…构造"中，session_nonce 对同本不同会话有区分度而 book_id 没有；book_id 以全宽 16B 进 AAD。纯切片可逐字节 review，零实现面 | 改 ζ 折叠或 book_id 混入，重算全部向量 |
| D2 | seq 全宽 64 bit 占 nonce 低 8 字节，方向占 1 字节 | 唯一可证明布局：截断 seq 即 nonce 复用（§1.3）；方向字节防御缺陷本对称段（§1.2 推论 1） | 无安全等价备选 |
| D3 | AAD 73B 定长、此字段序；不含 data_len/label/session_nonce | 满足 v2 §4"至少"清单；定长免长度歧义；排除项论证见 §2.4 | 调整需同步 WP-01 负例面与向量 |
| D4 | 溢出审计类别复用 0x030B；任一方向溢出整会话终止 | 不动 WP-01 错误码注册表（无新码上线）；半开继续无运行意义（§4.3 核算） | 若需独立码，走 WP-01 注册表修订卡 |
| D5 | 套件钉死 IETF ChaCha20-Poly1305（96-bit nonce）；XChaCha 禁用 | RFC 8439 是 v2 §1.2 命名依据；XChaCha 含 HChaCha20 内部派生，违反 §3.2 且属套件变更 | 增补套件走设计变更（规划 §7.2） |
| D6 | 密钥驻留 = 恰两个定长 [u8;32]，split-once，64B 缓冲即弃 | 最小副本面（规划 §2.2 CommittedSegment 约束的自然延伸） | — |

### 8.2 差异申报（规划 §7.2 口径）

| # | 事项 | 性质 | 处置 |
|---|---|---|---|
| DD0 | 无语义级设计缺陷申报 | — | 实现期若发现冲突，按规划 §7.2 走 DD 报告 |
| DD1 | 设计书 §9"96-bit nonce 由 book_id/session_nonce 域与方向、序号构造"未定具体域宽与切法 | 解读 + 构造补全 | 本规格 §1.1（D1/D2）给出唯一构造；如栋梁/安全审计裁定其他域来源，提交 DD |
| DD2 | 设计书 §9"序号溢出立即终止会话"未定终止细则 | 细化 | §4.3 七步流程；审计类别映射 0x030B 见 D4 |

---

## 9. 验收映射

| 验收口径 | 本规格条款 |
|---|---|
| 任务① nonce 逐 bit 布局 + 唯一性论证 | §1.1 布局与构造函数；§1.2 引理/定理/推论；§1.3 备选否决；§1.4 禁令 |
| 任务② AAD 逐字段定长清单 | §2.1（73B 布局）、§2.2 来源、§2.3 绑定目的、§2.4 排除项 |
| 任务③ 段拆分明确禁派生 | §3.1 冻结规则；§3.2 六类禁令（KDF/哈希/重组/复用/混入/XChaCha）；§3.3 依据 |
| 任务④ sequence 溢出语义完整 | §4.1 发送方义务；§4.2 接收方算法；§4.3 溢出定义与七步终止；§4.4 关闭路径 |
| 任务⑤ 敏感数据禁入清单 | §5.1 生命周期 L0–L6；§5.2 恰两副本不变量；§5.3 S 类对象 × 渠道矩阵；§5.4 平台边界 |
| 任务⑥ 规格入仓 docs/specs/ | 本文件提交于 `docs/specs/wp03-nonce-aad-key-lifecycle.md`（分支 architect/task-32） |
| 规划 WP-10 验收"直接照此构造" | §1.1/§2.1 构造函数 + §6 全部向量 + §7.1 核对清单 + §7.2 API 草案 |
| 规划 M0"nonce/AAD 逐字段固定并证明同方向同段内 sequence 唯一；序号溢出终止" | §1.2、§4.3 |
| 规划 §7.1 阻断条"nonce 不能机械证明唯一 / 溢出后仍继续 / 段进 KDF / 双向复用钥" | §1.2、§4.3、§3.2 |
| WP-01 D5"冻结后追加正式 KAT" | §6.4–6.5 |
