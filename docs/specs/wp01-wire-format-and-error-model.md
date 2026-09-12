# OTP 终端协议 v2 — WP-01 线格式、严格编码规则与错误模型规格

| 项 | 内容 |
|---|---|
| 任务 | 论坛任务 #30（WP-01 重发卡；前序 #26 两轮：首交误交脚本被打回，v1.0 重交后未及审计即随卡重发，本版 v1.1 为其向量自检修订版）· 工作包 WP-01（规划 §4：协议线格式与错误模型规格） |
| 设计依据 | `otp_terminal_protocol_v2.md` §1/§2/§4/§9（核心语义冻结，本规格不修改任何语义）；实现规划 §1.2（自定义严格长度前缀二进制 codec）、§2（`otp-codec` 职责） |
| 作者 | 斗拱（architect） |
| 状态 | 待评审；评审冻结后 WP-05（codec）/ WP-19（独立实现）以本文件为唯一线格式依据 |
| 范围内 | 6 类消息逐字节布局；严格长度前缀编码 canonical 规则与拒绝条件；统一错误码模型；每类消息正例+负例 golden vectors |
| 范围外 | 状态机与消息时序（WP-02）；96-bit nonce/AAD 规范构造与序号溢出（WP-03）；密码本文件/锚格式（WP-02/WP-06） |
| 修订 | v1.1（本次，任务 #30）：全文 38 条向量（正 12 + 负 26）逐字节独立复算校验通过（校验方法见 §6.0），修复 v1.0 三处向量缺陷与向量计数误报（§8）；v1.0（#26 重交）：以规格文本交付；v0.9（#26 首交）：误以 Python 生成器脚本充当规格，被审计打回。向量字节由经 RFC 8439 §2.8.2 KAT 校验的参考实现计算（见 §6.1） |

**评审重点**：§7 列出 6 个格式层决策点（D1–D6）。它们是对冻结设计书的*格式补全*而非语义修改，请评审逐条确认；任何一条被否决时只需改本文件并重算向量，不影响设计书。

---

## 1. 分层、约定与总则

### 1.1 分层

本规格覆盖以下两层，并把"谁执行哪条校验"写死，消除实现歧义：

| 层 | 职责 | 归属 |
|---|---|---|
| **framing（成帧）** | 从字节流切出一条完整消息：读 8 字节帧头，校验 version/msg_type/payload_len，再读 payload_len 字节 | WP-01 / `otp-codec` |
| **codec（消息编解码）** | 对单条消息 payload 按固定字段序解码/再编码；所有格式拒绝判定（§3）在此层 | WP-01 / `otp-codec` |
| record（AEAD 记录） | sealed/data 字段的开封、tag 校验、序号推进 | WP-03 / WP-10 |
| state（状态机/握手） | 消息时序、仲裁语义、绑定一致性校验 | WP-02 / WP-11 |

codec 层**不做任何密码学运算**：`sealed`/`data` 在本层是不透明字节串，其内容由 §4.4/§4.5 与 WP-03 约束。

### 1.2 基本约定

- 字节序：**所有多字节整数一律大端（big-endian / network order）**。
- 偏移量：§4 各表以"帧首字节 = 0"计；十六进制转储的左列偏移为十六进制。
- 原语类型：
  - `u8 / u16 / u32 / u64`：无符号定点宽整数，无符号位、无补码、无默认值；
  - `BYTES(n)`：恰好 n 字节；
  - 变长字段（仅 `DATA.data` 一处）：`u32` 长度前缀 + 字节串，上限见 §4.5。
- 传输假设：有序可靠字节流（TCP/loopback）。帧自定界，可背靠背拼接；无帧间填充。
- 所有长度字段的单位是**字节**。

### 1.3 常量

| 常量 | 值 | 说明 |
|---|---:|---|
| `VERSION` | 0x0002 | v2；不等于此值即拒绝（D1） |
| `MAX_APP_PLAINTEXT` | 65536 | 单条 DATA 的应用明文上限 |
| `TAG_LEN` | 16 | Poly1305 tag |
| `MAX_DATA_FIELD` | 65552 | 65536 + 16 |
| `MAX_FRAME_PAYLOAD` | 65568 | DATA payload 上限（= 16 + 65552） |
| `MAX_FRAME` | 65576 | 全协议最大帧长（= 8 + 65568） |

---

## 2. 帧格式与消息注册表

### 2.1 帧头（8 字节，所有消息相同）

| 帧偏移 | 长度 | 字段 | 类型 | 约束（违反→错误码，见 §5） |
|---|---:|---|---|---|
| 0 | 2 | `version` | u16 | 恒为 0x0002；否则 0x0301 |
| 2 | 2 | `msg_type` | u16 | ∈ {0x0001..0x0006}；否则 0x0305 |
| 4 | 4 | `payload_len` | u32 | 按类型精确/范围（§2.2）；否则 0x0302 |
| 8 | `payload_len` | payload | — | 各消息布局见 §4 |

`payload_len` 在读消息体**之前**校验：实现必须先确认它落在该类型的合法集合内，才允许按它分配/读取缓冲（防长度放大攻击；上限 `MAX_FRAME_PAYLOAD` = 65568）。

### 2.2 消息类型注册表

| msg_type | 名称 | 方向 | payload 长度 | 帧总长 | 阶段 |
|---:|---|---|---|---|---|
| 0x0001 | HELLO | C→S | 恰好 44 | 52 | 仲裁前 |
| 0x0002 | ARBITRATE | S→C | 恰好 25 | 33 | 仲裁 |
| 0x0003 | ISSUE_REQUEST | C→S | 恰好 40 | 48 | 签发 |
| 0x0004 | CONFIRM_C2S | C→S | 恰好 139 | 147 | 确认 |
| 0x0005 | CONFIRM_S2C | S→C | 恰好 139 | 147 | 确认 |
| 0x0006 | DATA | 双向 | 32 .. 65568 | 40 .. 65576 | 数据 |

0x0007..0xFFFF：未分配。接收未分配类型 → 0x0305（不允许"跳过未知消息"）。

### 2.3 方向约束

codec 解码 API 携带本端角色（client/server）。方向不符 → 0x0306（例如：服务端收到 msg_type=0x0002）。消息**时序**合法性（如 DATA 早于 CONFIRM_S2C）不在 codec 层，由 WP-02 状态机以 0x0309 判定。

---

## 3. 严格长度前缀编码规则（canonical）

### 3.1 canonical 形式

一条消息的合法字节串由以下规则**唯一确定**（对给定字段值有且仅有一种编码）：

1. 字段按 §4 各表顺序排列，无标签、无可选字段、无变体分支——采用**位置式编码**，从结构上排除"未知字段"的歧义（设计书 §4"字段顺序和最大长度固定"的直接实现）。
2. 定宽整数按 §1.2 编码；`BYTES(n)` 恰好 n 字节；唯一变长字段 `DATA.data` 以 u32 长度前缀界定。
3. 定长消息（0x0001..0x0005）的 `payload_len` 必须等于注册表常量；DATA 的 `payload_len` 必须落在 [32, 65568]。
4. 无填充、无对齐、无归一化步骤：解析成功的输入**本身就是 canonical 字节**。
5. **再编码恒等**：`encode(decode(x)) == x` 逐字节成立。这是 canonical 性的可测试判据（WP-05 性质测试）。

### 3.2 解码校验顺序（确定性要求）

对输入 buf 与角色 role，解码按以下顺序执行。**顺序是规范的一部分**：同一畸形输入必须总是产生同一错误码（WP-05 负例向量按此锁定）。

```text
decode(role, buf):
  1. len(buf) < 8                          -> 0x0308 FRAME_TRUNCATED
  2. buf[0:2]  != 0x0002                   -> 0x0301 BAD_VERSION
  3. buf[2:4]  not in {1..6}               -> 0x0305 UNKNOWN_MSG_TYPE
  4. payload_len := u32(buf[4:8])
     定长类型: payload_len != 常量          -> 0x0302 BAD_LENGTH
     DATA:       payload_len ∉ [32,65568]  -> 0x0302 BAD_LENGTH
  5. len(buf) < 8+payload_len              -> 0x0308 FRAME_TRUNCATED
     len(buf) > 8+payload_len              -> 0x0303 TRAILING_BYTES
  6. direction(msg_type) 与 role 不符       -> 0x0306 WRONG_DIRECTION
  7. 按 §4 表逐字段解析 payload：
     字段所需字节超出剩余 payload           -> 0x0302 BAD_LENGTH
     末字段解析完后 payload 有剩余字节       -> 0x0303 TRAILING_BYTES
  8. 枚举/组合校验（§4 各字段"约束"列）     -> 0x0304 BAD_ENUM / 0x0302
  返回解码结果（字段值 + 原始字节）
```

流式读取等价于：先攒到 8 字节执行 1–4（未通过即关闭，不读消息体），再按 payload_len 收齐后执行 5–8。EOF 出现在 payload 中途 → 0x0308。

### 3.3 拒绝条件总表

| 拒绝条件 | 错误码 | 说明 |
|---|---|---|
| 尾随字节（buf 长于帧 / payload 解析后有剩余） | 0x0303 | §3.2 步骤 5/7 |
| 超长/欠长（payload_len 非精确、data_len 越界、字段字节不足） | 0x0302 | 步骤 4/7/8 |
| 帧截断（输入不足 8+payload_len，含 EOF） | 0x0308 | 步骤 1/5 |
| 未知版本 | 0x0301 | 步骤 2 |
| 未知消息类型（"未知必选消息"） | 0x0305 | 步骤 3 |
| 未知枚举值（ARBITRATE.result、内层 direction 等） | 0x0304 | 步骤 8 |
| 消息方向与角色不符 | 0x0306 | 步骤 6 |

位置式编码不存在"带标签的未知字段"；其等价物即上表的未知类型/未知版本/未知枚举三类。任何拒绝都 **fail closed**：关闭连接、按 §5 计段费、写审计类别，绝不 best-effort 解析或降级。

---

## 4. 消息逐字节布局

以下各表"帧偏移"均自帧首字节计。字段"约束"列中，标 **[codec]** 者在解码时强制；标 **[state]** 者由握手/记录层校验（列出以便负例向量定位归属层）。

### 4.1 HELLO（0x0001，C→S，帧 52B）

对应设计书 §4 `HELLO(version, book_id, client_nonce, client_pointer, features)`；`version` 由帧头承载（决策 D1）。

| 帧偏移 | 长度 | 字段 | 类型 | 约束 |
|---|---:|---|---|---|
| 0 | 2 | version | u16 | =0x0002 **[codec]** |
| 2 | 2 | msg_type | u16 | =0x0001 **[codec]** |
| 4 | 4 | payload_len | u32 | =44 **[codec]** |
| 8 | 16 | book_id | BYTES(16) | 任意 16B **[codec]**；与本端配置不符 → 0x0100 **[state]** |
| 24 | 16 | client_nonce | BYTES(16) | 由客户端 CSPRNG 生成；非秘密 |
| 40 | 8 | client_pointer | u64 | 任意 u64 **[codec]**；≥ segment_count 视为不可能状态，按 CLIENT_AHEAD 处理 **[state]** |
| 48 | 4 | features | u32 | 任意 u32 **[codec]**；位语义见 D4，未知位必须忽略 **[state]** |

`features` 位定义：`bit0 (0x00000001) RECONNECT`（恢复流程预留，WP-16）；其余位未定义，接收端忽略。

### 4.2 ARBITRATE（0x0002，S→C，帧 33B）

对应设计书 §4 `ARBITRATE(server_pointer, result)`；补 `server_nonce`（决策 D2）。

| 帧偏移 | 长度 | 字段 | 类型 | 约束 |
|---|---:|---|---|---|
| 0 | 2 | version | u16 | =0x0002 **[codec]** |
| 2 | 2 | msg_type | u16 | =0x0002 **[codec]** |
| 4 | 4 | payload_len | u32 | =25 **[codec]** |
| 8 | 16 | server_nonce | BYTES(16) | 服务端 CSPRNG 生成，逐连接唯一；ISSUE_REQUEST 必须回显 |
| 24 | 8 | server_pointer | u64 | 语义随 result，见下表 |
| 32 | 1 | result | u8 | ∈{0..4}，否则 0x0304 **[codec]** |

`result` 与 `server_pointer` 的规范组合（**[codec]** 强制组合校验，违反 → 0x0304；语义由 **[state]** 判定）：

| result | 名称 | server_pointer 规范值 | 语义（设计书 §4） | 客户端动作 |
|---:|---|---|---|---|
| 0x00 | OK | i = 双方一致指针 | server_pointer == client_pointer | 发 ISSUE_REQUEST(i) |
| 0x01 | SERVER_AHEAD | 服务端 next（> client_pointer） | 服务端领先 | 跳到 i、废弃间隙段、只前进 |
| 0x02 | EXHAUSTED | = segment_count N | 段耗尽 | 终止，离线换本 |
| 0x03 | BOOK_MISMATCH | **恒为 0** | book_id 不符 | 终止，离线核对配对 |
| 0x04 | CLIENT_AHEAD | 服务端 next（< client_pointer） | 客户端领先，服务端绝不回退 | 进入恢复/人工路径（WP-02/16） |

客户端 **[state]** 校验：OK 时 server_pointer==client_pointer、SERVER_AHEAD 时 >、EXHAUSTED 时 == 本端 N，违反 → 0x0307。

### 4.3 ISSUE_REQUEST（0x0003，C→S，帧 48B）

对应设计书 §4 `ISSUE_REQUEST(chosen_pointer=i, client_nonce, server_nonce)`。

| 帧偏移 | 长度 | 字段 | 类型 | 约束 |
|---|---:|---|---|---|
| 0 | 2 | version | u16 | =0x0002 **[codec]** |
| 2 | 2 | msg_type | u16 | =0x0003 **[codec]** |
| 4 | 4 | payload_len | u32 | =40 **[codec]** |
| 8 | 8 | chosen_pointer | u64 | 任意 u64 **[codec]**；≠ 仲裁约定 i → 0x0307 **[state]** |
| 16 | 16 | client_nonce | BYTES(16) | 必须逐字节等于 HELLO.client_nonce，否则 0x0203 **[state]** |
| 32 | 16 | server_nonce | BYTES(16) | 必须逐字节等于 ARBITRATE.server_nonce，否则 0x0203 **[state]** |

服务端在以上三项全部通过后才进入 fail-to-waste 预留（规划 §0.3）；任何失败 → 关闭且**不消耗段**。

### 4.4 CONFIRM_C2S（0x0004，C→S，帧 147B）与 CONFIRM_S2C（0x0005，S→C，帧 147B）

对应设计书 §4 `CONFIRM(i, session_nonce, seq=0, AEAD_K("client-confirm"/"server-confirm", AAD))`。外层不设 sealed 长度字段：sealed 恒 103 字节（决策 D6）。

**外层帧：**

| 帧偏移 | 长度 | 字段 | 类型 | 约束 |
|---|---:|---|---|---|
| 0 | 2 | version | u16 | =0x0002 **[codec]** |
| 2 | 2 | msg_type | u16 | =0x0004 / 0x0005 **[codec]**；方向不符 → 0x0306 |
| 4 | 4 | payload_len | u32 | =139 **[codec]** |
| 8 | 8 | segment_index | u64 | 任意 u64 **[codec]**；≠ 本会话已签发 i → 0x0202 **[state]** |
| 16 | 16 | session_nonce | BYTES(16) | = client_nonce ⊕ server_nonce（D3）；不符 → 0x0203 **[state]** |
| 32 | 4 | epoch | u32 | 任意 u32 **[codec]**；≠0 → 0x030A **[state]** |
| 36 | 8 | seq | u64 | 任意 u64 **[codec]**；≠0 → 0x030B **[state]** |
| 44 | 103 | sealed | BYTES(103) | 不透明；= AEAD 密文(87) ‖ tag(16)；开封失败 → 0x0201 **[record]** |

**内层确认明文 confirm_body（sealed 解密后，恰好 87B，codec 另提供 body 解码器）：**

| body 偏移 | 长度 | 字段 | 类型 | 约束 |
|---|---:|---|---|---|
| 0 | 2 | version | u16 | =0x0002 **[codec]** |
| 2 | 16 | book_id | BYTES(16) | 任意 16B **[codec]**；≠ 会话 book_id → 0x0202 **[state]** |
| 18 | 8 | segment_index | u64 | ≠ 外层 i → 0x0202 **[state]** |
| 26 | 16 | client_nonce | BYTES(16) | ≠ HELLO 值 → 0x0203 **[state]** |
| 42 | 16 | server_nonce | BYTES(16) | ≠ ARBITRATE 值 → 0x0203 **[state]** |
| 58 | 1 | direction | u8 | ∈{0x01=C2S, 0x02=S2C}，否则 0x0304 **[codec]**；与消息方向不符 → 0x0202 **[state]** |
| 59 | 4 | epoch | u32 | ≠0/≠外层 → 0x030A/0x0202 **[state]** |
| 63 | 8 | seq | u64 | ≠0/≠外层 → 0x030B/0x0202 **[state]** |
| 71 | 2 | msg_type | u16 | =外层类型，≠ → 0x0202 **[state]** |
| 73 | 14 | label | BYTES(14) | C2S: `"client-confirm"`、S2C: `"server-confirm"`（逐字节比较）→ 不符 0x0202 **[state]** |

body 输入长度 ≠87 → 0x0302 **[codec]**。设计书要求"确认明文应包含上述字段的副本"（§4）——上表即其 canonical 布局；全部副本一致才认证通过。tag 无效、副本不一致、方向/段号/nonce 不符统一按 §5 归入认证失败（0x0200 类），且该段已消耗即浪费、绝不复用、不得降级。

### 4.5 DATA（0x0006，双向，帧 40..65576B）

对应设计书 §4 `DATA(epoch=0, sequence=1, ...)`；序号空间与 CONFIRM 连续：CONFIRM 占 seq=0，DATA 自 1 起、每方向每段内严格 +1（唯一性证明归 WP-03）。

| 帧偏移 | 长度 | 字段 | 类型 | 约束 |
|---|---:|---|---|---|
| 0 | 2 | version | u16 | =0x0002 **[codec]** |
| 2 | 2 | msg_type | u16 | =0x0006 **[codec]** |
| 4 | 4 | payload_len | u32 | ∈[32, 65568] **[codec]** |
| 8 | 4 | epoch | u32 | 任意 u32 **[codec]**；≠0 → 0x030A **[state]**（v2 仅定义 epoch 0） |
| 12 | 8 | seq | u64 | 任意 u64 **[codec]**；见下 **[record]** |
| 20 | 4 | data_len | u32 | ∈[16, 65552] **[codec]**；且 16+data_len 必须 == payload_len（由 §3.2 步骤 7 隐式保证） |
| 24 | data_len | data | BYTES(data_len) | 不透明；= 应用明文密文(len-16) ‖ tag(16)；tag 失败 → 0x0201 **[record]** |

`seq` **[record]** 判定：等于期望下一序号 → 通过；精确重复已收序号 → 0x0204（重放）；跳号/乱序/回退 → 0x030B。应用明文长度 = data_len − 16 ∈ [0, 65536]（0 允许：空记录仅含 tag）。

---

## 5. 错误模型

### 5.1 两套编号

1. **ARBITRATE.result（u8，线可见）**：仅仲裁结局四值 + OK（§4.2）。这是协议中**唯一**向对端传达错误语义的载体。
2. **统一错误码（u16，实现内）**：供 API 返回、审计日志、测试断言（WP-05/14/19）使用，不上线。两套编号的映射见 §5.2。

### 5.2 统一错误码注册表

高字节为类别：0x01 仲裁/密码本，0x02 认证，0x03 协议违规，0x04 内部。伞码（0x0200/0x0300/0x0400）用于只需类别的场合；子码用于审计与测试。

| 码 | 名称 | 触发条件（检测层） | 线上可见行为 | 段计费 | 处理方 |
|---|---|---|---|---|---|
| 0x0100 | BOOK_MISMATCH | 服务端：HELLO.book_id ≠ 本端配置（握手） | ARBITRATE(result=3) 后关闭 | 不耗段 | 客户端+运维：离线核对密码本配对 |
| 0x0101 | EXHAUSTED | 仲裁或签发时 next ≥ segment_count（握手/分配器） | ARBITRATE(result=2, sp=N) 后关闭 | 无段可耗 | 运维：离线换本（双端同 ID 原子切换，WP-17） |
| 0x0102 | CLIENT_AHEAD | client_pointer > 服务端 next（握手） | ARBITRATE(result=4) 后关闭；服务端绝不回退 | 不耗新段 | 人工恢复路径（WP-02/16）：客户端证明锚状态或废弃孤立段后重连 |
| 0x0103 | SERVER_AHEAD | 服务端 next > client_pointer（握手） | ARBITRATE(result=1, i=next)，会话可继续 | 间隙段全部废弃（浪费不回收） | 客户端：跳到 i，只前进 |
| 0x0200 | AUTH_FAILED（伞） | 见 0x0201–0x0204（record/握手） | **静默关闭，不区分子类** | 涉及段已预留 → 浪费，绝不复用 | 接收端：关闭、审计、不得降级 |
| 0x0201 | ├ TAG_INVALID | sealed/data AEAD 打不开（record） | 同上 | 同上 | 同上 |
| 0x0202 | ├ SEGMENT_BINDING | 内层副本任一不符（错误段号/方向/label/msg_type/book_id/version，record+state） | 同上 | 同上 | 同上 |
| 0x0203 | ├ NONCE_MISMATCH | session_nonce/nonce 回显不符（含旧 nonce）（state） | 同上 | 同上 | 同上 |
| 0x0204 | └ SEQ_REPLAY | 精确重复序号（重放旧 record）（record） | 同上 | 同上 | 同上 |
| 0x0300 | PROTOCOL_VIOLATION（伞） | 见 0x0301–0x030B（codec/状态机） | **静默关闭** | 签发前不耗段；签发后该段浪费 | 接收端：关闭、审计 |
| 0x0301 | ├ BAD_VERSION | version ≠ 0x0002（codec，§3.2 步 2） | 同上 | 同上 | 接收端 |
| 0x0302 | ├ BAD_LENGTH | payload_len 非精确/越界；字段字节不足；body≠87B；data_len 越界（codec） | 同上 | 同上 | 接收端 |
| 0x0303 | ├ TRAILING_BYTES | 尾随字节（codec） | 同上 | 同上 | 接收端 |
| 0x0304 | ├ BAD_ENUM | result∉{0..4}；BOOK_MISMATCH 时 sp≠0；body.direction∉{1,2}（codec） | 同上 | 同上 | 接收端 |
| 0x0305 | ├ UNKNOWN_MSG_TYPE | msg_type 未分配（codec） | 同上 | 同上 | 接收端 |
| 0x0306 | ├ WRONG_DIRECTION | 消息方向与角色不符（codec） | 同上 | 同上 | 接收端 |
| 0x0307 | ├ ISSUE_POINTER_MISMATCH | ISSUE.chosen ≠ 仲裁约定 i；ARBITRATE 结果与指针组合矛盾（state） | 同上 | **不耗段**（预留前拒绝） | 服务端/客户端 |
| 0x0308 | ├ FRAME_TRUNCATED | 输入不足 8+payload_len / EOF 中断（framing） | 同上 | 同上 | 接收端 |
| 0x0309 | └ BAD_ORDER | 消息时序违反状态机（触发表归 WP-02） | 同上 | 同上 | 接收端 |
| 0x030A | └ EPOCH_MISMATCH | epoch ≠ 0（state/record） | 同上 | 同上 | 接收端 |
| 0x030B | └ SEQ_UNEXPECTED | CONFIRM seq≠0；DATA 首序号≠1；跳号/乱序（state/record） | 同上 | 同上 | 接收端 |
| 0x0400 | INTERNAL（伞） | 见 0x0401–0x0403（本地实现） | 无线上行为；**fail closed，宁可拒绝服务** | 不确定时按已预留=浪费处理 | 本地运维 |
| 0x0401 | ├ IO_ERROR | 短写/EIO/ENOSPC 等（平台层） | — | 同上 | 本地 |
| 0x0402 | └ PERSISTENCE_UNVERIFIED | fsync 结果不确定（分配器，设计书 §6） | — | 候选段废弃 | 本地（WP-07/08） |
| 0x0403 | └ CSPRNG_FAILURE | getrandom 失败即终止握手（规划 §1.2） | 关闭 | 不耗段 | 本地 |

### 5.3 线上披露策略

- 只有 §4.2 的四种仲裁结局对端可见。除此之外**没有任何错误通告消息**（设计书未定义 ERROR 帧，本规格不增补）；一切失败表现为关闭连接。
- 认证失败子类（0x0201–0x0204）对对端不可区分：避免开放"离线猜测段内容/密钥"的区分 oracle。
- 审计日志按设计书 §9 白名单：`book_id、段号、结果、generation、错误类别`；错误类别即本节错误码（hex）。禁止记录段正文、方向密钥、确认明文、应用明文、tag。

### 5.4 设计书 §2/§4 错误路径追溯表（验收覆盖证明）

| 设计书位置 | 错误路径 | 本规格错误码 |
|---|---|---|
| §2 | MITM 篡改握手/确认/记录且保持格式合法 | 0x0201/0x0202（tag 与副本绑定失败） |
| §2 | MITM 篡改造成格式非法 | 0x0301–0x0306、0x0308 |
| §2 | 透明转发（不篡改） | 不触发错误（建立攻击者不可解密的会话） |
| §2/§4 | 重放旧报文（旧段号 i、旧 nonce） | 0x0202 / 0x0203 |
| §4 | 重放致重复序号 | 0x0204 |
| §2 | 拒绝服务（丢包/重排/资源） | 协议不补救；表现为 0x0308/0x030B/超时后关闭 |
| §4 | book_id 检查失败 | 0x0100（result=3） |
| §4 | 段耗尽 | 0x0101（result=2） |
| §4 | server_pointer > client_pointer | 0x0103（result=1；客户端跳指针、废弃间隙、只前进） |
| §4 | client_pointer > server_pointer | 0x0102（result=4；不回退，人工恢复） |
| §4 | "错误 tag、错误段号、旧 nonce、重复序号统一视为认证失败" | 0x0200（0x0201/0x0202/0x0203/0x0204）；不降级、段不复用 |
| §4 | 确认包字段混用（版本/段号/nonce/方向/epoch/序号/类型） | 0x0202/0x0203/0x030A/0x030B |
| §9 | 审计白名单 | §5.3 |

---

## 6. Golden vectors

### 6.0 向量可验证性声明

本节全部向量（含每个负例的十六进制字节串与期望错误码）均由与本规格相互独立的校验器逐字节复算过：参考实现先通过 RFC 8439 §2.8.2 KAT，再重算全部 sealed/data 密文与 tag；另按 §3.2 顺序独立实现解码器，对每个负例断言具确定错误码、对每个标 [state]/[record] 的负例断言 codec 层必须放行。校验器留存于作者 workspace（`verify_wp01.py`），不入仓；任何评审者可用任一 RFC 8439 实现按 §6.1 夹具独立复算。所有向量均为十六进制小写连续串，可直接作为 WP-05/WP-19 测试用例。

### 6.1 测试夹具（全部向量共用；仅测试用，禁止入生产）

| 夹具 | 值 |
|---|---|
| BOOK_ID | `00112233445566778899AABBCCDDEEFF` |
| CLIENT_NONCE | `101112131415161718191A1B1C1D1E1F` |
| SERVER_NONCE | `202122232425262728292A2B2C2D2E2F` |
| SESSION_NONCE | `30303030303030303030303030303030`（= C⊕S，D3） |
| 测试段 0（64B） | `00 01 02 … 3F`（即 00..3F 连续）；K_c2s = `00..1F`，K_s2c = `20..3F`（v2 §1.2 直接拆分，无派生） |
| TEST_NONCE（12B） | `000000000000000000000001` |
| TEST_AAD（13B） | ASCII `"wp01-test-aad"` = `77 70 30 31 2D 74 65 73 74 2D 61 61 64` |
| DATA 明文 | ASCII `"Hello, otp-term!"`（16B） |

> **nonce/AAD 声明（决策 D5）**：向量的 sealed/data 是**真实** ChaCha20-Poly1305 输出（密钥=测试段拆分的方向密钥），但 nonce/AAD 取上述测试夹具值；规范 96-bit nonce 与 AAD 构造由 WP-03 冻结。对 WP-01/WP-05 无影响：codec 将 sealed/data 视为不透明定长/限长字节。参考实现已经 RFC 8439 §2.8.2 KAT 校验。

### 6.2 向量格式

- hex 一律小写连续串，表示**整条帧**（或内层 body）的完整字节；长度标注在名称后。
- 正例期望：`decode → Ok`，且 `encode(decode(x)) == x`（§3.1 规则 5）。
- 负例期望给出**确定错误码**（按 §3.2 顺序）；标注 `[state]/[record]` 者表示 codec 层解码成功、由上层以该码拒绝——WP-05 只需断言 codec 层行为，WP-10/11/14 断言上层行为。
- 修改位点以"帧偏移（十进制，自帧首 0 计）"给出，便于生成变异测试。

### 6.3 HELLO 向量

**HELLO-POS-001**（52B）：

```text
字段: version=0002 msg_type=0001 payload_len=0000002C(44)
      book_id=00112233445566778899AABBCCDDEEFF
      client_nonce=101112131415161718191A1B1C1D1E1F
      client_pointer=0 features=00000000(bit 均未置位)
0000  00 02 00 01 00 00 00 2C  00 11 22 33 44 55 66 77
0010  88 99 AA BB CC DD EE FF  10 11 12 13 14 15 16 17
0020  18 19 1A 1B 1C 1D 1E 1F  00 00 00 00 00 00 00 00
0030  00 00 00 00
hex: 000200010000002c00112233445566778899aabbccddeeff101112131415161718191a1b1c1d1e1f000000000000000000000000
```

| 向量 | 长度 | 修改位点 | hex | 期望 |
|---|---:|---|---|---|
| HELLO-NEG-001 | 52B | 偏移 1：version 02→03 | `000300010000002c00112233445566778899aabbccddeeff101112131415161718191a1b1c1d1e1f000000000000000000000000` | 0x0301 |
| HELLO-NEG-002 | 51B | 末字节截断 | `000200010000002c00112233445566778899aabbccddeeff101112131415161718191a1b1c1d1e1f0000000000000000000000` | 0x0308 |
| HELLO-NEG-003 | 52B | 偏移 7：payload_len 2C→2D | `000200010000002d00112233445566778899aabbccddeeff101112131415161718191a1b1c1d1e1f000000000000000000000000` | 0x0302 |
| HELLO-NEG-004 | 53B | 末尾追加 1 字节 | `000200010000002c00112233445566778899aabbccddeeff101112131415161718191a1b1c1d1e1f00000000000000000000000000` | 0x0303 |

### 6.4 ARBITRATE 向量（正例覆盖全部 5 种 result）

公共头 `0002000200000019` + server_nonce `202122232425262728292a2b2c2d2e2f`。

| 向量 | 语义 | server_pointer | result | hex（33B） |
|---|---|---:|---:|---|
| ARBITRATE-POS-001 | OK，i=0（client_pointer=0） | 0 | 00 | `0002000200000019202122232425262728292a2b2c2d2e2f000000000000000000` |
| ARBITRATE-POS-002 | SERVER_AHEAD，i=5 | 5 | 01 | `0002000200000019202122232425262728292a2b2c2d2e2f000000000000000501` |
| ARBITRATE-POS-003 | EXHAUSTED，N=3 | 3 | 02 | `0002000200000019202122232425262728292a2b2c2d2e2f000000000000000302` |
| ARBITRATE-POS-004 | BOOK_MISMATCH（sp 恒 0） | 0 | 03 | `0002000200000019202122232425262728292a2b2c2d2e2f000000000000000003` |
| ARBITRATE-POS-005 | CLIENT_AHEAD，sp=2 | 2 | 04 | `0002000200000019202122232425262728292a2b2c2d2e2f000000000000000204` |

| 向量 | 长度 | 修改位点 | hex | 期望 |
|---|---:|---|---|---|
| ARBITRATE-NEG-001 | 33B | 偏移 32：result 00→05（未知枚举） | `0002000200000019202122232425262728292a2b2c2d2e2f000000000000000005` | 0x0304 |
| ARBITRATE-NEG-002 | 32B | 末字节截断 | `0002000200000019202122232425262728292a2b2c2d2e2f0000000000000000` | 0x0308 |
| ARBITRATE-NEG-003 | 33B | 字节同 POS-001，但 role=server 解码 | `0002000200000019202122232425262728292a2b2c2d2e2f000000000000000000` | 0x0306 |
| ARBITRATE-NEG-004 | 33B | POS-004 中 server_pointer 改 1（BOOK_MISMATCH 时 sp≠0） | `0002000200000019202122232425262728292a2b2c2d2e2f000000000000000103` | 0x0304 |

### 6.5 ISSUE_REQUEST 向量

**ISSUE-POS-001**（48B）：chosen=0（与 POS-001 仲裁一致），双 nonce 回显。

```text
0000  00 02 00 03 00 00 00 28  00 00 00 00 00 00 00 00
0010  10 11 12 13 14 15 16 17  18 19 1A 1B 1C 1D 1E 1F
0020  20 21 22 23 24 25 26 27  28 29 2A 2B 2C 2D 2E 2F
hex: 00020003000000280000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f
```

| 向量 | 长度 | 修改位点 | hex | 期望 |
|---|---:|---|---|---|
| ISSUE-NEG-001 | 48B | 偏移 15：chosen 0→1（约定 i=0） | `00020003000000280000000000000001101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f` | codec Ok；[state] 0x0307 |
| ISSUE-NEG-002 | 48B | 偏移 7：payload_len 28→27 | `00020003000000270000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f` | 0x0302 |
| ISSUE-NEG-003 | 47B | 末字节截断 | `00020003000000280000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e` | 0x0308 |

### 6.6 CONFIRM 向量

**内层 confirm_body 正例**（87B，codec 可独立测试）：

| 向量 | direction | msg_type | label | hex |
|---|---:|---:|---|---|
| CONFIRM-BODY-POS-001 | 01 | 0004 | client-confirm | `000200112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f010000000000000000000000000004636c69656e742d636f6e6669726d` |
| CONFIRM-BODY-POS-002 | 02 | 0005 | server-confirm | `000200112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f0200000000000000000000000000057365727665722d636f6e6669726d` |

| 向量 | 长度 | 修改位点 | hex | 期望 |
|---|---:|---|---|---|
| CONFIRM-BODY-NEG-001 | 87B | 偏移 58：S2C body 的 direction 02→01 | `000200112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f0100000000000000000000000000057365727665722d636f6e6669726d` | codec Ok；[state] 0x0202 |
| CONFIRM-BODY-NEG-002 | 87B | 偏移 86：label 末字符 m(6D)→6E | `000200112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f010000000000000000000000000004636c69656e742d636f6e6669726e` | codec Ok；[state] 0x0202 |
| CONFIRM-BODY-NEG-003 | 86B | 末字节截断（body≠87B） | `000200112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f010000000000000000000000000004636c69656e742d636f6e666972` | 0x0302 |

**外层帧正例**（147B；sealed = AEAD-ChaCha20-Poly1305(K 方向, TEST_NONCE, TEST_AAD, body)，密文 87B + tag 16B）：

CONFIRM_C2S-POS-001（tag = `6b0437744ffbe65360b787bee49e7980`）：

```text
0000  00 02 00 04 00 00 00 8B  00 00 00 00 00 00 00 00
0010  30 30 30 30 30 30 30 30  30 30 30 30 30 30 30 30
0020  00 00 00 00 00 00 00 00  00 00 00 00
002C  69 5E 7C C8 13 39 FC 2F  4B 06 F6 B6 19 AF DB CF   <- sealed[0..]
0083  ...（密文共 87B 至 0x82；0x83 起为 tag 16B，帧末 0x92）
hex: 000200040000008b000000000000000030303030303030303030303030303030000000000000000000000000695e7cc81339fc2f4b06f6b619afdbcffe0e3f40ceb1fc75453aa5393bfd8b1fc53af413a9e0b29e3f57cb0584c08eebe3d96d5aa34078184a14114e6f172f791fd260bac23a892d791349a4d4e9233beb6f16d059e4cb6b0437744ffbe65360b787bee49e7980
```

CONFIRM_S2C-POS-001（147B，K_s2c，tag = `02fe639321af7066c91ea6649cd7a96c`）：

```text
hex: 000200050000008b0000000000000000303030303030303030303030303030300000000000000000000000005355daa73436835bdc777c47861cc3453ed181caf8be66cfdfacb1cebf131df844de12fcb2e41a07e1259981a1f0f890dc556ff1bc52050861ffa54c184d9a2ad47903f6714aa8247b01b7446afc3c8d440cbf42a2d34002fe639321af7066c91ea6649cd7a96c
```

**外层负例：**

| 向量 | 长度 | 修改位点 | hex | 期望 |
|---|---:|---|---|---|
| CONFIRM_C2S-NEG-001 | 147B | 偏移 146：tag 末位 80→81 | `000200040000008b000000000000000030303030303030303030303030303030000000000000000000000000695e7cc81339fc2f4b06f6b619afdbcffe0e3f40ceb1fc75453aa5393bfd8b1fc53af413a9e0b29e3f57cb0584c08eebe3d96d5aa34078184a14114e6f172f791fd260bac23a892d791349a4d4e9233beb6f16d059e4cb6b0437744ffbe65360b787bee49e7981` | codec Ok；[record] 0x0201 |
| CONFIRM_C2S-NEG-002 | 147B | 偏移 7：payload_len 8B→8C | `000200040000008c000000000000000030303030303030303030303030303030000000000000000000000000695e7cc81339fc2f4b06f6b619afdbcffe0e3f40ceb1fc75453aa5393bfd8b1fc53af413a9e0b29e3f57cb0584c08eebe3d96d5aa34078184a14114e6f172f791fd260bac23a892d791349a4d4e9233beb6f16d059e4cb6b0437744ffbe65360b787bee49e7980` | 0x0302 |
| CONFIRM_C2S-NEG-003 | 146B | 末字节截断 | `000200040000008b000000000000000030303030303030303030303030303030000000000000000000000000695e7cc81339fc2f4b06f6b619afdbcffe0e3f40ceb1fc75453aa5393bfd8b1fc53af413a9e0b29e3f57cb0584c08eebe3d96d5aa34078184a14114e6f172f791fd260bac23a892d791349a4d4e9233beb6f16d059e4cb6b0437744ffbe65360b787bee49e79` | 0x0308 |
| CONFIRM_C2S-NEG-004 | 147B | 偏移 16：session_nonce 首字节 30→31 | `000200040000008b000000000000000031303030303030303030303030303030000000000000000000000000695e7cc81339fc2f4b06f6b619afdbcffe0e3f40ceb1fc75453aa5393bfd8b1fc53af413a9e0b29e3f57cb0584c08eebe3d96d5aa34078184a14114e6f172f791fd260bac23a892d791349a4d4e9233beb6f16d059e4cb6b0437744ffbe65360b787bee49e7980` | codec Ok；[state] 0x0203 |
| CONFIRM_C2S-NEG-005 | 147B | 偏移 35：epoch 低字节 00→01（epoch 字段位于帧偏移 32..35；偏移 27 属 session_nonce，v1.0 误标已修正） | `000200040000008b000000000000000030303030303030303030303030303030000000010000000000000000695e7cc81339fc2f4b06f6b619afdbcffe0e3f40ceb1fc75453aa5393bfd8b1fc53af413a9e0b29e3f57cb0584c08eebe3d96d5aa34078184a14114e6f172f791fd260bac23a892d791349a4d4e9233beb6f16d059e4cb6b0437744ffbe65360b787bee49e7980` | codec Ok；[state] 0x030A |
| CONFIRM_S2C-NEG-001 | 147B | 偏移 146：tag 末位 6C→6D | `000200050000008b0000000000000000303030303030303030303030303030300000000000000000000000005355daa73436835bdc777c47861cc3453ed181caf8be66cfdfacb1cebf131df844de12fcb2e41a07e1259981a1f0f890dc556ff1bc52050861ffa54c184d9a2ad47903f6714aa8247b01b7446afc3c8d440cbf42a2d34002fe639321af7066c91ea6649cd7a96d` | codec Ok；[record] 0x0201 |
| CONFIRM_S2C-NEG-002 | 146B | 末字节截断 | `000200050000008b0000000000000000303030303030303030303030303030300000000000000000000000005355daa73436835bdc777c47861cc3453ed181caf8be66cfdfacb1cebf131df844de12fcb2e41a07e1259981a1f0f890dc556ff1bc52050861ffa54c184d9a2ad47903f6714aa8247b01b7446afc3c8d440cbf42a2d34002fe639321af7066c91ea6649cd7a9` | 0x0308 |

### 6.7 DATA 向量

**DATA-POS-001**（56B，C→S；data = 密文 16B `213910b55e2698155901535bd6667a33` ‖ tag 16B `091b6d2fc46bf7ad65c94fdc39f26483`）：

```text
0000  00 02 00 06 00 00 00 30  00 00 00 00 00 00 00 00
0010  00 00 00 00 00 00 00 01  00 00 00 20  21 39 10 B5
0020  5E 26 98 15 59 01 53 5B  D6 66 7A 33  09 1B 6D 2F
0030  C4 6B F7 AD 65 C9 4F DC  39 F2 64 83
hex: 000200060000003000000000000000000000000100000020213910b55e2698155901535bd6667a33091b6d2fc46bf7ad65c94fdc39f26483
```

| 向量 | 长度 | 修改位点 | hex | 期望 |
|---|---:|---|---|---|
| DATA-NEG-001 | 56B | 偏移 23：data_len 20→21 | `000200060000003000000000000000000000000100000021213910b55e2698155901535bd6667a33091b6d2fc46bf7ad65c94fdc39f26483` | 0x0302 |
| DATA-NEG-002 | 56B | 偏移 24：密文首字节 21→20 | `000200060000003000000000000000000000000100000020203910b55e2698155901535bd6667a33091b6d2fc46bf7ad65c94fdc39f26483` | codec Ok；[record] 0x0201 |
| DATA-NEG-003 | 55B | 末字节截断 | `000200060000003000000000000000000000000100000020213910b55e2698155901535bd6667a33091b6d2fc46bf7ad65c94fdc39f264` | 0x0308 |
| DATA-NEG-004 | 56B | 偏移 19：seq 低字节 01→05 | `000200060000003000000000000000000000000500000020213910b55e2698155901535bd6667a33091b6d2fc46bf7ad65c94fdc39f26483` | codec Ok；[record] 0x030B |
| DATA-NEG-005 | 56B | 字节同 POS-001，在已收到 seq=1 后原样重发 | `000200060000003000000000000000000000000100000020213910b55e2698155901535bd6667a33091b6d2fc46bf7ad65c94fdc39f26483` | codec Ok；[record] 0x0204 |

### 6.8 向量 → WP-05 测试转换表

| 向量组 | WP-05 断言 |
|---|---|
| 全部 POS | `decode()` 成功；`encode()` 再编码逐字节等于输入（§3.1 规则 5）；字段值与 §6 表一致 |
| NEG-0x0301/02/03/04/05/06/08（codec 层） | `decode()` 返回该错误码且不 panic、不部分消费产生歧义 |
| 标注 [state]/[record] 的 NEG | codec 层 `decode()` **必须成功**（负例不得在 codec 被拦截）；上层断言归 WP-10/11/14 |
| 边界（由性质测试补充，不入内联向量） | DATA data_len ∈ {16, 65552} 合法、{15, 65553} 非法；payload_len ∈ {32, 65568} 合法；随机 0..70000 字节输入 fuzz 无 panic |

---

## 7. 接口、实现注意与遗留决策点

### 7.1 对下游工作包的接口

- **WP-05（codec）**：实现 §3 解码顺序与 §4 布局；导出 `decode(role, &[u8]) -> Result<Message, ErrorCode>`、`encode(&Message) -> Vec<u8>`、`decode_confirm_body(&[u8])`；正/负向量与边界性质全部入测试。
- **WP-02/WP-11（状态机/握手）**：§4 各 [state] 约束与其错误码；0x0309 触发表由 WP-02 定义。
- **WP-03/WP-10（nonce/AAD/record）**：sealed/data 的开封、96-bit nonce 与 AAD 构造、序号唯一性；本规格已把 `session_nonce` 与方向密钥拆分点（§6.1）作为输入定死。
- **WP-19（独立实现）**：以 §6 向量做互通判据。

### 7.2 实现注意（安全相关）

1. 先按 §2.1 校验 `payload_len` 再分配缓冲；任何路径不得因攻击者控制的长度产生 > 65576 的分配。
2. codec 无 crypto、无 unsafe、无 panic 路径（fuzz 目标 WP-14）。
3. 认证失败不得区分对外行为（§5.3）；tag/nonce 比较在 record 层常量时间（WP-10）。
4. 审计仅白名单字段（§5.3）。

### 7.3 遗留决策点（请评审逐条确认）

| # | 决策 | 理由 | 若否决 |
|---|---|---|---|
| D1 | `version`（0x0002）置于公共帧头，全部消息自描述版本 | 设计书 §4 AAD 要求绑定版本；帧头统一使 ARBITRATE/ISSUE/DATA 也受版本约束，且消除"HELLO 之外的版本歧义" | version 仅留 HELLO，重算向量 |
| D2 | ARBITRATE 补 `server_nonce` 字段 | 设计书 §4 字段简写未列，但 ISSUE_REQUEST 必须回显 server_nonce，其唯一合法来源是服务端先行下发；§4 AAD"双方 nonce"亦要求服务端有 nonce。属格式补全，非语义变更 | 需另立 server_nonce 下发途径（设计缺陷报告流程） |
| D3 | `session_nonce := client_nonce ⊕ server_nonce`（16B，双方确定性一致） | 免协商、免传输歧义；是否进入 96-bit nonce 域由 WP-03 定义 | 改为显式下发，重算向量 |
| D4 | `features` 未知位必须忽略 | 协商位语义上必须可忽略，否则无法演进；codec 不因未知位拒绝 | 收紧为必须为 0（0x0304） |
| D5 | 向量 sealed/data 用真实 AEAD + 测试 nonce/AAD 夹具 | WP-03 未冻结前保证向量可复算、可互操作验证；对 codec 无影响 | 冻结 WP-03 后追加正式 KAT 向量 |
| D6 | CONFIRM 外层无 sealed_len（sealed 恒 103B） | 定长即 canonical：payload_len==139 完全约束帧；消除伪长度字段被篡改的负例面 | 恢复 u16 长度前缀，重算向量 |

---

## 8. 变更记录

| 版本 | 日期 | 说明 |
|---|---|---|
| v0.9 | （#26 首交） | 误以 281 行 Python 生成器脚本充当规格；审计 FAIL |
| v1.0 | （#26 重交） | 全文重写为规格文本：6 类消息逐字节布局（§4）、canonical 规则与拒绝条件（§3）、错误码模型与 §2/§4 追溯（§5）、正/负 golden vectors（§6，sealed 长度字段取消，CONFIRM 帧定为 147B，原记 "28 组" 系计数误报，实为 38 条）；决策点 D1–D6 提请评审 |
| v1.1 | 本次（#30 重发卡） | 全部 38 条向量（正 12 + 负 26）逐字节独立复算：① CONFIRM_C2S-NEG-005 修改位点由帧偏移 27（实为 session_nonce 字节）更正为偏移 35（epoch 低字节），hex 同步更正，期望码 0x030A 不变；② ARBITRATE-NEG-003、DATA-NEG-005 的 "同 POS-001" 引用改写为显式 hex（向量自包含）；③ 新增 §6.0 向量可验证性声明；④ 向量计数由 "28 组" 更正为 38 条；其余条款与 v1.0 逐字不变（含 D1–D6） |
