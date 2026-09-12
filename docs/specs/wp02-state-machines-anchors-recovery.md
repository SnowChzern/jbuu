# WP-02 规格书：段分配器状态机 / 双锚记录 / 崩溃恢复决策 / 握手与会话状态机

| 项 | 内容 |
|---|---|
| 任务卡 | 论坛任务 #31 · 工作包 WP-02 |
| 执行人 | 斗拱（designer） |
| 设计依据 | v2 设计稿 §5（段管理状态机与并发语义）、§6（fail-to-waste 铁律及崩溃证明）、§7（回滚锚）；实现规划书 §2（`otp-anchor-spec`）、§4 WP-02、§7.1 阻断条件 |
| 规格状态 | 冻结，供 WP-07 / WP-08 / WP-11 机械对照 |
| 范围含 | allocator 五态转移表（含不可达标注）、锚记录字节布局与双锚比较、崩溃时点 × 锚状态处置矩阵、handshake/session 状态机（含 CLIENT_AHEAD 人工恢复路径） |
| 范围不含 | 线格式与错误码（WP-01）、nonce/AAD 构造（WP-03）、实现代码、跨进程锁细节（WP-09） |
| 冲突处理 | 本规格与 v2 设计书任何冲突：实现侧 fail closed，走设计缺陷流程（规划 §7.2），不得私改协议语义 |

> 修订记录：v1 交付缺失 allocator 状态转移表（审计 FAIL）。v2 全量重写：四项验收口径全部落成可逐行核对的表格（§1、§2、§3、§4/§5），补充锚记录 golden 字节（§2.6）与 WP-07/08 验收映射（§8）。v3（任务 #31）：修正章节重排导致的交叉引用偏移；§2.4 补 reconcile 修复写失败 fail-closed 处置；golden 字节经 SHA-256 独立复算验证一致；语义无变化。

---

## 0. 术语与总览

- **段（segment）**：密码本 64 字节记录 `B[i]`，`i` 为段号（`SegmentIndex`，u64；协议上限 2^40−1，WP-01 POINTER_CAP）。
- **指针（next）**：下一个可分配段号。本规格中 allocator 状态 `READY(p)` 与 v2 §5 记号一致：`p` 即持久化锚中的 `next`。
- **锚（anchor）**：持久化指针状态记录，两处独立介质各一份，记 **锚A / 锚B**（介质部署见 §2.7）。
- **generation**：每次成功 `issue()`（以及每次经审计的人工推进，§1.3 T12）加 1 的单调计数，用于双锚排序与回滚检测。
- **取段**：逻辑预留（v2 §6：先持久化 reservation intent 再读正文）；**正文读取（pread）**是其后的物理读取。
- **fail-to-waste 铁律**（v2 §6）：段一旦预留即推进指针并在两处独立介质 fsync；全部持久化成功前不得把段交给 AEAD；任何不确定只允许前进 / 浪费 / 拒绝服务，绝不回退、绝不复用。

三张状态机的关系：

```text
        ┌────────────────────────────────────────────────────┐
        │ allocator（本规格 §1，WP-07/08）                    │
        │  READY→RESERVED→COMMITTED→IN_USE→SPENT             │
        │  双锚持久化只发生在 RESERVED 进入/离开时刻           │
        └───────────────┬────────────────────────────────────┘
                        │ issue() 返回 CommittedSegment（唯一接口）
                        v
        ┌────────────────────────────────────────────────────┐
        │ handshake（本规格 §4，WP-11）                       │
        │  仲裁→ISSUE→双向 CONFIRM；CLIENT_AHEAD/SERVER_AHEAD │
        └───────────────┬────────────────────────────────────┘
                        │ 双向 tag 验证通过 → ESTABLISHED
                        v
        ┌────────────────────────────────────────────────────┐
        │ session（本规格 §5，WP-10）                         │
        │  DATA(epoch=0,seq 单调)→CLOSING→CLOSED / ABORTED    │
        └────────────────────────────────────────────────────┘
```

---

## 1. allocator 状态机（验收点 ①）

### 1.1 状态定义

| 状态 | 记号 | 语义 | 段可否交给 AEAD | 持久化投影（锚中可见形态） |
|---|---|---|---|---|
| READY | `READY(p)` | 指针 `p` 已加载并完成双锚对账（§2.4），无在途 `issue()` | 否 | 双锚一致于 `(gen g, next p)`，record_type 为上一次成功写入的形态（INIT/INTENT/COMMIT 之一） |
| RESERVED | `RESERVED(i, p=i+1)` | `issue()` 已选中候选 `i`；intent 双锚 fsync **必须**在本状态内完成；正文 pread 与最终锚写入在离开本状态的转移中完成 | **否**（铁律） | 双锚 INTENT`(gen g+1, next i+1, reserved=i)` |
| COMMITTED | `COMMITTED(i)` | intent 与最终（candidate）双锚 fsync 均确认，正文已读出校验；`issue()` 已返回/可返回 | 可装入 AEAD，但**不得发送 DATA**（须先过 §4 双向确认） | 双锚 COMMIT`(gen g+1, next i+1, previous_segment_hash=SHA-256(B[i]))` |
| IN_USE | `IN_USE(i)` | 双向 CONFIRM tag 均验证通过，会话 DATA 阶段进行中；段逻辑上已消耗 | 是（业务数据） | 与 COMMITTED 相同（无独立持久化形态） |
| SPENT | `SPENT(p)` | 终态：段已消耗或已浪费，**永不回收、永不再分配** | 否 | 锚形态等于消耗时的形态；SPENT 本身只在进程内存与审计日志中 |

RESERVED 内部两个可观测子标志（不新增状态，仅约束转移顺序，供故障注入编号引用）：

- `intent_durable`：INTENT 已双锚写满且各自 fsync 成功；
- `body_read`：`pread_exact(book_fd, i*64, 64)` 成功。

顺序强制：`intent_durable` 先于 `body_read`（v2 §6：工程上必须先持久化 reservation intent，再读取段正文），`body_read` 先于最终锚写入。

### 1.2 事件与守卫

| 事件 | 触发者 | 含义 |
|---|---|---|
| EV-ISSUE | 上层调用 `issue()` | 请求签发新段（须已持 `pointer_lock`） |
| EV-INTENT-OK | 存储后端 | INTENT 双锚写满 + 各自 fsync 成功 |
| EV-PERSIST-ERR | 存储后端 | 任一 write/fsync 失败、短写不可恢复、fsync 返回不确定 |
| EV-PREAD-OK / EV-PREAD-ERR | `otp-book` | 正文读取成功 / 失败（I/O 错、越界、校验失败） |
| EV-COMMIT-OK | 存储后端 | COMMIT 记录双锚写满 + 各自 fsync 成功 |
| EV-CONFIRM-OK / EV-CONFIRM-FAIL | §4 握手层 | 双向 CONFIRM tag 均通过 / 任一失败、超时、中止 |
| EV-CLOSE / EV-ABORT | §5 会话层 | 正常关闭 / 异常中止（tag 失败、序号溢出、传输错误、上层取消） |
| EV-CRASH | 外部 | 进程崩溃 / 断电；进程内状态丢失，只剩双锚（→ §3 恢复矩阵） |
| EV-OP-ADVANCE | 运维（人工，带审计） | 前向推进指针（CLIENT_AHEAD 人工恢复、SERVER_AHEAD 跳段、换本前 drain 等），见 §4.4 |

全局守卫：所有转移在 `pointer_lock` 临界区内（进程内互斥；跨进程 OFD 锁/租约由 WP-09 提供）；同临界区内并发请求必须分得不同 `i`（v2 §5）。

### 1.3 合法转移表（全部）

| # | 源状态 | 事件 | 守卫 | 目标状态 | 动作与持久化 |
|---|---|---|---|---|---|
| T1 | READY | EV-ISSUE | 对账后 `i=p < segment_count` | RESERVED | 选 `i=p`，进入 §1.1 顺序；若 `p >= segment_count` 则**不发生转移**，返回 EXHAUSTED（READY 保持，指针不动） |
| T2 | RESERVED | EV-INTENT-OK | — | RESERVED | `intent_durable:=true`；写审计日志 `{book_id, i, g+1, RESERVED}` |
| T3 | RESERVED | EV-PREAD-OK | `intent_durable==true` | RESERVED | `body_read:=true`，段正文暂存受保护内存（zeroize on drop） |
| T4 | RESERVED | EV-COMMIT-OK | `intent_durable && body_read` | COMMITTED | `issue()` 返回 `CommittedSegment`；释放锁；审计 `{i, g+1, COMMITTED}` |
| T5 | COMMITTED | EV-CONFIRM-OK | §4 双向 tag 通过 | IN_USE | 会话进入 DATA（epoch=0）；审计 `{i, IN_USE}` |
| T6 | COMMITTED | EV-CONFIRM-FAIL | — | SPENT | 段已持久消耗，按浪费计；审计 `{i, WASTED_CONFIRM_FAIL}`；关闭握手连接 |
| T7 | IN_USE | EV-CLOSE | — | SPENT | 正常关会话；zeroize 方向密钥；审计 `{i, SPENT_CLOSE}` |
| T8 | IN_USE | EV-ABORT | — | SPENT | 异常关会话（同 T7，错误类别不同） |
| T9 | RESERVED | EV-PREAD-ERR | `intent_durable==true` | SPENT | intent 已持久 ⇒ `i` 永不可再分配；本调用失败返回；**allocator 可继续服务**（下次 `issue()` 从 `i+1`）；审计 `{i, WASTED_PREAD_ERR}` |
| T10 | RESERVED | EV-PERSIST-ERR | — | SPENT | 持久化不确定 ⇒ `i` 按已消耗处理；**分配器服务必须停机（fail closed）**：拒绝后续 issue，直到重启走 §3 恢复或人工核账；尽力把 INTENT 补写满双锚（失败也不得回退/复用）；审计 `{i, HALT_PERSIST_ERR}` |
| T11 | RESERVED / COMMITTED | EV-ABORT（上层取消，含 CONFIRM 前超时） | — | SPENT | 同 T6 语义；审计 `{i, WASTED_ABORTED}` |
| T12 | READY | EV-OP-ADVANCE | 人工 + 审计 + 前向（`k >= p`） | READY | 双锚写 `(gen g+1, next k)`（COMMIT 形态；`[p,k)` 全部记浪费），fsync 后生效；`k < p` 一律拒绝 |
| T13 | 全部 | EV-CRASH | — | 见 §3 | 进程内状态丢失；按恢复矩阵重建 READY 或停机 |

注：T10 中"停机"是分配器服务级标志，不是第五态之外的新状态；SPENT/READY 等 slot 状态不受影响。

### 1.4 全转移矩阵（含**不可达/非法标注**，验收点①）

行 = 源状态，列 = 事件；`→X` 为合法转移（编号见表 1.3），`✗` 为**不可达转移**（正确实现中不可能，运行时检出即不变量破坏）。✗ 的统一处置：审计 `INV_<事件>`，**fail closed**（中止当前操作/连接；涉及指针者停机），且类型系统上应不可表达（plan §2.2：`ReservedSegment` 无转 AEAD 的公开路径）。

| 源\事件 | EV-ISSUE | EV-INTENT-OK | EV-PREAD-OK | EV-PREAD-ERR | EV-COMMIT-OK | EV-CONFIRM-OK | EV-CONFIRM-FAIL | EV-CLOSE | EV-ABORT | EV-PERSIST-ERR | EV-OP-ADVANCE |
|---|---|---|---|---|---|---|---|---|---|---|---|
| READY | →RESERVED (T1) | ✗ INV_ORDER | ✗ INV_ORDER | ✗ INV_ORDER | ✗ INV_ORDER | ✗ INV_STATE | ✗ INV_STATE | ✗ INV_STATE | ✗ INV_STATE | ✗ INV_STATE | →READY (T12) |
| RESERVED | ✗ INV_REENTRY | →RESERVED (T2) | →RESERVED (T3) | →SPENT (T9) | →COMMITTED (T4) | ✗ INV_SKIP_COMMIT | ✗ INV_SKIP_COMMIT | ✗ INV_SKIP_COMMIT | →SPENT (T11) | →SPENT+停机 (T10) | ✗ INV_REENTRY |
| COMMITTED | ✗ INV_REENTRY | ✗ INV_ORDER | ✗ INV_ORDER | ✗ INV_ORDER | ✗ INV_ORDER | →IN_USE (T5) | →SPENT (T6) | ✗ INV_STATE | →SPENT (T11) | ✗ INV_STATE | ✗ INV_REENTRY |
| IN_USE | ✗ INV_REENTRY | ✗ INV_ORDER | ✗ INV_ORDER | ✗ INV_ORDER | ✗ INV_ORDER | ✗ INV_STATE | ✗ INV_STATE | →SPENT (T7) | →SPENT (T8) | ✗ INV_STATE | ✗ INV_REENTRY |
| SPENT | ✗ INV_RECYCLE | ✗ INV_RECYCLE | ✗ INV_RECYCLE | ✗ INV_RECYCLE | ✗ INV_RECYCLE | ✗ INV_RECYCLE | ✗ INV_RECYCLE | ✗ INV_RECYCLE | ✗ INV_RECYCLE | ✗ INV_RECYCLE | ✗ INV_RECYCLE |

不可达转移的语义归类（实现与评审重点核对）：

1. **INV_RECYCLE（SPENT 出边全禁）**：SPENT 是终态。`SPENT→READY`（回收再分配）是被设计禁止的最高危路径，"区间未用尾部也不能回收"（v2 §5）。
2. **回退类（INV_STATE 中隐含）**：`RESERVED→READY`、`COMMITTED→RESERVED/READY`、`IN_USE→*` 非 SPENT：崩溃恢复映射（T13）只允许把这些状态映到 SPENT（浪费/已用），**绝不映射回 READY(p=i)**。
3. **INV_SKIP_COMMIT（铁律）**：`RESERVED→IN_USE` / RESERVED 直接收发 CONFIRM：intent/最终双 fsync 未全部确认前段不得进 AEAD——正是 fail-to-waste。
4. **INV_ORDER**：intent→pread→commit 的写序（§1.1）不允许乱序（如未 RESERVED 就 pread）。
5. **INV_REENTRY**：一次 `issue()` 生命周期内不重入；READY 在持有锁的签发中不可再被另一请求进入（并发请求须在同一临界区串行分得不同 `i`）。
6. **INV_STATE**（其余）：如对未 IN_USE 的会话发 CLOSE——上层状态机错误，连接层拒绝。

### 1.5 不可达状态（按上下文标注）

| 上下文 | 不可达状态/组合 | 原因 |
|---|---|---|
| 启动恢复完成后（任何崩溃时点） | IN_USE | IN_USE 只存在于进程内存；恢复只重建 READY（指针=采纳值），被崩掉的在途槽位一律落 SPENT（§3） |
| 启动恢复完成后 | RESERVED / COMMITTED（悬留） | 同上：锚中 INTENT/COMMIT 一律折算为"该槽已消耗"，不续跑旧调用 |
| 崩溃时点 CP0（§1.6）之后 | SPENT(i)（针对本次候选 `i`） | intent 尚未写入，`i` 未被预留，恢复后 `i` 可被下次正常签发——**唯一不浪费候选段的崩溃窗口** |
| 双锚均为 COMMIT 且哈希校验通过后 | READY(next=i)（指针停在旧值） | 最终锚已持久 `next=i+1`，回读到 `next=i` 即为回滚，禁止采纳 |
| 分配器服务生命期内 | SPENT→任何（含回收、重试同段） | fail-to-waste；重试只能换新段（`i+1` 起） |
| EXHAUSTED 后 | 任何进入 RESERVED 的转移 | `p >= segment_count` 时 T1 守卫不满足，无转移、无消耗、无越界 pread |

### 1.6 issue() 时序与崩溃窗口编号（供 §4 与 WP-13 故障注入引用）

```text
issue():
  lock(pointer_lock)                                 ─┐
  s = load_and_reconcile_anchor()          [T1]      │ CP0 ── intent 写入前（v2§6-1 前半）
  i = s.next; if i>=count: EXHAUSTED(no-op)           │
  write_full(anchorA, INTENT{g+1,next:i+1,res:i})     │ CP1a ─ A 写入中/未 fsync
  fsync(anchorA)                                       │ CP1b ─ A fsync 后、B 未写   （v2§6-2）
  write_full(anchorB, INTENT{...}); fsync(anchorB)    │ CP2  ─ 双 fsync 后、pread 前（v2§6-3 前半）
  segment = pread_exact(book, i*64, 64)      [T3]     │ CP3a ─ pread 后、最终锚写前 （v2§6-3 后半）
  write_full(anchorA, COMMIT{g+1,next:i+1,H(B[i])})   │ CP3b ─ A COMMIT fsync 后、B 未写
  fsync(anchorA); write_full(anchorB,COMMIT);fsync    │ CP4  ─ 双 fsync 后、返回/使用前（v2§6-4）
  mark_committed(i); unlock                    [T4]   ─┘
  return segment                                       CP5  ─ 使用中/使用后（v2§6-5）
```

任务卡五时点映射：**第一fsync后=CP1（a/b）**、**第二fsync后=CP2**、**取段后=CP3（a/b，含正文已读出）**、**使用前=CP4**、**使用中=CP5**；CP0 为 v2 §6 第 1 类（intent 写入前），一并纳入矩阵。每次 write/fsync/pread 边界均为 WP-13 可命名注入点。

### 1.7 并发语义（引用 v2 §5，实现归 WP-09）

单进程：`pointer_lock` 互斥，一次 `issue()` 一个临界区；多线程请求在同一临界区串行分得**不同**段号。多进程：OFD 锁/租约（WP-09）。集群禁止各自读同一密码本并发分配：单一分配器、线性化 CAS 共享存储或预切不重叠区间；区间未用尾部浪费不回收。会话恢复不重用旧段：重新仲裁 + 签发新段，旧会话标记关闭（§6.3）。

---

## 2. 锚记录格式与双锚比较（验收点②）

### 2.1 字段定义（v2 §7：`book_id、next、generation、previous_segment_hash` + 完整性保护）

| 字段 | 类型/长度 | 约束 |
|---|---|---|
| magic | 4 B ASCII `"OTPA"` | 固定，否则判无效 |
| anchor_version | u16 BE | `0x0002`；不识别即判无效（无协商） |
| record_type | u8 | `0x00 INIT`、`0x01 INTENT`、`0x02 COMMIT`；其他值无效 |
| flags | u8 | 本版本必须 `0x00`；任一位非零判无效（前向兼容走 fail-closed，不猜） |
| book_id | 16 B | 与密码本文件头、对端配置一致；不一致 → BOOK_MISMATCH（隔离） |
| generation | u64 BE | 单调不减；u64 溢出前必须换本 |
| next | u64 BE | 指针；`<= segment_count` |
| payload | 32 B | 语义随 record_type（§2.2） |
| integrity | 32 B | `SHA-256(record[0:72])`（完整性校验，见 §2.3 边界） |

### 2.2 payload 语义（canonical 编码，双锚比较要求字节级可比较）

| record_type | payload（32 B） | 附加 canonical 约束 |
|---|---|---|
| INIT（0x00） | 32×`0x00` | `generation==0 && next==0`（首启空锚） |
| INTENT（0x01） | `BE u64 reserved_index`（= `next−1`）+ 24×`0x00` | `next>=1`；`reserved_index==next-1`；后 24 B 全零 |
| COMMIT（0x02） | `previous_segment_hash = SHA-256(B[next−1])` | `next>=1`；启动时**必须**对密码本复核（§2.4 步骤 7） |

### 2.3 字节布局（定长 104 B，大端，无对齐填充）

```text
偏移   长度   字段
0      4      magic            "OTPA"
4      2      anchor_version   0x0002 (BE)
6      1      record_type      0x00/0x01/0x02
7      1      flags            0x00
8      16     book_id
24     8      generation       (BE u64)
32     8      next             (BE u64)
40     32     payload          （§2.2）
72     32     integrity        SHA-256(record[0:72])
—— 总长 104 B；写满即整记录覆盖写（write_full 循环至 104 B 全落），随后 fsync；新建文件须同步父目录。
```

**完整性校验方式**：定长 104 B → 长度校验；magic/version/flags/type 枚举校验；payload canonical 校验（§2.2）；`book_id` 等于本端配置；最后校验 `SHA-256(record[0:72]) == integrity`。任一失败 → 该锚 INVALID。
边界声明（v2 §7）：SHA-256 是**工程完整性/损坏检测**，不是信息论机制，不能抵御能写锚+能改哈希的攻击者；抗篡改依赖存储介质保护与可选外部单调水位（§2.5 步骤 5）。升级 MAC/TPM 绑定为部署选项，不改变本布局的语义字段。

### 2.4 记录全序与双锚比较规则

**记录序**（用于"谁是较新状态"）：`ord(r) = (generation, rank(record_type))`，字典序；`rank: INIT=0 < INTENT=1 < COMMIT=2`。
理由：一次 `issue()` 的两轮写（INTENT 与 COMMIT）共用同一 generation（v2 §6 伪代码），序关系只能由相位区分：COMMIT 晚于 INTENT 写入。此为**规格细化**（不改变 v2 语义，见 §7-DD2）。

启动/对账算法（`load_and_reconcile_anchor`，机械可执行）：

```text
1. ra = read+verify(anchorA);  rb = read+verify(anchorB)      # verify = §2.3 全套
2. if ra INVALID or rb INVALID          -> QUARANTINE（双锚冻结不动、不自动写回、
                                           拒绝服务、告警人工恢复；见 §3.2 C 列）
3. if ra.book_id != rb.book_id or != 本端配置 -> QUARANTINE(BOOK_MISMATCH)
4. if ord(ra) == ord(rb):
     if ra.bytes == rb.bytes            -> ADOPT(ra)                      # 一致
     else                               -> QUARANTINE(SAME_ORD_DIFF_BYTES) # 同序不同内容=篡改/异常
5. hi, lo = ord 较大/较小者
   if hi.next < lo.next                 -> QUARANTINE(ORDER_CONTRADICTION) # 违反"只前进"
   ADOPT(hi)；把 hi 完整 canonical 字节 write_full+fsync 覆盖 lo（修复陈旧副本）；
   修复后重读验证；修复写/fsync/重读任一失败 ⇒ fail closed（同 §1.3 T10：拒绝服务、
   不启动，绝不以 lo 继续）；[lo.next, hi.next) 全部记 WASTED_RANGE（仅记录端点，白名单字段）
6. 外部单调水位（若部署）：watermark(已见过的最大 generation，存 TPM/NVRAM 计数器
   或远端审计水位，issue 成功后前向更新)
   if adopted.generation < watermark    -> ROLLBACK_BLOCK：阻断启动+告警，人工处理
   （双锚同时被回滚到旧快照时软件自身不可判，靠水位发现——能力边界，v2 §7/规划 §5.2）
7. if adopted.type == COMMIT 且密码本在位：
   SHA-256(B[adopted.next − 1]) 必须 == adopted.payload，否则 QUARANTINE(BOOK_ANCHOR_MISMATCH)
   （复核只读取已消耗段的正文做完整性比对，不构成重用）
   INIT/INTENT 无哈希可验，跳过。
8. 输出 adopted -> allocator READY(adopted.next)；服务可启动。
```

规则要点（对 WP-08 的硬性要求）：**只采纳较高状态、只写高覆盖低、任何 QUARANTINE 不自动写回**；不存在任何"采用较低值"路径；`next` 与 `generation` 的折算不合法即隔离。

### 2.5 首启初始化

`anchor init`（受控运维操作）：两处介质上锚文件必须**均不存在**（存在即拒绝，防覆盖回滚），写入同一 INIT 记录（§2.6 golden#1），双锚各自 fsync + 父目录同步，外部水位（若有）置 0。此后才允许加载密码本服务。

### 2.6 golden 记录（book_id = `"OTPTERM-TESTBOOK"`，可直接作 WP-08/19 测试向量）

1. **INIT**（gen=0, next=0）：
   `4f545041 0002 0000 4f545045524d2d54455354424f4f4b 0000000000000000 0000000000000000` + 32×`00` payload +
   integrity `e7b9b5274ccaa9515f731468cf39a77f4dd7854b1e90cabd214c86a49cfb7cbd`
2. **INTENT**（gen=7, next=41, reserved=40）：
   `4f545041 0002 0100 4f545045524d2d54455354424f4f4b 0000000000000007 0000000000000029 0000000000000028` + 24×`00` +
   integrity `0ed866f85a72ef89e3e93f396e2477e22275c0b4503dbd6842ef21d254a13d1c`
3. **COMMIT**（gen=7, next=41，示意设 `B[40] = bytes(range(64))`，payload=`SHA-256(B[40])`）：
   `4f545041 0002 0200 4f545045524d2d54455354424f4f4b 0000000000000007 0000000000000029` +
   payload `fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108` +
   integrity `feaa64c277074e34c9b807810268b3ea013141c3a336826050e7e21489e6f62e`

（以上哈希为实际 SHA-256 计算值；解码器单元测试必须以字节串全等校验。）

### 2.7 介质与部署约束

双锚必须在**两处独立介质**（如 TPM/NVRAM 绑定计数器 + 独立加密持久盘）；同一物理介质上的两个文件不构成"独立"，宣称即违反规划 §7.1。密码本与锚分离存储；NFS/FUSE/overlay 等未验证文件系统不得作为锚存储（WP-09 探测、拒绝运行）。锚只含公开元数据（段号/generation/段哈希），不含段正文。

---

## 3. 恢复决策矩阵（验收点③）

### 3.1 观测模型

恢复器**只能观测**：双锚记录（VALID/INVALID、内容）、外部水位（若有）、密码本（供 §2.4 步骤 7 复核）。崩溃时点本身不可直接观测——矩阵按"崩溃时点 × 观测到的双锚状态"给出**必须执行的动作**；同一动作的时点不可分性由"采纳值决定一切"规则保证：

> **恢复总则**：设崩溃前指针为 `i`（本次候选段）。采纳 `next` 后：`adopted.next == i+1` ⇒ 段 `i` 已消耗（浪费或已用），永不复用；`adopted.next == i` ⇒ `i` 未被预留（仅 CP0 一致情形），可被后续正常签发。恢复后的 `next` 在任何格中都**不得低于**崩溃前双锚已持久化的任何 `next`。

锚状态三分类（§2.4 步骤 1–5 的输出）：
- **A 一致**：双锚均 VALID 且 canonical 字节全等；
- **B 一新一旧**：双锚均 VALID、`ord` 不等（含同 generation 的 INTENT/COMMIT 相位混合）；
- **C 校验失败**：任一锚 INVALID（长度/魔法/版本/flags/canonical/integrity/book_id/缺文件/短读），或 §2.4 判定的 QUARANTINE 类异常（SAME_ORD_DIFF_BYTES、ORDER_CONTRADICTION）。

### 3.2 处置矩阵（逐格；审计事件用白名单字段 book_id/段号/generation/结果/错误类别）

| 崩溃时点 ↓ \ 锚状态 → | A 双锚一致 | B 一新一旧 | C 校验失败 |
|---|---|---|---|
| **CP0** intent 写入前（v2§6-1） | **R0A** 采纳旧状态 `(g, next=i)`；段 `i` **未预留、不浪费**；服务可启动 | **R0B** 按 §2.4 采纳较高、修复较低、区间记浪费；服务可启动 | **R0C** 隔离：双锚冻结不动、拒绝服务、`ANC_QUARANTINED` 告警，人工恢复（§3.3）；`i` 保守计浪费 |
| **CP1** 第一 fsync 后、第二 fsync 前（v2§6-2） | **R1A** A 的写未落盘（fsync 失效或写在 CP1a 即丢）：采纳 `(g, next=i)`，`i` 未预留；服务可启动（同时按存储故障上报排查） | **R1B** 采纳 INTENT`(g+1, next=i+1)`；`i` **浪费**；修复旧副本；服务可启动 | **R1C** 同 R0C：隔离+人工；`i` 保守浪费 |
| **CP2** 双 fsync 后、pread 前（=第二fsync后/逻辑取段完成，v2§6-3前半） | **R2A** 采纳 INTENT`(g+1, next=i+1)`；`i` **浪费**（正文从未读出不影响判定：预留已持久化，`i` 只能浪费）；服务可启动 | **R2B** 采纳较高（INTENT`(g+1)` 或旧值，取 ord 大者 ⇒ 必为 INTENT）；`i` 浪费；修复；服务可启动 | **R2C** 同 R0C |
| **CP3** 正文读出后、最终锚完成前（v2§6-3后半；含 A-COMMIT/B-INTENT 相位混合） | **R3A** 双锚 INTENT`(g+1)` 一致（候选未写任何一处）：采纳 `next=i+1`；`i` 浪费；服务可启动 | **R3B** 采纳 `ord` 最大者：A=COMMIT/B=INTENT 同代 ⇒ COMMIT（相位高）；COMMIT/旧 ⇒ COMMIT；INTENT/旧 ⇒ INTENT——结果同为 `next=i+1`；`i` 浪费；修复较低者；服务可启动 | **R3C** 同 R0C |
| **CP4** 最终双 fsync 后、使用前（v2§6-4） | **R4A** 双锚 COMMIT`(g+1, next=i+1)` 一致：先过 §2.4 步骤 7 复核 `SHA-256(B[i])==payload`；通过 ⇒ `i` 浪费（已提交未使用），服务可启动 | **R4B** 采纳 COMMIT，复核哈希，修复旧副本；`i` 浪费；服务可启动 | **R4C** 同 R0C |
| **CP5** 使用中/使用后（v2§6-5） | **R5A** 正常后置状态：采纳 COMMIT`(g+1)`；复核哈希；`i` 记 SPENT-USED；会话状态已随进程丢失 ⇒ 终端恢复=**新握手+新段**（§6.3），绝不重试同段；服务可启动 | **R5B** 采纳较高、复核哈希、修复；`i` 记已用；服务可启动 | **R5C** 同 R0C（隔离+人工；已用段更不可复用） |
| **RR** 双锚同时回滚（外部水位 > 双锚 generation，规划 §5.2） | **RRA** 跨全部时点：`ROLLBACK_BLOCK` 阻断启动 + 告警；无外部水位部署时**软件不可判**——产品必须如实报告能力边界（doctor/文档不得虚假宣称），不得自动猜测前进后继续服务 | **RRB** 同 RRA | **RRC** 同 RRA（与隔离叠加，均为人工） |

补充格：

| 特殊行 | A | B | C |
|---|---|---|---|
| 正常停机（无崩溃） | 采纳当前值，服务可启动 | 不应出现（停机前已修复）；出现按 B 列通用规则处理 | 按 C 列隔离 |

### 3.3 C 列（校验失败）人工恢复规程（WP-08 实现为"隔离 + 只读取证 + 运维命令"，绝不自动写回）

1. 冻结双锚（只读），采集：两锚原始字节、失败类别（INVALID 枚举值）、密码本头、外部水位、审计日志尾部——全部为公开元数据；
2. 运维取证：以最大可信证据（含外部水位、对端锚状态、审计序列）确定**不低于**任何已观测 generation/next 的恢复值；恢复值必须满足 §2.4 步骤 5/7 的全部校验；
3. 以 `anchor repair`（类 T12 的 EV-OP-ADVANCE，带审计）把**两处**锚写成恢复值（只能前进，gap 全记浪费）；随后重新走 §2.4 对账；
4. 在证据不足以证明任何值安全时：**拒绝服务**（宁可停机浪费，不复用）。

### 3.4 恢复动作的可判定性质（供测试 oracle，WP-13/M2）

- P1（不下降）：恢复后 `next >= max(双锚中任何 VALID 记录的 next)`；
- P2（不复用）：恢复后再次 `issue()` 返回的段号 `>= 崩溃前双锚已持久化的最大 next`；
- P3（唯一不浪费窗口）：仅 (CP0 ∧ A ∧ adopted.next==i) 允许 `i` 日后被签发；
- P4（C 列零写回）：锚 INVALID 期间，除人工 `anchor repair` 外无任何路径写锚；
- P5（浪费上限）：单次崩溃最多额外损失 1 段（"最多一段"，v2 §6 前提：不含存储被反复破坏）。

---

## 4. handshake 状态机（验收点④之一；消息字段/线格式见 WP-01）

### 4.1 客户端状态枚举

| 状态 | 含义 |
|---|---|
| C-IDLE | 未发起；本地指针已对账 |
| C-HELLO-SENT | 已发 HELLO(version, book_id, client_nonce, client_pointer, features)，等 ARBITRATE |
| C-SYNC-JUMP | 收到 `SERVER_AHEAD(j)`（`j > client_pointer`）：废弃本地 `[client_pointer, j)` 孤立段（前向本地推进，类 T12），构造 `i=j` 后转 C-ISSUE-SENT |
| C-ISSUE-SENT | 已发 ISSUE_REQUEST(i, client_nonce, server_nonce)；本地 allocator 正在/已经 `issue()`（§1） |
| C-CONFIRM-SENT | 已发 CONFIRM_C2S(i, seq=0)，等 CONFIRM_S2C |
| C-ESTABLISHED | 双向 tag 通过 → 交 §5 session（epoch=0, seq 从 1 起） |
| C-AHEAD-RECOVERY | 收到 `CLIENT_AHEAD`：本地冻结 allocator，进入 §4.4 人工恢复流程 |
| C-CLOSED | 正常终态 |
| C-FAILED(`<sub>`) | 失败终态；sub ∈ {BOOK_MISMATCH, EXHAUSTED, TIMEOUT, TAG_FAIL, PROTO, IO}；会话关闭、本段 SPENT、不降级、不复用 |

### 4.2 客户端转移表

| # | 源 | 事件（触发） | 动作 | 目标 |
|---|---|---|---|---|
| H1 | C-IDLE | 发起连接 | 发 HELLO；起握手超时 | C-HELLO-SENT |
| H2 | C-HELLO-SENT | ARBITRATE `OK(i)`（`i == client_pointer`） | 置 `i` | C-ISSUE-SENT |
| H3 | C-HELLO-SENT | ARBITRATE `SERVER_AHEAD(j>i)` | **只前进**：废弃 `[client_pointer, j)`（审计 WASTED_GAP），`i:=j` | C-SYNC-JUMP → C-ISSUE-SENT |
| H4 | C-HELLO-SENT | ARBITRATE `CLIENT_AHEAD` | 冻结本地 allocator（不再 issue） | C-AHEAD-RECOVERY |
| H5 | C-HELLO-SENT | ARBITRATE `EXHAUSTED`/`BOOK_MISMATCH`；或超时/解析错 | 关连接 | C-FAILED(EXHAUSTED/BOOK_MISMATCH/…) |
| H6 | C-ISSUE-SENT | 本地 `issue()` 成功（§1 T4） | 发 ISSUE_REQUEST 后发 CONFIRM_C2S(seq=0, K_c2s) | C-CONFIRM-SENT |
| H7 | C-ISSUE-SENT | 本地 `issue()` 失败（EXHAUSTED/IO/停机） | 关连接 | C-FAILED(…)（未分配段不受影响） |
| H8 | C-CONFIRM-SENT | CONFIRM_S2C tag 验证通过（段号=i、nonce、方向、epoch 全绑定） | 进入 DATA | C-ESTABLISHED |
| H9 | C-CONFIRM-SENT | tag 失败 / 超时 / 消息错 | 关连接；本段 SPENT（T6/T11） | C-FAILED(TAG_FAIL/…) |
| H10 | C-ESTABLISHED | 会话结束（§5） | zeroize | C-CLOSED / C-FAILED(…) |
| H11 | C-AHEAD-RECOVERY | 人工恢复结论=服务端已前向推进 | 重新连接（回到 H1，指针已对账一致） | C-IDLE |
| H12 | C-AHEAD-RECOVERY | 人工恢复结论=拒绝/超时 | 终止 | C-FAILED(PROTO) / C-CLOSED |
| H13 | 任一非终态 | 底层传输错误/对端关闭 | 关连接；未 ESTABLISHED 者其段 SPENT | C-FAILED(IO) |

终态无出边（C-IDLE 复用属新会话新实例）。任何路径都不得：回退本地指针、重发同段、明文降级。

### 4.3 服务端状态枚举与转移

| 状态 | 含义 |
|---|---|
| S-IDLE | 监听 |
| S-HELLO-CHK | 收 HELLO：解析、校验 version/book_id；book_id 不符 → S-FAILED(BOOK_MISMATCH)（ARBITRATE 带 BOOK_MISMATCH） |
| S-ARB-SENT | 已发 ARBITRATE(server_pointer, result)；result 由指针仲裁决定（下表） |
| S-ISSUE-WAIT | result=OK/SERVER_AHEAD 后等 ISSUE_REQUEST |
| S-ALLOC | 收到 ISSUE_REQUEST(i')：校验 `i' == 本地 allocator.next`（不符 → S-FAILED(PROTO)，不消耗段）；执行 §1 issue() |
| S-CONFIRM-WAIT | 等 CONFIRM_C2S 并验证 tag |
| S-CONFIRM-SENT | tag 通过后已发 CONFIRM_S2C |
| S-ESTABLISHED | → §5 session |
| S-AHEAD-PENDING | result=CLIENT_AHEAD：**指针不动**，等证据/人工（§4.4） |
| S-CLOSED / S-FAILED(sub) | 终态（sub 同客户端） |

服务端仲裁规则（S-HELLO-CHK → S-ARB-SENT 的 result 判定）：

| 比较 | result | 服务端动作 |
|---|---|---|
| server_pointer == client_pointer | `OK(server_pointer)` | 正常等 ISSUE |
| server_pointer > client_pointer | `SERVER_AHEAD(server_pointer)` | 不动指针 |
| server_pointer < client_pointer | `CLIENT_AHEAD` | **绝不**按网络声明前推/回退指针 → S-AHEAD-PENDING |
| next >= segment_count | `EXHAUSTED` | 终态 |
| book_id 不匹配 | `BOOK_MISMATCH` | 终态 |

其余转移（S-ISSUE-WAIT→S-ALLOC→S-CONFIRM-WAIT→S-CONFIRM-SENT→S-ESTABLISHED→S-CLOSED；失败入 S-FAILED 并使对应段 SPENT）与客户端 H6–H13 镜像对称，处置同 §1 T4–T11，不再重复列表；超时、解析错、tag 错、`i'` 不符、重复 nonce/序号一律 fail closed（v2 §4）。

### 4.4 CLIENT_AHEAD 人工恢复路径（验收点④核心）

触发：ARBITRATE 判定 `client_pointer > server_pointer`（服务端滞后或客户端被回滚/异常）。

**禁止（无论任何配置）**：
- 服务端依据未认证的网络声明自动前推指针（伪造大指针=令服务端整本跳段浪费的 DoS 向量）；
- 任何一方回退指针（只前进，v2 §4）；
- 复用/补发客户端声称已用的任何段（服务端"不能凭空补出客户端已经使用过的段"）。

**流程（状态 S-AHEAD-PENDING / C-AHEAD-RECOVERY 并行推进）**：

```text
1. 服务端发 ARBITRATE(CLIENT_AHEAD, server_pointer) → S-AHEAD-PENDING（指针冻结不动）
2. 客户端收到后冻结本地 allocator → C-AHEAD-RECOVERY；提交"锚证据包"（全部为公开元数据）：
   双锚原始记录字节（§2.6 格式）、generation/next、previous_segment_hash、本地审计日志尾部
3. 运维/安全台比对三方证据：客户端锚证据 vs 服务端锚 vs 外部水位
4. 决策矩阵：
   a) 证据可信且水位一致
        → 运维在服务端执行 EV-OP-ADVANCE（T12，带审计）：next := max(server, client_next)，
          gap 全记浪费，generation+1 → 服务端回 S-IDLE；客户端 H11 重连
   b) 证据不足/矛盾
        → 拒绝；客户端离线重新核备/换本；协议不提供自动补段
   c) 外部水位矛盾（疑似双端回滚/回放）
        → 按 §3.2 RR 行处置：双端阻断 + 事件流程
5. 恢复后双方指针必须满足：彼此相等，且 >= 恢复前各自 next；重连走全新握手（H1）
```

配置说明：v2 §4 允许配置"客户端废弃孤立段并从服务端**更高**值重连"的自动路径——该路径仅适用于 `SERVER_AHEAD`（服务端值更高，客户端跳段，H3）；**CLIENT_AHEAD（服务端值更低）没有自动路径**，一律人工（§7-DD1 记录该解读）。

---

## 5. session 状态机（验收点④之二；nonce/AAD 构造见 WP-03）

### 5.1 状态枚举

| 状态 | 含义 |
|---|---|
| ST-DATA | 会话数据阶段：epoch 固定 0（一段一会话，无 rekey 状态——**明确不存在** ST-REKEY，防实现自创）；每方向独立单调 seq，首条 DATA seq=1（CONFIRM 消息为 seq=0） |
| ST-CLOSING | 本端发起关闭：发完在途 record 后等对端关闭 |
| ST-CLOSED | 正常终态；方向密钥 zeroize |
| ST-ABORTED | 异常终态：tag 失败 / 序号溢出（seq 达 2^64−1）/ 乱序重复 / 传输错误；密钥 zeroize；审计错误类别 |

### 5.2 转移表

| # | 源 | 事件 | 动作 | 目标 |
|---|---|---|---|---|
| S1 | ST-DATA | 收/发 record 且 tag 通过、seq 严格 +1 | seq++；交付/发送 | ST-DATA（自环） |
| S2 | ST-DATA | record tag 失败 / 乱序 / 重复 / 截断 / 跨方向搬运 | 立即关闭，**不输出任何未认证明文** | ST-ABORTED |
| S3 | ST-DATA | seq 溢出（本方向 2^64−1 后还需发送） | 立即终止（v2 §9"序号溢出立即终止会话"） | ST-ABORTED |
| S4 | ST-DATA | 本端 close | flush 在途 record | ST-CLOSING |
| S5 | ST-CLOSING | 对端关闭确认/超时 | zeroize | ST-CLOSED |
| S6 | ST-DATA/ST-CLOSING | 传输错误/对端 RST/超时 | zeroize | ST-ABORTED |
| S7 | ST-CLOSED/ST-ABORTED | （无出边） | 终态 | — |

### 5.3 恢复语义（引用 v2 §5，实现归 WP-16）

断线恢复终端上下文 = **重新仲裁 + 签发新段**，绝不重用旧段、绝不以恢复 token 代替新段与确认标签；恢复 token 只能是索引/句柄。并发恢复各得不同段（§1.7）；旧/新连接不得同时写同一 PTY（单主 lease/fencing token，WP-16）。

---

## 6. 参考接口（供 WP-07/08 机械对照；类型不实现语义）

```text
otp-anchor-spec（规划 §2）:
  RecordType ::= INIT | INTENT | COMMIT
  AnchorRecord ::= 104B canonical bytes（§2.3）
  encode(RecordType, book_id, generation, next, payload) -> [u8;104]
  decode(bytes) -> Result<AnchorRecord, AnchorError>     # 长度/魔法/版本/flags/canonical/integrity 全套
  ord(AnchorRecord) -> (u64, u8)                          # (generation, rank)
  reconcile(ra, rb, watermark, book) ->
      Adopt{record, repaired: Option<AnchorId>, wasted: Range} |
      Quarantine{reason} | RollbackBlocked
allocator（WP-07 实现）:
  issue() -> Result<CommittedSegment, AllocError>         # §1.6 全序；唯一对外接口（规划 §2.2）
  # CommittedSegment：不 Clone/Debug/序列化，drop 清零；类型上不存在 Reserved→AEAD 路径
recovery（WP-08 实现）:
  recover(anchor_a, anchor_b, watermark, book) -> RecoveryPlan（§3.2 矩阵动作）
```

---

## 7. 与 v2 设计书的差异申报（无擅自修改，均按规划 §7.2 留痕）

| # | 事项 | 性质 | 处置 |
|---|---|---|---|
| DD0 | 无语义级设计缺陷申报 | — | 实现期若发现冲突，按规划 §7.2 走 DD 报告 |
| DD1 | v2 §4"客户端较高时客户端废弃其孤立段并从服务端更高值重连"一句的适用对象存在歧义 | 解读 | 本规格解读为：自动跳段仅限 SERVER_AHEAD（值更高方获胜）；CLIENT_AHEAD 一律人工。如栋梁/安全裁定相反，提交 DD |
| DD2 | v2 §6 伪代码 INTENT 与 COMMIT 共用同一 generation，双锚"谁新"需相位序 | 规格细化 | §2.4 `ord=(generation, rank)`，不改变 v2 任何语义 |

---

## 8. 验收映射（对 WP-07 / WP-08 / M2 / v2 §9 测试）

| 对方验收条目 | 本规格条款 |
|---|---|
| WP-07：intent→双 fsync→pread→最终双 fsync 顺序；短写；耗尽；只返回 committed | §1.3 T1–T4、§1.6 时序、§1.4 INV_SKIP_COMMIT、§1.2 EXHAUSTED、§6 接口 |
| WP-08：一新一旧取高修复；损坏隔离；双回滚限制告警；不得回退 | §2.4（reconcile 步骤 4–6）、§3.2 B/C/RR 列、§3.4 P1–P4 |
| M2：每个 write/fsync/pread 边界 kill -9 后不复用 | §1.6 CP0–CP5 注入点 × §3.2 矩阵；P2/P3 oracle |
| v2 §9 测试 3（fsync 崩溃点） | §1.6 + §3.2 全矩阵 |
| v2 §9 测试 4（双副本一新一旧） | §3.2 B 列 + §2.4 步骤 5（角色互换用例：锚A/锚B 谁新都覆盖） |
| v2 §9 测试 5（双副本同时回滚告警限制） | §3.2 RR 行 + §2.4 步骤 6（场景 A 能力边界 / 场景 B 水位阻断） |
| v2 §9 测试 6（并发分配） | §1.7 + §1.2 守卫 |
| v2 §9 测试 9（耗尽） | §1.3 T1 守卫、§1.5 EXHAUSTED 行 |
| v2 §9 测试 10（恢复双主） | §5.3 + §4.4 |
| M3：CLIENT_AHEAD 进入人工处理、服务端不回退 | §4.3 仲裁表 + §4.4 禁止清单 |
