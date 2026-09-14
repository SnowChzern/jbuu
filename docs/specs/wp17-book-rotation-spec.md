# [jbuu][WP-17] 换本 drain/rotate 运维流程规格

| 项 | 内容 |
|---|---|
| 任务卡 | 论坛任务 #64 · [jbuu][WP-17-SPEC] 换本 drain/rotate 运维流程规格 |
| 执行人 | 斗拱（designer）；实现卡另建、派榫卯（规划 §4 WP-17 行） |
| 设计依据 | v2 设计书 §3（行 46：耗尽后必须离线换本、两端同时切换密码本 ID）、§7（行 144：轮换时两端 drain、停止新会话、离线核对 book_id/版本、双人授权后原子切换、旧本销毁不依赖 rm）；实现规划书 §4 WP-17 行、M4 验收行（drain 后不接新会话，换本需 book_id/version 明确核对并保留双人授权接口）；WP-02 规格书（allocator 五态/13 转移/崩溃矩阵、§4.3 服务端握手、§5 会话状态机、§2.5 锚初始化）；WP-01 规格书 §4.2/§5（ARBITRATE 布局与错误码注册表）；wp-06（密码本文件头 128B：version/book_id/segment_count）；v0.1 runbook（§2 初始化现状、§7 SSH 过渡垫=换本窗口的带外运维通道） |
| 规格状态 | 待评审；评审冻结后据此开实现卡（本文不含实现代码；纯 markdown 交付，不改产品代码） |
| 范围含 | ① drain 状态机（进入/退出、与 WP-02 五态及 session 状态机衔接、新会话拒绝的确切步骤+错误码）② 换本原子切换（book_id/version 双端核对、双人授权接口、原子性保证、逐条失败路径）③ 旧本处置（不被重新打开的可验证保证 + rm 之外的销毁规程）④ EXHAUSTED 与主动轮换两条入口 ⑤ golden/负例清单 + 偏差申报 |
| 范围不含 | 实现代码与测试代码；WP-01 线格式/仲裁结果枚举的任何修改；WP-02 allocator 状态机的任何修改；v2 §9 五字段审计白名单的任何扩展；doorkeeper（wp14）自身的行为变更；站点物理安保规程（只给出接口与记录格式） |
| 冲突处理 | 本规格与 v2 设计书/WP-01/WP-02/WP-15 冻结面冲突时：实现侧 fail closed，走设计缺陷流程（规划 §7.2）。本文 §8 声明全部决策点与偏差（硬偏差=0，解读细化 2 条，逐条列出） |

> 修订记录：v1.0（本次，任务 #64）：初版。

---

## 0. 术语、总览与冻结面

### 0.1 术语

| 术语 | 定义 |
|---|---|
| **端点** | 一台持有密码本副本与自有双锚的主机。server 端点运行 `jbuu serve`；client 端点按需运行 `jbuu connect`。两端点各持同一 book_id 的本（v2 §1.1） |
| **活跃集** | 一个端点当前服务的 (密码本文件, 锚A, 锚B) 三元组 + 其 book_id/version/segment_count 标识 |
| **drain（排空）** | 端点级运维态：活跃集不变，但**拒绝一切新会话准入**，存量会话自然跑完（v2 §7 行 144"停止新会话"） |
| **rotation（换本）** | 完整运维流程：两端点 drain → 离线核对新 book_id/version → 双人授权 → 每端原子切换活跃集 → 旧本处置 |
| **ceremony（换本仪式）** | 一次换本在一台端点上的全部受审计操作序列，以随机 `ceremony_id` 标识 |
| **managed 模式** | `serve --config-dir D` 启动：活跃集由 `D/active-set.json` 清单定义（§2.3）。drain/rotate 仅在 managed 模式可用 |
| **排空标记** | `D/drain.marker` 文件，绑定 book_id（§1.3），是主动 drain 的唯一持久载体 |
| **运维台账** | `D/rotate.ledger`：append-only JSONL，记录 ceremony 全事件（§7）。与 v2 §9 五字段**会话审计日志是两个制品**，白名单互不重叠（D9） |

### 0.2 总览

```text
                 入口①EXHAUSTED(next≥N,自动)          入口②主动轮换(运维)
                        │                                   │
                        ▼                                   ▼
        ┌───────────────────────────────────────────────────────────┐
        │ E-DRAINING（§1）：活跃集=旧本 B_old                          │
        │   · 准入门拒绝新 HELLO（ARBITRATE result=2, 内部 0x0501）   │
        │   · 存量会话照常；恢复重连=新 HELLO=被拒                     │
        └──────────────┬─────────────────────────────┬──────────────┘
           abort(双人) │                             │ 离线核对+stage(A)+commit(B)
                       ▼                             ▼
                 回到 E-ACTIVE(B_old)      E-ACTIVE(B_new) + E-RETIRED(B_old)（§2/§3）
                       │                             │
                       │                    处置授权(双人)→销毁→确认
                       │                             ▼
                       └──────── 不可回退 ───── E-DISPOSED(B_old)（终态）
```

换本全程（两条入口共用）对协议线格式零改动、对 allocator 五态零改动、对五字段审计白名单零改动——这是本规格的三条硬边界（§0.3）。

### 0.3 上游冻结面（本规格绝不触碰）

| 冻结面 | 出处 | 本规格的做法 |
|---|---|---|
| 线格式、消息注册表、`ARBITRATE.result∈{0..4}` | WP-01 §2/§4 | 不新增消息、不新增 result 值；drain 拒绝**复用** result=2（决策 D2，§8） |
| 统一错误码既有码值 0x0100–0x0103/0x02xx/0x03xx/0x04xx | WP-01 §5.2 | 不复用不重编；**新增** 0x05xx 运维类别（决策 D10，§6） |
| allocator 五态与 13 转移 | WP-02 §1 | drain 不进 allocator：准入门位于 T1 之前（§1.1） |
| handshake/session 状态机既有转移 | WP-02 §4/§5 | 只在 S-HELLO-CHK 前加一个准入分支，复用既有 EXHAUSTED 终态路径（§1.4） |
| 审计日志五字段白名单 | v2 §9、`otp-platform::audit` | 不扩字段；rotation 事件落**独立台账**（决策 D9，§7） |
| 锚记录 104B 格式与 INIT 语义 | WP-02 §2 | 新锚初始化逐字复用（fresh 路径，天然满足"两处均不存在"） |
| 密码本文件头 128B | wp-06 | 只读取 version/book_id/segment_count 做核对，不改格式 |
| `serve`/`connect` 既有参数行为 | WP-15 | 显式路径模式行为不变；新增互斥的 `--config-dir` 模式（决策 D8） |

---

## 1. ① drain 状态机

### 1.1 层次定位：drain 不是 allocator 第六态

WP-02 的 allocator 五态（READY/RESERVED/COMMITTED/IN_USE/SPENT）与 13 转移**原样保持**。drain 是**端点级新会话准入门（admission gate）**，位置在握手层收到并解码 HELLO 之后、进入 WP-02 §4.3 服务端仲裁之前：

```text
连接到达 → codec 解码 HELLO（WP-01 §3.2，0x0301–0x0308 不变）
        → 【ED-GATE 本规格新增】drain_active 判定（§1.3）
        → book_id 核对（0x0100）→ 指针仲裁（0x0101/0x0102/0x0103）
        → ISSUE_REQUEST → allocator T1…（WP-02 §1 不变）
```

关键性质（实现卡验收要点）：

| # | 性质 | 说明 |
|---|---|---|
| DG-1 | drain 期间 `issue()` 永不被新连接触发 | 准入在 T1 之前拒绝，allocator 停留在 READY，指针不动、零段消耗 |
| DG-2 | 准入前已进入握手的连接**不受影响** | drain 的切口=HELLO 准入时刻；已返回 OK/SERVER_AHEAD 的连接照常走完 T1–T5、CONFIRM、DATA、关闭（避免不必要浪费段——中途掐断只会把段变 SPENT） |
| DG-3 | drain 不获取 `pointer_lock` | 标记读取是无锁的单次小文件读（标记本身原子替换，§1.3），与分配器临界区零交互 |
| DG-4 | 存量会话的 allocator 槽位照常演化 | IN_USE →（T7/T8）→ SPENT 不受 drain 影响 |
| DG-5 | 恢复（`connect --recover`）在 drain 中被拒 | 恢复=重新握手+新段（WP-02 §5.3）=新 HELLO=被拒。**运维含义：drain 前应通知用户，断线即失终端** |

### 1.2 端点书本生命周期状态机（EBSM）

drain 的形式化载体是活跃集上叠加的**书本生命周期状态**（book-lifecycle，逐本追踪；一端同一时刻只有一个活跃集）：

| 状态 | 记号 | 语义 | 可观测证据（`--status` 判据） |
|---|---|---|---|
| 活跃 | `E-ACTIVE(B)` | B 为活跃集，接受新会话 | active-set.json 引用 B；无（匹配 B 的）drain.marker |
| 排空 | `E-DRAINING(B)` | B 仍为活跃集，拒绝新会话，存量会话继续 | drain.marker.book_id==B（管理性）；或锚 next≥N（结构性，无标记） |
| 退役 | `E-RETIRED(B)` | B 已被切换出活跃集，文件仍在，未被处置 | 台账有 COMMIT；旧集文件存在；无 DISPOSAL_AUTHORIZE |
| 已处置 | `E-DISPOSED(B)` | 终态：B 的全部文件已销毁，**永不回到任何状态** | 台账有 DISPOSAL_CONFIRM；旧本/旧锚路径全部不存在 |

**转移表（全部）：**

| # | 源状态 | 事件 | 守卫 | 目标状态 | 动作与持久化 |
|---|---|---|---|---|---|
| E1 | E-ACTIVE(B) | ED-DRAIN-SET（运维） | 单人 + 台账；本端 managed | E-DRAINING(B) | 原子写 drain.marker（绑定 B.book_id）+ 目录 fsync；台账 `DRAIN_SET` |
| E2 | E-ACTIVE(B) | ED-EXHAUSTED（自动） | 锚 next ≥ segment_count | E-DRAINING(B) | **不写标记**（锚状态即持久证据）；stderr/台账 `EXHAUSTED_DETECTED`（每次启动至多一条） |
| E3 | E-DRAINING(B) | ED-DRAIN-ABORT（运维） | 双人授权（§2.2）+ 仅当由 E1 进入 | E-ACTIVE(B) | 原子删 drain.marker + 目录 fsync；台账 `DRAIN_ABORT`。**结构性排空（E2 进入）不可 abort**——无段可签，只能换本 |
| E4 | E-DRAINING(B_old) | ED-SWITCH-COMMIT（运维，双人） | §2.4 C-5 全部守卫 | E-ACTIVE(B_new) ∧ E-RETIRED(B_old) | manifest 原子替换（§2.3）；台账 `COMMIT`（结果类，§7.2）；标记留待 serve 启动时按 stale 规则清理（§1.6） |
| E5 | E-RETIRED(B) | ED-ROLLBACK（运维，双人） | 台账无 DISPOSAL_AUTHORIZE | E-DRAINING(B) | manifest 回滚（§2.8）；台账 `ROLLBACK`；随后可走 E3 恢复 |
| E6 | E-RETIRED(B) | ED-DISPOSAL-AUTHORIZE（运维，双人） | — | E-RETIRED(B)（子态：已授权处置） | 台账 `DISPOSAL_AUTHORIZE`（含旧锚终态 next/generation/摘要）；**此后 E5 永久不可达** |
| E7 | E-RETIRED(B)（已授权） | ED-DISPOSAL-CONFIRM（运维，双人） | 旧本/旧锚/旧标记/旧 pending 路径全部不存在（§3.2 清单核销） | E-DISPOSED(B) | 台账 `DISPOSAL_CONFIRM`（含 method/media/执行人） |

不可达/非法（检出即 fail closed + 台账 `INV_*`）：

- `E-DISPOSED → 任何`：终态；处置确认后任何 B 的文件再现 = 安全告警 BLOCK（§3.3，0x0506）。
- `E-ACTIVE(B_old)` 在 E4 之后：manifest 单调前向，active-set.json 永不指回旧集（除非显式 E5 双人回滚）。
- E2 之后走 E3：结构性耗尽没有"恢复服务"语义。
- 同一 book_id 二次 E1/E4（同本重激活）：stale 规则之外一律拒绝（防旧本借 ceremony 复活，§3.1 OB3）。

### 1.3 drain_active 判定（单一布尔函数）

serve 对每个到达 HELLO 的连接求值（机械可执行）：

```text
drain_active(active_book_id, next, N) :=
      next >= N                                        # 结构性：EXHAUSTED（锚即持久证据）
   ∨  ( marker 存在 ∧ 可解析 ∧ marker.book_id == active_book_id )   # 管理性
其中 marker 存在 ∧ 不可解析  ⇒  视为 drain_active = true（fail closed）
                                 + 告警 0x0502 DRAIN_MARKER_INVALID
     marker 存在 ∧ 可解析 ∧ marker.book_id ≠ active_book_id ⇒ stale：
                                 仅在 serve 启动时评估（§1.6），连接期该标记不构成 drain
```

**drain.marker 格式**（JSON，原子替换：写 `drain.marker.tmp` + fsync + rename + 目录 fsync；幂等：重复 drain 覆盖为更新时刻）：

```json
{"magic":"JBUU-DRAIN-1","book_id":"<32hex>","version":<u16>,"segment_count":<u64>,
 "next_at_drain":<u64>,"generation_at_drain":<u64>,
 "set_by":"<操作人>","ts_utc":"<RFC3339>"}
```

规则：magic/version/book_id 校验失败 = 不可解析 = fail closed（宁可拒服务，绝不猜）。marker 只含公开元数据（与锚同级别），无秘密。撕裂读不可能出现（写侧原子替换）；读侧任何短读/坏 JSON 一律按 fail closed 处理——这使"磁盘故障导致标记损坏"自动落入安全侧。

### 1.4 新会话拒绝的确切口径（步骤 + 错误码）★M4 验收对应

**服务端（拒绝发生的唯一点）**——WP-02 §4.3 S-HELLO-CHK 状态内、既有检查之前插入一步：

```text
S1  收 HELLO 帧，codec 解码（WP-01 §3.2 全套：0x0301/0x0302/0x0303/0x0305/0x0306/0x0308 不变）
S2  【ED-GATE 新增·第一检查】求 drain_active：
      true  → 发 ARBITRATE(result=0x02 EXHAUSTED, server_pointer=N) → 关连接 → 结束
              内部错误码 0x0501 DRAIN_ACTIVE；stderr/ops-log 一行结构化记录（§7.3）；
              不比对 book_id、不读指针仲裁、不触发任何 allocator 转移（DG-1）
      false → 继续 S3
S3  book_id 核对（0x0100，不变）→ 指针仲裁（0x0101/0x0102/0x0103，不变）→ …
```

- **检查顺序是规范的一部分**：drain 判定先于 book_id 核对（决策 D3，§8；负例 N16 锁定该顺序：drain 期间错本 HELLO 也得 result=2）。
- **线上行为**：`ARBITRATE(result=2, server_pointer=N)`，N=活跃本 header 的 segment_count（公开元数据）。result=2 的 canonical 组合要求 sp==N（WP-01 §4.2 客户端 [state] 校验），客户端两端同本故校验通过。
- **golden 帧 V1**（33B，十六进制小写；server_nonce=16×0xAA，N=1024）：
  `0002000200000019aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000000000040002`
  （帧头 8B：version=0x0002, msg_type=0x0002, payload_len=25；nonce 16B；sp=0x0400 BE；result=0x02。）
  管理性 drain 与结构性 EXHAUSTED 发出的帧**逐字节同型**（P5：线上不可区分是设计属性，区分只在服务端 stderr/台账）。
- **客户端行为**：完全复用既有 H5/C-FAILED(EXHAUSTED) 路径（WP-02 §4.2）——终止、联系运维。客户端无法区分"耗尽"与"排空"；运维提示文案 SHOULD 提及两种可能（informational）。
- **零消耗**：拒绝发生在 T1 之前，锚不动、无段浪费、五字段审计日志无新条目（drain 拒绝不是段事件，落台账/stderr，D9）。

**客户端端点的"停止新会话"**：client 无常驻进程，drain=运维纪律（窗口内不发起新 `connect`）。协议不在带内传达 drain（无消息可载、不新增——冻结面）；错本/排空/耗尽在客户端侧本就表现为失败终止。

### 1.5 与 session 状态机 / 恢复路径的衔接

| 衔接点 | drain 期间的行为 | 依据 |
|---|---|---|
| ST-DATA 存量会话 | 照常收发（S1 自环）、关闭（S4/S5）、中止（S2/S3/S6）；密钥生命周期不变 | DG-2/DG-4；v2 §7 只要求"停止新会话" |
| ST-CLOSING/ST-CLOSED/ST-ABORTED | 不受影响 | 同上 |
| 恢复重连（WP-02 §5.3） | **被拒**（新 HELLO 过 ED-GATE → result=2）；旧终端随 lease 超时/PTY 生命周期消亡 | DG-5 |
| PTY 单主 lease（WP-16） | 不变；drain 不干预 lease 语义 | 冻结面 |
| CLIENT_AHEAD 人工恢复（WP-02 §4.4） | drain 期间照常可执行人工 `anchor repair`（类 T12 前向推进）——但即便修复，新会话仍被 ED-GATE 拒；两机制正交 | 互不感知 |

### 1.6 drain 的退出条件

| 退出方式 | 条件 | 机制 |
|---|---|---|
| 换本完成（正路） | E4 commit 后 serve 以新 manifest 启动 | serve 启动时读 marker：`marker.book_id ≠ 活跃 book_id` ⇒ stale ⇒ **删除标记（unlink + 目录 fsync）+ 台账 `DRAIN_MARKER_STALE_REMOVED` 告警**，新本正常服务。删除失败 ⇒ 拒绝启动（fail closed，F11）。commit 本身不删标记——防止旧 serve 尚在运行时窗口内恢复接新 |
| 主动中止 | E3 ED-DRAIN-ABORT | 双人授权删除标记（§2.2）；旧本恢复服务。仅限管理性 drain |
| 结构性耗尽 | 无退出 | 锚 next≥N 不可逆（fail-to-waste），唯一出路=换本 |

标记的持久性=换本窗口跨重启存活：serve 重启后标记仍在 ⇒ 继续排空（这正是 v2"停止新会话"在崩溃/重启下的延续）。

### 1.7 入口覆盖（任务④，详见 §4）

- **入口① EXHAUSTED（自动）**：E2。T1 守卫的仲裁层投影——每个新 HELLO 得 result=2（现有行为，DG-1 保证零副作用）；首次探测记 `EXHAUSTED_DETECTED`。客户端侧：本地 next≥N 时 connect 应在发起网络前本地失败（0x0101，推荐实现细节）。
- **入口② 主动轮换（运维）**：E1。可在任意剩余容量下发起（策略建议：监控 `anchor inspect` 的 next/N，如 80% 水位预警——站点决策，不入协议）。
- **边角：generation 上限**。WP-02 §2.1"u64 溢出前必须换本"：serve 启动时 generation ≥ 2^63 ⇒ `GEN_CEILING_WARN` 告警（台账）；issue 路径 generation 溢出检查失败 ⇒ fail closed 拒绝服务（0x04xx 内部错误类别复用，不新增码）——强制走换本。该情形实际不可达（2^63 次 issue），规格化仅为完备。

---

## 2. ② 换本原子切换

### 2.1 参与者与制品

| 角色/制品 | 定义 |
|---|---|
| 授权人 A / B | 两名到场运维人员。机械身份=OS 账号（uid，命令自动采集）；记录身份=`--authorizer-a/b` 声明串（非空、互异）。**本接口提供的是双人问责与双人机械闸门，不是密码学不可否认**——两名不同人类对应两个不同 OS 账号是站点纪律（sudoers 限定 rotate 角色账户），root 伪造一切属 v2 §2 恶意管理员非目标（D6 边界声明） |
| 分发介质 | 新本离线分发载体（只读校验介质，v2 §3）。**永不直接服务**：stage 时复制入端点集目录 |
| 带外通道 | 两端点操作员核对 book_id/version/N/全文件 SHA-256 所用通道（语音/签收单）。换本窗口内 jbuu 本体在 drain，运维终端可走 SSH 过渡垫（runbook §7 doorkeeper）——这正是 wp14 存在的运维意义 |

### 2.2 双人授权接口定义（授权对象、操作序列、审计格式）

**授权对象（受双人闸门保护的动作集）**：`COMMIT`（切换）、`DRAIN_ABORT`（中止排空）、`ROLLBACK`（回滚）、`DISPOSAL_AUTHORIZE`、`DISPOSAL_CONFIRM`。进入 drain（E1）单人即可——方向为"更安全态"，与断路器同理（D5）。

**操作序列（两步 stage/commit 模式）**：

```text
步骤 1（授权人 A 的 shell，OS 账号 uid_A）：
  jbuu rotate --stage --new-book /media/new.book \
       --book-id <32hex> --version <u16> --authorizer-a <A>
  → 校验（§2.5 本地核对全套）→ 复制新本入集目录 → 新锚 INIT（fresh 路径，WP-02 §2.5）
  → 写 rotate.pending（含 book_sha256/双锚摘要/superseded_book_id/uid_A/有效期）

步骤 2（授权人 B 的 shell，OS 账号 uid_B）：
  jbuu rotate --commit --book-id <32hex> --version <u16> \
       --authorizer-a <A> --authorizer-b <B>
  → 校验 pending 存在且未过期 → R2: A≠B 且均非空 → R1: uid_B ≠ pending.uid_A
  → 复核 staged 文件摘要未变 → manifest 原子替换（§2.3）→ 台账 COMMIT（结果类）→ 删除 pending
```

（台账条目分两类，见 §7.2 写入纪律：**意图类**（DRAIN_SET/STAGE/DISPOSAL_AUTHORIZE 等=授权事实）先记账后动作，写失败即命令中止；**结果类**（COMMIT/ROLLBACK/DISPOSAL_CONFIRM=既成事实）在原子动作成功后立刻记账，写失败仅告警退出——状态权威始终是 manifest/文件（F10、F13）。）

**机械规则**：

| # | 规则 | 违反→ |
|---|---|---|
| R1 | commit 执行 uid ≠ stage 执行 uid（读 pending.exec_uid） | 0x0504 |
| R2 | `--authorizer-a ≠ --authorizer-b` 且均非空 | 0x0504 |
| R3 | 逃生门 `--allow-single-user`（仅测试/受控环境）：允许 R1 失效，但台账条目 `single_user=true` 永久标记，`--status`/doctor 高危显示 | —（可见性换可用性，D6） |
| R4 | pending 有效期：默认 24h，`--expiry-secs`（300..86400）可调；过期 commit ⇒ 0x0504，须重新 stage | 0x0504 |
| R5 | stage 前置：本端 managed ∧ 处于 E-DRAINING（v2 §7 顺序的机械化：先排空后切换） | 0x0500 |

单人想独闯：stage(A) 后自任 B commit ⇒ R1 拦截；伪造 pending ⇒ 无从伪造 uid_A（除非同 uid ⇒ R1）；root 直改文件 ⇒ 超出边界（§2.1 声明）。

**审计记录格式**：见 §7 台账（事件、book_id/version/next/generation、摘要、authorizer、exec_uid、tty、result、error_code、链式摘要）。

### 2.3 managed 模式与 active-set.json（原子切换的载体）

**目录布局（约定，informative）**：

```text
/etc/jbuu/                          # config-dir（示例）
  active-set.json                   # 活跃集清单（原子替换对象）
  active-set.json.prev              # commit 前保存的旧清单（回滚凭据+证据）
  drain.marker / rotate.pending / rotate.ledger
/var/lib/jbuu/sets/<ceremony_id>/book                    # 新本 staged 副本
<独立介质A>/jbuu/sets/<ceremony_id>/anchor               # 新锚 A（INIT，fresh 路径）
<独立介质B>/jbuu/sets/<ceremony_id>/anchor               # 新锚 B（INIT，fresh 路径）
```

新锚默认路径=当前 manifest 两锚的**父目录**下新 `<ceremony_id>` 子目录（介质继承，`--new-anchor-a/b` 可覆盖）。fresh 路径天然满足 WP-02 §2.5"锚文件必须均不存在"——旧锚原地保留作处置证据，绝不覆盖。

**active-set.json 格式**：

```json
{"magic":"JBUU-ACTIVE-1","ceremony_id":"<32hex>",
 "book_id":"<32hex>","version":<u16>,"segment_count":<u64>,
 "book_path":"…","anchor_a_path":"…","anchor_b_path":"…",
 "superseded_book_id":"<32hex>",
 "activated_utc":"<RFC3339>","authorizer_a":"…","authorizer_b":"…"}
```

**原子替换（唯一状态变更动作）**：

```text
1. cp active-set.json → active-set.json.prev；fsync（证据+回滚凭据；崩溃于此 ⇒ active 未变，安全重试）
2. 写 active-set.json.tmp（新集全文）；fsync
3. rename(active-set.json.tmp → active-set.json)；fsync(目录)      ← 唯一原子点
```

**serve 绑定校验（V-M，启动时全套，任一失败拒绝启动=0x0503 fail closed）**：

| # | 校验 |
|---|---|
| V-M1 | magic/version/JSON 可解析；路径字段非空且为绝对路径 |
| V-M2 | `book_path` 头校验通过（wp-06 全套）；`version` ∈ 二进制支持集（当前 {0x0001}） |
| V-M3 | manifest.book_id == book 头 book_id == 锚A 解码 book_id == 锚B 解码 book_id（**三角一致**） |
| V-M4 | manifest.segment_count == book 头 segment_count |
| V-M5 | 锚经 `decode_and_verify` 全套（WP-02 §2.3）通过 |
| V-M6 | 若 drain.marker 存在：book_id 匹配 ⇒ 排空中启动（接 ED-GATE）；不匹配 ⇒ stale 清理流程（§1.6） |

`--config-dir` 与显式 `--book/--anchor-*` 互斥（同给即 CLI 错误）；显式路径模式=非托管（v0.1 行为不变，仅供测试/迁移前）：无标记/无 rotate 生命周期，结构性 EXHAUSTED 仍生效。**换本 ceremony 只在 managed 端点可用**（N17）。

### 2.4 全流程（两端点，C-0…C-12；golden 场景 G6/G7 的脚本骨架）

| 步 | 动作 | 校验/证据 |
|---|---|---|
| C-0 | 带外：约定维护窗口；`book generate` 生成 B_new；只读介质分发到两端点 | 双端各自 `book inspect` 通过（重复段/统计检查，规划 §5 测试 1） |
| C-1 | 带外核对（任务②"双端核对"）：两端操作员比对四个值：`book_id_new`、`version`、`segment_count`、**全文件 SHA-256** | 四值一致才继续；各自记录（stage 时写入 pending/台账） |
| C-2 | 两端点 drain：server 端 `jbuu drain --config-dir …`；client 端=纪律停止新 connect（§1.4） | E1；台账 DRAIN_SET；新 HELLO 得 V1 帧 |
| C-3 | 存量会话自然结束（或窗口策略到期后运维停 serve——serve 停止=存量即断，v0.1 语义） | 台账 SERVE_STOP |
| C-4 | server 端 stage（A） | R5/V-M 前置；pending 落盘 |
| C-5 | server 端 commit（B） | R1/R2/R4；manifest 原子替换；E4 |
| C-6 | server 端重启：`serve --config-dir` | V-M1..6；stale 标记清理+告警；新本服务 |
| C-7 | client 端重复 C-4/C-5/C-6（同 B_new） | client 端 E4 |
| C-8 | 端到端验证：新本 connect 成功（新 book_id，next 0→1） | 会话审计 issued；旧本 connect → result=3（G7） |
| C-9 | 两端 `rotate --status`：PENDING_DISPOSAL | 台账链完整 |
| C-10 | 双人 `rotate --authorize-disposal`（两端各自，针对各自 B_old 副本） | 旧锚终态入台账（final next/generation/摘要） |
| C-11 | 执行销毁（§3.2 规程） | 介质/卷密钥处置记录 |
| C-12 | 双人 `rotate --confirm-disposal`（文件层核销通过后） | E7；status=DISPOSED |

顺序说明（对 v2 行 46"两端同时切换"的细化，§8-DD2）：无跨端原子原语（协议带内无轮换消息，v2 规定离线流程）；不变量=**同一窗口内逐端切换，每端 commit 后立即不可逆脱离旧本，期间任何错配连接得 BOOK_MISMATCH(result=3) 而非成功会话**——不存在"一端旧一端新还建立会话"的状态。推荐 server 先切（client 错配自检更直观），顺序非规范。

### 2.5 book_id/version 核对步骤（任务②"双端核对"的机械层）

| 层 | 核对内容 | 执行点 | 失败→ |
|---|---|---|---|
| L1 | `--book-id`/`--version`（操作员手输）vs 新本文件头实际值 | stage（命令内） | 0x0503（N4）。**目的：强迫人真正查看并转写新本身份，拦住拿错文件/拿错版本** |
| L2 | 新本头校验（magic/version=支持集/segment_len=64/count∈[1,2^40−1]/header_hash） | stage | 0x0503 |
| L3 | 新锚 INIT 记录（gen=0,next=0）且 book_id==新本 | stage（写后回读验证） | 0x0503 |
| L4 | staged 文件摘要：commit 时重算 book/双锚 SHA-256 == pending 记录值 | commit | 0x0503（N5：stage 与 commit 之间被篡改） |
| L5 | 跨端一致：两端 pending/台账的 book_id/version/segment_count/book_sha256 相等 | C-1 带外 + 事后审计核对脚本（G8，比对两台账） | 流程拒绝继续（带外）；事后发现=事件流程 |

version 语义：当前支持集 {0x0001}；未来格式升版=显式迁移卡（二进制与头 version 不符即 0x0503，fail closed 不猜，N10）。

### 2.6 原子性保证（声明 + 论证）

**保证 G-A（切换原子性）**：从"活跃集=B_old"到"活跃集=B_new"之间不存在可观测的中间态；任何崩溃时点之后，`active-set.json` 的内容**就是**端点状态的唯一权威（single source of truth）。

论证：

1. 状态载体只有一个文件（active-set.json），其替换是单个 `rename(2)`——内核原子；目录 fsync 后跨崩溃持久。
2. rename 前：active=B_old（端点仍被 drain 标记排空）；rename 后：active=B_new。中间无第三值。
3. serve 不缓存活跃集跨重启；启动即重读 manifest 并做 V-M 全套——即使 rename 后 fsync 前掉电导致 rename 回滚，重启后 active=B_old 且**旧标记仍匹配旧本 ⇒ 继续排空**（安全侧）。
4. 旧集文件在处置前原地不动（新集全新路径），故切换动作不产生对旧本的写——处置证据链不被污染。

**保证 G-B（零段消耗）**：ceremony 的全部命令不触碰 allocator（marker/pending/manifest/台账均非锚路径）；C-3 后端点无会话。换本本身消耗 0 段（P2）。

**保证 G-C（不可逆脱离旧本）**：commit 后，本端不存在任何受支持的命令以旧本签发（serve 只经 manifest 打开 book；旧本路径无 manifest 引用）。回到旧本的唯一受支持路径=E5 双人回滚（且处置授权前）。

### 2.7 失败路径逐条（F1–F13）

| # | 时点 | 现象 | 错误码 | 状态归宿（权威=manifest） | 处置 |
|---|---|---|---|---|---|
| F1 | stage | 新本文件缺失/不可读 | 0x0503 | active 不变 | 修正介质后重 stage |
| F2 | stage | 新本头校验失败（坏 magic/长度/哈希） | 0x0503 | active 不变 | 换分发介质，事件上报 |
| F3 | stage | L1 核对不符（手输≠头） | 0x0503 | active 不变 | 重新转写（这正是核对的目的） |
| F4 | stage | 新锚 INIT 失败（路径已存在/IO/权限） | 0x0505 | active 不变；staged 目录清理 | 排查介质后重 stage |
| F5 | stage | 前置不满足（未 drain / 非 managed） | 0x0500 | active 不变 | 先 drain / 迁移 managed |
| F6 | commit | pending 缺失/过期/已被消费（重放） | 0x0504 | active 不变 | 重新 stage |
| F7 | commit | R1/R2 违反（同 uid / A==B / 空名） | 0x0504 | active 不变 | 换第二人到其账号执行 |
| F8 | commit | L4 摘要不符（staged 被篡改） | 0x0503 | active 不变；pending 作废+事件 | 全量重 stage；按事件调查 |
| F9 | commit | 步 1/2（prev 保存/tmp 写）IO 失败 | 0x0505 | active=B_old（rename 未发生） | 重试 |
| F10 | commit | 步 3 rename/fsync 失败或结果不确定 | 0x0505 | **以读回的 manifest 为准**：B_new ⇒ 已切换（告警后走 C-6 起）；B_old ⇒ 未切换，重试 | `rotate --status` 判读后处置 |
| F11 | serve 启动 | V-M 任一失败（三角不一致/头坏/锚坏） | 0x0503 | 拒绝启动（fail closed）；端点停机 | 修复 staged/manifest 后重试；无法证明安全则停机人工 |
| F12 | serve 启动 | stale 标记清理失败（unlink/fsync IO） | 0x0505 | **拒绝启动**（标记语义不明不冒险） | 人工清除后重启 |
| F13 | 任意 | 台账追加失败（IO） | 0x0505 | 意图类条目写失败 ⇒ 命令中止（状态不变）；结果类条目写失败 ⇒ 状态已变（权威=manifest），退出告警，status 对账报 INCONSISTENT | 排查磁盘；台账为审计生命线 |

规则汇总：所有失败 fail closed；不确定时以 manifest 读回值为权威；意图先记账、结果即记账（§7.2），对账不一致即 status BLOCK。

### 2.8 回滚（rollback）

- 命令：`jbuu rotate --rollback --book-id <旧本32hex> --authorizer-a A --authorizer-b B`；双人机械规则同 §2.2（R2 恒适用；R1 变体：**rollback 执行 uid ≠ 该 ceremony 台账 COMMIT 条目的 exec_uid**）。
- 守卫：台账存在该 book_id 的 COMMIT ∧ 不存在 DISPOSAL_AUTHORIZE；`active-set.json.prev` 存在且其 book_id==目标旧本。
- 动作：rename(prev → active-set.json)（原子，同 §2.3 步 3）+ 台账 ROLLBACK；旧本回到 E-DRAINING（标记仍在）⇒ 可 E3 abort 恢复服务。
- 处置授权后回滚**永久拒绝**（E6 之后 E5 不可达，N13）——"旧本不被重新打开"的终局保证从处置授权起算（§8-DD3 声明该起点的选择）。

---

## 3. ③ 旧本处置

### 3.1 "不被重新打开"的可验证保证（五层）

| 层 | 保证 | 验证方法（`rotate --status` / doctor / 测试） | 失败现象 |
|---|---|---|---|
| OB1 服务门 | 切换后任何旧 book_id 的 HELLO ⇒ ARBITRATE result=3 BOOK_MISMATCH（0x0100 既有路径） | 负测：旧本 connect（G7） | —（协议固有） |
| OB2 文件层 | 旧本/旧锚在台账登记路径上不存在（处置后） | status 核销清单逐路径 stat | 缺失即 0x0506 / status BLOCK |
| OB3 清单层 | 无任何 active/pending/prev 制品引用旧 book_id | manifest/pending/prev 的 book_id 机械比对 | 引用存在 ⇒ 0x0506 + BLOCK |
| OB4 锚层 | 不存在"旧 book_id 的锚被活跃 manifest 引用"；孤儿锚（在册路径外发现的 OTPA 记录）被告警 | 扫描锚存储区（同目录树）比对台账 | 孤儿锚 ⇒ status 高危告警（可能是被复制的旧锚） |
| OB5 台账层 | E-DISPOSED 链完整（COMMIT→DISPOSAL_AUTHORIZE→DISPOSAL_CONFIRM），链式摘要连续；manifest 与台账对账一致 | 链校验（§7.2）+ manifest↔台账对账 | 断链/缺环/对账不符 ⇒ status BLOCK |

补充句柄检查（OB2 扩展）：confirm 与 status 时扫描 `/proc/*/fd` 符号链接，任何进程仍打开旧本/旧锚路径 ⇒ 0x0506（"still open"字面兑现）。serve 是唯一合法打开者且已换集，此检查在实现上恒应为空——非空即异常（备份 agent、残余进程、取证快照等）。

**能力边界（如实声明，与 v2 §7 一致）**：以上保证对**积极配合的端点与受支持命令面**成立；能写任意文件的恶意管理员可手工把 serve 指回旧本文件——属 v2 非目标。G2–G5 的价值=把"意外重开"变成**必被检测**（文件再现=BLOCK 告警，§3.3）。

### 3.2 销毁规程（rm 之外）

v2 §7 明文："旧本销毁不能只依赖 rm"（普通删除不消除 SSD wear-leveling 残留）。规程（按部署形态）：

| # | 动作 | 说明 |
|---|---|---|
| D-S1 | **密码学擦除（首选，可审计）** | 密码本所在加密卷/硬件自加密盘：销毁卷密钥（LUKS kill-header/keyslot、SED crypto-erase）。密钥一死，介质残留密文不可读。处置记录写入台账 method 字段 |
| D-S2 | **介质物理销毁（高价值场景）** | 按站点规程：消磁/粉碎；SSD 另加 NVMe/ATA crypto-erase 或物理毁损。SSD over-provisioning 残留风险写入处置记录（不虚假宣称已消除） |
| D-S3 | **tmpfs 形态** | 卸载 tmpfs + 断电（RAM 残留随断电消失）；swap/core 约束由 doctor 既有检查背书（WP-15） |
| D-S4 | **锚与标记清理** | 旧锚（公开元数据，无秘密，但为卫生与 G4 完整性一并销毁）、drain.marker、rotate.pending、分发介质原件与运输副本——全部列入核销清单 |
| D-S5 | **分发介质追踪** | 新旧两代的 U 盘/运输站副本按台账 media_ids 清点销毁（v2 §7 泄露面第一项） |

命令面：`rotate --authorize-disposal`（双人，台账记录旧锚终态 next/generation/SHA-256——处置前最后的公开元数据证据）→ 执行 D-S1..S5 → `rotate --confirm-disposal --method <串> --media <ids>`（双人；核销清单全过才允许写入 DISPOSAL_CONFIRM，否则 0x0506，N14）。

### 3.3 处置后回归检测

`rotate --status` 与 `doctor`（managed 模式下）持续核对：台账记为 DISPOSED 的 book_id，其任何登记路径（或锚区扫描，OB4）再现 ⇒ **BLOCK + 0x0506 + 事件上报**（处置被回滚/介质复活/取证副本回流）。这是"旧本不被重新打开"在时间维度的延伸：不是一次性检查，而是可重复的巡检断言（N15）。

---

## 4. ④ 入口覆盖对照（任务卡④汇总）

| 入口 | 触发 | 进入 E-DRAINING 的机制 | drain 持久载体 | 后续 |
|---|---|---|---|---|
| ① EXHAUSTED | 锚 next ≥ N（T1 守卫的仲裁层投影） | E2 自动，无需人工 | 锚状态本身（无标记） | 只能换本（E4）；abort 不可达 |
| ② 主动轮换 | 运维策略（容量水位/周期/事件驱动） | E1 人工，drain.marker | marker 文件 | 换本（E4）或 abort（E3） |
| 边角：generation 上限 | gen ≥ 2^63 告警 / 溢出 fail closed | serve 拒绝服务（非 E-DRAINING 形式） | — | 强制换本 |

两入口在 ED-GATE 汇聚为同一拒绝口径（§1.4：result=2 / 0x0501 / 零消耗），在切换流程共用 §2.4 C-4 起的全套核对与授权。

---

## 5. ⑤ Golden 场景 / 负例清单（可直接转实现卡测试）

约定：退出码 0=成功，1=运行失败，2=策略/授权拒绝（复用 WP-15 `EXIT_POLICY_REFUSED` 语义），WP-15 骨架码 3 在 WP-17 实现落地后**退役**（`e2e_tcp.rs:907` 现有断言须同步更新——实现卡范围）。所有用例证据落 `evidence/<run-id>/`（命令、stdout/stderr、manifest/marker/台账快照、锚 inspect 前后对照）。

### 5.1 Golden（正路）

| ID | 前置 | 操作 | 期望（可观测） |
|---|---|---|---|
| G1 | managed serve 运行，next=5,N=1024 | `drain`；新 connect | 线上收 V1 帧逐字节相等；连接即关；serve stderr/ops-log 一行 `{event:drain_reject, code:0x0501}`；锚前后 next=5 不变（零消耗）；五字段审计日志无新条目 |
| G2 | 已完成 HELLO 准入（ARBITRATE OK 已发）瞬间 drain | 该连接继续 | 完整走完 CONFIRM→DATA→CLOSE；段正常 SPENT（审计 issued/spent） |
| G3 | 存量 PTY 会话中 drain | 会话内继续 I/O；`--recover` 重连 | I/O 正常；重连得 result=2 被拒（DG-5） |
| G4 | 3 段测试本耗尽 | 第 4 次 connect | result=2, sp=3；`EXHAUSTED_DETECTED` 一条；无 marker 文件（结构性） |
| G5 | 管理性 drain | `drain --abort`（双人、双 uid） | 标记删除+台账 DRAIN_ABORT；新 connect 恢复成功 |
| G6 | §2.4 C-2..C-6 全步骤（server 端） | ceremony golden | pending→commit→manifest 原子替换；serve 重启 V-M 全过；stale 标记清理+`DRAIN_MARKER_STALE_REMOVED`；新 book_id 会话成功 next 0→1；status=PENDING_DISPOSAL |
| G7 | server 已切 B_new | 旧本 connect；新本 connect | 旧→result=3 BOOK_MISMATCH；新→成功（E2E） |
| G8 | 两端点均完成 ceremony | 比对两台账 | book_id/version/segment_count/book_sha256 四值相等（跨端核对审计脚本） |
| G9 | RETIRED 态 | authorize-disposal→销毁→confirm-disposal | 台账三段完整、链连续；status=DISPOSED |
| G10 | commit 后、authorize 前 | `rotate --rollback`（双人） | manifest 回滚；旧本经 abort 恢复服务；新集被 status 标记为孤儿待处置 |
| G11 | commit 已成功 | 重复同参 commit | 0x0504（pending 已消费；重放防护） |
| G12 | manifest 三角一致 | `serve --config-dir` | V-M1..6 全过，正常 LISTEN |

### 5.2 负例

| ID | 操作 | 期望 |
|---|---|---|
| N1 | commit 无 pending | 0x0504，exit 2，无状态变更 |
| N2 | `--authorizer-a==--authorizer-b` | 0x0504 |
| N3 | 同一 uid 先 stage 后 commit | 0x0504（R1；加 `--allow-single-user` 后放行且台账 single_user=true，status 高危显示） |
| N4 | stage 手输 book_id/version ≠ 新本头 | 0x0503（L1 拦截，F3） |
| N5 | stage 后篡改 staged book 一个字节再 commit | 0x0503（L4 摘要复核，F8）；pending 作废 |
| N6 | 篡改 staged 锚（改 book_id/非 INIT）再 commit | 0x0503 |
| N7 | pending 过期后 commit | 0x0504（R4） |
| N8 | 未 drain 即 stage | 0x0500（R5：v2 顺序机械化） |
| N9 | 手工写坏 drain.marker 后 connect | 拒绝（fail closed）+0x0502+告警；doctor/status BLOCK |
| N10 | version=0x0002 的新本 stage | 0x0503（支持集外，fail closed 不猜） |
| N11 | manifest.book_id 改成与头/锚不一致后 serve | 拒绝启动 0x0503（V-M3 三角） |
| N12 | drain 中 `--recover` | result=2（=G3 后半，单列以便测试映射） |
| N13 | DISPOSAL_AUTHORIZE 后 rollback | 0x0504 拒绝（E6 后 E5 不可达） |
| N14 | 旧本文件仍在即 confirm-disposal | 0x0506（核销清单不过） |
| N15 | DISPOSED 后手工放回旧本文件 | status/doctor BLOCK+0x0506（回归检测） |
| N16 | drain 期间以**错本** HELLO 连接 | 仍 result=2（S2 先于 S3 的顺序锁定，D3） |
| N17 | 非 managed（无 config-dir）执行 drain/rotate | 0x0500 提示迁移 managed |
| N18 | 手工放置他本 book_id 的 marker 后 serve 启动 | stale 清理+告警，正常服务（不误入 drain） |

### 5.3 性质断言（性质测试 oracle，P1–P6）

- P1：drain 期间该端点零新段（锚 next 不变；审计无 issued）。
- P2：ceremony 全部命令零段消耗（rotate/drain 不触 allocator）。
- P3：切换原子性崩溃注入——在 §2.3 步 1/2/3 各 kill：重启后 manifest 读回值只有 B_old 或 B_new 两态，且各态后续行为正确（B_old ⇒ 仍被排空；B_new ⇒ V-M 过后服务）。
- P4：台账链：seq 单调、digest 链连续、断链即 status BLOCK。
- P5：管理 drain 与 EXHAUSTED 的 ARBITRATE 帧线上逐字节同型（V1 复用于两者）。
- P6：处置后任何旧 book_id HELLO→result=3；文件再现→BLOCK。

---

## 6. 错误码注册表扩展（0x05xx 运维类别；WP-01 §5.2 申报新增，决策 D10）

高字节 0x05 = 运维/换本（新类别；线上不可见——0x05xx 全部为本地实现码，供 CLI 退出、stderr/台账、测试断言）。段计费：**全部不耗段**（rotation 不触 allocator）。

| 码 | 名称 | 触发条件（检测层） | 线上可见行为 | 段计费 | 处理方 |
|---|---|---|---|---|---|
| 0x0500 | MAINTENANCE（伞） | 前置不满足（未 drain 即 stage、非 managed 端点执行运维命令） | 无（命令拒绝，exit 2） | 不耗段 | 运维 |
| 0x0501 | DRAIN_ACTIVE | ED-GATE：drain_active=true 拒新会话（握手准入层） | **ARBITRATE(result=2, sp=N) 后关闭**（复用 EXHAUSTED 线上形态） | 不耗段 | 客户端终止；运维推进换本 |
| 0x0502 | DRAIN_MARKER_INVALID | marker 存在但不可解析（fail closed 视为排空） | 同 0x0501（无法区分） | 不耗段 | 运维修复/删除标记 |
| 0x0503 | ROTATE_VERIFY_FAILED | L1–L4 任一核对失败；serve V-M1..6 失败 | 命令拒绝/拒绝启动（exit 2） | 不耗段 | 运维：重新核对/换介质 |
| 0x0504 | ROTATE_AUTH_INCOMPLETE | R1/R2/R4 违反；pending 缺失/过期/已消费；处置授权后 rollback | 命令拒绝（exit 2） | 不耗段 | 运维：补第二授权人 |
| 0x0505 | ROTATE_SWITCH_IO | §2.3 步 1–3 或标记/pending/台账 IO 失败 | 命令拒绝；**以 manifest 读回为权威**（F10） | 不耗段 | 运维：status 判读后重试 |
| 0x0506 | OLD_BOOK_STILL_OPEN | 处置核销：文件仍存在/仍被进程持有/已处置 book_id 文件再现 | status/doctor BLOCK | 不耗段 | 事件流程（安全调查） |

注册纪律：0x05xx 常量落 `otp-codec::ErrorCode`（与既有码同源，避免各 crate 私定漂移）；`Display` 仅码名+hex（同 WP-01 §5.3 红线）。**不占用/不改写 0x01xx–0x04xx 任何既有码。**

---

## 7. 运维台账（rotation ledger）记录格式

### 7.1 与五字段会话审计日志的关系（决策 D9）

v2 §9 与 `otp-platform::audit` 的五字段白名单（book_id/段号/结果/generation/错误类别）是**会话/段事件**审计，冻结不动。rotation 事件（drain/授权/切换/处置）不是段事件，且需要人员标识与摘要字段——若塞进五字段日志即扩白名单（违规划 §7.2 变更门槛）。故独立制品：**运维台账** `rotate.ledger`。两者字段集互不重叠、用途互补；台账同样守"无秘密"红线（§7.2 注）。

### 7.2 字段白名单（封闭集合；扩字段走设计变更）

```json
{"seq":<u64>,"ts_utc":"<RFC3339>","ceremony_id":"<32hex|null>",
 "event":"<枚举>","book_id":"<32hex>","version":<u16>,
 "next":<u64|null>,"generation":<u64|null>,
 "book_sha256":"<64hex|null>","anchor_a_sha256":"<64hex|null>","anchor_b_sha256":"<64hex|null>",
 "authorizer_a":"<串|null>","authorizer_b":"<串|null>","exec_uid":<u32|null>,"tty":"<串|null>",
 "disposal_method":"<串|null>","media_ids":["<串>"],
 "result":"ok|rejected","error_code":"<0x05xx hex|null>","single_user":<bool>,
 "prev_digest":"<64hex>","digest":"<64hex>"}
```

- `event` 枚举：`DRAIN_SET / EXHAUSTED_DETECTED / DRAIN_ABORT / DRAIN_REJECT / SERVE_START / SERVE_STOP / STAGE / COMMIT / ROLLBACK / DISPOSAL_AUTHORIZE / DISPOSAL_CONFIRM / DRAIN_MARKER_STALE_REMOVED / GEN_CEILING_WARN / STATUS_CHECK / INV_*`。
- `digest = SHA-256(seq‖ts_utc‖…‖single_user‖prev_digest)`（canonical 序，首条 prev_digest=64×"0"）：链式摘要，篡改可见（P4）。攻击者能重写全链+尾的情形属恶意管理员边界（与 §3.1 同声明）。
- 禁止出现：段正文、方向密钥、确认明文、应用明文、tag（与 v2 §9 同红线；台账=公开元数据+人员标识+摘要）。人员姓名/uid/tty 属**问责标识**，按定义非秘密（D11；如站点视为敏感，属本地日志保管策略，非协议面）。
- 写入纪律：0600、append（O_APPEND）、单条单 `write`、逐条 fsync。**两类条目**：意图类（DRAIN_SET/STAGE/DISPOSAL_AUTHORIZE/ROLLBACK 前置的授权事实）必须在动作前落账，写失败命令中止（F13）；结果类（COMMIT/ROLLBACK/DISPOSAL_CONFIRM）在原子动作成功后立刻落账，写失败告警退出（权威=manifest，status 对账报 INCONSISTENT）。serve 的 `DRAIN_REJECT` 逐条记可选（高频）：默认 stderr 结构化行（同字段子集）+ journald 承载，`--ops-log` 可选转投台账文件。

### 7.3 serve stderr 行格式（drain 拒绝的最小观测）

`{"event":"DRAIN_REJECT","book_id":"<32hex>","next":<u64>,"code":"0x0501"}`（单行 JSON，公开元数据；供 journald/测试抓取）。

---

## 8. 决策点、解读细化与偏差申报（任务⑤后半）

### 8.1 与 v2 设计书的偏差申报（目标=0）

| # | v2 条款 | 本规格处理 | 性质 |
|---|---|---|---|
| DD0 | — | **硬语义偏差：0 条。** 本规格未修改 v2 任何冻结语义；全部新增位于运维层（标记/清单/台账/错误码），协议面零改动 | — |
| DD1 | 行 144"停止新会话" | 细化为切口语义：**以 HELLO 准入时刻为界**——准入前者跑完（DG-2，中途掐断只增浪费）、恢复重连属新会话被拒（DG-5）。v2 未定义切口粒度；此细化不改变"停止新会话"的方向与安全性（宁严不宽中的必要精确化） | 解读细化（申报） |
| DD2 | 行 46"两端同时切换密码本 ID" | 细化为：同一维护窗口内**逐端**切换，每端 commit 即不可逆脱离旧本，窗口内错配连接得 result=3 而非会话（§2.4 顺序说明）。协议无跨端原子原语（v2 自身规定离线流程），"同时"取其意图（不存在两端异本成功会话的状态）而非字面同时刻 | 解读细化（申报） |
| DD3 | 行 144"旧本销毁不能只依赖 rm" | 处置三段式（授权→销毁→确认）；"不被重新打开"的终局保证从 **DISPOSAL_AUTHORIZE** 起算（此前存在受双人闸门保护的回滚路径，§2.8）——回滚是运维必需，v2 未禁止 | 解读细化（申报） |

### 8.2 决策点（提请评审逐条确认；否决任一条只改本文件，不触及其他规格）

| # | 决策 | 备选与代价 |
|---|---|---|
| D1 | drain=端点级准入门，不是 allocator 第六态 | 备选：加 allocator 状态 ⇒ 违反 WP-02 冻结面且引入未定义转移，否决 |
| D2 | drain 拒绝线上复用 ARBITRATE result=2（sp=N），内部以 0x0501 区分 | 备选 result=5 DRAINING：需改 WP-01 §4.2 枚举+codec 0x0304+golden 向量（协议变更）；若评审要线上可区分，走设计变更卡，本规格届时只改 §1.4/§6 两处 |
| D3 | drain 判定先于 book_id 核对（S2 先于 S3） | 备选（book_id 先）：drain 窗口内错本客户端得 result=3，掩盖排空事实；两案皆安全，取"全局准入一刀切"更简，N16 锁定 |
| D4 | 持久 drain.marker 绑定 book_id；stale 由 serve 启动清理 | 备选：内存态标志——重启即失效，违反"窗口跨重启"；commit 即删标记——旧 serve 在跑时窗口内复活，均否决 |
| D5 | drain 进入单人、abort/rollback/commit/处置双人 | 进入=向安全态（断路器）；退出=逆转受批准的维护态，需第二人。对称双人=过度；对称单人=单人可无限拖延换本，均劣 |
| D6 | 两步 stage/commit + uid 机械规则（R1）+ `--allow-single-user` 逃生门（台账永久标记） | 单命令双人名=仪式性无闸门，否决；无逃生门=CI/受控环境不可测，取可见性换可用性 |
| D7 | 原子切换=active-set.json 单文件 rename | 备选：目录/symlink swap——锚在独立介质无法单 rename 包含；多文件替换无原子性，否决 |
| D8 | serve 增 `--config-dir`（managed，与显式路径互斥）；显式模式行为=v0.1 不变 | 备选：直接改 serve 语义——破坏 v0.1/runbook 兼容，否决；managed 迁移是换本前置条件（N17 提示） |
| D9 | 台账与五字段审计日志分离，白名单各自封闭 | 备选：扩五字段加 operator 等——触 v2 §9/规划 §7.2 变更门槛且混用途，否决 |
| D10 | 新增 0x05xx 运维错误码类别（7 个码，§6） | 备选：塞 0x04xx 内部类——语义错类且该类别已有冻结子码结构，否决 |
| D11 | 台账含人员标识（姓名/uid/tty） | 问责最小必要；按定义非秘密。站点如视姓名敏感→本地保管策略，不改字段 |
| D12 | 销毁=密钥销毁/介质规程，工具只做核销与记录；SSD 残留如实声明不消除 | 与 v2 §7/runbook 口径一致；任何"软件保证彻底销毁"的宣称都是虚假 |

### 8.3 上游规格缺陷申报

**无新增缺陷**（DD0）。两点观察记录备查（不构成缺陷）：①WP-01 注册表原无运维类别，属规划空缺，本规格以 D10 补齐；②WP-02 §2.5 生产路径缺少 `anchor init` 运维命令（v0.1 runbook 以脚本代劳），本规格的 stage 内置 INIT 落地顺带补位，格式逐字节复用 WP-02 §2.6 golden#1。

---

## 9. 验收映射

| 验收方 | 条目 | 本规格条款 |
|---|---|---|
| 任务卡验收 1 | drain 状态机完整（进入/退出、衔接、拒绝口径+错误码、M4 行） | §1.2 转移表、§1.1/§1.5 衔接、§1.4 口径（S2 步+result=2+0x0501）、§6 码表 |
| 任务卡验收 2 | 原子切换（双端核对、双人授权接口、原子性、失败路径） | §2.5（L1–L5）、§2.2（R1–R5+序列）、§2.6（G-A/G-B/G-C）、§2.7（F1–F13）、§2.8 |
| 任务卡验收 3 | 旧本处置（不被重开+销毁规程+两入口） | §3.1（OB1–OB5）、§3.2（D-S1..S5）、§3.3、§4 |
| 任务卡验收 4 | golden/负例可转测试；偏差=0 或申报 | §5（G1–G12/N1–N18/P1–P6+V1 帧向量）、§8.1（硬偏差 0、细化 3 条逐列） |
| 任务卡验收 5 | 落仓/分支/证据/交付帖 | 分支 `designer/task-64-wp17-rotation-spec`；交付帖与 evidence 索引见任务 #64 论坛帖 |
| 规划 §4 WP-17 行 | 状态与双人授权规格；drain 阻止新会话；book_id/version 原子切换；旧本不被重新打开 | §1/§2.2/§2.3/§2.6/§3.1 |
| 规划 M4 验收行 | drain 后不接新会话；换本需 book_id/version 明确核对并保留双人授权接口 | §1.4（ED-GATE）、§2.5 L1（强迫核对）、§2.2（接口留痕于 CLI 冻结参数面 +pending/台账） |
| v2 行 46 | 耗尽后必须离线换本；两端同时切换密码本 ID | §1.7 入口①、§2.4（DD2 细化） |
| v2 行 144 | 两端 drain/停止新会话/离线核对/双人授权原子切换/销毁不依赖 rm | §1/§2.5/§2.2/§2.6/§3.2 |

### 9.1 实现卡范围提示（供调度拆卡，非本卡范围）

CLI 参数面落位（drain/rotate/serve --config-dir；§2.2/§2.3）；`otp-cli` 新增 rotation 模块（marker/manifest/pending/台账）——**不触 otp-allocator/otp-recovery/otp-session**（CODEOWNERS 高危路径，榫卯禁改；ED-GATE 落在 otp-cli 准入层即满足此约束）；0x05xx 常量入 `otp-codec`（CODEOWNERS：architect+principal）；`e2e_tcp.rs` 骨架断言（drain/rotate→exit 3）更新为真实行为；runbook 增补 §"换本操作规程"（按 §2.4 C-0..C-12 命令化）；G1–G12/N1–N18/P1–P6 转集成测试。
