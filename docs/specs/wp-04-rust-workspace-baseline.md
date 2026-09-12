# WP-04 规格：Rust workspace、CI 与依赖基线

- **任务卡**：论坛 #33（[otp-term][WP-04] Rust workspace、CI 与依赖基线）
- **执行**：榫卯（engineer）
- **依据**：设计书 `~/agents/security/workspace/otp_terminal_protocol_v2.md`（核心语义冻结）；
  实现规划 `~/agents/principal/workspace/otp_protocol_impl_plan.md` §1（技术栈）、§2（模块拆分）
- **状态**：已交付骨架；接口形状以本文为准，业务实现归后续工作包

## 1. 范围与不做的事

**做**：workspace/crate 骨架 + 接口签名（函数体 `todo!("WP-xx")`）、固定工具链、
锁定依赖（Cargo.lock）、质量门脚本、核心 crate `forbid(unsafe_code)`、
`.gitignore` / `CODEOWNERS`、本规格文档。

**不做**（规划 WP-04 行明确排除）：任何业务逻辑实现。codec 编解码、
book 读取、allocator 事务、恢复、握手、AEAD、传输、PTY、CLI 业务
分别在 WP-05~WP-17 落地。

**数量勘误**：任务卡正文写“14 个 crate”，但其枚举列表与规划 §2 表均为
**13 个**（types/codec/book/anchor-spec/allocator/recovery/handshake/session/
transport/terminal/platform/cli/testkit）。以规划书为准，本骨架为 13 个 crate。
若需补充第 14 个（例如独立 internal shim crate，见 §3.2），由 WP-06/07 评审后建卡。

## 2. Workspace 结构与工具链

```text
otp-term/
├── Cargo.toml              # workspace 根；[workspace.dependencies] 统一版本区间
├── Cargo.lock              # 精确版本锁定（提交入库）
├── rust-toolchain.toml     # 固定 stable 1.98.1 + rustfmt + clippy
├── deny.toml               # cargo-deny：许可/禁用/来源/advisories
├── .cargo/config.toml      # rsproxy 镜像（main 已有，WP-04 沿用）
├── .gitignore              # *.book/*.anchor/core*/evidence//target 等
├── CODEOWNERS              # 高危路径双批准（文档性质，见 §6）
├── scripts/quality-gate.sh # 质量门（CI 入口）
├── scripts/check-unsafe.sh # 核心 crate unsafe 检查（质量门第 4 项）
├── docs/specs/             # 规格文档（本文件）
└── crates/                 # 13 个 crate，见 §3
```

- **工具链**：`channel = "1.98.1"`（stable）、profile minimal、components
  rustfmt+clippy。升级工具链 = 单独评审 + 更新 Cargo.lock + 全量重跑质量门。
- **edition 2024 / resolver 3**；`rust-version = 1.85`。
- 所有 crate `publish = false`（私有仓，防误发布）。

## 3. Crate 骨架与模块边界

### 3.1 一览（职责/禁止事项摘自规划 §2，骨架已按其落位）

| crate | 关键接口（骨架签名） | 实现包 |
|---|---|---|
| otp-types | `BookId`/`SegmentIndex`/`Generation`/`Sequence`/`Direction`/`Role`/`Nonce<N>`/`ErrorCategory`；常量 `SEGMENT_LEN=64` 等 | —（本包即完整基线） |
| otp-codec | `Message` 枚举（HELLO/ARBITRATE/ISSUE_REQUEST/CONFIRM_C2S/S2C/DATA）、`encode`/`decode`（拒绝尾随字节）、`CodecError` | WP-05 |
| otp-book | `Book::open`（头校验）、`read_segment`（**crate-private**）、`Segment`（Drop 清零，无 Clone/Debug） | WP-06 |
| otp-anchor-spec | `AnchorRecord`、`AnchorStore` trait（仅 `read_verified`/`write_full_and_sync`/`sync_parent_if_created`）、`RecoveryDecision`/`decide` | WP-02 |
| otp-allocator | `SegmentIssuer::issue()->CommittedSegment`、`CommittedSegment`（无 Clone/Debug/序列化，Drop 清零）、`ReservedSegment`（无公开转换）、`Allocator` | WP-07（栋梁） |
| otp-recovery | `recover(a,b)->RecoveryReport/RecoveryError`、`RecoveryWarning`（含双回滚能力边界告警） | WP-08（栋梁） |
| otp-handshake | `ClientHandshake`/`ServerHandshake`、`Step`、`HandshakeError`；取段仅经 `SegmentIssuer` | WP-11 |
| otp-session | `Session::new(role,&[u8;64],ctx)`（32+32 直接拆键，无 KDF）、`seal`/`open`、`RecordAad`、`nonce96` | WP-10 |
| otp-transport | `FramedStream` trait、`LoopbackTransport`/`TcpTransport`/`TcpListener`、`TransportError` | WP-12 |
| otp-terminal | `TerminalSession::connect/resize/wait`、`PtyLeaseGuard`、`acquire_pty_lease`（单主 lease） | WP-16 |
| otp-platform | `acquire_ofd_lock`/`acquire_lease`（fencing token）、`fsync_file`/`fsync_dir`、`mlock_best_effort`、`probe_environment`、`AuditEntry`/`AuditLogSink`（白名单字段） | WP-09（栋梁主责） |
| otp-cli | `otp-term` 二进制：serve/connect/book/anchor/doctor/drain/rotate（骨架返回 NotImplemented） | WP-15 |
| otp-testkit | `TestBook`、`FaultyAnchorStore`（failpoint 注入，9 个命名边界）、`CrashController`、`IssueOracle`（唯一性/不回退 oracle）、proptest `strategies` | WP-13 |

依赖方向严格按规划 §2.1 依赖图（见各 crate Cargo.toml）；无环；
`otp-cli` 不依赖 `otp-testkit`（测试代码不进生产二进制）。

### 3.2 模块边界强制点（规划 §2.2）

1. **握手取段只经 `SegmentIssuer::issue()`**：`otp-handshake` 不依赖
   otp-book/otp-platform；类型系统中无 `ReservedSegment -> 密钥` 的公开路径
   （`ReservedSegment` 无任何公开方法；`CommittedSegment::as_bytes` 是唯一
   读出口且文档限定会话层建链使用）。
2. **`otp-book::read_segment` 为 crate-private**：生产路径仅 allocator 在双
   reservation fsync 后可调用。跨 crate 封印机制（doc(hidden) 受控入口 /
   独立 internal shim / 宏）由 WP-06+WP-07 联合定稿；骨架期间提供
   `#[doc(hidden)] __allocator_read_segment` 过渡入口，且本目录在 CODEOWNERS
   双批准清单内，任何放松都需栋梁+安全审计复核。
3. **`CommittedSegment` 安全属性**：无 Clone/Debug/PartialEq/序列化，
   `#[derive(ZeroizeOnDrop)]`，编译期形状已由单测固化。
4. **锚后端抽象只暴露三操作**：`AnchorStore` trait 恰为
   `read_verified`/`write_full_and_sync`/`sync_parent_if_created`；
   故障注入后端实现于 otp-testkit（WP-13）。
5. **审计日志白名单**：`AuditEntry` 只有 book_id/段号/generation/结果/
   错误类别五字段，编译期无法携带自由格式敏感对象。

## 4. 依赖基线（Cargo.lock 锁定）

直接依赖（版本区间在 workspace 根统一声明，精确版本见 Cargo.lock）：

| 依赖 | 锁定版本 | 用途（规划 §1.2） | 使用 crate |
|---|---|---|---|
| rustix | 1.1.4 | pread/fsync/文件锁/目录同步；features: std,fs | otp-book, otp-platform |
| chacha20poly1305 | 0.10.1 | 会话层 AEAD（RustCrypto；不做段派生） | otp-session |
| getrandom | 0.3.4 | OS CSPRNG（nonce/测试本；失败即终止） | otp-handshake, otp-testkit |
| zeroize | 1.9.0 | 敏感内存清零（derive 特性：ZeroizeOnDrop） | otp-book, otp-allocator, otp-session |
| secrecy | 0.10.3 | 方向密钥受控暴露（SecretBox） | otp-session |
| sha2 | 0.10.9 | 仅 previous_segment_hash 完整性锚 | otp-anchor-spec, otp-allocator |
| proptest | 1.11.0 | 解析器/状态机性质测试 | otp-testkit |
| clap | 4.6.6 | CLI 参数解析（derive） | otp-cli |

说明：
- 集内存在 getrandom 0.2/0.3/0.4 多版本（来自 rand/proptest 等传递依赖），
  `cargo deny bans multiple-versions=warn` 允许，后续 WP 收敛。
- `cargo test --locked` 强制：任何依赖变化必须显式更新 Cargo.lock，
  不得悄悄漂移。
- 许可白名单（deny.toml）：MIT / Apache-2.0 / Apache-2.0 WITH LLVM-exception /
  Unicode-3.0 / BSD-2/3-Clause；新增项须附理由过供应链评审。

## 5. 质量门（scripts/quality-gate.sh）

一条命令验收（clone 后）：

```bash
./scripts/quality-gate.sh
```

| # | 检查 | 内容 |
|---|---|---|
| 1 | `cargo fmt --all -- --check` | 格式 |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings` | 警告零容忍 |
| 3 | `cargo test --workspace --locked` | 测试 + 锁文件纪律 |
| 4 | `scripts/check-unsafe.sh` | 核心 crate `forbid(unsafe_code)` 且源码零 `unsafe`；其余业务 crate 亦须 forbid |
| 5 | `cargo deny check licenses bans sources` | 许可/禁用/来源（advisories 需联网：`DENY_ADVISORIES=1`） |

环境变量：`SKIP_DENY=1` 跳过 cargo-deny（须在交付帖注明）；
`DENY_CHECKS="..."` 自定义 deny 检查项。

**unsafe 政策**（规划 §1.2）：
- 核心 crate（otp-allocator / otp-recovery / otp-session）：`#![forbid(unsafe_code)]`
  + 质量门源码扫描双保险。
- 其余业务 crate 一律 `#![forbid(unsafe_code)]`（types/codec/book/anchor-spec/
  handshake/transport/terminal/testkit/cli）。
- otp-platform 为唯一豁免点：`#![deny(unsafe_code)]`（可经单独审计卡显式
  allow），仅限 rustix 未覆盖的 syscall 包装。

## 6. 仓库卫生

- `.gitignore`：`*.book`、`*.anchor`、`core*`、`core`、`evidence/`、`/target`、
  日志/临时文件（规划 §6.1：禁止提交真实密码本、锚、core、流量明文）。
- `CODEOWNERS`（文档性质，本集群 git 无平台级强制，评审纪律人工执行）：
  - `/crates/otp-allocator|otp-recovery|otp-session/` → 栋梁 + 安全审计双批准；
  - `/crates/otp-anchor-spec|otp-codec/`、`/docs/specs/` → 斗拱 + 栋梁；
  - `Cargo.lock`/`Cargo.toml`/`rust-toolchain.toml`/`deny.toml`/`scripts/` →
    栋梁 + 榫卯。

## 7. 已知限制与后续决策点

1. **book→allocator 封印机制**：骨架用 `#[doc(hidden)]` 过渡入口 + CODEOWNERS
   把关；WP-06/07 定稿后收紧（候选：独立 internal shim crate 或宏导出）。
2. **transport 异步形态**：骨架为同步 trait；异步化决策留 WP-12 评审
   （规划 §2 仅要求“异步 framed stream”语义，未指定运行时）。
3. **cargo-deny advisories** 需联网拉漏洞库，质量门默认跑
   licenses/bans/sources 三项，`DENY_ADVISORIES=1` 附加。
4. **cargo-fuzz** 不入 workspace 依赖（独立 fuzz target 仓/目录随 WP-14 建）。

## 8. 验证记录

交付时全量验证：质量门五项全绿（fmt / clippy -D warnings / test --locked /
unsafe 检查 / deny licenses+bans+sources），另附联网跑通 `cargo deny check
advisories`（0 漏洞）。完整输出与 lockfile 哈希见交付帖及
`~/agents/engineer/workspace/evidence/task-33/`（不入库）。
