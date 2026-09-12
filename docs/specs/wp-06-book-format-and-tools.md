# WP-06 规格：密码本文件格式 / 读取器模块边界 / 测试本工具

| 项 | 内容 |
|---|---|
| 任务卡 | 论坛任务 #35 · 工作包 WP-06 |
| 执行人 | 榫卯（engineer） |
| 设计依据 | 设计书 v2 §3（预分发、段布局）、§7（"运行时只按段读取……避免预读整个 1GB"）、§9 测试项 1；实现规划 §2（otp-book 行）、§2.2（模块边界）、§5 测试 1；WP-02 §0/§1.1（段号上限、`intent_durable` 先于 `body_read`） |
| 实现位置 | `crates/otp-book`（`src/header.rs` / `src/lib.rs` / `src/generate.rs` / `src/inspect.rs`）、`crates/otp-cli`（`book generate` / `book inspect` 入口） |
| 状态 | 已实现；格式字段冻结，改动须过 CODEOWNERS 评审 |

## 1. 密码本文件格式（v1，冻结）

设计书 §3 只固定字段集合（版本、密码本 ID、段长 64、总段数、校验元数据），
本规格落成可机械核对的字节布局（风格与 WP-02 锚记录一致：magic + 定长
字段 + 保留区全零 + SHA-256 完整性）：

```text
文件 = 文件头（128 B）+ 段正文区（N × 64 B）

文件头（128 B，大端，无对齐填充）：
偏移   长度   字段           约束（违反 → InvalidHeader，fail-closed）
0      4      magic          "OTPB"
4      2      version        0x0001；不识别即拒绝（无协商、无默认值）
6      4      segment_len    必须为 64
10     8      segment_count  1 ..= 2^40-1（协议段号上限，WP-02 §0）
18     16     book_id        公开标识，绑定两端配置与锚记录（WP-02 §2.1）
34     2      reserved0      必须为 0x0000
36     60     reserved_pad   60 × 0x00；任一非零即拒绝（前向兼容不猜）
96     32     header_hash    SHA-256(header[0:96])（校验元数据，设计书 §3）

段正文区：段 i 位于偏移 128 + i × 64（128 = 2×64，段边界全程 64B 对齐）
```

附加不变量（`Book::open` / `inspect_book` 强制）：

1. 必须为常规文件（目录、字符设备等拒绝）；
2. 文件长度必须**恰等于** `128 + segment_count × 64`（截断/尾部垃圾拒绝）；
3. 文件头不得包含可推导秘密的内容（设计书 §3）。

golden 头向量（version=1 / 段长 64 / 3 段 / `book_id="OTPTERM-TESTBOOK"`）：
前缀 hex
`4f54504200010000004000000000000000034f54505445524d2d54455354424f4f4b` + 62×`00`，
`header_hash = 6b25e3aa0d7c631a64f3dab6d125a564bcff14a3c1db319fcd073481d8e7a8e8`
（`crates/otp-book/src/header.rs` 单测全等校验，前缀与哈希由 python hashlib
独立预计算，防自证循环）。

## 2. 读取器与模块边界（WP-06 验收 2）

- `Book::open`：打开（`O_RDONLY|O_CLOEXEC`）→ fstat 常规文件检查 →
  **只读一次 128 B 头** → 全部头校验 → 文件长度一致性。不读任何段正文。
- `Book::read_segment`：**`pub(crate)`**（类型系统强制 crate-private）。
  单次 `pread_exact(64)`（EINTR 重试、短读/EOF fail-closed），不缓存、
  不预读相邻段；`index >= segment_count` → `SegmentOutOfRange`，偏移计算
  全程 checked、绝不越界读/回卷（EXHAUSTED 语义归 allocator，本层只做
  硬边界）。
- 调用契约：仅 otp-allocator 可在**双锚 reservation intent 写满并各自
  fsync 成功后**调用（WP-02 §1.1：`intent_durable` 先于 `body_read`；
  设计书 §6 fail-to-waste）。跨 crate 过渡入口
  `#[doc(hidden) Book::__allocator_read_segment` 沿用 WP-04 骨架形状，
  待 WP-06+07 联合定稿封印机制（独立 internal shim crate / 宏导出）后
  移除或收紧；`crates/otp-book/` 在 CODEOWNERS 评审面内。
- `Segment`：`ZeroizeOnDrop`，无 Clone/Debug/PartialEq/序列化；唯一读取
  出口为 `#[doc(hidden)] Segment::expose_for_allocator`（过渡）。
- 架构测试（`tests/api_surface.rs`）：源码级断言 `read_segment` 为
  `pub(crate)`、无公开读段入口、过渡入口 `#[doc(hidden)]`（与
  `scripts/check-unsafe.sh` 同款源扫描模式）。
- 不预读证明：`open` 后修改段区磁盘内容，`read_segment` 必读到新值
  （无缓存）；行为级单测固化。

## 3. 测试本工具（规划 §5 测试 1 / 设计书 §9 测试项 1）

### 3.1 `otp-term book generate <path> --segments N [--book-id HEX32]`

- 随机源：OS CSPRNG（`getrandom`），失败即终止（fail-closed），绝不降级
  弱源；`book_id` 缺省 CSPRNG 随机（16 B），可显式指定（两端锚配置对账用）；
- `O_CREAT|O_EXCL`、mode 0600：**拒绝覆盖已存在文件**；
- 64 KiB/块流式生成（`Zeroizing` 缓冲，峰值内存 ≤ 64 KiB）；
- 成功路径：写头+正文 → `fsync` 文件 → `fsync` 父目录；任一步失败尽力
  `unlink` 半成品并报错。

### 3.2 `otp-term book inspect <path> [--json]`

- 头/长度验证与生产 `Book::open` **同一条验证路径**（无第二套略检读法）；
  这是唯一允许全本顺序读取的路径（离线工具，与生产按索引单段读完全分离）；
- 检查项：
  1. 全段 SHA-256 去重：`duplicate_count > 0` ⇒ 失败（注入重复段必检出）；
  2. 全零段：`zero_segment_count > 0` ⇒ 失败；
  3. 统计：256 桶字节频数 + 全本 bit=1 比例；比例出 0.5±0.02 带仅告警，
     **不宣称随机性证明**（规划 §5 测试 1 通过标准原文）；
- 输出只含公开元数据（段号/计数/比例），不含段正文/段哈希，可安全入
  `evidence/`；`--json` 机器可读；
- 退出码：检查通过 0；失败 1（供 CI/脚本判定）。

## 4. 验收映射（任务 #35 验收口径）

| 验收条 | 落点 |
|---|---|
| 1 文件头验证+按索引读段 | §1 布局与不变量；`header.rs` golden/畸形头单测；`lib.rs` read_segment 单测 |
| 2 read_segment crate-private 仅 allocator 可调 | §2 `pub(crate)` + 契约文档 + `tests/api_surface.rs` 源断言 + CODEOWNERS |
| 3 100 万段生成 + 重复段必检出 | §3 工具；CI 级测试（8 KiB/4 KiB 段注入检出）+ evidence 1,000,000 段实测 |
| 4 不预读不越界 | §2 不预读证明单测；SegmentOutOfRange（含 u64::MAX）单测；EXHAUSTED 归 allocator 只做硬边界 |
| 5 分支 push + commit hash | 交付帖 |

## 5. 已知边界与后续决策点

1. 跨 crate 封印机制（`__allocator_read_segment` 过渡入口的替代）待
   WP-07 联合定稿（候选：独立 internal shim crate / 宏导出）；
2. inspect 的 SHA-256 为工程去重哈希，不是随机性证明；随机性健康仅
   bit 比例/频数告警；
3. 生产读取路径无全本扫描；"重复段检测"只属于离线工具语义；
4. 大本（> 2^40−1 段）与 0 段本均拒绝（fail-closed）。
