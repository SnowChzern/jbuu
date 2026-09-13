# 任务 #43 阻断报告（复核版）

## 结论

停手，不交付换名或换包装的公开裸读路径。当前 crate 拆分下，任务要求与 Rust 稳定版可见性规则不可同时满足：

1. `otp-book::Book::read_segment` 保持 `pub(crate)`；
2. 独立 crate `otp-allocator` 可以调用它；
3. 任意其它外部模拟 crate 调用段读取路径必须编译失败。

Rust 没有“只允许指定依赖 crate”的可见性修饰符。`pub(crate)` 的范围是定义它的 crate；`pub`（无论是否 `#[doc(hidden)]`、是否改名、是否包装成协议入口）对所有依赖 crate 可见。因此继续改造只能在两种结果之间选择：allocator 编译失败，或负向测试失败。

## 基线与现状

- 基线：`b62c8a8c7d9fb584351a3beccea090f21143a4dc`（`principal/task-40`）
- 当前分支：`principal/task-43`
- 当前交付 commit：`bce3063604afadb8a0a52bceb93951608201e25f`
- 阻断符号仍在基线代码中：
  - `crates/otp-book/src/lib.rs`：`read_segment` 为 `pub(crate)`，同时存在 `pub fn __allocator_read_segment`；
  - `Segment` 同时存在 `pub fn expose_for_allocator`；
  - `crates/otp-allocator/src/lib.rs` 通过两者读取段正文；
  - `crates/otp-book/tests/api_surface.rs` 仅为源码字符串断言，不是编译级负向测试。

## 已排除的伪修复

- `pub(super)` / `pub(crate)`：allocator 立即无法编译，因为它是独立 crate；
- capability token：若 allocator 能构造/获得公开 token，任意外部 crate 也能获得；
- `#[doc(hidden)]`、命名约定、源码扫描：均不构成 Rust 权限边界；
- 将双 fsync 顺序包装进 `pub fn`：能约束实现顺序，但不能阻止外部 crate 调用该公开函数。

## 能真正收敛的方案（需调度/安全裁决）

### 方案 A（推荐）——合并高危边界

将段生产读取实现、双 reservation 事务与 allocator transaction 放入同一真实受控 crate/模块；对外只暴露 `SegmentIssuer::issue() -> CommittedSegment`。这样 `read_segment` 可保持 crate-private（或进一步私有），外部模拟 crate 对任何裸读路径均编译失败。代价是调整 crate 依赖图和规划 §2.1。

### 方案 B——修订规划 §4.1

保留独立 crate 的唯一公开桥接 API，并以 reservation proof/API 审计约束调用；同时明确这不是“仅 otp-allocator 可调用”的编译级权限边界。该方案不能满足当前验收标准 1/2，必须由调度与安全审计明确放宽后实施。

## zeroize 生命周期复核

未重构源码，故没有破坏现有生命周期：

- `otp-book::Segment` 仍由 `#[derive(ZeroizeOnDrop)]` 管理，未实现 `Clone`/`Debug`/序列化；
- `otp-allocator::CommittedSegment` 仍由 `#[derive(ZeroizeOnDrop)]` 管理，未实现 `Clone`/`Debug`/序列化；
- 现有 allocator 在 `issue()` 中仅在最终双锚 fsync 成功后构造并返回 `CommittedSegment`；
- 因未执行方案 A/B，不能声称已完成任务 #43 的代码验收。

## 验证阻塞

当前环境没有可用的 `cargo`/`rustc`（包括 `~/.cargo/bin`），因此未虚报 `scripts/quality-gate.sh` 或 `cargo test -p otp-allocator` 输出。待调度拍板方案 A 或 B、并补齐工具链后再执行验证。

请 @小雪 调度升级 @芥末 拍板。未获裁决前不删除裸入口、不改名伪装、不提交不满足负向编译验收的实现。
