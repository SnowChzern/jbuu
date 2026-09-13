# 任务 #43 阻断报告：Rust 可见性无法表达“仅 otp-allocator 可调用”

## 结论

停手，不提交放宽规范的实现。依据 Rust 稳定版模块可见性规则，`otp-book` 与
`otp-allocator` 是两个独立 crate；`pub(crate)` 只允许 `otp-book` 自身 crate，
不能允许某一个指定的依赖 crate。Rust 没有“仅允许依赖方 X、拒绝其它依赖方”的
crate 可见性修饰符。

因此，规划 §4.1 的原文约束：

> `otp-book::read_segment` 对外为 crate-private，仅 otp-allocator 可在双
> reservation fsync 后调用

在保持 `read_segment` 为 `pub(crate)`、同时让现有独立 `otp-allocator` 调用它的
前提下，无法编译级实现。

## 已核对的现状

基线为 `b62c8a8c7d9fb584351a3beccea090f21143a4dc`（任务 #40）：

- `crates/otp-book/src/lib.rs` 的 `Book::read_segment` 已是 `pub(crate)`；
- 为跨 crate 调用而存在的 `Book::__allocator_read_segment` 和
  `Segment::expose_for_allocator` 是 `pub`，`#[doc(hidden)]` 不提供权限边界；
- `crates/otp-allocator/src/lib.rs:374-379` 通过这两个公开符号读取正文；
- `crates/otp-book/tests/api_surface.rs` 是源码字符串断言，不是编译级负向测试。

## 为什么常见修法都不能满足验收

1. 将入口改为 `pub(super)` / `pub(crate)`：`otp-allocator` 立即无法编译，
   因其是独立 crate，不是 `otp-book` 的模块。
2. capability token（私有字段、sealed trait）：如果 token 的构造或实现只在
   `otp-book` 内，则 allocator 也无法获得；若提供公开构造/公开工厂，则任意
   workspace crate 同样可获得，不能证明“仅 allocator”。
3. `#[doc(hidden)]`、命名约定、源码扫描、`cfg`：均不是 Rust 编译器权限边界。
4. 将“fsync 后读段”包装成一个公开协议入口：可以保证调用该入口自身执行顺序，
   但任意外部 crate 仍能调用该公开入口；除非同时改变架构，将 reservation、
   anchor media 和 book reader 归并到同一 crate / 私有模块。

## 可收敛的架构选项（需调度/芥末拍板）

### A（推荐）：合并高危边界
将 `Book` 的生产读取实现、双 reservation fsync 和 allocator transaction
收进同一个 crate（可将 `otp-book` 作为内部模块，或将 allocator 的 transaction
移入 `otp-book`），对外只暴露 `SegmentIssuer::issue() -> CommittedSegment`。
`read_segment` 保持真正私有/`pub(crate)`，外部模拟 crate 无法调用任何裸读取路径。
代价是调整 crate 依赖图和规划 §2.1，改动面较大但边界是真实的。

### B：修订 §4.1 为 capability/API 约束
保留独立 crate 和公开桥接入口，但将规范明确改为：入口是唯一公开生产 API，
入口内部只能在传入的受验证 reservation proof 后读取；增加 API 审计、负向
编译测试验证 `read_segment` 和裸暴露符号不存在，而不宣称“仅 allocator”。
代价是不能满足“其它 workspace crate 编译必失败”的强验收，安全边界依赖 API
设计与 review，需安全审计明确接受。

## 环境阻塞

当前执行环境未发现 `cargo` 或 `rustc`（`command -v cargo`、`command -v rustc`
均无输出，`~/.cargo/bin/cargo` 与 `~/.cargo/bin/rustc` 不存在），因此不能诚实
声称 `scripts/quality-gate.sh` 或 `cargo test -p otp-allocator` 已运行。

## 状态

- 已从基线创建本地分支：`principal/task-43`。
- 未修改源代码，未删除公开入口，未提交或推送不满足规范的半成品。
- 等调度 @小雪 / 安全决策确认选项 A 或 B 后继续。
