//! # jbuu CLI 库层（WP-15，任务 #52；二进制名 v0.1.1 起 otp-term→jbuu，任务 #62）
//!
//! `main.rs` 只做参数解析与进程编排；可测试的业务逻辑在库层：
//!
//! - [`proto`]：基于 otp-transport + otp-handshake + otp-session +
//!   otp-allocator 的**端到端加密会话驱动**（服务端回显口径 = WP-12 M1
//!   口径，PTY 终端形态归 WP-16）；
//! - [`anchorio`]：锚 inspect（§65：只读、仅公开元数据）；
//! - [`auditlog`]：结构化白名单审计日志（§94）的条目构造助手——只暴露
//!   五个白名单字段的填充函数，自由格式在类型层即无通道；
//! - [`doctor`]：doctor 报告的采集/覆盖/渲染（§151），高风险 → 拒绝启动。
//!
//! 模块级红线（规划 §2 otp-cli 行）：默认不打印秘密；所有错误/日志只含
//! 公开元数据（错误码/类别/指针），不含段正文、方向密钥或业务明文。

#![forbid(unsafe_code)]

pub mod anchorio;
pub mod auditlog;
pub mod doctor;
pub mod proto;
pub mod recoveryio;
