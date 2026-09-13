//! # otp-terminal —— PTY 终端会话（WP-16，任务 #54）
//!
//! 实现规划 §2 职责：单主 lease、PTY 输入输出、窗口/退出码、恢复时新
//! 签发段、旧会话关闭。
//!
//! ## 恢复语义（唯一依据：wp02 §5.3）
//!
//! 断线恢复终端上下文 = **重新仲裁 + 签发新段**，绝不重用旧段、绝不以
//! 恢复 token 代替新段与确认标签；**恢复 token 只能是索引/句柄**——
//! [`TerminalHandle`] 是服务端句柄计数器（u64），与段材料/密钥无任何
//! 构造路径（见 [`frame`] 文档）。并发恢复各得不同段（每次附着前调用
//! 方都完成一次全新 WP-11 握手 = allocator 新段）；旧/新连接不得同时
//! 写同一 PTY——由 [`lease`] 的单主租约 + fencing token 强制。
//!
//! ## 单主 lease/fencing（规划 §5 测试 10 口径）
//!
//! - 每次 [`lease::LeaseManager::acquire`] 至多一个活跃 writer；holder
//!   活跃时后继申请一律 `Busy`（绝不双主，**单主不变量优先于任何性能
//!   优化**）；
//! - 每次授予/接管 fencing token 单调 +1；holder 放弃（连接关闭）或
//!   lease 超时（无心跳）后接管；陈旧 token 的一切写/续期一律
//!   [`TerminalError::StaleWriter`]（陈旧 writer 不得继续写）；
//! - PTY 写在 lease 锁内执行（[`lease::LeaseManager::with_write_gate`]）：
//!   接管与写不可能交错。
//!
//! ## 分层与依赖
//!
//! - 握手（"重新仲裁+签发新段"）由调用方（otp-cli）每连接驱动一次
//!   WP-11/WP-15 既有路径，本 crate 在 **Established 之后**接管会话；
//! - 终端帧全部作为 WP-10 DATA record 的应用明文传输（PTY 数据流走
//!   record 加密，明文不出传输层——测试有 WireTap 断言）；
//! - PTY/termios syscall 集中在 `otp-platform::pty`（既有 platform 层
//!   libc 模式），本 crate `#![forbid(unsafe_code)]`。
//!
//! ## 禁止事项（规划 §2）
//!
//! 不允许旧/新连接同时写同一 PTY（单主 lease 强制）；不做密钥派生；
//! 日志/错误面只含公开元数据（句柄/token/计数），绝不携带 PTY 数据。
//!
//! 实现归属：榫卯 WP-16。

#![forbid(unsafe_code)]

pub mod client;
pub mod frame;
pub mod hub;
pub mod lease;
pub mod server;

use std::time::Duration;

pub use client::{AttachMode, ClientOptions, TerminalEvent, TerminalSession};
pub use frame::{DATA_CHUNK_MAX, DenyReason, TerminalFrame};
pub use hub::{PtyHub, TerminalRegistry};
pub use lease::{ConnId, FencingToken, LeaseDenied, LeaseGrant, LeaseManager, LeaseSnapshot};
pub use server::{ServeEnd, ServeOptions, ServeSummary, serve_connection};

use otp_handshake::HandshakeError;
use otp_session::SessionError;
use otp_transport::TransportError;

/// 终端恢复句柄（**索引/句柄，非段材料**；wp02 §5.3）。
///
/// 服务端注册表计数器（1, 2, ...）的 newtype；类型层不存在从段字节/
/// 密钥构造它的路径。Granted 帧回传给客户端，断线后随
/// [`AttachMode::Recover`] 提交。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct TerminalHandle(pub u64);

/// 终端窗口大小。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WindowSize {
    /// 行数。
    pub rows: u16,
    /// 列数。
    pub cols: u16,
}

impl WindowSize {
    /// 常用默认窗口（非 tty 输入时）。
    pub const FALLBACK: Self = Self { rows: 24, cols: 80 };
}

/// 子进程退出状态（信号终止按 shell 惯例映射为 128+signal）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExitStatus {
    /// 退出码。
    pub code: i32,
}

/// 终端配置（lease/心跳时序）。
#[derive(Clone, Copy, Debug)]
pub struct TerminalConfig {
    /// PTY 单主 lease 超时（客户端须按约 1/3 周期发心跳）。
    pub lease_timeout: Duration,
}

impl Default for TerminalConfig {
    fn default() -> Self {
        Self {
            lease_timeout: Duration::from_secs(15),
        }
    }
}

impl TerminalConfig {
    /// 心跳周期（lease_timeout/3，下限 100ms）。
    #[must_use]
    pub fn ping_interval(&self) -> Duration {
        (self.lease_timeout / 3).max(Duration::from_millis(100))
    }
}

/// 终端错误（只携带公开元数据；Debug/Display 不含任何 PTY 数据）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TerminalError {
    /// PTY 写租约被其他活跃连接持有（单主拒绝；holder 为 0 表示服务端
    /// 未回传 holder id）。
    LeaseHeldByOther {
        /// 当前 holder 连接（观测元数据）。
        holder: ConnId,
    },
    /// 陈旧 writer（fencing token 落后）：拒绝写/续期。
    StaleWriter,
    /// 恢复句柄不存在或终端已退出。
    TerminalGone,
    /// 握手失败。
    Handshake(HandshakeError),
    /// 会话层错误。
    Session(SessionError),
    /// 传输错误。
    Transport(TransportError),
    /// I/O 错误。
    Io,
    /// 会话已关闭。
    Closed,
    /// 应用帧/协议违规（fail closed）。
    Protocol,
    /// 期限内无进展。
    Timeout,
}

impl core::fmt::Display for TerminalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 只输出错误名/公开元数据，绝不携带 PTY 数据内容。
        let name = match self {
            Self::LeaseHeldByOther { holder } => return write!(f, "lease-held-by-other({holder})"),
            Self::StaleWriter => "stale-writer",
            Self::TerminalGone => "terminal-gone",
            Self::Handshake(_) => "handshake",
            Self::Session(_) => "session",
            Self::Transport(_) => "transport",
            Self::Io => "io",
            Self::Closed => "closed",
            Self::Protocol => "protocol",
            Self::Timeout => "timeout",
        };
        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_and_exit_status_are_plain_metadata() {
        let w = WindowSize { rows: 24, cols: 80 };
        assert_eq!((w.rows, w.cols), (24, 80));
        assert_eq!(w, WindowSize::FALLBACK);
        let e = ExitStatus { code: 0 };
        assert_eq!(e.code, 0);
    }

    #[test]
    fn ping_interval_is_third_of_lease_with_floor() {
        let cfg = TerminalConfig {
            lease_timeout: Duration::from_secs(15),
        };
        assert_eq!(cfg.ping_interval(), Duration::from_secs(5));
        let tiny = TerminalConfig {
            lease_timeout: Duration::from_millis(300),
        };
        assert!(tiny.ping_interval() >= Duration::from_millis(100));
    }

    #[test]
    fn display_carries_no_pty_data() {
        assert_eq!(
            format!("{}", TerminalError::LeaseHeldByOther { holder: 42 }),
            "lease-held-by-other(42)"
        );
        assert_eq!(format!("{}", TerminalError::StaleWriter), "stale-writer");
    }
}
