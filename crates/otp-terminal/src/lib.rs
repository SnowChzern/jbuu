//! # otp-terminal —— PTY 终端会话
//!
//! 实现规划 §2 职责：单主 lease、PTY 输入输出、窗口/退出码、恢复时新签发段、
//! 旧会话关闭。
//!
//! 禁止事项（规划 §2）：不允许旧/新连接同时写同一 PTY（单主 lease 强制，
//! 超时接管必须用递增 fencing token fence 掉陈旧 writer，规划 M4）。
//!
//! 恢复语义（设计书 §5）：会话恢复不重新使用旧段 —— 断线恢复必须重新仲裁并
//! 新耗一段，旧会话标记关闭。
//!
//! 实现归属：榫卯 WP-16。

#![forbid(unsafe_code)]

use otp_handshake::{ClientHandshake, HandshakeError};
use otp_session::SessionError;
use otp_transport::{FramedStream, TransportError};

/// 终端配置。
pub struct TerminalConfig {
    /// 初始窗口大小。
    pub window: WindowSize,
}

/// 终端窗口大小。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WindowSize {
    /// 行数。
    pub rows: u16,
    /// 列数。
    pub cols: u16,
}

/// 子进程退出状态。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExitStatus {
    /// 退出码。
    pub code: i32,
}

/// PTY 单主写租约守卫（RAII：drop 释放）。竞争请求只能被拒绝或降级只读，
/// 不得双主（规划 M4 验收 10）。
pub struct PtyLeaseGuard {
    /// 内部状态随 WP-16 落地。
    _wp16: (),
}

/// 已建立的终端会话。
pub struct TerminalSession {
    /// 内部状态随 WP-16 落地。
    _wp16: (),
}

impl TerminalSession {
    /// 建立终端会话：握手（新签发段）+ PTY attach。恢复场景同样必须新耗一段。
    pub fn connect<T: FramedStream>(
        _transport: T,
        _handshake: ClientHandshake,
        _cfg: TerminalConfig,
    ) -> Result<Self, TerminalError> {
        todo!("WP-16")
    }

    /// 窗口变更（SIGWINCH 语义）。
    pub fn resize(&mut self, _window: WindowSize) -> Result<(), TerminalError> {
        todo!("WP-16")
    }

    /// 等待子进程退出并返回退出码。
    pub fn wait(&mut self) -> Result<ExitStatus, TerminalError> {
        todo!("WP-16")
    }
}

/// 获取 PTY 单主写租约。已持有时第二个请求必须被拒绝/降级只读。
pub fn acquire_pty_lease(_session_token: &str) -> Result<PtyLeaseGuard, TerminalError> {
    todo!("WP-16")
}

/// 终端错误。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TerminalError {
    /// PTY 写租约已被其他连接持有（拒绝双主）。
    LeaseHeldByOther,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_and_exit_status_are_plain_metadata() {
        let w = WindowSize { rows: 24, cols: 80 };
        assert_eq!((w.rows, w.cols), (24, 80));
        let e = ExitStatus { code: 0 };
        assert_eq!(e.code, 0);
    }
}
