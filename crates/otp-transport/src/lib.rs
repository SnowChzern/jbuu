//! # otp-transport —— framed stream 传输层
//!
//! 实现规划 §2 职责：异步 framed stream、loopback/TCP 适配、超时和关闭。
//!
//! 禁止事项（规划 §2）：不吞掉解析/认证错误（字节搬运错误必须原样上抛，
//! 由 codec/session 判定）；不赋予网络消息持久化语义（传输层无状态）。
//!
//! 注：帧边界只做长度前缀搬运；帧内消息语义由 otp-codec / otp-session
//! 判定。同步 trait 形态先行，异步化（或保持同步+线程池）在 WP-12 评审定稿。
//!
//! 实现归属：榫卯 WP-12。

#![forbid(unsafe_code)]

use std::time::Duration;

/// framed 流抽象。
pub trait FramedStream {
    /// 发送一帧（内部保证完整写：短写循环补齐）。
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransportError>;
    /// 接收一帧（返回完整帧；截断/超时/对端关闭分别报错，不吞错）。
    fn recv_frame(&mut self) -> Result<Vec<u8>, TransportError>;
    /// 设置读写超时。
    fn set_deadline(&mut self, timeout: Duration) -> Result<(), TransportError>;
    /// 主动关闭。
    fn close(&mut self) -> Result<(), TransportError>;
}

/// 测试用回环传输（进程内配对；真实实现见 otp-testkit::loopback_pair）。
pub struct LoopbackTransport {
    /// 内部状态随 WP-12 落地。
    _wp12: (),
}

impl LoopbackTransport {
    /// 创建一对互通的回环传输（client/server 两端）。
    pub fn new_pair() -> (Self, Self) {
        todo!("WP-12")
    }
}

/// TCP 传输。
pub struct TcpTransport {
    /// 内部状态随 WP-12 落地。
    _wp12: (),
}

impl TcpTransport {
    /// 连接到 `addr`（host:port）。
    pub fn connect(_addr: &str) -> Result<Self, TransportError> {
        todo!("WP-12")
    }
}

/// TCP 监听器。
pub struct TcpListener {
    /// 内部状态随 WP-12 落地。
    _wp12: (),
}

impl TcpListener {
    /// 监听 `addr` 并返回首个 accept 的连接（多连接策略见 WP-12/M3）。
    pub fn bind_and_accept(_addr: &str) -> Result<TcpTransport, TransportError> {
        todo!("WP-12")
    }
}

impl FramedStream for LoopbackTransport {
    fn send_frame(&mut self, _frame: &[u8]) -> Result<(), TransportError> {
        todo!("WP-12")
    }
    fn recv_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        todo!("WP-12")
    }
    fn set_deadline(&mut self, _timeout: Duration) -> Result<(), TransportError> {
        todo!("WP-12")
    }
    fn close(&mut self) -> Result<(), TransportError> {
        todo!("WP-12")
    }
}

impl FramedStream for TcpTransport {
    fn send_frame(&mut self, _frame: &[u8]) -> Result<(), TransportError> {
        todo!("WP-12")
    }
    fn recv_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        todo!("WP-12")
    }
    fn set_deadline(&mut self, _timeout: Duration) -> Result<(), TransportError> {
        todo!("WP-12")
    }
    fn close(&mut self) -> Result<(), TransportError> {
        todo!("WP-12")
    }
}

/// 传输错误。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransportError {
    /// I/O 错误。
    Io,
    /// 超时。
    Timeout,
    /// 对端关闭。
    ClosedByPeer,
    /// 帧长超限（防 DoS；上限联动 otp-codec::MAX_MESSAGE_LEN）。
    FrameTooLarge {
        /// 声明帧长。
        len: usize,
    },
    /// 帧结构非法（长度前缀损坏等）。
    FrameMalformed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_variants_are_public_metadata_only() {
        let e = TransportError::FrameTooLarge { len: 99999 };
        assert!(matches!(e, TransportError::FrameTooLarge { .. }));
    }
}
