//! # otp-handshake —— 客/服握手状态机
//!
//! 实现规划 §2 职责：客/服握手状态机、指针仲裁、nonce 上下文、确认消息、
//! CLIENT_AHEAD 人工恢复路径。
//!
//! 禁止事项（规划 §2）：不直接访问密码本/锚；失败后不复用该段。
//!
//! ## 模块边界（规划 §2.2）
//!
//! - 取段只能经 [`SegmentIssuer::issue()`]（otp-allocator）；本 crate 不 import
//!   otp-book / 锚后端。
//! - 仲裁只允许前进：SERVER_AHEAD 时客户端跳到服务端指针并弃用间隙段；
//!   CLIENT_AHEAD 时服务端绝不回退，走人工恢复/客户端弃用重连（设计书 §4）。
//!
//! 实现归属：榫卯 WP-11。

#![forbid(unsafe_code)]

use otp_allocator::{IssueError, SegmentIssuer};
use otp_codec::{ErrorCode, Message, ProtocolVersion};
use otp_session::{Session, SessionError};
use otp_types::{BookId, SegmentIndex};

/// 握手状态机一步的产物。
pub enum Step {
    /// 需要发送的消息（交给 transport）。
    Send(Message),
    /// 握手完成：已建立的会话 + 所用段号（进入 DATA 阶段，sequence 从 1 起）。
    Established {
        /// 已建立的加密会话。
        session: Session,
        /// 本会话消耗的段号。
        segment: SegmentIndex,
    },
    /// 等待对端下一条消息。
    AwaitPeer,
    /// 失败：会话终止；本段按规则消耗/废弃，绝不重试同段。
    Failed(HandshakeError),
}

/// 客户端握手配置。
pub struct ClientConfig {
    /// 协议版本。
    pub version: ProtocolVersion,
    /// 期望 book_id。
    pub book_id: BookId,
    /// 本地指针（来自本地锚）。
    pub local_pointer: SegmentIndex,
}

/// 服务端握手配置。
pub struct ServerConfig {
    /// 协议版本。
    pub version: ProtocolVersion,
    /// 本端 book_id。
    pub book_id: BookId,
}

/// 客户端握手状态机。
pub struct ClientHandshake {
    /// 内部状态随 WP-11 落地。
    _wp11: (),
}

/// 服务端握手状态机。
pub struct ServerHandshake {
    /// 内部状态随 WP-11 落地。
    _wp11: (),
}

impl ClientHandshake {
    /// 以本地配置启动握手。
    pub fn new(_cfg: ClientConfig) -> Self {
        todo!("WP-11")
    }

    /// 产生首条 HELLO(version, book_id, client_nonce, client_pointer, features)。
    /// nonce 来自 OS CSPRNG；CSPRNG 失败即终止握手（规划 §1.2）。
    pub fn start(&mut self) -> Message {
        todo!("WP-11")
    }

    /// 推进状态机：ARBITRATE → （SERVER_AHEAD 则跳进并弃用间隙）→
    /// ISSUE_REQUEST → CONFIRM_S2C 验证 → Established。
    pub fn handle(&mut self, _msg: &Message) -> Step {
        todo!("WP-11")
    }
}

impl ServerHandshake {
    /// 以服务端配置启动。
    pub fn new(_cfg: ServerConfig) -> Self {
        todo!("WP-11")
    }

    /// 处理 HELLO → 产出 ARBITRATE：检查 book_id，读本地指针执行仲裁
    /// （OK / SERVER_AHEAD / CLIENT_AHEAD / EXHAUSTED / BOOK_MISMATCH）。
    pub fn on_hello(&mut self, _hello: &Message) -> Message {
        todo!("WP-11")
    }

    /// 处理 ISSUE_REQUEST：经 SegmentIssuer 签发新段，产出 CONFIRM_S2C。
    /// 签发失败（耗尽/持久化不确定）→ Failed，段不复用。
    pub fn on_issue_request(&mut self, _req: &Message, _issuer: &mut dyn SegmentIssuer) -> Step {
        todo!("WP-11")
    }

    /// 处理 CONFIRM_C2S：验证 tag（隐式认证，设计书 §2），双向确认后
    /// Established。
    pub fn on_confirm(&mut self, _confirm: &Message) -> Step {
        todo!("WP-11")
    }
}

/// 握手错误。只携带指针/类别等公开元数据。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandshakeError {
    /// 两端错本（book_id 不符）。
    BookMismatch,
    /// CLIENT_AHEAD：客户端指针更高 —— 服务端绝不回退，进入人工恢复或
    /// 客户端弃用孤立段后从服务端更高值重连。
    ClientAhead {
        /// 客户端指针。
        client: SegmentIndex,
        /// 服务端指针。
        server: SegmentIndex,
    },
    /// SERVER_AHEAD：客户端只允许跳到服务端指针，中间段全部废弃。
    ServerAheadJump {
        /// 原指针。
        from: SegmentIndex,
        /// 跳至指针。
        to: SegmentIndex,
    },
    /// 密码本耗尽。
    Exhausted,
    /// 确认 tag 验证失败：隐式认证失败，会话终止。
    AuthenticationFailed,
    /// 消息解码失败（统一错误码，WP-01 §5.2）。
    Codec(ErrorCode),
    /// 段签发失败。
    Issuer(IssueError),
    /// 会话层错误。
    Session(SessionError),
    /// 消息序列违反协议（顺序/回显字段不符等）。
    ProtocolViolation {
        /// 原因说明。
        reason: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configs_bind_book_id_and_pointer() {
        let cfg = ClientConfig {
            version: ProtocolVersion(2),
            book_id: BookId::from_bytes([3; 16]),
            local_pointer: SegmentIndex::ZERO,
        };
        assert_eq!(cfg.local_pointer, SegmentIndex::ZERO);
    }

    #[test]
    fn error_variants_carry_only_public_metadata() {
        let e = HandshakeError::ClientAhead {
            client: SegmentIndex::new(5),
            server: SegmentIndex::new(3),
        };
        assert!(matches!(e, HandshakeError::ClientAhead { .. }));
    }
}
