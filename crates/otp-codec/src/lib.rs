//! # otp-codec —— 严格长度前缀二进制编解码
//!
//! 实现规划 §2 职责：HELLO / ARBITRATE / ISSUE_REQUEST / CONFIRM / DATA 的
//! 严格编解码；长度、版本、字段上限、canonical 检查。逐字节布局、上限与
//! golden vectors 由 WP-01（斗拱）冻结。
//!
//! 禁止事项（规划 §2）：不接受尾随字节/未知必选字段；不记录明文
//! （`Debug` 实现不打印密文内容）。
//!
//! 消息语义（设计书 §4）：
//! ```text
//! C -> S: HELLO(version, book_id, client_nonce, client_pointer, features)
//! S -> C: ARBITRATE(server_pointer, result)
//! C -> S: ISSUE_REQUEST(chosen_pointer, client_nonce, server_nonce)
//! C -> S: CONFIRM_C2S(i, session_nonce, seq=0, AEAD_Kc2s("client-confirm", AAD))
//! S -> C: CONFIRM_S2C(i, session_nonce, seq=0, AEAD_Ks2c("server-confirm", AAD))
//! DATA(epoch, sequence, ciphertext)
//! ```

#![forbid(unsafe_code)]

use core::fmt;
use otp_types::{AuthTag, BookId, Epoch, SegmentIndex, Sequence, SessionNonce};

/// 协议版本（HELLO 携带；不匹配即拒绝，fail-closed）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProtocolVersion(pub u16);

/// HELLO features 位图。未知位不得静默忽略，位定义由 WP-01 冻结。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct FeatureFlags(pub u16);

/// 单条消息的最大线长度。精确上限以 WP-01 定稿为准；骨架先取保守值，
/// 超长必须在 decode 入口拒绝（防 DoS 放大）。
pub const MAX_MESSAGE_LEN: usize = 4096;

/// ARBITRATE 结果（设计书 §4）：只允许前进，永不回退。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ArbitrateResult {
    /// 双方指针一致或服务端认可 `i`，客户端可发 ISSUE_REQUEST。
    Ok(SegmentIndex),
    /// 服务端指针更高：客户端跳到该指针并弃用间隙段（段绝不再使用）。
    ServerAhead(SegmentIndex),
    /// 客户端指针更高：服务端绝不回退，进入人工恢复/客户端弃用重连路径。
    ClientAhead,
    /// 密码本耗尽：需离线换本。
    Exhausted,
    /// book_id 不匹配：两端错本。
    BookMismatch,
}

/// 协议消息。字段均为非秘密元数据（设计书 §4：段号/nonce/指针可公开），
/// 唯独 `Data` 的密文不得进入日志（见 `Debug` 实现）。
#[derive(Clone, PartialEq, Eq)]
pub enum Message {
    /// C -> S：HELLO。
    Hello {
        /// 协议版本。
        version: ProtocolVersion,
        /// 密码本 ID。
        book_id: BookId,
        /// 客户端 nonce。
        client_nonce: otp_types::ClientNonce,
        /// 客户端本地指针。
        client_pointer: SegmentIndex,
        /// 特性位图。
        features: FeatureFlags,
    },
    /// S -> C：指针仲裁结果。
    Arbitrate {
        /// 服务端当前指针。
        server_pointer: SegmentIndex,
        /// 仲裁结果。
        result: ArbitrateResult,
    },
    /// C -> S：请求签发选定段。
    IssueRequest {
        /// 客户端选定指针（只允许等于/前进到服务端指针）。
        chosen_pointer: SegmentIndex,
        /// 客户端 nonce（回显绑定）。
        client_nonce: otp_types::ClientNonce,
        /// 服务端 nonce（回显绑定）。
        server_nonce: otp_types::ServerNonce,
    },
    /// C -> S：客户端确认（seq=0）。
    ConfirmC2s {
        /// 已签发段号。
        segment: SegmentIndex,
        /// 会话 nonce。
        session_nonce: SessionNonce,
        /// 序号（确认消息固定为 0）。
        sequence: Sequence,
        /// AEAD 标签。
        tag: AuthTag,
    },
    /// S -> C：服务端确认（seq=0）。
    ConfirmS2c {
        /// 已签发段号。
        segment: SegmentIndex,
        /// 会话 nonce。
        session_nonce: SessionNonce,
        /// 序号（确认消息固定为 0）。
        sequence: Sequence,
        /// AEAD 标签。
        tag: AuthTag,
    },
    /// 加密 DATA record（密文由 otp-session 产出，tag 附于密文尾部）。
    Data {
        /// 会话 epoch。
        epoch: Epoch,
        /// record 序号。
        sequence: Sequence,
        /// 密文（含认证标签）。
        ciphertext: Vec<u8>,
    },
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 审计安全：绝不打印 Data 密文/明文；其余为公开元数据（设计书 §4）
        match self {
            Self::Hello {
                version,
                book_id,
                client_pointer,
                ..
            } => write!(
                f,
                "Hello{{version: {version:?}, book_id: {book_id:?}, client_pointer: {client_pointer:?}, ..}}"
            ),
            Self::Arbitrate {
                server_pointer,
                result,
            } => write!(
                f,
                "Arbitrate{{server_pointer: {server_pointer:?}, result: {result:?}}}"
            ),
            Self::IssueRequest { chosen_pointer, .. } => {
                write!(f, "IssueRequest{{chosen_pointer: {chosen_pointer:?}, ..}}")
            }
            Self::ConfirmC2s {
                segment, sequence, ..
            } => write!(
                f,
                "ConfirmC2s{{segment: {segment:?}, sequence: {sequence:?}, ..}}"
            ),
            Self::ConfirmS2c {
                segment, sequence, ..
            } => write!(
                f,
                "ConfirmS2c{{segment: {segment:?}, sequence: {sequence:?}, ..}}"
            ),
            Self::Data {
                epoch,
                sequence,
                ciphertext,
            } => write!(
                f,
                "Data{{epoch: {epoch:?}, sequence: {sequence:?}, ciphertext_len: {}}}",
                ciphertext.len()
            ),
        }
    }
}

/// 编解码错误。绝不携带任何明文或密钥材料。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CodecError {
    /// 输入不足最小长度。
    TooShort,
    /// 超过最大消息长度。
    TooLong {
        /// 实际长度。
        len: usize,
    },
    /// 解码完成后仍有尾随字节（严格拒绝，规划 §2）。
    TrailingBytes {
        /// 尾随字节数。
        count: usize,
    },
    /// 未知消息类型。
    UnknownMessageType {
        /// 类型码。
        code: u8,
    },
    /// 版本不支持。
    VersionUnsupported {
        /// 收到的版本号。
        got: u16,
    },
    /// 字段取值非法（越界/不 canonical）。
    InvalidField {
        /// 字段名。
        field: &'static str,
    },
}

/// 编码一条消息到 `out`（严格长度前缀；字段顺序与上限固定，WP-01 冻结）。
pub fn encode(_msg: &Message, _out: &mut Vec<u8>) -> Result<(), CodecError> {
    todo!("WP-05：严格长度前缀编码（canonical、字段顺序/上限冻结）")
}

/// 从 `buf` 解码一条消息。拒绝尾随字节、未知必选字段、超长与非 canonical 编码。
pub fn decode(_buf: &[u8]) -> Result<Message, CodecError> {
    todo!("WP-05：严格解码（拒绝尾随字节/未知字段/超长）")
}

#[cfg(test)]
mod tests {
    use super::*;
    use otp_types::ClientNonce;

    #[test]
    fn message_variants_are_constructible_and_debug_is_redacted() {
        let hello = Message::Hello {
            version: ProtocolVersion(2),
            book_id: BookId::from_bytes([7; 16]),
            client_nonce: ClientNonce::from_bytes([0; 16]), // WP-01 §4.1 冻结：BYTES(16)（otp-types 同步修正）
            client_pointer: SegmentIndex::ZERO,
            features: FeatureFlags::default(),
        };
        assert!(matches!(hello, Message::Hello { .. }));

        let data = Message::Data {
            epoch: Epoch::new(0),
            sequence: Sequence::new(1),
            ciphertext: vec![1, 2, 3],
        };
        let dbg = format!("{data:?}");
        // 密文字节绝不进入 Debug 输出
        assert!(!dbg.contains("ciphertext=[") && !dbg.contains("1, 2, 3"));
        assert!(dbg.contains("ciphertext_len: 3"));
    }

    #[test]
    fn max_message_len_is_bounded() {
        // 编译期即固定：上限必须在保守区间内（精确值 WP-01 定稿）
        const _: () = assert!(MAX_MESSAGE_LEN >= 128 && MAX_MESSAGE_LEN <= 64 * 1024);
    }
}
