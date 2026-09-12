//! # otp-codec —— 严格长度前缀二进制编解码（WP-05）
//!
//! 唯一线格式依据：`docs/specs/wp01-wire-format-and-error-model.md`（v1.1，
//! 评审冻结）。本 crate 实现其中：
//!
//! - §2 帧格式与消息注册表（8B 帧头 + 6 类消息）；
//! - §3 canonical 规则与拒绝条件（尾随字节/超长/截断/未知版本/未知类型/
//!   未知枚举/方向不符全部拒绝，fail closed）；
//! - §4 各消息逐字节布局 + 内层 confirm body；
//! - §5.2 统一错误码注册表（[`ErrorCode`]）；
//! - §6 golden vectors（`tests/golden.rs`，38 条全量）与 §6.8 边界/
//!   proptest 性质（`tests/property.rs`、`tests/boundary.rs`）。
//!
//! 决策点 D1–D6 均按规格实现。本层**不做任何密码学运算**：`sealed`/`data`
//! 是不透明字节串（开封、tag 校验、序号推进归 WP-03/WP-10）。
//!
//! 禁止事项（规划 §2 / 任务卡）：不记录明文（[`Debug`](core::fmt::Debug)
//! 实现对密文只打印长度）；不做 I/O；无 unsafe；无 panic 路径（fuzz 前提，
//! WP-14）。
//!
//! 典型用法：
//! ```
//! use otp_codec::{decode, encode, Message, FeatureFlags, ErrorCode};
//! use otp_types::{BookId, Role, SegmentIndex, ClientNonce};
//!
//! let hello = Message::Hello {
//!     book_id: BookId::from_bytes([7; 16]),
//!     client_nonce: ClientNonce::from_bytes([9; 16]),
//!     client_pointer: SegmentIndex::ZERO,
//!     features: FeatureFlags::default(),
//! };
//! let wire = encode(&hello).expect("canonical message");
//! assert_eq!(wire.len(), 52); // §2.2 注册表：HELLO 帧 52B
//! // HELLO 是 C→S 消息，只能由服务端解码
//! assert_eq!(decode(Role::Server, &wire), Ok(hello));
//! assert_eq!(decode(Role::Client, &wire), Err(ErrorCode::WRONG_DIRECTION));
//! ```

#![forbid(unsafe_code)]

pub mod error;
pub mod message;

mod decode;
mod encode;

pub use decode::{decode, decode_confirm_body};
pub use encode::{encode, encode_confirm_body, encode_into};
pub use error::ErrorCode;
pub use message::{
    ARBITRATE_PAYLOAD_LEN, ArbitrateResult, CONFIRM_BODY_LEN, CONFIRM_LABEL_LEN,
    CONFIRM_PAYLOAD_LEN, ConfirmBody, FRAME_HEADER_LEN, FeatureFlags, HELLO_PAYLOAD_LEN,
    ISSUE_PAYLOAD_LEN, MAX_APP_PLAINTEXT, MAX_DATA_FIELD, MAX_FRAME, MAX_FRAME_PAYLOAD,
    MIN_DATA_FIELD, MIN_FRAME_PAYLOAD, Message, MsgType, ProtocolVersion, SEALED_LEN,
    body_direction_from_wire, body_direction_wire,
};
pub use otp_types::Role;

/// 协议版本（§1.3）：恒为 0x0002；帧头 version ≠ 此值即 0x0301（决策 D1）。
pub const VERSION: u16 = 0x0002;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_constant_is_frozen() {
        // §1.3 常量表：VERSION = 0x0002。
        assert_eq!(VERSION, 0x0002);
        assert_eq!(ProtocolVersion::V2.0, VERSION);
    }
}
