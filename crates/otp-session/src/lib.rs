//! # otp-session —— AEAD record 会话层【核心】
//!
//! 实现规划 §2 职责：64B 段直接拆两个 32B 方向密钥；ChaCha20-Poly1305
//! record 层；AAD/nonce/方向/epoch/sequence；tag 失败和溢出终止。
//!
//! 密钥构造（冻结，设计书 §1.2）：`K_c2s = B[i][0..32]`、
//! `K_s2c = B[i][32..64]` —— 直接取段，无任何 HKDF/哈希/派生。
//!
//! 禁止事项（规划 §2）：不做 KDF；不切换套件（无状态协商）；不接受重放/乱序。
//!
//! 安全不变量：
//! - tag 验证失败 → 立即终止会话，绝不输出未认证明文（RFC 5116）。
//! - 同方向同段内 sequence 唯一；溢出即终止（设计书 §9）。
//! - 96-bit nonce 构造冻结于 WP-03（见 [`nonce96`]）。
//!
//! 实现归属：榫卯 WP-10（CODEOWNERS 双批准路径）。

#![forbid(unsafe_code)]

use core::fmt;

use otp_types::{
    BookId, DIRECTION_KEY_LEN, Direction, Epoch, Nonce96, Role, SEGMENT_LEN, SegmentIndex,
    Sequence, SessionNonce,
};
use secrecy::SecretBox;
use zeroize::ZeroizeOnDrop;

/// 方向密钥（32B）：Drop 清零、受控暴露（secrecy）。
pub type DirectionKey = SecretBox<[u8; DIRECTION_KEY_LEN]>;

/// record 类型（进入 AAD，防止跨类型搬运）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageType {
    /// 客户端确认（明文 "client-confirm"，设计书 §4）。
    ClientConfirm,
    /// 服务端确认（明文 "server-confirm"）。
    ServerConfirm,
    /// 业务数据。
    Data,
}

/// AAD 字段集（设计书 §4：至少包括版本、book_id、段号、双方 nonce、方向、
/// epoch、序号和消息类型；逐字段构造冻结于 WP-03）。
pub struct RecordAad {
    /// 协议版本。
    pub version: u16,
    /// 密码本 ID。
    pub book_id: BookId,
    /// 本会话使用的段号。
    pub segment: SegmentIndex,
    /// 会话 nonce。
    pub session_nonce: SessionNonce,
    /// 方向。
    pub direction: Direction,
    /// epoch。
    pub epoch: Epoch,
    /// 消息类型。
    pub message_type: MessageType,
}

/// 单条加密 record：密文尾随 16B Poly1305 标签（chacha20poly1305 统一封套）。
/// 不实现 Clone/PartialEq：record 是一次性流式消费的。
pub struct Record {
    /// record 序号。
    pub sequence: Sequence,
    /// 密文 + 16B tag。
    pub ciphertext_and_tag: Vec<u8>,
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 审计安全：只打印序号与长度，绝不打印密文
        write!(
            f,
            "Record{{sequence: {:?}, len: {}}}",
            self.sequence,
            self.ciphertext_and_tag.len()
        )
    }
}

/// 解密后的明文载荷：Drop 清零，只能经 [`Payload::as_bytes`] 读取。
#[derive(ZeroizeOnDrop)]
pub struct Payload(Vec<u8>);

impl Payload {
    /// 明文字节视图。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// 会话层错误。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionError {
    /// tag 验证失败：立即终止会话，绝不输出明文。
    AuthenticationFailed,
    /// 重放/乱序/重复序号：拒绝并终止（不接受重放/乱序，规划 §2）。
    ReplayOrDisorder,
    /// 序号溢出：立即终止（设计书 §9）。
    SequenceOverflow,
    /// 会话已关闭。
    Closed,
}

/// 会话上下文（进入 AAD 的绑定材料）。
pub struct SessionContext {
    /// 本端角色。
    pub role: Role,
    /// 密码本 ID。
    pub book_id: BookId,
    /// 本会话段号。
    pub segment: SegmentIndex,
    /// 会话 nonce。
    pub session_nonce: SessionNonce,
    /// epoch。
    pub epoch: Epoch,
}

/// 已建立的加密会话。内部密钥状态随 WP-10 落地。
pub struct Session {
    /// 内部状态（双方向密钥、收发序号）随 WP-10 落地。
    _wp10: (),
}

impl Session {
    /// 由已提交段建立会话：直接拆 32+32 方向密钥（无任何 KDF/哈希）。
    ///
    /// 输入必须来自 `SegmentIssuer::issue()` 返回的 `CommittedSegment`
    /// （规划 §2.2：不存在从 Reserved 到 AEAD key 的公开路径）。
    pub fn new(_committed_segment: &[u8; SEGMENT_LEN], _ctx: SessionContext) -> Self {
        todo!("WP-10")
    }

    /// 加密一条 record。nonce96 = f(session_nonce, direction, sequence)，
    /// 构造冻结于 WP-03，同方向同段内绝不重复。
    pub fn seal(&mut self, _plaintext: &[u8], _aad: &RecordAad) -> Result<Record, SessionError> {
        todo!("WP-10")
    }

    /// 解密并验证：tag 失败、序号回退、重复、乱序、跨方向/跨 epoch 搬运
    /// 均返回 Err 并终止会话。
    pub fn open(&mut self, _record: &Record, _aad: &RecordAad) -> Result<Payload, SessionError> {
        todo!("WP-10")
    }

    /// 下一发送序号（审计/测试可见）。
    pub fn next_send_sequence(&self) -> Sequence {
        todo!("WP-10")
    }
}

/// 96-bit nonce 构造（冻结于 WP-03）：由会话 nonce 域 + 方向 + 序号组成，
/// 机械可证同方向同段内唯一；序号溢出路径由调用方先终止。
pub fn nonce96(
    _session_nonce: &SessionNonce,
    _direction: Direction,
    _sequence: Sequence,
) -> Nonce96 {
    todo!("WP-03/WP-10")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_debug_never_prints_ciphertext() {
        let r = Record {
            sequence: Sequence::new(7),
            ciphertext_and_tag: vec![9, 9, 9],
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("sequence: Sequence(7)") || dbg.contains("sequence"));
        assert!(!dbg.contains("9, 9, 9"));
    }

    #[test]
    fn direction_key_len_matches_design() {
        // K_c2s/K_s2c 各 32B，共 64B —— 无截断、无哈希（设计书 §1.2）
        assert_eq!(DIRECTION_KEY_LEN * 2, SEGMENT_LEN);
    }
}
