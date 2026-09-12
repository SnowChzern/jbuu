//! 96-bit nonce 构造（WP-03 §1，评审冻结；本模块是规范 §1.1 构造函数的逐字节等价实现）。
//!
//! 布局（12 字节定长）：
//!
//! ```text
//! 偏移 0  长度 3  session_domain = session_nonce[0..3]   （纯切片，无任何变换）
//! 偏移 3  长度 1  direction = 0x01（C2S）/ 0x02（S2C）  （发送方方向）
//! 偏移 4  长度 8  seq（u64 大端，全宽，禁止截断）
//! ```
//!
//! 唯一性论证见规格 §1.2（后缀单射 + 序号严格分配 ⇒ 同方向同段内两两不同；
//! 方向字节隔离两方向）。§1.4 禁令在本实现的体现：无哈希、无随机、seq 全宽、
//! nonce 与帧内 seq 取同一计数器（[`crate::Session`] 内部状态）、方向字节固定
//! 编码 0x01/0x02。

use otp_types::{Direction, Nonce96, Sequence, SessionNonce};

/// nonce 中会话域的长度（24 bit）。
pub const SESSION_DOMAIN_LEN: usize = 3;
/// AEAD nonce 总长（96-bit，RFC 8439）。
pub const RECORD_NONCE_LEN: usize = 12;

/// C2S 方向的线格式编码（WP-01 §4.4 `confirm_body.direction` 同一编码）。
pub const DIRECTION_WIRE_C2S: u8 = 0x01;
/// S2C 方向的线格式编码。
pub const DIRECTION_WIRE_S2C: u8 = 0x02;

/// 会话 nonce 域 = `session_nonce[0..3]`（纯切片）。
///
/// 非秘密（v2 §4：会话随机数公开）；24 bit 对同本不同会话提供区分度，
/// 是纵深防御而非保证（规格 §1.2 推论 2）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionNonceDomain([u8; SESSION_DOMAIN_LEN]);

impl SessionNonceDomain {
    /// 从 16B 会话 nonce 纯切片取前 3 字节（无折叠、无哈希）。
    pub fn from_session_nonce(session_nonce: &SessionNonce) -> Self {
        let mut domain = [0u8; SESSION_DOMAIN_LEN];
        domain.copy_from_slice(&session_nonce.as_bytes()[..SESSION_DOMAIN_LEN]);
        Self(domain)
    }

    /// 原始字节视图。
    pub const fn as_bytes(&self) -> &[u8; SESSION_DOMAIN_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for SessionNonceDomain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 非秘密值，hex 打印便于向量比对
        f.write_str("SessionNonceDomain(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// 方向 → 线格式字节（0x01/0x02；§1.4 禁令 4：不得改为 0/1/bit 标志）。
pub const fn direction_wire(direction: Direction) -> u8 {
    match direction {
        Direction::ClientToServer => DIRECTION_WIRE_C2S,
        Direction::ServerToClient => DIRECTION_WIRE_S2C,
    }
}

/// 线格式字节 → 方向；仅接受 0x01/0x02（供 WP-11/14 从帧字段重建）。
pub const fn direction_from_wire(b: u8) -> Option<Direction> {
    match b {
        DIRECTION_WIRE_C2S => Some(Direction::ClientToServer),
        DIRECTION_WIRE_S2C => Some(Direction::ServerToClient),
        _ => None,
    }
}

/// record nonce 构造（规格 §1.1 规范性定义，逐字节等价）：
///
/// ```text
/// d = session_nonce[0..3]
/// n = d ‖ enc8(direction) ‖ BE64(seq)     // 恰 12 字节
/// ```
pub fn record_nonce(domain: &SessionNonceDomain, direction: Direction, seq: Sequence) -> Nonce96 {
    let mut nonce = [0u8; RECORD_NONCE_LEN];
    nonce[..SESSION_DOMAIN_LEN].copy_from_slice(domain.as_bytes());
    nonce[SESSION_DOMAIN_LEN] = direction_wire(direction);
    nonce[SESSION_DOMAIN_LEN + 1..].copy_from_slice(&seq.get().to_be_bytes());
    Nonce96::from_bytes(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_wire_encoding_is_frozen() {
        // §1.1：0x01 / 0x02，与 WP-01 §4.4 同一编码；往返无损
        assert_eq!(direction_wire(Direction::ClientToServer), 0x01);
        assert_eq!(direction_wire(Direction::ServerToClient), 0x02);
        assert_eq!(direction_from_wire(0x01), Some(Direction::ClientToServer));
        assert_eq!(direction_from_wire(0x02), Some(Direction::ServerToClient));
        assert_eq!(direction_from_wire(0x00), None);
        assert_eq!(direction_from_wire(0x03), None);
        assert_eq!(direction_from_wire(0x81), None);
    }

    #[test]
    fn domain_is_plain_slice_of_first_three_bytes() {
        let mut raw = [0u8; 16];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        let d = SessionNonceDomain::from_session_nonce(&SessionNonce::from_bytes(raw));
        assert_eq!(d.as_bytes(), &[0x00, 0x01, 0x02]);
    }

    #[test]
    fn nonce_layout_matches_spec_formula() {
        // §1.1：3B 域 + 1B 方向 + 8B 大端序号，无任何其他字节
        let domain = SessionNonceDomain::from_session_nonce(&SessionNonce::from_bytes([0x30; 16]));
        let n = record_nonce(
            &domain,
            Direction::ClientToServer,
            Sequence::new(0x0102030405060708),
        );
        assert_eq!(n.as_bytes()[0..3], [0x30, 0x30, 0x30]);
        assert_eq!(n.as_bytes()[3], 0x01);
        assert_eq!(n.as_bytes()[4..], 0x0102030405060708u64.to_be_bytes());
    }
}
