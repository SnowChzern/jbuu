//! # otp-session —— AEAD record 会话层【核心】
//!
//! 实现规划 §2 职责：64B 段直接拆两个 32B 方向密钥；ChaCha20-Poly1305
//! record 层；AAD/nonce/方向/epoch/sequence；tag 失败和溢出终止。
//!
//! **唯一规格依据**：`docs/specs/wp03-nonce-aad-key-lifecycle.md`（v1.0，
//! 评审冻结）。本 crate 是其 §7.1 核对清单的实现：
//!
//! - [`nonce`]：96-bit nonce = `ζ[0..3] ‖ direction(0x01/0x02) ‖ BE64(seq)`
//!   （§1.1；域=纯切片、seq 全宽、无哈希无随机——§1.4 七禁令全数规避）；
//! - [`aad`]：73B 定长 AAD，9 字段固定序，CONFIRM 与 DATA 共用（§2.1）；
//! - [`keys`]：`K_c2s = B[i][0..32]`、`K_s2c = B[i][32..64]` 直接拆分，
//!   split-once、恰两副本、Drop 清零（§3/§5.2）；**无任何 KDF/哈希**；
//! - [`session`]：CONFIRM 占 seq=0、DATA 自 1 起严格 +1（§4.1）；接收
//!   先判 seq 后 open、无窗口（§4.2）；发送 2^64−1 后整会话终止（§4.3）；
//!   任何 tag 失败/截断/乱序/重放 → 立即焚毁密钥、绝不输出未认证明文（§4.4）。
//!
//! 密码学不自研（规划 §0.4）：AEAD 用 RustCrypto `chacha20poly1305`
//! 的整体 seal/open（tag 先验证后释放明文，RFC 8439 构造；§5.2.6 禁止
//! 手工两段拼装）；tag 比较由库内常量时间完成（WP-01 §7.2.3）。
//!
//! 禁止事项（规划 §2）：不做 KDF；不切换套件（无协商，v2 §1.2）；
//! 不接受重放/乱序。
//!
//! 安全不变量：
//! - tag 验证失败 → 立即终止会话，绝不输出未认证明文（RFC 5116）；
//! - 同方向同段内 sequence 唯一（nonce 唯一性证明见规格 §1.2）；
//! - 密钥/段/明文类型无 Clone/Debug/Display/Eq/序列化，Drop = zeroize；
//! - 日志白名单外字段一律不落（§5.3；本 crate 不打日志，Debug 实现脱敏）。
//!
//! 实现归属：榫卯 WP-10（任务 #37）；CODEOWNERS 双批准路径。

#![forbid(unsafe_code)]

mod aad;
mod keys;
mod nonce;
mod session;

pub use aad::{AAD_LEN, MessageType, VERSION};
pub use keys::{CommittedSegment, SessionKeys};
pub use nonce::{
    DIRECTION_WIRE_C2S, DIRECTION_WIRE_S2C, RECORD_NONCE_LEN, SESSION_DOMAIN_LEN,
    SessionNonceDomain, direction_from_wire, direction_wire, record_nonce,
};
pub use session::{Payload, Record, Session, SessionContext, SessionError};

/// 方向密钥长度（32B = 256-bit；K_c2s/K_s2c 各一，直接拆自 64B 段）。
pub use otp_types::DIRECTION_KEY_LEN;
/// 64B 段长（两个方向密钥之和，无任何剩余字节）。
pub use otp_types::SEGMENT_LEN;
/// Poly1305 tag 长度（16B）。
pub use otp_types::TAG_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_material_lens_match_design() {
        // 设计书 §1.2：64B 段 = 2 × 32B 方向密钥，无派生无剩余
        assert_eq!(SEGMENT_LEN, 2 * DIRECTION_KEY_LEN);
        assert_eq!(DIRECTION_KEY_LEN, 32);
        assert_eq!(TAG_LEN, 16);
        assert_eq!(RECORD_NONCE_LEN, 12);
        assert_eq!(AAD_LEN, 73);
    }

    #[test]
    fn version_constant_is_frozen() {
        // WP-01 §1.3：version 恒 0x0002（AAD 首字段）
        assert_eq!(VERSION, 0x0002);
    }
}
