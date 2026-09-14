//! PAD_* 控制面 payload（设计书 §1.3/§2.3）。
//!
//! 控制面消息**承载于现有 AEAD 控制通道**（首个 64B 会话段拆出的
//! ChaCha20-Poly1305 record 层，即 `otp-session` 的 DATA record）：
//! 调用方用现有会话把本模块编码的 payload 密封为 v2 DATA 帧收发
//! （集成实证见 `tests/control_aead.rs`）。因此：
//!
//! - **序号空间与 OTP 数据天然分离**：控制面走 AEAD session 的
//!   epoch/seq（u64，CONFIRM 占 0、DATA 自 1 起），OTP 数据走每方向
//!   `record_seq`（从 0 起），互不相干；
//! - **严禁承载终端字符**：四类 payload 均为定长元数据（bundle 号/基址），
//!   解码器对一切多余字节 fail closed，结构上不存在 PTY 字节路径；
//!   窗口尺寸/心跳/退出输出也不在本控制面（归接线卡的上层帧）。
//!
//! canonical payload 布局（大端、无标签、无变体分支；code ∈ 0x01..=0x04，
//! 其余 fail closed）：
//!
//! ```text
//! PAD_OFFER  0x01 ‖ BE64 bundle_id ‖ BE64 base_segment   （17B，S→C）
//! PAD_ACK    0x02 ‖ BE64 bundle_id                        （9B，C→S）
//! PAD_NEED   0x03                                        （1B，双向）
//! CLOSE      0x04                                        （1B，双向）
//! ```

use crate::error::ControlError;

/// PAD_OFFER 线上码。
pub const CONTROL_PAD_OFFER: u8 = 0x01;
/// PAD_ACK 线上码。
pub const CONTROL_PAD_ACK: u8 = 0x02;
/// PAD_NEED 线上码。
pub const CONTROL_PAD_NEED: u8 = 0x03;
/// CLOSE 线上码。
pub const CONTROL_CLOSE: u8 = 0x04;

const PAD_OFFER_LEN: usize = 17;
const PAD_ACK_LEN: usize = 9;

/// 控制面消息（编码前的公共投影；全部公开元数据）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PadControl {
    /// 服务端协调者：下一 bundle 已 fail-to-waste 预留，公告分配序号与基址。
    PadOffer { bundle_id: u64, base_segment: u64 },
    /// 客户端：本地已采纳（本地安全指针恰为公告基址并同样预留）。
    PadAck { bundle_id: u64 },
    /// 任一侧：某方向可用量低于 [`crate::LOW_WATER`]，请求预取下一 bundle。
    PadNeed,
    /// 关闭：当前+预取 bundle 尾部全部浪费（§4.2）。
    Close,
}

impl PadControl {
    /// canonical 编码（追加写入 `out`）。
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match *self {
            Self::PadOffer {
                bundle_id,
                base_segment,
            } => {
                out.push(CONTROL_PAD_OFFER);
                out.extend_from_slice(&bundle_id.to_be_bytes());
                out.extend_from_slice(&base_segment.to_be_bytes());
            }
            Self::PadAck { bundle_id } => {
                out.push(CONTROL_PAD_ACK);
                out.extend_from_slice(&bundle_id.to_be_bytes());
            }
            Self::PadNeed => out.push(CONTROL_PAD_NEED),
            Self::Close => out.push(CONTROL_CLOSE),
        }
    }

    /// canonical 编码为独立缓冲。
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PAD_OFFER_LEN);
        self.encode_into(&mut buf);
        buf
    }
}

/// 严格解码：定长匹配、未知码/尾随字节/截断一律 fail closed。
#[must_use = "解码失败必须关闭会话，不得忽略"]
pub fn decode(bytes: &[u8]) -> Result<PadControl, ControlError> {
    let (&code, rest) = bytes.split_first().ok_or(ControlError::TooShort)?;
    match code {
        CONTROL_PAD_OFFER => {
            if rest.len() != PAD_OFFER_LEN - 1 {
                return Err(ControlError::LengthMismatch);
            }
            Ok(PadControl::PadOffer {
                bundle_id: u64::from_be_bytes(rest[..8].try_into().expect("恰 8B")),
                base_segment: u64::from_be_bytes(rest[8..].try_into().expect("恰 8B")),
            })
        }
        CONTROL_PAD_ACK => {
            if rest.len() != PAD_ACK_LEN - 1 {
                return Err(ControlError::LengthMismatch);
            }
            Ok(PadControl::PadAck {
                bundle_id: u64::from_be_bytes(rest.try_into().expect("恰 8B")),
            })
        }
        CONTROL_PAD_NEED if rest.is_empty() => Ok(PadControl::PadNeed),
        CONTROL_CLOSE if rest.is_empty() => Ok(PadControl::Close),
        // 已知码但长度不符（PAD_NEED/CLOSE 携带载荷即拒绝）
        0x03 | 0x04 => Err(ControlError::LengthMismatch),
        _ => Err(ControlError::UnknownCode),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_exact_lengths() {
        let cases = [
            (
                PadControl::PadOffer {
                    bundle_id: 7,
                    base_segment: 896,
                },
                17,
            ),
            (PadControl::PadAck { bundle_id: 7 }, 9),
            (PadControl::PadNeed, 1),
            (PadControl::Close, 1),
        ];
        for (msg, len) in cases {
            let wire = msg.encode();
            assert_eq!(wire.len(), len);
            assert_eq!(decode(&wire), Ok(msg));
        }
    }

    #[test]
    fn wire_bytes_are_frozen() {
        // 显式冻结字节序（大端、code 前置）
        assert_eq!(
            PadControl::PadOffer {
                bundle_id: 1,
                base_segment: 256
            }
            .encode(),
            vec![0x01, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0]
        );
        assert_eq!(
            PadControl::PadAck { bundle_id: 1 }.encode(),
            vec![0x02, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(PadControl::PadNeed.encode(), vec![0x03]);
        assert_eq!(PadControl::Close.encode(), vec![0x04]);
    }

    #[test]
    fn rejects_unknown_truncated_and_trailing() {
        // 未知码
        for bad in [0x00u8, 0x05, 0xFF] {
            assert_eq!(decode(&[bad]), Err(ControlError::UnknownCode));
        }
        // 截断 / 尾随
        assert_eq!(decode(&[]), Err(ControlError::TooShort));
        assert_eq!(decode(&[0x01, 0, 0]), Err(ControlError::LengthMismatch));
        let mut offer = PadControl::PadOffer {
            bundle_id: 0,
            base_segment: 0,
        }
        .encode();
        offer.push(0xEE);
        assert_eq!(decode(&offer), Err(ControlError::LengthMismatch));
        // PAD_NEED/CLOSE 携带任何载荷即拒绝（禁止承载终端字符的结构投影）
        assert_eq!(decode(&[0x03, b'x']), Err(ControlError::LengthMismatch));
        assert_eq!(decode(&[0x04, 0x00]), Err(ControlError::LengthMismatch));
    }
}
