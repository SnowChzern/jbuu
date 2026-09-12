//! AAD 构造字段（WP-03 §2，冻结；73 字节定长布局）。
//!
//! 布局（[`AAD_LEN`]）：
//!
//! | 偏移 | 长 | 字段 |
//! |---:|---:|---|
//! | 0 | 2 | version（恒 0x0002） |
//! | 2 | 2 | msg_type（0x0004/0x0005/0x0006） |
//! | 4 | 1 | direction（0x01/0x02） |
//! | 5 | 16 | book_id |
//! | 21 | 8 | segment_index |
//! | 29 | 16 | client_nonce |
//! | 45 | 16 | server_nonce |
//! | 61 | 4 | epoch |
//! | 65 | 8 | seq |
//!
//! 拼装函数是 [`crate::SessionContext::build_aad`]；CONFIRM 与 DATA 共用
//! 同一布局（§2.1），任何字段被替换均使 tag 失败（§2.2/§2.3）。

/// AAD 定长（9 字段，73 字节；无长度前缀、无填充、无变体分支）。
pub const AAD_LEN: usize = 73;
/// 进入 AAD 的协议版本（WP-01 §1.3：恒 0x0002）。
pub const VERSION: u16 = 0x0002;

/// 进入 AAD 的 record 类型（§2.1：该 record 的帧类型；阻断跨类型搬运）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageType {
    /// CONFIRM_C2S（0x0004），仅客户端发送。
    ClientConfirm,
    /// CONFIRM_S2C（0x0005），仅服务端发送。
    ServerConfirm,
    /// DATA（0x0006），双向。
    Data,
}

impl MessageType {
    /// 线格式码（WP-01 §2 消息注册表）。
    pub const fn wire_code(self) -> u16 {
        match self {
            Self::ClientConfirm => 0x0004,
            Self::ServerConfirm => 0x0005,
            Self::Data => 0x0006,
        }
    }

    /// CONFIRM 类型固有的方向（§2.2：0x0004→C2S、0x0005→S2C）；DATA 无固有方向。
    pub const fn confirm_direction(self) -> Option<otp_types::Direction> {
        match self {
            Self::ClientConfirm => Some(otp_types::Direction::ClientToServer),
            Self::ServerConfirm => Some(otp_types::Direction::ServerToClient),
            Self::Data => None,
        }
    }

    /// 是否为确认类 record（占 seq=0；DATA 自 1 起，WP-01 §4.4/§4.5）。
    pub const fn is_confirm(self) -> bool {
        !matches!(self, Self::Data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_len_is_frozen_at_73() {
        // §2.1：2+2+1+16+8+16+16+4+8 = 73
        assert_eq!(AAD_LEN, 73);
        assert_eq!(2 + 2 + 1 + 16 + 8 + 16 + 16 + 4 + 8, AAD_LEN);
    }

    #[test]
    fn message_type_wire_codes_are_frozen() {
        assert_eq!(MessageType::ClientConfirm.wire_code(), 0x0004);
        assert_eq!(MessageType::ServerConfirm.wire_code(), 0x0005);
        assert_eq!(MessageType::Data.wire_code(), 0x0006);
        assert!(MessageType::ClientConfirm.is_confirm());
        assert!(MessageType::ServerConfirm.is_confirm());
        assert!(!MessageType::Data.is_confirm());
    }
}
