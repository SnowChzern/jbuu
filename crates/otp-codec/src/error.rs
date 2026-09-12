//! 统一错误码注册表（WP-01 §5.2，规格 v1.1）。
//!
//! 两套编号中的**实现内**编号：供 API 返回、审计日志、测试断言
//! （WP-05/14/19）使用，不上线。线上只允许 ARBITRATE.result（u8）向对端
//! 传达仲裁结局（§5.3），除此之外没有任何错误通告消息。
//!
//! 高字节为类别：0x01 仲裁/密码本、0x02 认证、0x03 协议违规、0x04 内部。
//! 伞码（0x0200/0x0300/0x0400）用于只需类别的场合；本 codec 解码拒绝只
//! 产生 0x0301–0x0308 子码，其余码常量供上层工作包（WP-10/11/14）与
//! 审计断言复用，避免各 crate 私自定义漂移。

use core::fmt;

/// 统一错误码（u16）。`Debug`/`Display` 只输出码名与十六进制值，
/// 绝不携带明文、密钥或字段内容（§5.3 审计白名单）。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ErrorCode(pub u16);

impl ErrorCode {
    // ---- 0x01xx 仲裁/密码本（握手层触发）----
    /// HELLO.book_id 与本端配置不符（线上 ARBITRATE result=3）。
    pub const BOOK_MISMATCH: Self = Self(0x0100);
    /// next ≥ segment_count，段耗尽（线上 ARBITRATE result=2）。
    pub const EXHAUSTED: Self = Self(0x0101);
    /// client_pointer > 服务端 next（线上 ARBITRATE result=4；绝不回退）。
    pub const CLIENT_AHEAD: Self = Self(0x0102);
    /// 服务端 next > client_pointer（线上 ARBITRATE result=1；只前进）。
    pub const SERVER_AHEAD: Self = Self(0x0103);

    // ---- 0x02xx 认证失败（线上静默关闭，不区分子类）----
    /// 认证失败伞码。
    pub const AUTH_FAILED: Self = Self(0x0200);
    /// AEAD tag 校验失败（record 层）。
    pub const TAG_INVALID: Self = Self(0x0201);
    /// 内层副本绑定失败（段号/方向/label/msg_type/book_id/version）。
    pub const SEGMENT_BINDING: Self = Self(0x0202);
    /// nonce 回显不符（含旧 nonce）。
    pub const NONCE_MISMATCH: Self = Self(0x0203);
    /// 精确重复序号（重放）。
    pub const SEQ_REPLAY: Self = Self(0x0204);

    // ---- 0x03xx 协议违规（线上静默关闭）----
    /// 协议违规伞码。
    pub const PROTOCOL_VIOLATION: Self = Self(0x0300);
    /// version ≠ 0x0002（codec §3.2 步 2）。
    pub const BAD_VERSION: Self = Self(0x0301);
    /// payload_len 非精确/越界；字段字节不足；body≠87B；data_len 越界（codec）。
    pub const BAD_LENGTH: Self = Self(0x0302);
    /// 尾随字节（codec §3.2 步 5/7）。
    pub const TRAILING_BYTES: Self = Self(0x0303);
    /// 未知枚举：result∉{0..4}；BOOK_MISMATCH 时 sp≠0；body.direction∉{1,2}（codec）。
    pub const BAD_ENUM: Self = Self(0x0304);
    /// msg_type 未分配（codec §3.2 步 3；不允许“跳过未知消息”）。
    pub const UNKNOWN_MSG_TYPE: Self = Self(0x0305);
    /// 消息方向与接收角色不符（codec §3.2 步 6）。
    pub const WRONG_DIRECTION: Self = Self(0x0306);
    /// ISSUE.chosen ≠ 仲裁约定 i 等（state 层，WP-11）。
    pub const ISSUE_POINTER_MISMATCH: Self = Self(0x0307);
    /// 输入不足 8+payload_len / EOF 中断（framing §3.2 步 1/5）。
    pub const FRAME_TRUNCATED: Self = Self(0x0308);
    /// 消息时序违反状态机（state 层，触发表归 WP-02）。
    pub const BAD_ORDER: Self = Self(0x0309);
    /// epoch ≠ 0（v2 仅定义 epoch 0；state/record 层）。
    pub const EPOCH_MISMATCH: Self = Self(0x030A);
    /// CONFIRM seq≠0；DATA 首序号≠1；跳号/乱序（state/record 层）。
    pub const SEQ_UNEXPECTED: Self = Self(0x030B);

    // ---- 0x04xx 内部（本地实现；fail closed，宁可拒绝服务）----
    /// 内部错误伞码。
    pub const INTERNAL: Self = Self(0x0400);
    /// 短写/EIO/ENOSPC 等（平台层）。
    pub const IO_ERROR: Self = Self(0x0401);
    /// fsync 结果不确定（分配器，设计书 §6）。
    pub const PERSISTENCE_UNVERIFIED: Self = Self(0x0402);
    /// getrandom 失败即终止握手（规划 §1.2）。
    pub const CSPRNG_FAILURE: Self = Self(0x0403);

    /// 错误码名称（WP-01 §5.2 注册表；审计白名单可安全打印）。
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            0x0100 => "BOOK_MISMATCH",
            0x0101 => "EXHAUSTED",
            0x0102 => "CLIENT_AHEAD",
            0x0103 => "SERVER_AHEAD",
            0x0200 => "AUTH_FAILED",
            0x0201 => "TAG_INVALID",
            0x0202 => "SEGMENT_BINDING",
            0x0203 => "NONCE_MISMATCH",
            0x0204 => "SEQ_REPLAY",
            0x0300 => "PROTOCOL_VIOLATION",
            0x0301 => "BAD_VERSION",
            0x0302 => "BAD_LENGTH",
            0x0303 => "TRAILING_BYTES",
            0x0304 => "BAD_ENUM",
            0x0305 => "UNKNOWN_MSG_TYPE",
            0x0306 => "WRONG_DIRECTION",
            0x0307 => "ISSUE_POINTER_MISMATCH",
            0x0308 => "FRAME_TRUNCATED",
            0x0309 => "BAD_ORDER",
            0x030A => "EPOCH_MISMATCH",
            0x030B => "SEQ_UNEXPECTED",
            0x0400 => "INTERNAL",
            0x0401 => "IO_ERROR",
            0x0402 => "PERSISTENCE_UNVERIFIED",
            0x0403 => "CSPRNG_FAILURE",
            _ => "UNKNOWN",
        }
    }

    /// 类别高字节（0x01/0x02/0x03/0x04）。
    #[must_use]
    pub const fn category(self) -> u8 {
        (self.0 >> 8) as u8
    }

    /// 是否为本 codec 解码可产生的拒绝码（§3.2/§3.3）。
    #[must_use]
    pub const fn is_codec_reject(self) -> bool {
        matches!(self.0, 0x0301..=0x0308)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(0x{:04X})", self.name(), self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_values_match_wp01() {
        // WP-01 §5.2 注册表逐码核对（防常量手滑）。
        assert_eq!(ErrorCode::BOOK_MISMATCH.0, 0x0100);
        assert_eq!(ErrorCode::EXHAUSTED.0, 0x0101);
        assert_eq!(ErrorCode::CLIENT_AHEAD.0, 0x0102);
        assert_eq!(ErrorCode::SERVER_AHEAD.0, 0x0103);
        assert_eq!(ErrorCode::AUTH_FAILED.0, 0x0200);
        assert_eq!(ErrorCode::TAG_INVALID.0, 0x0201);
        assert_eq!(ErrorCode::SEGMENT_BINDING.0, 0x0202);
        assert_eq!(ErrorCode::NONCE_MISMATCH.0, 0x0203);
        assert_eq!(ErrorCode::SEQ_REPLAY.0, 0x0204);
        assert_eq!(ErrorCode::PROTOCOL_VIOLATION.0, 0x0300);
        assert_eq!(ErrorCode::BAD_VERSION.0, 0x0301);
        assert_eq!(ErrorCode::BAD_LENGTH.0, 0x0302);
        assert_eq!(ErrorCode::TRAILING_BYTES.0, 0x0303);
        assert_eq!(ErrorCode::BAD_ENUM.0, 0x0304);
        assert_eq!(ErrorCode::UNKNOWN_MSG_TYPE.0, 0x0305);
        assert_eq!(ErrorCode::WRONG_DIRECTION.0, 0x0306);
        assert_eq!(ErrorCode::ISSUE_POINTER_MISMATCH.0, 0x0307);
        assert_eq!(ErrorCode::FRAME_TRUNCATED.0, 0x0308);
        assert_eq!(ErrorCode::BAD_ORDER.0, 0x0309);
        assert_eq!(ErrorCode::EPOCH_MISMATCH.0, 0x030A);
        assert_eq!(ErrorCode::SEQ_UNEXPECTED.0, 0x030B);
        assert_eq!(ErrorCode::INTERNAL.0, 0x0400);
        assert_eq!(ErrorCode::IO_ERROR.0, 0x0401);
        assert_eq!(ErrorCode::PERSISTENCE_UNVERIFIED.0, 0x0402);
        assert_eq!(ErrorCode::CSPRNG_FAILURE.0, 0x0403);
    }

    #[test]
    fn category_and_codec_reject_classification() {
        assert_eq!(ErrorCode::BAD_VERSION.category(), 0x03);
        assert_eq!(ErrorCode::BOOK_MISMATCH.category(), 0x01);
        assert!(ErrorCode::BAD_LENGTH.is_codec_reject());
        assert!(ErrorCode::WRONG_DIRECTION.is_codec_reject());
        assert!(!ErrorCode::BAD_ORDER.is_codec_reject()); // state 层
        assert!(!ErrorCode::TAG_INVALID.is_codec_reject()); // record 层
    }

    #[test]
    fn display_prints_no_payload() {
        let s = format!("{}", ErrorCode::BAD_LENGTH);
        assert_eq!(s, "BAD_LENGTH(0x0302)");
    }
}
