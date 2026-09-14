//! 错误分类（设计书 §6：本地审计白名单专用；线上统一表现为关闭，
//! 不回传可区分 oracle）。

/// OTP_DATA 线格式结构错误（审计类别 `OTP_FORMAT`）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireError {
    TooShort,
    TooLong,
    Version,
    MsgType,
    Mode,
    Direction,
    CiphertextLen,
    LengthMismatch,
    OffsetBounds,
}

/// PAD_* 控制面 payload 结构错误。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ControlError {
    TooShort,
    TooLong,
    UnknownCode,
    LengthMismatch,
}

/// 数据面/数据泵错误。任何变体出现 ⇒ 会话关闭、当前+预取 bundle 尾部
/// 全部浪费（设计书 §3.2/§9.2）；错误类别仅供本地审计。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OtpError {
    /// 线格式结构错误（`OTP_FORMAT`）。
    Wire(WireError),
    /// 记录方向与本端接收流不符（跨方向搬运，`OTP_DIRECTION`）。
    Direction,
    /// bundle_id/base_segment 与本端状态不符（跨 bundle/连接搬运，
    /// `OTP_BUNDLE`）。
    Bundle,
    /// `record_seq < expected`（原样重放，`OTP_REPLAY`）。
    Replay,
    /// `record_seq > expected`（插入/删除/乱序，`OTP_GAP`）。
    Gap,
    /// `pad_offset != cursor`（`OTP_OFFSET`）。
    Offset,
    /// 一次性 Poly1305 tag 验证失败（`OTP_TAG_INVALID`）。
    Tag,
    /// 会话已关闭（正常关闭或此前失败已浪费全部材料）。
    Closed,
    /// 记录不跨 bundle：明文放不进当前 bundle 剩余空间且不可缩短
    /// （内部误用；公开 API 只会在可容纳时调用）。
    DoesNotFit,
}

impl OtpError {
    /// 审计类别（设计书 §6 错误类别表；白名单内字符串）。
    #[must_use]
    pub const fn audit_category(self) -> &'static str {
        match self {
            Self::Wire(_) => "OTP_FORMAT",
            Self::Direction => "OTP_DIRECTION",
            Self::Bundle => "OTP_BUNDLE",
            Self::Replay => "OTP_REPLAY",
            Self::Gap => "OTP_GAP",
            Self::Offset => "OTP_OFFSET",
            Self::Tag => "OTP_TAG_INVALID",
            Self::Closed => "OTP_CLOSED",
            Self::DoesNotFit => "OTP_INTERNAL",
        }
    }
}

impl From<WireError> for OtpError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}

/// 发送侧错误（非关闭类：不浪费材料）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SendError {
    /// 会话已关闭。
    Closed,
    /// 空明文（记录密文长度下限为 1，§3.1）。
    EmptyPlaintext,
    /// record_seq 空间耗尽（2^64−1 之后；§3.1 严格 +1 不可回绕）。
    SequenceExhausted,
    /// 内部不变量破坏（fail closed）。
    Internal,
}

/// 数据泵处理控制面消息的错误（已 fail closed：材料全浪费、会话关闭）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PumpError {
    /// 数据面/协议状态机违规。
    Data(OtpError),
    /// 材料来源（reserve_range 路径）失败。
    Source(PadSourceError),
}

/// pad 材料来源（allocator `reserve_range`）失败分类。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PadSourceError {
    /// 客户端本地安全指针与公告范围不符（采纳失败 ⇒ fail closed）。
    PointerMismatch { local: u64, announced: u64 },
    /// 预留失败：密码本耗尽 / 持久化不确定 / I/O（细节由实现方审计）。
    Reserve(&'static str),
}
