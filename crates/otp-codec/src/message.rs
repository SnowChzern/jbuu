//! 消息数据模型（WP-01 §2/§4 逐字节布局的 Rust 投影）。
//!
//! 位置式编码（§3.1）：字段按 §4 各表顺序排列，无标签、无可选字段、无
//! 变体分支，从结构上排除“未知字段”歧义；对给定字段值有且仅有一种编码。

use core::fmt;
use otp_types::{BookId, Direction, Epoch, SegmentIndex, Sequence};

// ---- 帧与长度常量（WP-01 §1.3 / §2.2，全部为编译期冻结值）----

/// 帧头长度：version(2) + msg_type(2) + payload_len(4)。
pub const FRAME_HEADER_LEN: usize = 8;
/// 单条 DATA 的应用明文上限。
pub const MAX_APP_PLAINTEXT: usize = 65536;
/// DATA.data 字段上限（明文 65536 + tag 16）。
pub const MAX_DATA_FIELD: usize = 65552;
/// DATA.data 字段下限（空记录仅含 tag）。
pub const MIN_DATA_FIELD: usize = 16;
/// payload 上限（DATA：16 + 65552）。
pub const MAX_FRAME_PAYLOAD: usize = 65568;
/// DATA payload 下限（16 定长头 + 16 最小 data）。
pub const MIN_FRAME_PAYLOAD: usize = 32;
/// 全协议最大帧长（8 + 65568）。
pub const MAX_FRAME: usize = 65576;
/// HELLO payload 恰长。
pub const HELLO_PAYLOAD_LEN: usize = 44;
/// ARBITRATE payload 恰长。
pub const ARBITRATE_PAYLOAD_LEN: usize = 25;
/// ISSUE_REQUEST payload 恰长。
pub const ISSUE_PAYLOAD_LEN: usize = 40;
/// CONFIRM payload 恰长（8+16+4+8+103）。
pub const CONFIRM_PAYLOAD_LEN: usize = 139;
/// CONFIRM.sealed 恒长（密文 87 + tag 16，决策 D6：无长度字段）。
pub const SEALED_LEN: usize = 103;
/// 内层确认明文 body 恰长。
pub const CONFIRM_BODY_LEN: usize = 87;
/// 内层 label 恒长（"client-confirm"/"server-confirm"）。
pub const CONFIRM_LABEL_LEN: usize = 14;

// 编译期自洽：常量必须与 §1.3/§4 逐项一致。
const _: () = assert!(MAX_FRAME == FRAME_HEADER_LEN + MAX_FRAME_PAYLOAD);
const _: () = assert!(MAX_FRAME_PAYLOAD == 16 + MAX_DATA_FIELD);
const _: () = assert!(MAX_DATA_FIELD == MAX_APP_PLAINTEXT + otp_types::TAG_LEN);
const _: () = assert!(CONFIRM_PAYLOAD_LEN == 8 + 16 + 4 + 8 + SEALED_LEN);
const _: () = assert!(MIN_FRAME_PAYLOAD == 16 + MIN_DATA_FIELD);

/// 协议版本（决策 D1：置于公共帧头，全部消息自描述版本）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProtocolVersion(pub u16);

impl ProtocolVersion {
    /// 本规格唯一合法版本 0x0002。
    pub const V2: Self = Self(crate::VERSION);
}

/// HELLO features 位图（u32；WP-01 §4.1/D4：未知位必须忽略，codec 不拒绝）。
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct FeatureFlags(pub u32);

impl FeatureFlags {
    /// bit0：RECONNECT（恢复流程预留，WP-16）。
    pub const RECONNECT: Self = Self(0x0000_0001);

    /// 是否置位 RECONNECT。
    #[must_use]
    pub const fn has_reconnect(self) -> bool {
        self.0 & Self::RECONNECT.0 != 0
    }
}

/// 消息类型注册表（WP-01 §2.2）。0x0007..0xFFFF 未分配，收到即 0x0305。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MsgType {
    /// 0x0001，C→S。
    Hello,
    /// 0x0002，S→C。
    Arbitrate,
    /// 0x0003，C→S。
    IssueRequest,
    /// 0x0004，C→S。
    ConfirmC2s,
    /// 0x0005，S→C。
    ConfirmS2c,
    /// 0x0006，双向。
    Data,
}

impl MsgType {
    /// 线上 u16 值。
    #[must_use]
    pub const fn wire(self) -> u16 {
        match self {
            Self::Hello => 0x0001,
            Self::Arbitrate => 0x0002,
            Self::IssueRequest => 0x0003,
            Self::ConfirmC2s => 0x0004,
            Self::ConfirmS2c => 0x0005,
            Self::Data => 0x0006,
        }
    }

    /// 从线上值解析；未分配类型返回 `None`（→ 0x0305）。
    #[must_use]
    pub const fn from_wire(v: u16) -> Option<Self> {
        match v {
            0x0001 => Some(Self::Hello),
            0x0002 => Some(Self::Arbitrate),
            0x0003 => Some(Self::IssueRequest),
            0x0004 => Some(Self::ConfirmC2s),
            0x0005 => Some(Self::ConfirmS2c),
            0x0006 => Some(Self::Data),
            _ => None,
        }
    }

    /// 发送方向；DATA 双向返回 `None`。
    #[must_use]
    pub const fn send_direction(self) -> Option<Direction> {
        match self {
            Self::Hello | Self::IssueRequest | Self::ConfirmC2s => Some(Direction::ClientToServer),
            Self::Arbitrate | Self::ConfirmS2c => Some(Direction::ServerToClient),
            Self::Data => None,
        }
    }

    /// 合法 payload_len 闭区间（定长消息两端相等）。
    #[must_use]
    pub const fn payload_len_range(self) -> (usize, usize) {
        match self {
            Self::Hello => (HELLO_PAYLOAD_LEN, HELLO_PAYLOAD_LEN),
            Self::Arbitrate => (ARBITRATE_PAYLOAD_LEN, ARBITRATE_PAYLOAD_LEN),
            Self::IssueRequest => (ISSUE_PAYLOAD_LEN, ISSUE_PAYLOAD_LEN),
            Self::ConfirmC2s | Self::ConfirmS2c => (CONFIRM_PAYLOAD_LEN, CONFIRM_PAYLOAD_LEN),
            Self::Data => (MIN_FRAME_PAYLOAD, MAX_FRAME_PAYLOAD),
        }
    }
}

/// ARBITRATE.result（u8，线上可见；WP-01 §4.2）。
/// 仅仲裁结局四值 + OK；`server_pointer` 是独立字段，规范组合校验见
/// [`crate::decode`]（BOOK_MISMATCH 时 sp 恒 0）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ArbitrateResult {
    /// 0x00：双方指针一致，客户端发 ISSUE_REQUEST(i)。
    Ok,
    /// 0x01：服务端领先，客户端跳到 i、废弃间隙、只前进。
    ServerAhead,
    /// 0x02：段耗尽，终止换本。
    Exhausted,
    /// 0x03：book_id 不符（server_pointer 恒 0）。
    BookMismatch,
    /// 0x04：客户端领先，服务端绝不回退，进入恢复/人工路径。
    ClientAhead,
}

impl ArbitrateResult {
    /// 线上 u8 值。
    #[must_use]
    pub const fn wire(self) -> u8 {
        match self {
            Self::Ok => 0x00,
            Self::ServerAhead => 0x01,
            Self::Exhausted => 0x02,
            Self::BookMismatch => 0x03,
            Self::ClientAhead => 0x04,
        }
    }

    /// 从线上值解析；∉{0..4} 返回 `None`（→ 0x0304）。
    #[must_use]
    pub const fn from_wire(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Ok),
            0x01 => Some(Self::ServerAhead),
            0x02 => Some(Self::Exhausted),
            0x03 => Some(Self::BookMismatch),
            0x04 => Some(Self::ClientAhead),
            _ => None,
        }
    }
}

/// 协议消息。字段全部为非秘密元数据或**不透明密文**（设计书 §4）。
///
/// `version` 不入结构体：决策 D1 冻结于帧头常量 [`crate::VERSION`]，
/// codec 层拒绝一切 ≠0x0002（0x0301）。
#[derive(Clone, PartialEq, Eq)]
pub enum Message {
    /// 0x0001，C→S，帧 52B（§4.1）。
    Hello {
        /// 任意 16B；与本端配置不符由 state 层判 0x0100。
        book_id: BookId,
        /// 客户端 nonce（CSPRNG 生成，非秘密）。
        client_nonce: otp_types::ClientNonce,
        /// 客户端本地指针（任意 u64）。
        client_pointer: SegmentIndex,
        /// 特性位图（任意 u32；未知位忽略，D4）。
        features: FeatureFlags,
    },
    /// 0x0002，S→C，帧 33B（§4.2）。
    Arbitrate {
        /// 服务端 nonce（逐连接唯一，ISSUE_REQUEST 必须回显，D2）。
        server_nonce: otp_types::ServerNonce,
        /// 语义随 result（§4.2 组合表）；codec 仅强制 BOOK_MISMATCH 时为 0。
        server_pointer: SegmentIndex,
        /// 仲裁结果。
        result: ArbitrateResult,
    },
    /// 0x0003，C→S，帧 48B（§4.3）。
    IssueRequest {
        /// 客户端选定指针（≠ 仲裁约定 i 由 state 层判 0x0307）。
        chosen_pointer: SegmentIndex,
        /// 必须回显 HELLO.client_nonce（state 层 0x0203）。
        client_nonce: otp_types::ClientNonce,
        /// 必须回显 ARBITRATE.server_nonce（state 层 0x0203）。
        server_nonce: otp_types::ServerNonce,
    },
    /// 0x0004，C→S，帧 147B（§4.4）。sealed 不透明：密文 87B ‖ tag 16B。
    ConfirmC2s {
        /// 已签发段号。
        segment_index: SegmentIndex,
        /// = client_nonce ⊕ server_nonce（D3；不符由 state 层判 0x0203）。
        session_nonce: otp_types::SessionNonce,
        /// 任意 u32（≠0 由 state 层判 0x030A）。
        epoch: Epoch,
        /// 任意 u64（≠0 由 state 层判 0x030B）。
        seq: Sequence,
        /// BYTES(103)：AEAD 密文+tag，本层不解读（开封归 WP-10）。
        sealed: [u8; SEALED_LEN],
    },
    /// 0x0005，S→C，帧 147B（§4.4）。
    ConfirmS2c {
        /// 已签发段号。
        segment_index: SegmentIndex,
        /// = client_nonce ⊕ server_nonce（D3）。
        session_nonce: otp_types::SessionNonce,
        /// 任意 u32。
        epoch: Epoch,
        /// 任意 u64。
        seq: Sequence,
        /// BYTES(103)：AEAD 密文+tag，本层不解读。
        sealed: [u8; SEALED_LEN],
    },
    /// 0x0006，双向，帧 40..=65576B（§4.5）。
    Data {
        /// 任意 u32（≠0 由 state 层判 0x030A）。
        epoch: Epoch,
        /// 任意 u64（期望值/重放/乱序判定归 record 层）。
        seq: Sequence,
        /// 密文(len-16) ‖ tag(16)，长度 ∈ [16, 65552]；本层不解读。
        data: Vec<u8>,
    },
}

impl Message {
    /// 消息类型。
    #[must_use]
    pub const fn msg_type(&self) -> MsgType {
        match self {
            Self::Hello { .. } => MsgType::Hello,
            Self::Arbitrate { .. } => MsgType::Arbitrate,
            Self::IssueRequest { .. } => MsgType::IssueRequest,
            Self::ConfirmC2s { .. } => MsgType::ConfirmC2s,
            Self::ConfirmS2c { .. } => MsgType::ConfirmS2c,
            Self::Data { .. } => MsgType::Data,
        }
    }

    /// 发送方向（DATA 双向 → `None`）。
    #[must_use]
    pub const fn direction(&self) -> Option<Direction> {
        self.msg_type().send_direction()
    }
}

// 审计安全（§5.3 / 规划 §2）：Debug 绝不打印 sealed/data（密文与 tag 同属
// 禁止记录面），只打印长度；其余为公开元数据。
impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hello {
                book_id,
                client_nonce,
                client_pointer,
                features,
            } => write!(
                f,
                "Hello{{book_id: {book_id:?}, client_nonce: {client_nonce:?}, client_pointer: {client_pointer:?}, features: {features:?}}}"
            ),
            Self::Arbitrate {
                server_nonce,
                server_pointer,
                result,
            } => write!(
                f,
                "Arbitrate{{server_nonce: {server_nonce:?}, server_pointer: {server_pointer:?}, result: {result:?}}}"
            ),
            Self::IssueRequest {
                chosen_pointer,
                client_nonce,
                server_nonce,
            } => write!(
                f,
                "IssueRequest{{chosen_pointer: {chosen_pointer:?}, client_nonce: {client_nonce:?}, server_nonce: {server_nonce:?}}}"
            ),
            Self::ConfirmC2s {
                segment_index,
                session_nonce,
                epoch,
                seq,
                ..
            } => write!(
                f,
                "ConfirmC2s{{segment_index: {segment_index:?}, session_nonce: {session_nonce:?}, epoch: {epoch:?}, seq: {seq:?}, sealed: [103B redacted]}}"
            ),
            Self::ConfirmS2c {
                segment_index,
                session_nonce,
                epoch,
                seq,
                ..
            } => write!(
                f,
                "ConfirmS2c{{segment_index: {segment_index:?}, session_nonce: {session_nonce:?}, epoch: {epoch:?}, seq: {seq:?}, sealed: [103B redacted]}}"
            ),
            Self::Data { epoch, seq, data } => write!(
                f,
                "Data{{epoch: {epoch:?}, seq: {seq:?}, data: [{}B redacted]}}",
                data.len()
            ),
        }
    }
}

/// 内层确认明文 body（sealed 解密后恰好 87B；WP-01 §4.4）。
///
/// codec 层只强制：长度 87、version=0x0002、direction∈{0x01,0x02}；
/// book_id/segment_index/nonce 回显/epoch/seq/msg_type/label 的一致性
/// 均为 [state] 约束（0x0202/0x0203/0x030A/0x030B），本层不透明保存。
#[derive(Clone, PartialEq, Eq)]
pub struct ConfirmBody {
    /// 任意 16B（≠ 会话 book_id 由 state 层判 0x0202）。
    pub book_id: BookId,
    /// ≠ 外层 i 由 state 层判 0x0202。
    pub segment_index: SegmentIndex,
    /// ≠ HELLO 值由 state 层判 0x0203。
    pub client_nonce: otp_types::ClientNonce,
    /// ≠ ARBITRATE 值由 state 层判 0x0203。
    pub server_nonce: otp_types::ServerNonce,
    /// ∈{0x01=C2S, 0x02=S2C}（codec 强制，违反 0x0304）；与消息方向
    /// 的一致性归 state 层（0x0202）。
    pub direction: Direction,
    /// 任意 u32。
    pub epoch: Epoch,
    /// 任意 u64。
    pub seq: Sequence,
    /// 外层消息类型副本（0x0004/0x0005）；保留原始 u16，≠ 外层由
    /// state 层判 0x0202，codec 不因未分配值拒绝。
    pub msg_type: u16,
    /// BYTES(14)：C2S "client-confirm" / S2C "server-confirm"；逐字节
    /// 比较归 state 层（0x0202），本层不透明。
    pub label: [u8; CONFIRM_LABEL_LEN],
}

impl fmt::Debug for ConfirmBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 确认明文整 body 均为禁止日志面（§5.3），只打印结构摘要。
        write!(
            f,
            "ConfirmBody{{direction: {:?}, segment_index: {:?}, epoch: {:?}, seq: {:?}, msg_type: 0x{:04X}, ..redacted}}",
            self.direction, self.segment_index, self.epoch, self.seq, self.msg_type
        )
    }
}

/// body 的 direction 线上值。
#[must_use]
pub const fn body_direction_wire(d: Direction) -> u8 {
    match d {
        Direction::ClientToServer => 0x01,
        Direction::ServerToClient => 0x02,
    }
}

/// 解析 body 的 direction 线上值（∉{1,2} → `None`，调用方判 0x0304）。
#[must_use]
pub const fn body_direction_from_wire(v: u8) -> Option<Direction> {
    match v {
        0x01 => Some(Direction::ClientToServer),
        0x02 => Some(Direction::ServerToClient),
        _ => None,
    }
}

/// 长度字段上界防卫（§7.2：不得因攻击者控制的长度产生越界/巨量分配；
/// DATA 范围 [32, 65568]，定长类型精确匹配）。
pub(super) const fn plen_ok(t: MsgType, plen: u32) -> bool {
    let (min, max) = t.payload_len_range();
    (plen as usize) >= min && (plen as usize) <= max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_type_registry_roundtrip() {
        for t in [
            MsgType::Hello,
            MsgType::Arbitrate,
            MsgType::IssueRequest,
            MsgType::ConfirmC2s,
            MsgType::ConfirmS2c,
            MsgType::Data,
        ] {
            assert_eq!(MsgType::from_wire(t.wire()), Some(t));
        }
        for bad in [0x0000u16, 0x0007, 0x00FF, 0xFFFF] {
            assert_eq!(MsgType::from_wire(bad), None);
        }
    }

    #[test]
    fn payload_ranges_match_registry() {
        assert_eq!(MsgType::Hello.payload_len_range(), (44, 44));
        assert_eq!(MsgType::Arbitrate.payload_len_range(), (25, 25));
        assert_eq!(MsgType::IssueRequest.payload_len_range(), (40, 40));
        assert_eq!(MsgType::ConfirmC2s.payload_len_range(), (139, 139));
        assert_eq!(MsgType::ConfirmS2c.payload_len_range(), (139, 139));
        assert_eq!(MsgType::Data.payload_len_range(), (32, 65568));
    }

    #[test]
    fn arbitrate_result_wire_values() {
        assert_eq!(ArbitrateResult::Ok.wire(), 0);
        assert_eq!(ArbitrateResult::ServerAhead.wire(), 1);
        assert_eq!(ArbitrateResult::Exhausted.wire(), 2);
        assert_eq!(ArbitrateResult::BookMismatch.wire(), 3);
        assert_eq!(ArbitrateResult::ClientAhead.wire(), 4);
        assert_eq!(ArbitrateResult::from_wire(5), None);
        assert_eq!(ArbitrateResult::from_wire(0xFF), None);
    }

    #[test]
    fn debug_never_prints_ciphertext() {
        let msg = Message::Data {
            epoch: Epoch::new(0),
            seq: Sequence::new(1),
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let s = format!("{msg:?}");
        assert!(!s.contains("deadbeef") && !s.contains("DE, AD"));
        assert!(s.contains("redacted"));

        let confirm = Message::ConfirmC2s {
            segment_index: SegmentIndex::ZERO,
            session_nonce: otp_types::SessionNonce::from_bytes([0x41; 16]),
            epoch: Epoch::new(0),
            seq: Sequence::ZERO,
            sealed: [0x5A; SEALED_LEN],
        };
        let s = format!("{confirm:?}");
        assert!(!s.contains("5a5a") && !s.contains("[90;"));
        assert!(s.contains("redacted"));
    }
}
