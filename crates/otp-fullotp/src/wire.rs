//! OTP_DATA 线格式：canonical header + XOR 体 + 16B 一次性 Poly1305 tag
//! （设计书 §3.1；逐字节布局见 crate 文档"冻结的线格式值"）。
//!
//! 本模块只做**纯编码/解码与结构界限校验**（fail closed）：不做 MAC、不碰
//! pad、不推进游标。字段语义校验（方向/bundle/seq/offset 与本端状态一致）
//! 归 [`crate::record`] / [`crate::pump`]，与 WP-01 对 otp-codec/state 的分层
//! 同构。

use otp_types::{Direction, TAG_LEN};

use crate::error::WireError;

/// 新协议主版本（设计书 §3.1 建议 0x0003；v2 decoder 拒收一切 ≠0x0002，
/// 旧协议不可能误解析本格式）。
pub const OTP_VERSION: u16 = 0x0003;
/// v3 命名空间内的 OTP_DATA 独立消息类型（最终注册归 WP-01 修订卡）。
pub const MSG_TYPE_OTP_DATA: u16 = 0x0010;
/// 唯一注册的协议模式：一次性 Poly1305 profile（FOD-1：裸 XOR 不注册）。
pub const MODE_FULL_OTP_POLY1305: u8 = 0x01;
/// 方向线上值（与 WP-01 ConfirmBody.direction 同值域）。
pub const DIRECTION_WIRE_C2S: u8 = 0x01;
pub const DIRECTION_WIRE_S2C: u8 = 0x02;
/// canonical header 长度（固定 34B，§3.1 表全字段，无标签、无变体分支）。
pub const HEADER_LEN: usize = 34;
/// 单条记录密文上限（§3.1：1..=4064 且 offset+32+len<=4096）。
pub const MAX_CIPHERTEXT_LEN: usize = 4064;
/// 单条记录密文下限（空记录非法：无内容却消耗 32B key 属浪费面）。
pub const MIN_CIPHERTEXT_LEN: usize = 1;
/// 全协议最大帧长（34 + 4064 + 16）。
pub const MAX_FRAME_LEN: usize = HEADER_LEN + MAX_CIPHERTEXT_LEN + TAG_LEN;
/// 每方向 pad 流长（FOD-2）。
pub const PAD_HALF_WIRE: usize = 4096;

const _: () = assert!(MAX_FRAME_LEN == 4114);

/// 方向 ↔ 线上值。
#[must_use]
pub const fn direction_wire(d: Direction) -> u8 {
    match d {
        Direction::ClientToServer => DIRECTION_WIRE_C2S,
        Direction::ServerToClient => DIRECTION_WIRE_S2C,
    }
}

/// 线上值 → 方向；∉{1,2} 返回 `None`（解码层拒绝，0x0304 语义）。
#[must_use]
pub const fn direction_from_wire(v: u8) -> Option<Direction> {
    match v {
        DIRECTION_WIRE_C2S => Some(Direction::ClientToServer),
        DIRECTION_WIRE_S2C => Some(Direction::ServerToClient),
        _ => None,
    }
}

/// 一条 OTP_DATA 记录（编码前后的公共投影；字段均为公开元数据或不透明密文）。
///
/// `ciphertext`/`tag` 非秘密（设计书 §1.1：长度/方向/序号公开），但 Debug
/// 仍只打印长度，避免审计输出堆积大段密文 hex。
pub struct OtpDataRecord {
    pub direction: Direction,
    pub bundle_id: u64,
    pub base_segment: u64,
    pub record_seq: u64,
    pub pad_offset: u16,
    pub ciphertext: Vec<u8>,
    pub tag: [u8; TAG_LEN],
}

impl OtpDataRecord {
    /// canonical 编码（header ‖ ciphertext ‖ tag）。`out` 追加写入。
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&canonical_header(
            self.direction,
            self.bundle_id,
            self.base_segment,
            self.record_seq,
            self.pad_offset,
            self.ciphertext.len(),
        ));
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
    }

    /// canonical 编码为独立缓冲。
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_LEN + self.ciphertext.len() + TAG_LEN);
        self.encode_into(&mut buf);
        buf
    }
}

impl core::fmt::Debug for OtpDataRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 审计安全：公开元数据照打，密文/tag 只打长度
        write!(
            f,
            "OtpDataRecord{{dir: {:?}, bundle_id: {}, base_segment: {}, record_seq: {}, \
             pad_offset: {}, ciphertext: [{}B], tag: [16B]}}",
            self.direction,
            self.bundle_id,
            self.base_segment,
            self.record_seq,
            self.pad_offset,
            self.ciphertext.len()
        )
    }
}

/// canonical header（§3.1 全字段：version/msg_type/mode/direction/bundle_id/
/// base_segment/record_seq/pad_offset/ciphertext_len，大端定序）。
#[must_use]
pub(crate) fn canonical_header(
    direction: Direction,
    bundle_id: u64,
    base_segment: u64,
    record_seq: u64,
    pad_offset: u16,
    ciphertext_len: usize,
) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..2].copy_from_slice(&OTP_VERSION.to_be_bytes());
    h[2..4].copy_from_slice(&MSG_TYPE_OTP_DATA.to_be_bytes());
    h[4] = MODE_FULL_OTP_POLY1305;
    h[5] = direction_wire(direction);
    h[6..14].copy_from_slice(&bundle_id.to_be_bytes());
    h[14..22].copy_from_slice(&base_segment.to_be_bytes());
    h[22..30].copy_from_slice(&record_seq.to_be_bytes());
    h[30..32].copy_from_slice(&pad_offset.to_be_bytes());
    h[32..34].copy_from_slice(&(ciphertext_len as u16).to_be_bytes());
    h
}

/// 严格解码：结构/界限校验全部通过才返回记录；任何偏差 fail closed
/// （错误类别 `OTP_FORMAT`）。语义校验（方向/bundle/seq/offset/tag）不在本层。
#[must_use = "解码失败必须关闭会话，不得忽略"]
pub fn decode(bytes: &[u8]) -> Result<OtpDataRecord, WireError> {
    if bytes.len() < HEADER_LEN + MIN_CIPHERTEXT_LEN + TAG_LEN {
        return Err(WireError::TooShort);
    }
    if bytes.len() > MAX_FRAME_LEN {
        return Err(WireError::TooLong);
    }
    if u16::from_be_bytes([bytes[0], bytes[1]]) != OTP_VERSION {
        return Err(WireError::Version);
    }
    if u16::from_be_bytes([bytes[2], bytes[3]]) != MSG_TYPE_OTP_DATA {
        return Err(WireError::MsgType);
    }
    if bytes[4] != MODE_FULL_OTP_POLY1305 {
        return Err(WireError::Mode);
    }
    let direction = direction_from_wire(bytes[5]).ok_or(WireError::Direction)?;
    let bundle_id = u64::from_be_bytes(bytes[6..14].try_into().expect("恰 8B"));
    let base_segment = u64::from_be_bytes(bytes[14..22].try_into().expect("恰 8B"));
    let record_seq = u64::from_be_bytes(bytes[22..30].try_into().expect("恰 8B"));
    let pad_offset = u16::from_be_bytes([bytes[30], bytes[31]]);
    let ciphertext_len = u16::from_be_bytes([bytes[32], bytes[33]]) as usize;
    if !(MIN_CIPHERTEXT_LEN..=MAX_CIPHERTEXT_LEN).contains(&ciphertext_len) {
        return Err(WireError::CiphertextLen);
    }
    // 长度界限：无尾随字节、无截断（canonical：一种字段值恰一种编码）
    if bytes.len() != HEADER_LEN + ciphertext_len + TAG_LEN {
        return Err(WireError::LengthMismatch);
    }
    // §3.1 结构约束：offset+32+len <= 4096（记录不跨 bundle 的线格式投影）
    if usize::from(pad_offset) + MAC_KEY_BOUND + ciphertext_len > PAD_HALF_WIRE {
        return Err(WireError::OffsetBounds);
    }
    let ciphertext = bytes[HEADER_LEN..HEADER_LEN + ciphertext_len].to_vec();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&bytes[bytes.len() - TAG_LEN..]);
    Ok(OtpDataRecord {
        direction,
        bundle_id,
        base_segment,
        record_seq,
        pad_offset,
        ciphertext,
        tag,
    })
}

/// MAC key 在方向流中的固定前置宽度（§2.1：每记录 32B key 先于 L B XOR pad）。
pub(crate) const MAC_KEY_BOUND: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> OtpDataRecord {
        OtpDataRecord {
            direction: Direction::ClientToServer,
            bundle_id: 0,
            base_segment: 1,
            record_seq: 0,
            pad_offset: 0,
            ciphertext: vec![0xAB, 0xCD],
            tag: [0x5A; TAG_LEN],
        }
    }

    #[test]
    fn header_layout_is_frozen() {
        let h = canonical_header(Direction::ServerToClient, 7, 128, 9, 33, 100);
        assert_eq!(h[0..2], [0x00, 0x03]);
        assert_eq!(h[2..4], [0x00, 0x10]);
        assert_eq!(h[4], 0x01);
        assert_eq!(h[5], 0x02);
        assert_eq!(h[6..14], 7u64.to_be_bytes());
        assert_eq!(h[14..22], 128u64.to_be_bytes());
        assert_eq!(h[22..30], 9u64.to_be_bytes());
        assert_eq!(h[30..32], 33u16.to_be_bytes());
        assert_eq!(h[32..34], 100u16.to_be_bytes());
        assert_eq!(h.len(), 34);
    }

    #[test]
    fn roundtrip_and_exact_length() {
        let rec = sample();
        let wire = rec.encode();
        assert_eq!(wire.len(), 34 + 2 + 16);
        let back = decode(&wire).unwrap();
        assert!(matches!(back.direction, Direction::ClientToServer));
        assert_eq!(back.bundle_id, 0);
        assert_eq!(back.base_segment, 1);
        assert_eq!(back.record_seq, 0);
        assert_eq!(back.pad_offset, 0);
        assert_eq!(back.ciphertext, vec![0xAB, 0xCD]);
        assert_eq!(back.tag, [0x5A; TAG_LEN]);
    }

    #[test]
    fn rejects_all_structural_violations() {
        let wire = sample().encode();
        // 截断 / 尾随 / 超长
        assert!(matches!(
            decode(&wire[..wire.len() - 1]),
            Err(WireError::TooShort) | Err(WireError::LengthMismatch)
        ));
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(matches!(
            decode(&trailing),
            Err(WireError::LengthMismatch) | Err(WireError::TooLong)
        ));
        assert!(matches!(decode(&[]), Err(WireError::TooShort)));
        // 版本 / 类型 / 模式 / 方向（v2 DATA 伪装、未知 mode、未知方向均拒绝）
        let mut m = wire.clone();
        m[1] = 0x02; // version=0x0002（v2 伪装）
        assert!(matches!(decode(&m), Err(WireError::Version)));
        let mut m = wire.clone();
        m[3] = 0x06; // msg_type=0x0006（v2 DATA 伪装）
        assert!(matches!(decode(&m), Err(WireError::MsgType)));
        let mut m = wire.clone();
        m[4] = 0x02; // 未知 mode
        assert!(matches!(decode(&m), Err(WireError::Mode)));
        let mut m = wire.clone();
        m[5] = 0x03; // 未知方向
        assert!(matches!(decode(&m), Err(WireError::Direction)));
        // 长度字段与实际不符
        let mut m = wire.clone();
        m[33] = 0x03; // ciphertext_len=3 但体只有 2
        assert!(matches!(decode(&m), Err(WireError::LengthMismatch)));
        // offset 界限：offset+32+2 > 4096
        let mut m = wire.clone();
        m[30] = 0x10; // pad_offset = 0x1000 = 4096
        m[31] = 0x00;
        assert!(matches!(decode(&m), Err(WireError::OffsetBounds)));
    }

    #[test]
    fn boundary_lengths_accepted() {
        // L=4064 恰满新 bundle；L=1 最小记录
        for (l, offset) in [(4064usize, 0u16), (1, 0), (1, 4063)] {
            let rec = OtpDataRecord {
                direction: Direction::ClientToServer,
                bundle_id: 0,
                base_segment: 0,
                record_seq: 0,
                pad_offset: offset,
                ciphertext: vec![0u8; l],
                tag: [0u8; TAG_LEN],
            };
            assert!(decode(&rec.encode()).is_ok(), "l={l} offset={offset}");
        }
        // L=4065 越界（头部先用 canonical 构造，避免版本字节先拒；体长控制在
        // MAX_FRAME_LEN 内以精准命中 CiphertextLen 判定）
        let mut bad = canonical_header(Direction::ClientToServer, 0, 0, 0, 0, 4065).to_vec();
        bad.extend_from_slice(&[0u8; MAX_CIPHERTEXT_LEN + TAG_LEN]);
        assert!(matches!(decode(&bad), Err(WireError::CiphertextLen)));
    }
}
