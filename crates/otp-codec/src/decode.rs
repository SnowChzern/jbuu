//! 严格解码（WP-01 §3.2 顺序为规范的一部分）。
//!
//! 同一畸形输入必须总是产生同一错误码；步骤顺序：
//!
//! ```text
//! 1. len < 8                                -> 0x0308 FRAME_TRUNCATED
//! 2. version ≠ 0x0002                       -> 0x0301 BAD_VERSION
//! 3. msg_type ∉ {0x0001..0x0006}            -> 0x0305 UNKNOWN_MSG_TYPE
//! 4. payload_len 越出该类型合法区间          -> 0x0302 BAD_LENGTH
//!    （先于一切缓冲分配/读取，防长度放大）
//! 5. len < 8+payload_len                    -> 0x0308 FRAME_TRUNCATED
//!    len > 8+payload_len                    -> 0x0303 TRAILING_BYTES
//! 6. direction(msg_type) 与接收角色不符      -> 0x0306 WRONG_DIRECTION
//! 7. payload 逐字段解析：不足 -> 0x0302；剩余 -> 0x0303
//! 8. 枚举/组合校验                          -> 0x0304 / 0x0302
//! ```
//!
//! 本层不做任何密码学运算；sealed/data 不透明。全函数无 panic、无 unsafe、
//! 无 I/O。任何拒绝都是 fail-closed（关闭连接、审计、计段费由上层执行）。

use otp_types::{Role, SegmentIndex};

use crate::error::ErrorCode;
use crate::message::{
    ArbitrateResult, CONFIRM_BODY_LEN, CONFIRM_LABEL_LEN, ConfirmBody, FRAME_HEADER_LEN,
    FeatureFlags, MAX_DATA_FIELD, MIN_DATA_FIELD, Message, MsgType, SEALED_LEN, plen_ok,
};

/// 解码一条完整帧。`role` 为**本端（接收方）角色**（§2.3）：C→S 消息须由
/// server 解码，S→C 消息须由 client 解码，DATA 双向均可。
///
/// 消息时序合法性（0x0309）不在本层。
///
/// # Panics
///
/// 不 panic（fuzz 目标 WP-14 的前提）。
pub fn decode(role: Role, buf: &[u8]) -> Result<Message, ErrorCode> {
    // 步 1：帧头不足。
    if buf.len() < FRAME_HEADER_LEN {
        return Err(ErrorCode::FRAME_TRUNCATED);
    }
    // 步 2：版本。
    let version = u16::from_be_bytes([buf[0], buf[1]]);
    if version != crate::VERSION {
        return Err(ErrorCode::BAD_VERSION);
    }
    // 步 3：消息类型（0x0007..0xFFFF 未分配，不允许跳过未知消息）。
    let raw_type = u16::from_be_bytes([buf[2], buf[3]]);
    let Some(msg_type) = MsgType::from_wire(raw_type) else {
        return Err(ErrorCode::UNKNOWN_MSG_TYPE);
    };
    // 步 4：payload_len 先于消息体读取校验（防长度放大；上限 65568）。
    let payload_len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if !plen_ok(msg_type, payload_len) {
        return Err(ErrorCode::BAD_LENGTH);
    }
    let payload_len = payload_len as usize;
    // 步 5：帧界精确（尾随字节一律拒绝）。
    let Some(end) = FRAME_HEADER_LEN.checked_add(payload_len) else {
        return Err(ErrorCode::BAD_LENGTH);
    };
    match buf.len().cmp(&end) {
        core::cmp::Ordering::Less => return Err(ErrorCode::FRAME_TRUNCATED),
        core::cmp::Ordering::Greater => return Err(ErrorCode::TRAILING_BYTES),
        core::cmp::Ordering::Equal => {}
    }
    // 步 6：方向约束。
    match msg_type.send_direction() {
        Some(otp_types::Direction::ClientToServer) if role != Role::Server => {
            return Err(ErrorCode::WRONG_DIRECTION);
        }
        Some(otp_types::Direction::ServerToClient) if role != Role::Client => {
            return Err(ErrorCode::WRONG_DIRECTION);
        }
        _ => {}
    }
    // 步 7/8：payload 解析（`end == buf.len()` 已由步 5 保证）。
    let payload = &buf[FRAME_HEADER_LEN..end];
    match msg_type {
        MsgType::Hello => decode_hello(payload),
        MsgType::Arbitrate => decode_arbitrate(payload),
        MsgType::IssueRequest => decode_issue(payload),
        MsgType::ConfirmC2s => {
            decode_confirm(payload).map(|(seg, sn, ep, sq, sealed)| Message::ConfirmC2s {
                segment_index: seg,
                session_nonce: sn,
                epoch: ep,
                seq: sq,
                sealed,
            })
        }
        MsgType::ConfirmS2c => {
            decode_confirm(payload).map(|(seg, sn, ep, sq, sealed)| Message::ConfirmS2c {
                segment_index: seg,
                session_nonce: sn,
                epoch: ep,
                seq: sq,
                sealed,
            })
        }
        MsgType::Data => decode_data(payload),
    }
}

/// 解码内层确认明文 body（§4.4；恰好 87B）。
///
/// codec 只强制长度/version/direction 枚举；副本一致性归 state 层。
pub fn decode_confirm_body(buf: &[u8]) -> Result<ConfirmBody, ErrorCode> {
    if buf.len() != CONFIRM_BODY_LEN {
        return Err(ErrorCode::BAD_LENGTH);
    }
    let mut c = Cursor::new(buf);
    let version = c.u16()?;
    if version != crate::VERSION {
        return Err(ErrorCode::BAD_VERSION);
    }
    let book_id = otp_types::BookId::from_bytes(c.fixed16()?);
    let segment_index = SegmentIndex::new(c.u64()?);
    let client_nonce = otp_types::ClientNonce::from_bytes(c.fixed16()?);
    let server_nonce = otp_types::ServerNonce::from_bytes(c.fixed16()?);
    let direction = crate::message::body_direction_from_wire(c.u8()?).ok_or(ErrorCode::BAD_ENUM)?;
    let epoch = otp_types::Epoch::new(c.u32()?);
    let seq = otp_types::Sequence::new(c.u64()?);
    let msg_type = c.u16()?;
    let label: [u8; CONFIRM_LABEL_LEN] = c
        .take(CONFIRM_LABEL_LEN)?
        .try_into()
        .map_err(|_| ErrorCode::BAD_LENGTH)?;
    c.done()?;
    Ok(ConfirmBody {
        book_id,
        segment_index,
        client_nonce,
        server_nonce,
        direction,
        epoch,
        seq,
        msg_type,
        label,
    })
}

fn decode_hello(p: &[u8]) -> Result<Message, ErrorCode> {
    let mut c = Cursor::new(p);
    let book_id = otp_types::BookId::from_bytes(c.fixed16()?);
    let client_nonce = otp_types::ClientNonce::from_bytes(c.fixed16()?);
    let client_pointer = SegmentIndex::new(c.u64()?);
    let features = FeatureFlags(c.u32()?);
    c.done()?;
    Ok(Message::Hello {
        book_id,
        client_nonce,
        client_pointer,
        features,
    })
}

fn decode_arbitrate(p: &[u8]) -> Result<Message, ErrorCode> {
    let mut c = Cursor::new(p);
    let server_nonce = otp_types::ServerNonce::from_bytes(c.fixed16()?);
    let server_pointer = SegmentIndex::new(c.u64()?);
    let result = ArbitrateResult::from_wire(c.u8()?).ok_or(ErrorCode::BAD_ENUM)?;
    c.done()?;
    // §4.2 规范组合（codec 强制）：BOOK_MISMATCH 时 server_pointer 恒 0。
    if result == ArbitrateResult::BookMismatch && server_pointer.get() != 0 {
        return Err(ErrorCode::BAD_ENUM);
    }
    Ok(Message::Arbitrate {
        server_nonce,
        server_pointer,
        result,
    })
}

fn decode_issue(p: &[u8]) -> Result<Message, ErrorCode> {
    let mut c = Cursor::new(p);
    let chosen_pointer = SegmentIndex::new(c.u64()?);
    let client_nonce = otp_types::ClientNonce::from_bytes(c.fixed16()?);
    let server_nonce = otp_types::ServerNonce::from_bytes(c.fixed16()?);
    c.done()?;
    Ok(Message::IssueRequest {
        chosen_pointer,
        client_nonce,
        server_nonce,
    })
}

type ConfirmParts = (
    SegmentIndex,
    otp_types::SessionNonce,
    otp_types::Epoch,
    otp_types::Sequence,
    [u8; SEALED_LEN],
);

fn decode_confirm(p: &[u8]) -> Result<ConfirmParts, ErrorCode> {
    let mut c = Cursor::new(p);
    let segment_index = SegmentIndex::new(c.u64()?);
    let session_nonce = otp_types::SessionNonce::from_bytes(c.fixed16()?);
    let epoch = otp_types::Epoch::new(c.u32()?);
    let seq = otp_types::Sequence::new(c.u64()?);
    let sealed: [u8; SEALED_LEN] = c
        .take(SEALED_LEN)?
        .try_into()
        .map_err(|_| ErrorCode::BAD_LENGTH)?;
    c.done()?;
    Ok((segment_index, session_nonce, epoch, seq, sealed))
}

fn decode_data(p: &[u8]) -> Result<Message, ErrorCode> {
    let mut c = Cursor::new(p);
    let epoch = otp_types::Epoch::new(c.u32()?);
    let seq = otp_types::Sequence::new(c.u64()?);
    let data_len = c.u32()? as usize;
    // §4.5 [codec]：data_len ∈ [16, 65552]（16+data_len == payload_len 由
    // 步 7 的精确消费隐式保证）。
    if !(MIN_DATA_FIELD..=MAX_DATA_FIELD).contains(&data_len) {
        return Err(ErrorCode::BAD_LENGTH);
    }
    let data = c.take(data_len)?.to_vec();
    c.done()?;
    Ok(Message::Data { epoch, seq, data })
}

/// 只前进的光标；一切越界都映射为 [`ErrorCode::BAD_LENGTH`]（步 7“字段
/// 所需字节超出剩余 payload”），剩余字节由 [`Cursor::done`] 判 0x0303。
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ErrorCode> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or(ErrorCode::BAD_LENGTH)?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn done(&self) -> Result<(), ErrorCode> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(ErrorCode::TRAILING_BYTES)
        }
    }

    fn u8(&mut self) -> Result<u8, ErrorCode> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ErrorCode> {
        let b: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| ErrorCode::BAD_LENGTH)?;
        Ok(u16::from_be_bytes(b))
    }

    fn u32(&mut self) -> Result<u32, ErrorCode> {
        let b: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| ErrorCode::BAD_LENGTH)?;
        Ok(u32::from_be_bytes(b))
    }

    fn u64(&mut self) -> Result<u64, ErrorCode> {
        let b: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| ErrorCode::BAD_LENGTH)?;
        Ok(u64::from_be_bytes(b))
    }

    fn fixed16(&mut self) -> Result<[u8; 16], ErrorCode> {
        self.take(16)?.try_into().map_err(|_| ErrorCode::BAD_LENGTH)
    }
}
