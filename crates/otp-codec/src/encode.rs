//! canonical 编码（WP-01 §3.1）。
//!
//! 对给定字段值有且仅有一种编码：字段按 §4 表顺序、大端、无填充/对齐/
//! 归一化；定长消息 payload_len 恒为注册表常量。与 [`crate::decode`]
//! 互为逆函数（`encode(decode(x)) == x`，§3.1 规则 5）。
//!
//! `encode*` 是全函数：对任何输入要么产出 canonical 字节，要么返回
//! [`ErrorCode`]（非 canonical 构造，如 BOOK_MISMATCH 时 sp≠0、data 长度
//! 越界），绝不 panic、不部分写入语义歧义（`encode_into` 失败时 `out`
//! 可能含前缀字节，调用方按错误丢弃整个缓冲即可）。

use crate::error::ErrorCode;
use crate::message::{
    ArbitrateResult, CONFIRM_BODY_LEN, CONFIRM_LABEL_LEN, ConfirmBody, FRAME_HEADER_LEN,
    MAX_DATA_FIELD, MIN_DATA_FIELD, Message, SEALED_LEN,
};

/// 编码一条消息为完整帧（帧头 8B + payload）。
pub fn encode(msg: &Message) -> Result<Vec<u8>, ErrorCode> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload_len_of(msg));
    encode_into(msg, &mut out)?;
    Ok(out)
}

/// 追加编码到 `out`（供 transport 复用缓冲）。
///
/// 先校验后写入：返回 `Err` 时 `out` 保证未被追加任何字节。
pub fn encode_into(msg: &Message, out: &mut Vec<u8>) -> Result<(), ErrorCode> {
    // 非 canonical 构造在写任何字节前拒绝（§4.2 组合 / §4.5 长度）。
    match msg {
        Message::Arbitrate {
            server_pointer,
            result,
            ..
        } => {
            if *result == ArbitrateResult::BookMismatch && server_pointer.get() != 0 {
                return Err(ErrorCode::BAD_ENUM);
            }
        }
        Message::Data { data, .. } if !(MIN_DATA_FIELD..=MAX_DATA_FIELD).contains(&data.len()) => {
            return Err(ErrorCode::BAD_LENGTH);
        }
        _ => {}
    }
    let ty = msg.msg_type();
    out.extend_from_slice(&crate::VERSION.to_be_bytes());
    out.extend_from_slice(&ty.wire().to_be_bytes());
    out.extend_from_slice(&(payload_len_of(msg) as u32).to_be_bytes());
    match msg {
        Message::Hello {
            book_id,
            client_nonce,
            client_pointer,
            features,
        } => {
            out.extend_from_slice(book_id.as_bytes());
            out.extend_from_slice(client_nonce.as_bytes());
            out.extend_from_slice(&client_pointer.get().to_be_bytes());
            out.extend_from_slice(&features.0.to_be_bytes());
        }
        Message::Arbitrate {
            server_nonce,
            server_pointer,
            result,
        } => {
            out.extend_from_slice(server_nonce.as_bytes());
            out.extend_from_slice(&server_pointer.get().to_be_bytes());
            out.push(result.wire());
        }
        Message::IssueRequest {
            chosen_pointer,
            client_nonce,
            server_nonce,
        } => {
            out.extend_from_slice(&chosen_pointer.get().to_be_bytes());
            out.extend_from_slice(client_nonce.as_bytes());
            out.extend_from_slice(server_nonce.as_bytes());
        }
        Message::ConfirmC2s {
            segment_index,
            session_nonce,
            epoch,
            seq,
            sealed,
        }
        | Message::ConfirmS2c {
            segment_index,
            session_nonce,
            epoch,
            seq,
            sealed,
        } => {
            out.extend_from_slice(&segment_index.get().to_be_bytes());
            out.extend_from_slice(session_nonce.as_bytes());
            out.extend_from_slice(&epoch.get().to_be_bytes());
            out.extend_from_slice(&seq.get().to_be_bytes());
            out.extend_from_slice(sealed);
        }
        Message::Data { epoch, seq, data } => {
            out.extend_from_slice(&epoch.get().to_be_bytes());
            out.extend_from_slice(&seq.get().to_be_bytes());
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(data);
        }
    }
    Ok(())
}

/// 编码内层确认明文 body（恰好 87B）。
///
/// `msg_type` 原样写入（含未分配值——body 的 msg_type 副本对 codec 不
/// 透明，一致性归 state 层）；`direction` 只接受合法两值。
pub fn encode_confirm_body(body: &ConfirmBody) -> Result<Vec<u8>, ErrorCode> {
    let mut out = Vec::with_capacity(CONFIRM_BODY_LEN);
    out.extend_from_slice(&crate::VERSION.to_be_bytes());
    out.extend_from_slice(body.book_id.as_bytes());
    out.extend_from_slice(&body.segment_index.get().to_be_bytes());
    out.extend_from_slice(body.client_nonce.as_bytes());
    out.extend_from_slice(body.server_nonce.as_bytes());
    out.push(crate::message::body_direction_wire(body.direction));
    out.extend_from_slice(&body.epoch.get().to_be_bytes());
    out.extend_from_slice(&body.seq.get().to_be_bytes());
    out.extend_from_slice(&body.msg_type.to_be_bytes());
    out.extend_from_slice(&body.label);
    debug_assert_eq!(out.len(), CONFIRM_BODY_LEN);
    Ok(out)
}

/// 预测 payload 长度（容量预估 / 帧头写入；仅在通过 encode_into 前置
/// 校验后使用，此时值恒在注册表区间内）。
fn payload_len_of(msg: &Message) -> usize {
    match msg {
        // §4.5：payload = 定长头 16B（epoch 4 + seq 8 + data_len 4） + data。
        Message::Data { data, .. } => 16 + data.len(),
        _ => msg.msg_type().payload_len_range().0,
    }
}

// 编译期布局自洽：87 = 2+16+8+16+16+1+4+8+2+14。
const _: () = assert!(CONFIRM_BODY_LEN == 2 + 16 + 8 + 16 + 16 + 1 + 4 + 8 + 2 + CONFIRM_LABEL_LEN);
const _: () = assert!(SEALED_LEN == 87 + 16);
