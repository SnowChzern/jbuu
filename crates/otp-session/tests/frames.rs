//! 整帧向量回放（WP-03 §6.5 FRAME-* / §6.6 REC-NEG-*）。
//!
//! 帧字段按 WP-01 §4.4/§4.5 冻结偏移解析（帧级编解码归 otp-codec，
//! record 层只消费已解码字段）；向量 hex 逐字节抄自规格表。

mod common;

use common::*;
use otp_session::{MessageType, SessionError};
use otp_types::{Direction, Role, Sequence};

const FRAME_CONFIRM_C2S_K1: &str = "000200040000008b0000000000000000303030303030303030303030303030300000000000000000000000002d7bec766d3da3393e54bfc4078c3d32a21276d0268aba2d30632259fce04e58b7b6e5c5610b9a031cb80dac6dedcb4fd9f2dbd37cd07850bb9569d9d0b6de562309b98e7f513cb5c32536a5254accf5e462debf9c4457d96242d7396bc0fb4e2f81cd33ab7fbd";
const FRAME_DATA_K1: &str = "0002000600000030000000000000000000000001000000206ce1e72949eab99255ba29ecb16e446a1142284a43daab7fda7babf52389bafb";
// REC-NEG-1：tag 末字节 bd→bc
const REC_NEG_1: &str = "000200040000008b0000000000000000303030303030303030303030303030300000000000000000000000002d7bec766d3da3393e54bfc4078c3d32a21276d0268aba2d30632259fce04e58b7b6e5c5610b9a031cb80dac6dedcb4fd9f2dbd37cd07850bb9569d9d0b6de562309b98e7f513cb5c32536a5254accf5e462debf9c4457d96242d7396bc0fb4e2f81cd33ab7fbc";
// REC-NEG-2：DATA 帧 seq=2（期待 1）
const REC_NEG_2: &str = "0002000600000030000000000000000000000002000000206ce1e72949eab99255ba29ecb16e446a1142284a43daab7fda7babf52389bafb";
// REC-NEG-4：K-V1 密文装进 DATA 帧（data_len=103，跨记录类型搬运）
const REC_NEG_4: &str = "0002000600000077000000000000000000000001000000672d7bec766d3da3393e54bfc4078c3d32a21276d0268aba2d30632259fce04e58b7b6e5c5610b9a031cb80dac6dedcb4fd9f2dbd37cd07850bb9569d9d0b6de562309b98e7f513cb5c32536a5254accf5e462debf9c4457d96242d7396bc0fb4e2f81cd33ab7fbd";

/// 服务端会话，已按 FRAME-CONFIRM-C2S-K1 接受 C2S 确认（seq=0）。
fn server_after_confirm() -> otp_session::Session {
    let mut server = fixture_session(Role::Server);
    let frame = unhex(FRAME_CONFIRM_C2S_K1);
    let f = parse_confirm_frame(&frame);
    server
        .open(MessageType::ClientConfirm, Sequence::new(f.seq), f.sealed)
        .expect("FRAME-CONFIRM-C2S-K1 必过");
    server
}

#[test]
fn frame_confirm_c2s_k1_opens() {
    // §6.5：整帧 CONFIRM 在服务端会话 open 成功，还原 87B 确认明文
    let mut server = fixture_session(Role::Server);
    let frame = unhex(FRAME_CONFIRM_C2S_K1);
    let f = parse_confirm_frame(&frame);
    assert_eq!(f.segment_index, 0);
    assert_eq!(hex(&f.session_nonce), SESSION_NONCE_HEX);
    assert_eq!(f.epoch, 0);
    assert_eq!(f.seq, 0);
    let payload = server
        .open(MessageType::ClientConfirm, Sequence::new(f.seq), f.sealed)
        .expect("整帧向量必过");
    assert_eq!(payload.as_bytes(), confirm_body_pos_001());
    assert_eq!(
        server.last_accepted(Direction::ClientToServer),
        Some(Sequence::ZERO)
    );
}

#[test]
fn frame_data_k1_opens_after_confirm() {
    // §6.5：CONFIRM(0) 之后 DATA(1) 按序 open，还原 "Hello, otp-term!"
    let mut server = server_after_confirm();
    let frame = unhex(FRAME_DATA_K1);
    let f = parse_data_frame(&frame);
    assert_eq!(f.epoch, 0);
    assert_eq!(f.seq, 1);
    assert_eq!(f.data.len(), 32);
    let payload = server
        .open(MessageType::Data, Sequence::new(f.seq), f.data)
        .expect("FRAME-DATA-K1 必过");
    assert_eq!(payload.as_bytes(), DATA_PLAINTEXT);
}

#[test]
fn rec_neg_1_tampered_tag_is_0201_and_closes() {
    // §6.6 REC-NEG-1：codec Ok；[record] 0x0201；立即关闭、不输出明文
    let mut server = fixture_session(Role::Server);
    let frame = unhex(REC_NEG_1);
    let f = parse_confirm_frame(&frame);
    let r = server.open(MessageType::ClientConfirm, Sequence::new(f.seq), f.sealed);
    match r {
        Err(e) => {
            assert_eq!(e, SessionError::AuthenticationFailed);
            assert_eq!(e.wire_code(), Some(0x0201));
        }
        Ok(p) => panic!("篡改 tag 必拒，却得到明文 {}B", p.as_bytes().len()),
    }
    assert!(!server.is_active());
    // 后续一切操作 Closed（会话已死）
    let ok_raw = unhex(FRAME_CONFIRM_C2S_K1);
    let ok_frame = parse_confirm_frame(&ok_raw);
    assert!(matches!(
        server.open(MessageType::ClientConfirm, Sequence::ZERO, ok_frame.sealed),
        Err(SessionError::Closed)
    ));
}

#[test]
fn rec_neg_2_seq_gap_is_030b() {
    // §6.6 REC-NEG-2：已收 CONFIRM(0)、期待 DATA(1)，到达 seq=2 ⇒ 0x030B
    let mut server = server_after_confirm();
    let frame = unhex(REC_NEG_2);
    let f = parse_data_frame(&frame);
    assert_eq!(f.seq, 2, "REC-NEG-2 是跳号帧");
    match server.open(MessageType::Data, Sequence::new(f.seq), f.data) {
        Err(e) => {
            assert_eq!(e, SessionError::SequenceUnexpected);
            assert_eq!(e.wire_code(), Some(0x030B));
        }
        Ok(_) => panic!("跳号必拒"),
    }
    assert!(!server.is_active());
}

#[test]
fn rec_neg_3_replayed_frame_is_0204() {
    // §6.6 REC-NEG-3：FRAME-DATA-K1 原样重放（已收 seq=1）⇒ 0x0204
    let mut server = server_after_confirm();
    let frame = unhex(FRAME_DATA_K1);
    let f = parse_data_frame(&frame);
    server
        .open(MessageType::Data, Sequence::new(f.seq), f.data)
        .expect("首达必过");
    match server.open(MessageType::Data, Sequence::new(f.seq), f.data) {
        Err(e) => {
            assert_eq!(e, SessionError::SequenceReplay);
            assert_eq!(e.wire_code(), Some(0x0204));
        }
        Ok(_) => panic!("重放必拒"),
    }
    assert!(!server.is_active());
}

#[test]
fn rec_neg_4_confirm_ciphertext_in_data_frame_is_0201() {
    // §6.6 REC-NEG-4：K-V1 密文装进 DATA 帧（seq=1）——AAD msg_type 不符 ⇒ 0x0201
    let mut server = server_after_confirm();
    let frame = unhex(REC_NEG_4);
    let f = parse_data_frame(&frame);
    assert_eq!(f.seq, 1);
    assert_eq!(f.data.len(), 103);
    match server.open(MessageType::Data, Sequence::new(f.seq), f.data) {
        Err(e) => {
            assert_eq!(e, SessionError::AuthenticationFailed);
            assert_eq!(e.wire_code(), Some(0x0201));
        }
        Ok(_) => panic!("跨类型搬运必拒"),
    }
    assert!(!server.is_active());
}

#[test]
fn confirm_frame_replay_is_0204() {
    // 行为负例：CONFIRM(seq=0) 整帧重放 ⇒ 精确重复 0x0204
    let mut server = fixture_session(Role::Server);
    let frame = unhex(FRAME_CONFIRM_C2S_K1);
    let f = parse_confirm_frame(&frame);
    server
        .open(MessageType::ClientConfirm, Sequence::new(f.seq), f.sealed)
        .unwrap();
    assert!(matches!(
        server.open(MessageType::ClientConfirm, Sequence::new(f.seq), f.sealed),
        Err(SessionError::SequenceReplay)
    ));
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}
