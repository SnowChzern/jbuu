//! 集成测试共享夹具：WP-03 §6.1 测试向量、hex 工具、帧字段解析
//! （帧布局按 WP-01 §4.4/§4.5；帧级编解码归 otp-codec，此处仅按冻结偏移
//! 切字段，供 record 层直接回放规格整帧向量）。
#![allow(dead_code)]

use otp_session::{CommittedSegment, Session, SessionContext};
use otp_types::{BookId, ClientNonce, Role, SegmentIndex, ServerNonce};

/// hex 解码（仅测试；向量均为夹具值与公开密文，非秘密）。
pub fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex 长度必须为偶数");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("合法 hex"))
        .collect()
}

// ---- WP-03 §6.1 测试夹具（沿 WP-01 §6.1，跨文档可链）----

pub const BOOK_ID_HEX: &str = "00112233445566778899AABBCCDDEEFF";
pub const CLIENT_NONCE_HEX: &str = "101112131415161718191A1B1C1D1E1F";
pub const SERVER_NONCE_HEX: &str = "202122232425262728292A2B2C2D2E2F";
/// session_nonce = C ⊕ S = 16×0x30 ⇒ session_domain = 303030
pub const SESSION_NONCE_HEX: &str = "30303030303030303030303030303030";
pub const DATA_PLAINTEXT: &[u8] = b"Hello, otp-term!";

/// 测试段 0（64B）：00 01 … 3F ⇒ K_c2s=00..1F、K_s2c=20..3F（§3.1 直接拆分）
pub fn fixture_segment() -> CommittedSegment {
    CommittedSegment::from_bytes(core::array::from_fn(|i| i as u8))
}

pub fn fixture_ctx(role: Role) -> SessionContext {
    SessionContext {
        role,
        book_id: BookId::from_bytes(unhex(BOOK_ID_HEX).try_into().unwrap()),
        segment: SegmentIndex::ZERO,
        client_nonce: ClientNonce::from_bytes(unhex(CLIENT_NONCE_HEX).try_into().unwrap()),
        server_nonce: ServerNonce::from_bytes(unhex(SERVER_NONCE_HEX).try_into().unwrap()),
    }
}

pub fn fixture_session(role: Role) -> Session {
    Session::new(fixture_segment(), fixture_ctx(role))
}

/// CONFIRM-BODY-POS-001（WP-01 §6.6 定稿向量 hex，client 方向，87B）。
pub fn confirm_body_pos_001() -> Vec<u8> {
    unhex(
        "000200112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f\
202122232425262728292a2b2c2d2e2f010000000000000000000000000004636c69656e742d636f6e6669726d",
    )
}

/// CONFIRM-BODY-POS-002（WP-01 §6.6 定稿向量 hex，server 方向，87B）。
pub fn confirm_body_pos_002() -> Vec<u8> {
    unhex(
        "000200112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f\
202122232425262728292a2b2c2d2e2f0200000000000000000000000000057365727665722d636f6e6669726d",
    )
}

// ---- 帧字段解析（WP-01 §4.4/§4.5 冻结偏移）----

pub struct ConfirmFrame<'a> {
    pub segment_index: u64,
    pub session_nonce: [u8; 16],
    pub epoch: u32,
    pub seq: u64,
    pub sealed: &'a [u8],
}

/// CONFIRM 帧（147B）：seg@8、session_nonce@16、epoch@32、seq@36、sealed@44（103B）。
pub fn parse_confirm_frame(frame: &[u8]) -> ConfirmFrame<'_> {
    assert_eq!(frame.len(), 147, "CONFIRM 帧恒 147B");
    ConfirmFrame {
        segment_index: u64::from_be_bytes(frame[8..16].try_into().unwrap()),
        session_nonce: frame[16..32].try_into().unwrap(),
        epoch: u32::from_be_bytes(frame[32..36].try_into().unwrap()),
        seq: u64::from_be_bytes(frame[36..44].try_into().unwrap()),
        sealed: &frame[44..147],
    }
}

pub struct DataFrame<'a> {
    pub epoch: u32,
    pub seq: u64,
    pub data: &'a [u8],
}

/// DATA 帧（40+data_len）：epoch@8、seq@12、data_len@20、data@24。
pub fn parse_data_frame(frame: &[u8]) -> DataFrame<'_> {
    assert!(frame.len() >= 24, "DATA 帧下限 40B（data_len>=16）");
    let data_len = u32::from_be_bytes(frame[20..24].try_into().unwrap()) as usize;
    assert_eq!(frame.len(), 24 + data_len, "data_len 与帧长一致");
    DataFrame {
        epoch: u32::from_be_bytes(frame[8..12].try_into().unwrap()),
        seq: u64::from_be_bytes(frame[12..20].try_into().unwrap()),
        data: &frame[24..],
    }
}
