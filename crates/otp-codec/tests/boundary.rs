//! WP-01 §6.8 边界向量 + §3.2 解码顺序确定性测试。
//!
//! - DATA data_len ∈ {16, 65552} 合法、{15, 65553} 非法；
//! - payload_len ∈ {32, 65568} 合法；
//! - 步骤顺序锁定：同一畸形输入总产生规范规定的同一错误码（步 1→8）；
//! - 防长度放大：payload_len 声明越界在缓冲读取前拒绝。

use otp_codec::{ErrorCode, FeatureFlags, MAX_FRAME, Message, decode, encode};
use otp_types::{
    BookId, ClientNonce, Epoch, Role, SegmentIndex, Sequence, ServerNonce, SessionNonce,
};

fn data_msg(len: usize) -> Message {
    Message::Data {
        epoch: Epoch::new(0),
        seq: Sequence::new(1),
        data: vec![0xA5; len],
    }
}

/// 手工拼 DATA 帧：完全控制 payload_len 声明与 data_len 字段，
/// payload 实际携带 `payload_bytes` 字节。
fn raw_data_frame(payload_len: u32, data_len_field: u32, payload_bytes: usize) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&0x0002u16.to_be_bytes());
    f.extend_from_slice(&0x0006u16.to_be_bytes());
    f.extend_from_slice(&payload_len.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes()); // epoch
    f.extend_from_slice(&1u64.to_be_bytes()); // seq
    f.extend_from_slice(&data_len_field.to_be_bytes());
    f.extend(std::iter::repeat_n(0xA5u8, payload_bytes));
    f
}

#[test]
fn data_boundary_min_data_len_16_is_valid() {
    // §6.8：data_len=16（空记录仅含 tag）合法；payload_len=32 合法。
    let msg = data_msg(16);
    let wire = encode(&msg).unwrap();
    assert_eq!(wire.len(), 40); // 8 + 32
    assert_eq!(&wire[4..8], &32u32.to_be_bytes());
    assert_eq!(&wire[20..24], &16u32.to_be_bytes());
    for role in [Role::Client, Role::Server] {
        assert_eq!(decode(role, &wire), Ok(msg.clone()));
    }
}

#[test]
fn data_boundary_max_data_len_65552_is_valid() {
    // §6.8：data_len=65552 合法 → payload_len=65568、帧 65576=MAX_FRAME。
    let msg = data_msg(65552);
    let wire = encode(&msg).unwrap();
    assert_eq!(wire.len(), MAX_FRAME);
    assert_eq!(&wire[4..8], &65568u32.to_be_bytes());
    assert_eq!(&wire[20..24], &65552u32.to_be_bytes());
    let back = decode(Role::Server, &wire).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn data_boundary_len_15_and_65553_are_rejected() {
    // §6.8：data_len ∈ {15, 65553} 非法。
    // 15：编码侧拒绝；
    assert_eq!(
        encode(&data_msg(15)),
        Err(ErrorCode::BAD_LENGTH),
        "data_len=15 编码拒绝"
    );
    // 15：payload_len=31（=16+15，步 4 拒：31 < 32）。
    let f = raw_data_frame(31, 15, 15);
    assert_eq!(decode(Role::Server, &f), Err(ErrorCode::BAD_LENGTH));
    // 15：payload_len=32（声明合法），data_len=15 超出 [16,65552] 下界 →
    // §4.5 字段校验拒（0x0302）。
    let f = raw_data_frame(32, 15, 16);
    assert_eq!(decode(Role::Server, &f), Err(ErrorCode::BAD_LENGTH));
    // 17：data_len 声明超出剩余 payload（16+17=33 > 32）→ 字段字节不足 0x0302。
    let f = raw_data_frame(32, 17, 16);
    assert_eq!(decode(Role::Server, &f), Err(ErrorCode::BAD_LENGTH));
    // 65553：编码侧拒绝（超出上界）。
    assert_eq!(
        encode(&data_msg(65553)),
        Err(ErrorCode::BAD_LENGTH),
        "data_len=65553 编码拒绝"
    );
}

#[test]
fn data_payload_len_boundary_31_and_65569_rejected() {
    // payload_len=31：DATA 下界之外 → 步 4 拒。
    let f = raw_data_frame(31, 16, 23);
    assert_eq!(decode(Role::Server, &f), Err(ErrorCode::BAD_LENGTH));
    // payload_len=65569：上界之外 → 步 4 拒（缓冲不足无关：步 4 先于步 5）。
    let f = raw_data_frame(65569, 16, 23);
    assert_eq!(decode(Role::Server, &f), Err(ErrorCode::BAD_LENGTH));
}

#[test]
fn oversize_payload_len_claim_rejected_before_buffer_read() {
    // §7.2 防长度放大：仅 8B 头、payload_len=0xFFFFFFFF → 步 4 拒（BAD_LENGTH），
    // 而非步 5 的 FRAME_TRUNCATED，也不产生任何大分配。
    let mut f = Vec::new();
    f.extend_from_slice(&0x0002u16.to_be_bytes());
    f.extend_from_slice(&0x0006u16.to_be_bytes());
    f.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    assert_eq!(decode(Role::Server, &f), Err(ErrorCode::BAD_LENGTH));
}

#[test]
fn decode_order_is_deterministic_per_spec() {
    // §3.2 顺序锁定：复合畸形输入必须报“最先触发”的那一步的码。
    // 步 2 先于步 3：version 错 + type 未分配 → BAD_VERSION。
    let mut f = Vec::new();
    f.extend_from_slice(&0x0003u16.to_be_bytes());
    f.extend_from_slice(&0x0007u16.to_be_bytes());
    f.extend_from_slice(&44u32.to_be_bytes());
    f.extend(std::iter::repeat_n(0u8, 44));
    assert_eq!(decode(Role::Server, &f), Err(ErrorCode::BAD_VERSION));
    // 步 3 先于步 4：type 未分配 + payload_len 荒谬 → UNKNOWN_MSG_TYPE。
    let mut f = Vec::new();
    f.extend_from_slice(&0x0002u16.to_be_bytes());
    f.extend_from_slice(&0x00FFu16.to_be_bytes());
    f.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    assert_eq!(decode(Role::Server, &f), Err(ErrorCode::UNKNOWN_MSG_TYPE));
    // 步 4 先于步 5：HELLO payload_len=45 + 输入只有 8B → BAD_LENGTH 非 TRUNCATED。
    let mut f = Vec::new();
    f.extend_from_slice(&0x0002u16.to_be_bytes());
    f.extend_from_slice(&0x0001u16.to_be_bytes());
    f.extend_from_slice(&45u32.to_be_bytes());
    assert_eq!(decode(Role::Server, &f), Err(ErrorCode::BAD_LENGTH));
    // 步 4 先于步 6：ISSUE payload_len=39（错）+ 角色也错 → BAD_LENGTH。
    let mut f = Vec::new();
    f.extend_from_slice(&0x0002u16.to_be_bytes());
    f.extend_from_slice(&0x0003u16.to_be_bytes());
    f.extend_from_slice(&39u32.to_be_bytes());
    f.extend(std::iter::repeat_n(0u8, 39));
    assert_eq!(decode(Role::Client, &f), Err(ErrorCode::BAD_LENGTH));
    // 步 5 先于步 6：ARBITRATE 帧尾多 1B + 角色错 → TRAILING_BYTES。
    let mut f = Vec::new();
    f.extend_from_slice(&0x0002u16.to_be_bytes());
    f.extend_from_slice(&0x0002u16.to_be_bytes());
    f.extend_from_slice(&25u32.to_be_bytes());
    f.extend(std::iter::repeat_n(0u8, 26));
    assert_eq!(decode(Role::Server, &f), Err(ErrorCode::TRAILING_BYTES));
    // 步 1 先于一切：空输入 / 7B 输入 → FRAME_TRUNCATED。
    assert_eq!(decode(Role::Server, &[]), Err(ErrorCode::FRAME_TRUNCATED));
    assert_eq!(
        decode(Role::Server, &[0, 2, 0, 1, 0, 0, 0]),
        Err(ErrorCode::FRAME_TRUNCATED)
    );
}

#[test]
fn unknown_message_types_rejected() {
    // §2.2：0x0007..0xFFFF 未分配 → 0x0305；0x0000 同样未分配。
    for bad in [0x0000u16, 0x0007, 0x1234, 0xFFFF] {
        let mut f = Vec::new();
        f.extend_from_slice(&0x0002u16.to_be_bytes());
        f.extend_from_slice(&bad.to_be_bytes());
        f.extend_from_slice(&44u32.to_be_bytes());
        f.extend(std::iter::repeat_n(0u8, 44));
        assert_eq!(
            decode(Role::Server, &f),
            Err(ErrorCode::UNKNOWN_MSG_TYPE),
            "type {bad:#06x}"
        );
    }
}

#[test]
fn arbitrate_canonical_combination_enforced() {
    // §4.2：BOOK_MISMATCH 时 sp 必须为 0 —— 解码与编码双向强制（0x0304）。
    let mut f = Vec::new();
    f.extend_from_slice(&0x0002u16.to_be_bytes());
    f.extend_from_slice(&0x0002u16.to_be_bytes());
    f.extend_from_slice(&25u32.to_be_bytes());
    f.extend_from_slice(&[0x20; 16]); // server_nonce
    f.extend_from_slice(&7u64.to_be_bytes()); // sp=7
    f.push(0x03); // BOOK_MISMATCH
    assert_eq!(decode(Role::Client, &f), Err(ErrorCode::BAD_ENUM));

    let bad = Message::Arbitrate {
        server_nonce: ServerNonce::from_bytes([0x20; 16]),
        server_pointer: SegmentIndex::new(7),
        result: otp_codec::ArbitrateResult::BookMismatch,
    };
    assert_eq!(encode(&bad), Err(ErrorCode::BAD_ENUM));
}

#[test]
fn confirm_body_strictness() {
    // body ≠ 87B → 0x0302。
    assert_eq!(
        otp_codec::decode_confirm_body(&[0u8; 86]),
        Err(ErrorCode::BAD_LENGTH)
    );
    assert_eq!(
        otp_codec::decode_confirm_body(&[0u8; 88]),
        Err(ErrorCode::BAD_LENGTH)
    );
    // version ≠ 0x0002 → 0x0301。
    let mut b = [0u8; 87];
    b[0] = 0x00;
    b[1] = 0x03;
    assert_eq!(
        otp_codec::decode_confirm_body(&b),
        Err(ErrorCode::BAD_VERSION)
    );
    // direction ∉ {1,2} → 0x0304。
    for bad in [0u8, 0x03, 0xFF] {
        let mut b = [0u8; 87];
        b[1] = 0x02; // version ok
        b[58] = bad;
        assert_eq!(
            otp_codec::decode_confirm_body(&b),
            Err(ErrorCode::BAD_ENUM),
            "direction {bad:#04x}"
        );
    }
}

#[test]
fn hello_features_unknown_bits_are_ignored_not_rejected() {
    // D4：features 未知位必须忽略（codec 不因未知位拒绝）。
    let mut f = Vec::new();
    f.extend_from_slice(&0x0002u16.to_be_bytes());
    f.extend_from_slice(&0x0001u16.to_be_bytes());
    f.extend_from_slice(&44u32.to_be_bytes());
    f.extend_from_slice(&[0x00; 16]); // book_id
    f.extend_from_slice(&[0x10; 16]); // client_nonce
    f.extend_from_slice(&u64::MAX.to_be_bytes()); // client_pointer
    f.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // features 全 1
    let msg = decode(Role::Server, &f).expect("未知 features 位必须放行");
    let Message::Hello { features, .. } = msg else {
        panic!("expected Hello")
    };
    assert_eq!(features, FeatureFlags(0xFFFF_FFFF));
    assert!(features.has_reconnect());
}

#[test]
fn hello_minimal_header_edge_and_full_u64_pointer() {
    // 恰 8B 头但 payload 未到 → 0x0308；u64 边界值透传。
    let mut f = Vec::new();
    f.extend_from_slice(&0x0002u16.to_be_bytes());
    f.extend_from_slice(&0x0001u16.to_be_bytes());
    f.extend_from_slice(&44u32.to_be_bytes());
    assert_eq!(decode(Role::Server, &f), Err(ErrorCode::FRAME_TRUNCATED));

    let msg = Message::Hello {
        book_id: BookId::from_bytes([1; 16]),
        client_nonce: ClientNonce::from_bytes([2; 16]),
        client_pointer: SegmentIndex::new(u64::MAX),
        features: FeatureFlags::RECONNECT,
    };
    let wire = encode(&msg).unwrap();
    assert_eq!(decode(Role::Server, &wire), Ok(msg));
}

#[test]
fn session_nonce_in_confirm_is_opaque_16b() {
    // D3：session_nonce 16B 不透明字节，codec 不做 ⊕ 一致性（归 state 层）。
    let msg = Message::ConfirmS2c {
        segment_index: SegmentIndex::new(u64::MAX),
        session_nonce: SessionNonce::from_bytes([0x77; 16]),
        epoch: Epoch::new(u32::MAX),
        seq: Sequence::new(u64::MAX),
        sealed: [0x5A; 103],
    };
    let wire = encode(&msg).unwrap();
    assert_eq!(wire.len(), 147);
    assert_eq!(decode(Role::Client, &wire), Ok(msg));
}
