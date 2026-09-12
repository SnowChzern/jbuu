//! 已知答案测试（WP-03 §6 golden vectors + RFC 8439 §2.8.2 KAT）。
//!
//! 全部向量逐字节抄自规格表/RFC 正文；另由仓外独立校验器
//! `evidence/task-37/verify-wp03-vectors.py`（pycryptodome）交叉复算。

mod common;

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce as AeadNonce,
    aead::{AeadInPlace, KeyInit},
};
use common::*;
use otp_session::{
    MessageType, SessionContext, SessionError, SessionKeys, SessionNonceDomain, record_nonce,
};
use otp_types::{Direction, Epoch, Role, Sequence};

// ---- RFC 8439 §2.8.2：原语级 KAT（常量取自 RFC 正文）----

const RFC_KEY: &[u8] = &[
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
];
const RFC_NONCE: &[u8; 12] = &[
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
];
const RFC_AAD: &[u8] = &[
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
];
const RFC_PT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
const RFC_CT: &[u8] = &[
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
    0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
    0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
    0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
    0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
    0x61, 0x16,
];
const RFC_TAG: &[u8; 16] = &[
    0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
];

#[test]
fn rfc8439_282_known_answer_seal() {
    // 整体 seal（encrypt_in_place_detached + tag 拼接 = 生产同一路径）
    let cipher = ChaCha20Poly1305::new(Key::from_slice(RFC_KEY));
    let mut buf = RFC_PT.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(AeadNonce::from_slice(RFC_NONCE), RFC_AAD, &mut buf)
        .expect("RFC 8439 §2.8.2 向量必过");
    assert_eq!(buf.as_slice(), RFC_CT);
    assert_eq!(tag.as_slice(), RFC_TAG);
}

#[test]
fn rfc8439_282_known_answer_open() {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(RFC_KEY));
    let mut buf = RFC_CT.to_vec();
    cipher
        .decrypt_in_place_detached(
            AeadNonce::from_slice(RFC_NONCE),
            RFC_AAD,
            &mut buf,
            chacha20poly1305::Tag::from_slice(RFC_TAG),
        )
        .expect("正确 tag 必过");
    assert_eq!(buf.as_slice(), RFC_PT);
}

#[test]
fn rfc8439_282_tampered_tag_rejected() {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(RFC_KEY));
    let mut bad_tag = *RFC_TAG;
    bad_tag[15] ^= 0x01;
    let mut buf = RFC_CT.to_vec();
    assert!(
        cipher
            .decrypt_in_place_detached(
                AeadNonce::from_slice(RFC_NONCE),
                RFC_AAD,
                &mut buf,
                chacha20poly1305::Tag::from_slice(&bad_tag),
            )
            .is_err()
    );
}

// ---- WP-03 §6.2 nonce 向量 ----

fn fixture_domain() -> SessionNonceDomain {
    SessionNonceDomain::from_session_nonce(&otp_types::SessionNonce::from_bytes(
        unhex(SESSION_NONCE_HEX).try_into().unwrap(),
    ))
}

#[test]
fn nonce_vectors_n_v1_to_n_v5() {
    let d = fixture_domain();
    let cases: &[(Direction, u64, &str)] = &[
        (Direction::ClientToServer, 0, "303030010000000000000000"), // N-V1
        (Direction::ServerToClient, 0, "303030020000000000000000"), // N-V2
        (Direction::ClientToServer, 1, "303030010000000000000001"), // N-V3
        (
            Direction::ClientToServer,
            1 << 32,
            "303030010000000100000000",
        ), // N-V4
        (
            Direction::ServerToClient,
            u64::MAX,
            "30303002ffffffffffffffff",
        ), // N-V5
    ];
    for &(dir, seq, want) in cases {
        let n = record_nonce(&d, dir, Sequence::new(seq));
        assert_eq!(hex(n.as_bytes()), want, "direction={dir:?} seq={seq}");
    }
}

#[test]
fn nonce_uniqueness_sample() {
    // §6.2：13 个不同 seq 的 C2S nonce 互异；同 seq 双方向互异（§1.2 定理）
    let d = fixture_domain();
    let seqs = [
        0u64,
        1,
        2,
        3,
        255,
        256,
        1 << 16,
        1 << 24,
        1 << 32,
        1 << 48,
        1 << 63,
        u64::MAX - 1,
        u64::MAX,
    ];
    let mut seen = std::collections::HashSet::new();
    for dir in [Direction::ClientToServer, Direction::ServerToClient] {
        for &s in &seqs {
            assert!(
                seen.insert(*record_nonce(&d, dir, Sequence::new(s)).as_bytes()),
                "nonce 冲突：dir={dir:?} seq={s}"
            );
        }
    }
    assert_eq!(seen.len(), 2 * seqs.len());
}

// ---- WP-03 §6.3 AAD 向量 ----

#[test]
fn aad_vectors_a_v1_to_a_v3() {
    let ctx = fixture_ctx(Role::Client);
    let cases: &[(MessageType, Direction, u64, &str)] = &[
        (
            MessageType::ClientConfirm,
            Direction::ClientToServer,
            0,
            "000200040100112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f000000000000000000000000",
        ),
        (
            MessageType::ServerConfirm,
            Direction::ServerToClient,
            0,
            "000200050200112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f000000000000000000000000",
        ),
        (
            MessageType::Data,
            Direction::ClientToServer,
            1,
            "000200060100112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f000000000000000000000001",
        ),
    ];
    for &(mt, dir, seq, want) in cases {
        let aad = ctx.build_aad(mt, dir, Epoch::new(0), Sequence::new(seq));
        assert_eq!(aad.len(), 73);
        assert_eq!(hex(&aad), want, "mt={mt:?} dir={dir:?} seq={seq}");
    }
}

// ---- WP-03 §6.4 AEAD KAT（通过 Session 公共 API，完整构造路径）----

const K_V1: &str = "2d7bec766d3da3393e54bfc4078c3d32a21276d0268aba2d30632259fce04e58b7b6e5c5610b9a031cb80dac6dedcb4fd9f2dbd37cd07850bb9569d9d0b6de562309b98e7f513cb5c32536a5254accf5e462debf9c4457d96242d7396bc0fb4e2f81cd33ab7fbd";
const K_V2: &str = "c2578c0aea067ae4d03750f90b7c1bdc7aef0f7a136c731a061fbfe878a29e8672b704704848649dedc6cd922ee6b63403c6c37bb1039e2a206a32b6e3027cd87eaedfc4a7de6005efd0c07fd1e13929b1ea54ec22a773d00aae7a47a5b1da8d168558d823056d";
const K_V3: &str = "6ce1e72949eab99255ba29ecb16e446a1142284a43daab7fda7babf52389bafb";

#[test]
fn kat_k_v1_client_confirm() {
    // K-V1：seal(K_c2s, N-V1, A-V1, CONFIRM-BODY-POS-001) —— 客户端会话
    let mut client = fixture_session(Role::Client);
    let rec = client
        .seal(MessageType::ClientConfirm, &confirm_body_pos_001())
        .expect("夹具必过");
    assert_eq!(rec.sequence, Sequence::ZERO);
    assert_eq!(hex(rec.sealed()), K_V1);
}

#[test]
fn kat_k_v2_server_confirm() {
    // K-V2：seal(K_s2c, N-V2, A-V2, CONFIRM-BODY-POS-002) —— 服务端会话
    let mut server = fixture_session(Role::Server);
    let rec = server
        .seal(MessageType::ServerConfirm, &confirm_body_pos_002())
        .expect("夹具必过");
    assert_eq!(hex(rec.sealed()), K_V2);
}

#[test]
fn kat_k_v3_data_after_confirm() {
    // K-V3：seal(K_c2s, N-V3, A-V3, "Hello, otp-term!") —— CONFIRM(0) 之后的 DATA(1)
    let mut client = fixture_session(Role::Client);
    client
        .seal(MessageType::ClientConfirm, &confirm_body_pos_001())
        .unwrap();
    let rec = client
        .seal(MessageType::Data, DATA_PLAINTEXT)
        .expect("夹具必过");
    assert_eq!(rec.sequence.get(), 1);
    assert_eq!(hex(rec.sealed()), K_V3);
}

#[test]
fn kat_end_to_end_open() {
    // K-V1/K-V3 在对端（服务端会话）按序 open 还原明文（完整收发路径）
    let mut client = fixture_session(Role::Client);
    let mut server = fixture_session(Role::Server);
    let c = client
        .seal(MessageType::ClientConfirm, &confirm_body_pos_001())
        .unwrap();
    let d = client.seal(MessageType::Data, DATA_PLAINTEXT).unwrap();

    let opened_confirm = server
        .open(MessageType::ClientConfirm, c.sequence, c.sealed())
        .expect("K-V1 必过");
    assert_eq!(opened_confirm.as_bytes(), confirm_body_pos_001());
    assert_eq!(
        server.last_accepted(Direction::ClientToServer),
        Some(Sequence::ZERO)
    );

    let opened_data = server
        .open(MessageType::Data, d.sequence, d.sealed())
        .expect("K-V3 必过");
    assert_eq!(opened_data.as_bytes(), DATA_PLAINTEXT);
}

// ---- §6.4 KAT 负性质（四种错误上下文 open 必败）----

#[test]
fn kat_negative_contexts_reject_kv1() {
    let ctx = fixture_ctx(Role::Client);
    let kv1 = unhex(K_V1);
    let k_c2s: [u8; 32] = core::array::from_fn(|i| i as u8);
    let k_s2c: [u8; 32] = core::array::from_fn(|i| 0x20 + i as u8);
    let d = fixture_domain();

    let open_with = |key: &[u8; 32], nonce: &[u8; 12], aad: &[u8]| {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let mut buf = kv1[..kv1.len() - 16].to_vec();
        cipher
            .decrypt_in_place_detached(
                AeadNonce::from_slice(nonce),
                aad,
                &mut buf,
                chacha20poly1305::Tag::from_slice(&kv1[kv1.len() - 16..]),
            )
            .is_err()
    };

    let a_v1 = ctx.build_aad(
        MessageType::ClientConfirm,
        Direction::ClientToServer,
        Epoch::new(0),
        Sequence::ZERO,
    );
    let a_v3 = ctx.build_aad(
        MessageType::Data,
        Direction::ClientToServer,
        Epoch::new(0),
        Sequence::new(1),
    );
    let n_v1 = record_nonce(&d, Direction::ClientToServer, Sequence::ZERO);
    let n_v2 = record_nonce(&d, Direction::ServerToClient, Sequence::ZERO);

    // ① AAD 首字节翻 1 bit
    let mut bad_aad = a_v1;
    bad_aad[0] ^= 0x01;
    assert!(open_with(&k_c2s, n_v1.as_bytes(), &bad_aad), "AAD 翻位必拒");
    // ② 换 N-V2（跨方向 nonce）
    assert!(open_with(&k_c2s, n_v2.as_bytes(), &a_v1), "错误 nonce 必拒");
    // ③ 换 K_s2c（跨方向密钥）
    assert!(open_with(&k_s2c, n_v1.as_bytes(), &a_v1), "错误密钥必拒");
    // ④ 换 A-V3（跨类型 AAD）
    assert!(open_with(&k_c2s, n_v1.as_bytes(), &a_v3), "错误 AAD 必拒");
}

#[test]
fn kat_session_level_cross_context_reject() {
    // 会话级负例：K-V1 在"另一会话上下文"（book_id/段号/双 nonce 任一不同）必拒
    let mut client = fixture_session(Role::Client);
    let rec = client
        .seal(MessageType::ClientConfirm, &confirm_body_pos_001())
        .unwrap();

    let variants: [(&str, SessionContext); 4] = [
        ("book_id 不同", {
            let mut c = fixture_ctx(Role::Server);
            c.book_id = otp_types::BookId::from_bytes([0x99; 16]);
            c
        }),
        ("段号不同", {
            let mut c = fixture_ctx(Role::Server);
            c.segment = otp_types::SegmentIndex::new(1);
            c
        }),
        ("client_nonce 不同", {
            let mut c = fixture_ctx(Role::Server);
            c.client_nonce = otp_types::ClientNonce::from_bytes([0x99; 16]);
            c
        }),
        ("server_nonce 不同", {
            let mut c = fixture_ctx(Role::Server);
            c.server_nonce = otp_types::ServerNonce::from_bytes([0x99; 16]);
            c
        }),
    ];
    for (name, ctx) in variants {
        let mut other = otp_session::Session::new(fixture_segment(), ctx);
        let r = other.open(MessageType::ClientConfirm, rec.sequence, rec.sealed());
        assert!(
            matches!(r, Err(SessionError::AuthenticationFailed)),
            "{name} 必拒（0x0201）"
        );
    }
}

/// 测试用 hex 编码（断言输出仅为公开密文/向量；密钥/明文从不断言打印）。
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

// 引用未用警告抑制：SessionKeys 在此测试集中经由 Session 路径覆盖，
// 显式引用以保证拆分 API 在公共接口上可用（WP-03 §7.2 草案）。
#[test]
fn session_keys_split_api_is_public_and_split_once() {
    let keys = SessionKeys::split(fixture_segment());
    drop(keys);
}
