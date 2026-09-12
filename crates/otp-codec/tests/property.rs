//! WP-01 §6.8 性质测试（proptest）：
//!
//! 1. **往返性质**：`decode(role, encode(x)) == x` 且 `encode(decode(x)) == x`
//!    （§3.1 规则 5，canonical 的可测试判据）。
//! 2. **随机垃圾输入不 panic**：0..=70000 字节任意输入 × 两个角色，decode
//!    要么 Err 要么 Ok，绝不 panic（fuzz 目标 WP-14 的前置保证）。
//! 3. **canonical 接受性质**：decode 接受的**任意**输入（含垃圾/篡改输入）
//!    必是 canonical 字节（再编码逐字节相等）——严格性的强形式。
//! 4. **单 bit 篡改不 panic**：对合法帧任一 bit 翻转，仍满足 2/3。
//! 5. **任意真前缀必为 FRAME_TRUNCATED**（§3.2 步 5：前缀保留同一
//!    payload_len 声明，帧界永不提前闭合）。

use otp_codec::{ArbitrateResult, ErrorCode, FeatureFlags, MAX_FRAME, Message, decode, encode};
use otp_types::{
    BookId, ClientNonce, Epoch, Role, SegmentIndex, Sequence, ServerNonce, SessionNonce,
};
use proptest::prelude::*;

fn arb_book_id() -> impl Strategy<Value = BookId> {
    any::<[u8; 16]>().prop_map(BookId::from_bytes)
}

fn arb_client_nonce() -> impl Strategy<Value = ClientNonce> {
    any::<[u8; 16]>().prop_map(ClientNonce::from_bytes)
}

fn arb_server_nonce() -> impl Strategy<Value = ServerNonce> {
    any::<[u8; 16]>().prop_map(ServerNonce::from_bytes)
}

fn arb_session_nonce() -> impl Strategy<Value = SessionNonce> {
    any::<[u8; 16]>().prop_map(SessionNonce::from_bytes)
}

fn arb_hello() -> impl Strategy<Value = Message> {
    (
        arb_book_id(),
        arb_client_nonce(),
        any::<u64>(),
        any::<u32>(),
    )
        .prop_map(
            |(book_id, client_nonce, client_pointer, features)| Message::Hello {
                book_id,
                client_nonce,
                client_pointer: SegmentIndex::new(client_pointer),
                features: FeatureFlags(features),
            },
        )
}

/// canonical ARBITRATE：BOOK_MISMATCH 时 server_pointer 恒 0（§4.2 组合），
/// 其余 result 的 sp 为任意 u64（与 client_pointer 的关系归 state 层）。
fn arb_arbitrate() -> impl Strategy<Value = Message> {
    (0u8..5, arb_server_nonce()).prop_flat_map(|(tag, server_nonce)| {
        let sp = if tag == 3 {
            Just(0u64).boxed()
        } else {
            any::<u64>().boxed()
        };
        (Just(server_nonce), sp, Just(tag)).prop_map(|(server_nonce, sp, tag)| Message::Arbitrate {
            server_nonce,
            server_pointer: SegmentIndex::new(sp),
            result: match tag {
                0 => ArbitrateResult::Ok,
                1 => ArbitrateResult::ServerAhead,
                2 => ArbitrateResult::Exhausted,
                3 => ArbitrateResult::BookMismatch,
                _ => ArbitrateResult::ClientAhead,
            },
        })
    })
}

fn arb_issue() -> impl Strategy<Value = Message> {
    (any::<u64>(), arb_client_nonce(), arb_server_nonce()).prop_map(
        |(chosen_pointer, client_nonce, server_nonce)| Message::IssueRequest {
            chosen_pointer: SegmentIndex::new(chosen_pointer),
            client_nonce,
            server_nonce,
        },
    )
}

fn arb_sealed() -> impl Strategy<Value = [u8; 103]> {
    proptest::collection::vec(any::<u8>(), 103).prop_map(|v| {
        let mut a = [0u8; 103];
        a.copy_from_slice(&v);
        a
    })
}

fn arb_confirm_c2s() -> impl Strategy<Value = Message> {
    (
        any::<u64>(),
        arb_session_nonce(),
        any::<u32>(),
        any::<u64>(),
        arb_sealed(),
    )
        .prop_map(
            |(segment_index, session_nonce, epoch, seq, sealed)| Message::ConfirmC2s {
                segment_index: SegmentIndex::new(segment_index),
                session_nonce,
                epoch: Epoch::new(epoch),
                seq: Sequence::new(seq),
                sealed,
            },
        )
}

fn arb_confirm_s2c() -> impl Strategy<Value = Message> {
    (
        any::<u64>(),
        arb_session_nonce(),
        any::<u32>(),
        any::<u64>(),
        arb_sealed(),
    )
        .prop_map(
            |(segment_index, session_nonce, epoch, seq, sealed)| Message::ConfirmS2c {
                segment_index: SegmentIndex::new(segment_index),
                session_nonce,
                epoch: Epoch::new(epoch),
                seq: Sequence::new(seq),
                sealed,
            },
        )
}

fn arb_data() -> impl Strategy<Value = Message> {
    (
        any::<u32>(),
        any::<u64>(),
        proptest::collection::vec(any::<u8>(), 16..=256),
    )
        .prop_map(|(epoch, seq, data)| Message::Data {
            epoch: Epoch::new(epoch),
            seq: Sequence::new(seq),
            data,
        })
}

fn arb_message() -> BoxedStrategy<Message> {
    prop_oneof![
        arb_hello(),
        arb_arbitrate(),
        arb_issue(),
        arb_confirm_c2s(),
        arb_confirm_s2c(),
        arb_data(),
    ]
    .boxed()
}

/// 该消息类型的合法接收角色（§2.3；DATA 双向取 Server，另一角色另行断言）。
fn receiver_role(m: &Message) -> Role {
    match m {
        Message::Arbitrate { .. } | Message::ConfirmS2c { .. } => Role::Client,
        _ => Role::Server,
    }
}

fn opposite(r: Role) -> Role {
    match r {
        Role::Client => Role::Server,
        Role::Server => Role::Client,
    }
}

fn frame_len(m: &Message) -> usize {
    match m {
        Message::Hello { .. } => 52,
        Message::Arbitrate { .. } => 33,
        Message::IssueRequest { .. } => 48,
        Message::ConfirmC2s { .. } | Message::ConfirmS2c { .. } => 147,
        Message::Data { data, .. } => 24 + data.len(),
    }
}

proptest! {
    /// 性质 1：编解码往返 + 定向消息反角色必 0x0306。
    #[test]
    fn roundtrip_encode_decode(msg in arb_message()) {
        let bytes = encode(&msg).expect("canonical 策略必可编码");
        prop_assert!(bytes.len() <= MAX_FRAME);
        prop_assert_eq!(bytes.len(), frame_len(&msg));

        let role = receiver_role(&msg);
        let decoded = decode(role, &bytes).expect("canonical 字节必可解码");
        prop_assert_eq!(&decoded, &msg);
        // §3.1 规则 5：再编码恒等
        prop_assert_eq!(encode(&decoded).unwrap(), &bytes[..]);

        if !matches!(msg, Message::Data { .. }) {
            prop_assert_eq!(decode(opposite(role), &bytes), Err(ErrorCode::WRONG_DIRECTION));
        } else {
            // DATA 双向
            prop_assert!(decode(opposite(role), &bytes).is_ok());
        }
    }
}

proptest! {
    /// 性质 2+3：随机垃圾输入不 panic；一旦被接受必为 canonical 字节。
    #[test]
    fn garbage_never_panics_and_accepts_only_canonical(
        bytes in proptest::collection::vec(any::<u8>(), 0..=70000)
    ) {
        for role in [Role::Client, Role::Server] {
            if let Ok(m) = decode(role, &bytes) {
                prop_assert!(bytes.len() <= MAX_FRAME, "接受面不得超出最大帧");
                prop_assert_eq!(encode(&m).unwrap(), &bytes[..], "被接受的输入必是 canonical");
            }
            // Err 情形不 panic 即可（错误码由 golden/boundary 测试锁定）
        }
    }
}

proptest! {
    /// 性质 4：合法帧任意单 bit 翻转不 panic，且接受仍只可能是 canonical。
    #[test]
    fn bitflip_never_panics(
        (msg, byte, bit) in arb_message().prop_flat_map(|m| {
            let len = frame_len(&m);
            (Just(m), 0..len, 0u8..8)
        })
    ) {
        let mut bytes = encode(&msg).unwrap();
        bytes[byte] ^= 1 << bit;
        for role in [Role::Client, Role::Server] {
            if let Ok(m2) = decode(role, &bytes) {
                prop_assert_eq!(encode(&m2).unwrap(), &bytes[..]);
            }
        }
    }
}

proptest! {
    /// 性质 5：合法帧的任意真前缀必为 0x0308 FRAME_TRUNCATED（§3.2 步 5）。
    #[test]
    fn every_proper_prefix_is_frame_truncated(
        (msg, cut) in arb_message().prop_flat_map(|m| {
            let len = frame_len(&m);
            (Just(m), 1..len)
        })
    ) {
        let bytes = encode(&msg).unwrap();
        let role = receiver_role(&msg);
        for n in 0..cut {
            prop_assert_eq!(
                decode(role, &bytes[..n]),
                Err(ErrorCode::FRAME_TRUNCATED),
                "prefix len {}",
                n
            );
        }
    }
}

proptest! {
    /// 补充性质：confuse body 帧头字段（把外层帧当 body 解 / 反向）不 panic。
    #[test]
    fn body_decoder_never_panics_on_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..=300)
    ) {
        if let Ok(body) = otp_codec::decode_confirm_body(&bytes) {
            prop_assert_eq!(bytes.len(), 87);
            prop_assert_eq!(otp_codec::encode_confirm_body(&body).unwrap(), &bytes[..]);
        }
    }
}
