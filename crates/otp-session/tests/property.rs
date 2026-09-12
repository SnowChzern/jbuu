//! 性质测试（WP-03 §6.7 边界行 + §7.1 核对清单）：
//! nonce 公式/单射性、AAD 布局、seal↔open 往返、随机垃圾无 panic。

use otp_session::{
    MessageType, Session, SessionContext, SessionError, SessionNonceDomain, record_nonce,
};
use otp_types::{
    BookId, ClientNonce, Direction, Epoch, Role, SegmentIndex, Sequence, ServerNonce, SessionNonce,
};
use proptest::prelude::*;

fn any_16b() -> impl Strategy<Value = [u8; 16]> {
    any::<[u8; 16]>()
}

fn any_ctx(role: Role) -> impl Strategy<Value = SessionContext> {
    (any_16b(), any_16b(), any_16b(), any::<u64>()).prop_map(move |(book, cn, sn, seg)| {
        SessionContext {
            role,
            book_id: BookId::from_bytes(book),
            segment: SegmentIndex::new(seg),
            client_nonce: ClientNonce::from_bytes(cn),
            server_nonce: ServerNonce::from_bytes(sn),
        }
    })
}

proptest! {
    /// §1.1 公式：任意 (ζ, 方向, seq) 下 nonce = ζ[0..3] ‖ dir ‖ BE64(seq)
    #[test]
    fn nonce_matches_spec_formula(zeta in any_16b(), c2s in any::<bool>(), seq in any::<u64>()) {
        let session_nonce = SessionNonce::from_bytes(zeta);
        let domain = SessionNonceDomain::from_session_nonce(&session_nonce);
        let dir = if c2s { Direction::ClientToServer } else { Direction::ServerToClient };
        let n = record_nonce(&domain, dir, Sequence::new(seq));
        let mut want = [0u8; 12];
        want[0..3].copy_from_slice(&zeta[0..3]);
        want[3] = if c2s { 0x01 } else { 0x02 };
        want[4..].copy_from_slice(&seq.to_be_bytes());
        prop_assert_eq!(n.as_bytes(), &want);
    }

    /// §1.2 单射性：同方向不同 seq ⇒ 不同 nonce；同 seq 双方向 ⇒ 不同 nonce
    #[test]
    fn nonce_is_injective_per_direction(
        zeta in any_16b(),
        s1 in any::<u64>(),
        s2 in any::<u64>(),
    ) {
        prop_assume!(s1 != s2);
        let domain = SessionNonceDomain::from_session_nonce(&SessionNonce::from_bytes(zeta));
        for dir in [Direction::ClientToServer, Direction::ServerToClient] {
            let n1 = record_nonce(&domain, dir, Sequence::new(s1));
            let n2 = record_nonce(&domain, dir, Sequence::new(s2));
            prop_assert_ne!(n1.as_bytes(), n2.as_bytes());
        }
        let n_c = record_nonce(&domain, Direction::ClientToServer, Sequence::new(s1));
        let n_s = record_nonce(&domain, Direction::ServerToClient, Sequence::new(s1));
        prop_assert_ne!(n_c.as_bytes()[3], n_s.as_bytes()[3]);
    }

    /// §6.7 边界：seq ∈ {0, 1, 2^32, 2^63, 2^64−1} 构造无回绕（低 8 字节精确编码）
    #[test]
    fn nonce_boundaries_do_not_wrap(zeta in any_16b()) {
        let domain = SessionNonceDomain::from_session_nonce(&SessionNonce::from_bytes(zeta));
        for s in [0u64, 1, 1 << 32, 1 << 63, u64::MAX, u64::MAX - 1] {
            let n = record_nonce(&domain, Direction::ClientToServer, Sequence::new(s));
            prop_assert_eq!(&n.as_bytes()[4..], &s.to_be_bytes());
        }
    }

    /// §2.1 布局：随机上下文下 9 字段各就各位、长度恒 73
    #[test]
    fn aad_layout_is_frozen(
        ctx in any_ctx(Role::Client),
        mt in prop_oneof![Just(MessageType::ClientConfirm), Just(MessageType::ServerConfirm), Just(MessageType::Data)],
        c2s in any::<bool>(),
        epoch in any::<u32>(),
        seq in any::<u64>(),
    ) {
        let dir = if c2s { Direction::ClientToServer } else { Direction::ServerToClient };
        let aad = ctx.build_aad(mt, dir, Epoch::new(epoch), Sequence::new(seq));
        prop_assert_eq!(aad.len(), 73);
        prop_assert_eq!(&aad[0..2], &0x0002u16.to_be_bytes());
        prop_assert_eq!(&aad[2..4], &mt.wire_code().to_be_bytes());
        prop_assert_eq!(aad[4], if c2s { 0x01 } else { 0x02 });
        prop_assert_eq!(&aad[5..21], ctx.book_id.as_bytes());
        prop_assert_eq!(&aad[21..29], &ctx.segment.get().to_be_bytes());
        prop_assert_eq!(&aad[29..45], ctx.client_nonce.as_bytes());
        prop_assert_eq!(&aad[45..61], ctx.server_nonce.as_bytes());
        prop_assert_eq!(&aad[61..65], &epoch.to_be_bytes());
        prop_assert_eq!(&aad[65..73], &seq.to_be_bytes());
    }

    /// seal↔open 往返：随机会话/随机明文，双方向按序收发全还原
    #[test]
    fn seal_open_roundtrip_both_directions(
        ctx_c in any_ctx(Role::Client),
        segment in any::<[u8; 64]>(),
        texts in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..200), 1..8),
    ) {
        let ctx_s = SessionContext { role: Role::Server, ..ctx_c };
        let mut client = Session::new(otp_session::CommittedSegment::from_bytes(segment), ctx_c);
        let mut server = Session::new(otp_session::CommittedSegment::from_bytes(segment), ctx_s);

        // 确认交换
        let cc = client.seal(MessageType::ClientConfirm, b"c").unwrap();
        let sc = server.seal(MessageType::ServerConfirm, b"s").unwrap();
        let got_c = server.open(MessageType::ClientConfirm, cc.sequence, cc.sealed()).unwrap();
        prop_assert_eq!(got_c.as_bytes(), b"c");
        let got_s = client.open(MessageType::ServerConfirm, sc.sequence, sc.sealed()).unwrap();
        prop_assert_eq!(got_s.as_bytes(), b"s");

        // 双方向 DATA 按序收发
        for t in &texts {
            let c2s = client.seal(MessageType::Data, t).unwrap();
            let s2c = server.seal(MessageType::Data, t).unwrap();
            let got_c2s = server.open(MessageType::Data, c2s.sequence, c2s.sealed()).unwrap();
            prop_assert_eq!(got_c2s.as_bytes(), t.as_slice());
            let got_s2c = client.open(MessageType::Data, s2c.sequence, s2c.sealed()).unwrap();
            prop_assert_eq!(got_s2c.as_bytes(), t.as_slice());
        }
        prop_assert!(client.is_active() && server.is_active());
    }

    /// 随机垃圾 sealed：不 panic、恒 0x0201、会话即关（fuzz 前置性质）
    #[test]
    fn garbage_sealed_always_fails_closed(
        ctx in any_ctx(Role::Server),
        segment in any::<[u8; 64]>(),
        garbage in prop::collection::vec(any::<u8>(), 0..80),
    ) {
        let ctx_c = SessionContext { role: Role::Client, ..ctx };
        let mut client = Session::new(otp_session::CommittedSegment::from_bytes(segment), ctx_c);
        let mut server = Session::new(otp_session::CommittedSegment::from_bytes(segment), ctx);
        let cc = client.seal(MessageType::ClientConfirm, b"c").unwrap();
        server.open(MessageType::ClientConfirm, cc.sequence, cc.sealed()).unwrap();

        match server.open(MessageType::Data, Sequence::new(1), &garbage) {
            Err(SessionError::AuthenticationFailed) => {}
            Err(SessionError::Closed) => unreachable!("首条失败不得是 Closed"),
            Err(other) => panic!("期望 0x0201，得到 {other:?}"),
            Ok(_) => panic!("垃圾必拒"),
        }
        prop_assert!(!server.is_active());
    }
}
