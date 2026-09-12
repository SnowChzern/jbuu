//! 篡改/乱序/重放/截断全拒绝测试（任务卡验收 3；规划 §5 第 8 行性质）。
//!
//! 性质：第一处不合法 record 即关闭会话；不输出未认证明文；
//! sequence 不回退、不跳过后继续；无 panic。

mod common;

use common::*;
use otp_session::{MessageType, Session, SessionError};
use otp_types::{BookId, ClientNonce, Role, SegmentIndex, Sequence, ServerNonce};

/// 建立一对已互认确认的会话（client→server C2S 方向就绪，DATA 从 seq=1 起）。
fn established_pair() -> (Session, Session) {
    let mut client = fixture_session(Role::Client);
    let mut server = fixture_session(Role::Server);
    let c = client
        .seal(MessageType::ClientConfirm, b"client-confirm-body")
        .unwrap();
    let s = server
        .seal(MessageType::ServerConfirm, b"server-confirm-body")
        .unwrap();
    server
        .open(MessageType::ClientConfirm, c.sequence, c.sealed())
        .unwrap();
    client
        .open(MessageType::ServerConfirm, s.sequence, s.sealed())
        .unwrap();
    (client, server)
}

#[test]
fn every_tampered_byte_is_rejected_and_closes_session() {
    // 篡改：sealed 任意字节（密文区/tag 区）翻转任一 bit ⇒ 0x0201 + 会话终止
    let (mut client, _server) = established_pair();
    let rec = client.seal(MessageType::Data, b"payload-16-bytes").unwrap();
    let sealed = rec.sealed().to_vec();
    assert_eq!(sealed.len(), 16 + 16);

    for i in 0..sealed.len() {
        for bit in [0x01u8, 0x80] {
            let mut tampered = sealed.clone();
            tampered[i] ^= bit;
            // 每个篡改位用新鲜对（established_pair 内部已完成确认交换，
            // 服务端期待 C2S DATA seq=1，与 rec 同序号）
            let (_cl, mut sv) = established_pair();
            match sv.open(MessageType::Data, Sequence::new(1), &tampered) {
                Err(SessionError::AuthenticationFailed) => {}
                Err(other) => panic!("字节 {} bit {:#x}：期望 0x0201，得到 {other:?}", i, bit),
                Ok(_) => panic!("字节 {} bit {:#x}：篡改必拒", i, bit),
            }
            assert!(!sv.is_active(), "第一处失败即关闭");
        }
    }
}

#[test]
fn truncated_sealed_is_rejected_for_all_lengths() {
    // 截断：sealed 去掉任意后缀（含短于 tag、空）⇒ 0x0201；无 panic
    let (mut client, _server) = established_pair();
    let rec = client.seal(MessageType::Data, &[0xA5; 24]).unwrap();
    let sealed = rec.sealed();
    for cut in 0..sealed.len() {
        let mut server = {
            let (cl, sv) = established_pair();
            let _ = cl;
            sv
        };
        let truncated = &sealed[..cut];
        match server.open(MessageType::Data, Sequence::new(1), truncated) {
            Err(SessionError::AuthenticationFailed) => {}
            Err(other) => panic!("截断到 {cut}B：期望 0x0201，得到 {other:?}"),
            Ok(_) => panic!("截断到 {cut}B：必拒"),
        }
        assert!(!server.is_active());
    }
    // 完整 sealed 正常通过（对照组）
    let (mut client, mut server) = established_pair();
    let rec = client.seal(MessageType::Data, &[0xA5; 24]).unwrap();
    assert!(
        server
            .open(MessageType::Data, Sequence::new(1), rec.sealed())
            .is_ok()
    );
}

#[test]
fn out_of_order_is_rejected_no_window() {
    // 乱序：期待 2 到达 3 ⇒ 0x030B；回退到 1 ⇒ 重复 0x0204；
    // 乱序后不接受"补发"继续（无窗口）
    let (mut client, mut server) = established_pair();
    let r1 = client.seal(MessageType::Data, b"msg-one-xxxxxxxx").unwrap();
    let _r2 = client.seal(MessageType::Data, b"msg-two-xxxxxxxx").unwrap();
    let r3 = client.seal(MessageType::Data, b"msg-three-xxxxxx").unwrap();

    assert!(
        server
            .open(MessageType::Data, r1.sequence, r1.sealed())
            .is_ok()
    );

    // 跳号：期待 2，到达 3
    assert!(matches!(
        server.open(MessageType::Data, r3.sequence, r3.sealed()),
        Err(SessionError::SequenceUnexpected)
    ));
    assert!(!server.is_active(), "乱序即关闭");

    // 回退：期待 2，到达 1（重复）——在全新对上验证
    let (mut client, mut server) = established_pair();
    let r1 = client.seal(MessageType::Data, b"msg-one-xxxxxxxx").unwrap();
    let _r2 = client.seal(MessageType::Data, b"msg-two-xxxxxxxx").unwrap();
    assert!(
        server
            .open(MessageType::Data, r1.sequence, r1.sealed())
            .is_ok()
    );
    assert!(matches!(
        server.open(MessageType::Data, r1.sequence, r1.sealed()),
        Err(SessionError::SequenceReplay)
    ));
    // 会话已终止：补发的 r2 也无法继续（无窗口、不恢复）
    assert!(matches!(
        server.open(MessageType::Data, _r2.sequence, _r2.sealed()),
        Err(SessionError::Closed)
    ));
}

#[test]
fn replayed_record_is_rejected() {
    // 重放：同一 sealed 重复投递（seq 与密文均同）⇒ 0x0204
    let (mut client, mut server) = established_pair();
    let r = client
        .seal(MessageType::Data, b"replay-me-please!!")
        .unwrap();
    assert!(
        server
            .open(MessageType::Data, r.sequence, r.sealed())
            .is_ok()
    );
    assert!(matches!(
        server.open(MessageType::Data, r.sequence, r.sealed()),
        Err(SessionError::SequenceReplay)
    ));
    assert!(!server.is_active());
}

#[test]
fn cross_direction_carry_is_rejected() {
    // 跨方向搬运：客户端 C2S record 让"客户端自己"open（其接收方向是 S2C，
    // nonce/AAD/密钥全部错位）⇒ 0x0201；服务端正常路径通过（对照组）
    let (mut client, mut server) = established_pair();
    let r = client
        .seal(MessageType::Data, b"cross-direction!x")
        .unwrap();

    assert!(
        server
            .open(MessageType::Data, r.sequence, r.sealed())
            .is_ok()
    );

    // 客户端会话已消耗 C2S 的 seq=1；用全新对做跨方向 open
    let (mut client2, _server2) = established_pair();
    let r2 = client2
        .seal(MessageType::Data, b"cross-direction!x")
        .unwrap();
    match client2.open(MessageType::Data, r2.sequence, r2.sealed()) {
        Err(SessionError::AuthenticationFailed) => {}
        Err(other) => panic!("跨方向：期望 0x0201，得到 {other:?}"),
        Ok(_) => panic!("跨方向搬运必拒"),
    }
    assert!(!client2.is_active());
}

#[test]
fn confirm_type_confusion_is_rejected() {
    // 类型混淆场景 1：CONFIRM 密文装进 DATA 位置（mt=Data、seq=1）——
    // AAD msg_type 与 nonce 的 seq 域全错位 ⇒ 0x0201（REC-NEG-4 同型）
    let mut client = fixture_session(Role::Client);
    let mut server = fixture_session(Role::Server);
    let c = client
        .seal(MessageType::ClientConfirm, b"confirm-body-here!!")
        .unwrap();
    server
        .open(MessageType::ClientConfirm, c.sequence, c.sealed())
        .unwrap(); // 先按真类型接受确认（期待 DATA seq=1）
    match server.open(MessageType::Data, Sequence::new(1), c.sealed()) {
        Err(SessionError::AuthenticationFailed) => {}
        Err(other) => panic!("类型混淆：期望 0x0201，得到 {other:?}"),
        Ok(_) => panic!("类型混淆必拒"),
    }
    assert!(!server.is_active());

    // 场景 2：S2C 类型（ServerConfirm）投给 C2S 接收方 ⇒ 本地配对拒绝
    // （0x0306 fail-closed：服务端接收方向恒为 C2S）
    let mut peer_client = fixture_session(Role::Client);
    let c2 = peer_client
        .seal(MessageType::ClientConfirm, b"confirm-body-here!!")
        .unwrap();
    let mut server2 = fixture_session(Role::Server);
    match server2.open(MessageType::ServerConfirm, c2.sequence, c2.sealed()) {
        Err(SessionError::WrongDirection) => {}
        Err(other) => panic!("跨类型配对：期望 0x0306，得到 {other:?}"),
        Ok(_) => panic!("跨类型配对必拒"),
    }
    assert!(!server2.is_active());
}

#[test]
fn cross_session_carry_is_rejected() {
    // 跨会话搬运：会话 A 的 record 让会话 B（不同 ζ/book_id/段号）open ⇒ 0x0201
    let (mut client_a, _server_a) = established_pair();
    let r = client_a
        .seal(MessageType::Data, b"from-session-A!!!")
        .unwrap();

    let ctx_b = Session2Ctx::variant();
    let mut server_b = Session::new(
        otp_session::CommittedSegment::from_bytes(core::array::from_fn(|i| i as u8)),
        ctx_b,
    );
    // B 侧先自我确认（不同密钥/ζ，必然失败在 tag）
    match server_b.open(MessageType::Data, r.sequence, r.sealed()) {
        // B 未先收 CONFIRM ⇒ 期待 seq=0，先撞 0x030B；为覆盖 tag 路径，
        // 用 B 自己的 CONFIRM 推进到期待 DATA(1) 后再投 A 的 record
        Err(SessionError::SequenceUnexpected) => {}
        Err(other) => panic!("B 首条期待 0，得到 {other:?}"),
        Ok(_) => panic!("B 首条期待 0，不应得到明文"),
    }
    // 新会话 B'：先走完自己的确认，再投 A 的 DATA(1)
    let mut server_b = Session::new(
        otp_session::CommittedSegment::from_bytes(core::array::from_fn(|i| i as u8)),
        ctx_b,
    );
    let b_confirm = {
        let mut ctx = Session2Ctx::variant();
        ctx.role = Role::Client; // B 会话的客户端侧（同 ζ/段/book，密钥相同）
        let mut fake_client = Session::new(
            otp_session::CommittedSegment::from_bytes(core::array::from_fn(|i| i as u8)),
            ctx,
        );
        fake_client
            .seal(MessageType::ClientConfirm, b"session-b-confirm!")
            .unwrap()
    };
    server_b
        .open(
            MessageType::ClientConfirm,
            b_confirm.sequence,
            b_confirm.sealed(),
        )
        .unwrap();
    match server_b.open(MessageType::Data, r.sequence, r.sealed()) {
        Err(SessionError::AuthenticationFailed) => {}
        Err(other) => panic!("跨会话：期望 0x0201，得到 {other:?}"),
        Ok(_) => panic!("跨会话搬运必拒"),
    }
}

/// 会话 B 的上下文（book_id/双 nonce/段号均与会话 A 不同）。
struct Session2Ctx;
impl Session2Ctx {
    fn variant() -> otp_session::SessionContext {
        otp_session::SessionContext {
            role: Role::Server,
            book_id: BookId::from_bytes([0x77; 16]),
            segment: SegmentIndex::new(9),
            client_nonce: ClientNonce::from_bytes([0x0A; 16]),
            server_nonce: ServerNonce::from_bytes([0x0B; 16]),
        }
    }
}

#[test]
fn failure_never_outputs_plaintext_and_kills_both_operations() {
    // 综合性质：任何失败后，本会话 seal 与 open 全部失效（半开不存在）
    let (mut client, mut server) = established_pair();
    let r = client
        .seal(MessageType::Data, b"will-be-tampered!")
        .unwrap();
    let mut bad = r.sealed().to_vec();
    bad[0] ^= 0xFF;
    assert!(matches!(
        server.open(MessageType::Data, r.sequence, &bad),
        Err(SessionError::AuthenticationFailed)
    ));
    assert!(!server.is_active());
    assert!(matches!(
        server.seal(MessageType::Data, b"after-death"),
        Err(SessionError::Closed)
    ));
    assert!(matches!(
        server.open(MessageType::Data, Sequence::new(2), r.sealed()),
        Err(SessionError::Closed)
    ));
    // 正常 close 幂等
    server.close();
    server.close();
}

#[test]
fn garbage_sealed_no_panic() {
    // fuzz 前置：任意伪随机字节作为 sealed 不 panic、恒失败、会话关闭
    for len in [0usize, 1, 15, 16, 17, 32, 103, 104] {
        let garbage: Vec<u8> = (0..len)
            .map(|j| (j as u8).wrapping_mul(31).wrapping_add(7 ^ len as u8))
            .collect();
        let (_client, mut server) = established_pair();
        match server.open(MessageType::Data, Sequence::new(1), &garbage) {
            Err(SessionError::AuthenticationFailed) => {}
            Err(SessionError::Closed) => unreachable!("首条失败不应是 Closed"),
            Err(other) => panic!("垃圾 {len}B：期望 0x0201，得到 {other:?}"),
            Ok(_) => panic!("垃圾 {len}B：必拒"),
        }
        assert!(!server.is_active());
    }
}
