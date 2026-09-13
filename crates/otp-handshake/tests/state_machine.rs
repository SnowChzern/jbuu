//! 状态转移全覆盖（任务 #47 验收 ①）：合法转移逐条实证 + 非法转移全拒绝。
//!
//! 对照 wp02 §4.2（H1–H13）/§4.3（服务端表）；全部使用真实分配器
//! （`CommittedSegment` 无法被 mock，类型系统强制完整 fail-to-waste 事务）。

#![forbid(unsafe_code)]

mod common;

use common::*;
use otp_codec::{ArbitrateResult, Message, MsgType};
use otp_handshake::{
    CONFIRM_LABEL_C2S, CONFIRM_LABEL_S2C, ClientPhase, HandshakeError, ServerPhase, Step,
};
use otp_session::MessageType;
use otp_types::{ClientNonce, Direction, Epoch, SegmentIndex, Sequence, ServerNonce};

// ───────────────────────── H1：HELLO 产出 ─────────────────────────

#[test]
fn h1_start_produces_canonical_hello_from_idle() {
    let (mut client, _server, client_alloc, _server_alloc) = machines("h1", fill_a(1), fill_a(1));
    let hello = client.start().unwrap();
    let Message::Hello {
        book_id,
        client_nonce,
        client_pointer,
        features,
    } = &hello
    else {
        panic!("start 必须产出 HELLO");
    };
    assert_eq!(*book_id, ID);
    assert_eq!(*client_pointer, client_alloc.state().0);
    assert_eq!(features.0, 0);
    // nonce 非全零（CSPRNG；全零概率 2^-128，可安全断言）
    assert_ne!(client_nonce.as_bytes(), &[0u8; 16]);
    // 线格式：52B 帧（WP-01 §2.2 注册表）
    assert_eq!(otp_codec::encode(&hello).unwrap().len(), 52);
    assert_eq!(client.phase(), ClientPhase::HelloSent);
}

#[test]
fn h1_start_twice_is_illegal_and_fails_closed() {
    let (mut client, _s, _ca, _sa) = machines("h1x", fill_a(1), fill_a(1));
    client.start().unwrap();
    let err = client.start().unwrap_err();
    assert_eq!(err.code(), otp_codec::ErrorCode::BAD_ORDER); // 0x0309
    assert_eq!(client.phase(), ClientPhase::Failed);
}

// ───────────── H2+H6+S1..S4+H8：完整正序（含 DATA） ─────────────

#[test]
fn full_sequence_ok_to_established_then_bidirectional_data() {
    let e = establish("full");
    // 阶段与段号
    assert_eq!(e.segment, SegmentIndex::ZERO);
    assert_eq!(e.client.phase(), ClientPhase::Established);
    assert_eq!(e.server.phase(), ServerPhase::Established);
    // 两端指针同步前进到 1（M1 验收：双方 next=1，绝不回到 0）
    assert_eq!(e.client_alloc.state().0, SegmentIndex::new(1));
    assert_eq!(e.server_alloc.state().0, SegmentIndex::new(1));
    // 消息类型序列：HELLO→ARBITRATE(OK)→ISSUE→CONFIRM_C2S→CONFIRM_S2C
    assert_eq!(e.hello.msg_type(), MsgType::Hello);
    let Message::Arbitrate {
        result,
        server_pointer,
        ..
    } = &e.arbitrate
    else {
        panic!()
    };
    assert_eq!(*result, ArbitrateResult::Ok);
    assert_eq!(*server_pointer, SegmentIndex::ZERO);
    assert_eq!(e.issue_request.msg_type(), MsgType::IssueRequest);
    assert_eq!(e.confirm_c2s.msg_type(), MsgType::ConfirmC2s);
    assert_eq!(e.confirm_s2c.msg_type(), MsgType::ConfirmS2c);
    // CONFIRM 外层纪律：epoch=0、seq=0、ζ 一致
    let Message::ConfirmC2s {
        epoch,
        seq,
        session_nonce,
        ..
    } = &e.confirm_c2s
    else {
        panic!()
    };
    assert_eq!(epoch.get(), 0);
    assert_eq!(seq.get(), 0);
    let Message::ConfirmS2c {
        session_nonce: z2, ..
    } = &e.confirm_s2c
    else {
        panic!()
    };
    assert_eq!(session_nonce, z2);

    // DATA 阶段（wp03 §4.1：CONFIRM=0，DATA 自 1 起严格 +1，双向独立）
    let (mut cs, mut ss) = (e.client_session, e.server_session);
    let p1 = cs.seal(MessageType::Data, b"ping-1").unwrap();
    assert_eq!(p1.sequence.get(), 1);
    let p2 = cs.seal(MessageType::Data, b"ping-2").unwrap();
    assert_eq!(p2.sequence.get(), 2);
    let opened = ss
        .open(MessageType::Data, p1.sequence, p1.sealed())
        .unwrap();
    assert_eq!(opened.as_bytes(), b"ping-1");
    let opened = ss
        .open(MessageType::Data, p2.sequence, p2.sealed())
        .unwrap();
    assert_eq!(opened.as_bytes(), b"ping-2");
    let q1 = ss.seal(MessageType::Data, b"pong-1").unwrap();
    assert_eq!(q1.sequence.get(), 1);
    let opened = cs
        .open(MessageType::Data, q1.sequence, q1.sealed())
        .unwrap();
    assert_eq!(opened.as_bytes(), b"pong-1");
}

#[test]
fn consecutive_sessions_consume_consecutive_segments_never_reuse() {
    // M1 验收：会话后双方 next=1；**同一对分配器**上重连，下一会话使用
    // 段 1，绝不回到段 0。
    let e = establish("sess1");
    assert_eq!(e.segment, SegmentIndex::ZERO);
    let mut client_alloc = e.client_alloc;
    let mut server_alloc = e.server_alloc;
    assert_eq!(client_alloc.state().0, SegmentIndex::new(1));
    assert_eq!(server_alloc.state().0, SegmentIndex::new(1));
    let (mut client2, mut server2) = (
        otp_handshake::ClientHandshake::new(client_cfg(client_alloc.state().0, COUNT)).unwrap(),
        otp_handshake::ServerHandshake::new(server_cfg(server_alloc.state().0, COUNT)).unwrap(),
    );
    let hello2 = client2.start().unwrap();
    let arb2 = server2.on_hello(&hello2).unwrap();
    let Step::Send(out2) = client2.handle(&arb2, &mut client_alloc) else {
        panic!()
    };
    let Step::AwaitPeer = server2.on_issue_request(&out2[0], &mut server_alloc) else {
        panic!()
    };
    let Step::Established {
        outbox,
        segment: seg2,
        ..
    } = server2.on_confirm(&out2[1])
    else {
        panic!()
    };
    assert_eq!(seg2, SegmentIndex::new(1), "使用段 1，绝不回到段 0");
    let Step::Established { .. } = client2.handle(&outbox[0], &mut client_alloc) else {
        panic!()
    };
    assert_eq!(client_alloc.state().0, SegmentIndex::new(2));
    assert_eq!(server_alloc.state().0, SegmentIndex::new(2));
}

// ───────────── H3：SERVER_AHEAD 只前进并废弃间隙 ─────────────

#[test]
fn h3_server_ahead_client_jumps_forward_wastes_gap_only() {
    let (mut client, _server0, mut client_alloc, mut server_alloc) =
        machines("sa", fill_a(2), fill_a(2));
    // 服务端领先 2 段（next=2）；客户端指针 0。先推锚再建状态机（配置
    // 必须取推进后的指针）。
    advance(&mut server_alloc, 2);
    assert_eq!(server_alloc.state().0, SegmentIndex::new(2));
    let mut server =
        otp_handshake::ServerHandshake::new(server_cfg(server_alloc.state().0, COUNT)).unwrap();

    let hello = client.start().unwrap();
    let arbitrate = server.on_hello(&hello).unwrap();
    let Message::Arbitrate {
        result,
        server_pointer,
        ..
    } = &arbitrate
    else {
        panic!()
    };
    assert_eq!(*result, ArbitrateResult::ServerAhead);
    assert_eq!(*server_pointer, SegmentIndex::new(2));

    // 客户端：跳段（废弃 [0,2)）→ ISSUE(2) + CONFIRM_C2S
    let Step::Send(outbound) = client.handle(&arbitrate, &mut client_alloc) else {
        panic!("SERVER_AHEAD 应继续握手");
    };
    // 审计：WASTED_GAP 端点
    assert_eq!(
        client.wasted_gap(),
        Some((SegmentIndex::ZERO, SegmentIndex::new(2)))
    );
    assert_eq!(client.arbitrated_segment(), Some(SegmentIndex::new(2)));
    let Message::IssueRequest { chosen_pointer, .. } = &outbound[0] else {
        panic!()
    };
    assert_eq!(*chosen_pointer, SegmentIndex::new(2));

    let Step::AwaitPeer = server.on_issue_request(&outbound[0], &mut server_alloc) else {
        panic!()
    };
    let Step::Established {
        outbox,
        session,
        segment,
    } = server.on_confirm(&outbound[1])
    else {
        panic!()
    };
    assert_eq!(segment, SegmentIndex::new(2));
    let Step::Established { .. } = client.handle(&outbox[0], &mut client_alloc) else {
        panic!()
    };
    // 两端指针同步 = 3（间隙 0、1 与会话段 2 均已消耗，绝不回收）
    assert_eq!(client_alloc.state().0, SegmentIndex::new(3));
    assert_eq!(server_alloc.state().0, SegmentIndex::new(3));
    assert!(session.is_active());
    // 服务端零动作零回退：其分配器只因自身 issue 前进（2→3）
    assert_eq!(server_alloc.state().0, SegmentIndex::new(3));
}

// ───────────── H4/S1‴：CLIENT_AHEAD 人工态、服务端零回退 ─────────────

#[test]
fn h4_client_ahead_freezes_both_sides_server_never_rolls_back() {
    let (_client0, mut server, mut client_alloc, server_alloc) =
        machines("ca", fill_a(3), fill_a(3));
    // 客户端领先 2 段（next=2）；服务端指针 0。先推锚再建状态机。
    advance(&mut client_alloc, 2);
    let mut client =
        otp_handshake::ClientHandshake::new(client_cfg(client_alloc.state().0, COUNT)).unwrap();

    let hello = client.start().unwrap();
    let arbitrate = server.on_hello(&hello).unwrap();
    let Message::Arbitrate {
        result,
        server_pointer,
        ..
    } = &arbitrate
    else {
        panic!()
    };
    assert_eq!(*result, ArbitrateResult::ClientAhead);
    assert_eq!(*server_pointer, SegmentIndex::ZERO);
    // 服务端：指针冻结（AheadPending，绝不回退/前推）
    assert_eq!(server.phase(), ServerPhase::AheadPending);
    assert_eq!(server_alloc.state().0, SegmentIndex::ZERO);

    // 客户端：AheadRecovery（本地分配器冻结，本实例不再 issue）
    let Step::Failed(HandshakeError::ClientAhead {
        client: c,
        server: s,
    }) = client.handle(&arbitrate, &mut client_alloc)
    else {
        panic!("CLIENT_AHEAD 应进入恢复态失败终态");
    };
    assert_eq!(c, SegmentIndex::new(2));
    assert_eq!(s, SegmentIndex::ZERO);
    assert_eq!(client.phase(), ClientPhase::AheadRecovery);
    assert_eq!(
        client_alloc.state().0,
        SegmentIndex::new(2),
        "客户端指针冻结"
    );

    // 两端均为终态：后续任何消息一律拒绝（无自动路径，wp02 §4.4）。
    // AheadRecovery 收到协议消息 = 非法转移 → 更严的 Failed 终态。
    let Step::Failed(err) = client.handle(&arbitrate, &mut client_alloc) else {
        panic!()
    };
    assert_eq!(err.code(), otp_codec::ErrorCode::BAD_ORDER);
    assert_eq!(client.phase(), ClientPhase::Failed, "终态无出边");
    assert!(server.on_hello(&hello).is_err());
    assert_eq!(server.phase(), ServerPhase::Failed);
    assert_eq!(server_alloc.state().0, SegmentIndex::ZERO, "零回退");
}

// ───────────── H5：EXHAUSTED / BOOK_MISMATCH ─────────────

#[test]
fn h5_exhausted_at_arbitration_closes_without_issuing() {
    let (_client0, _server0, mut client_alloc, mut server_alloc) =
        machines("exh", fill_a(4), fill_a(4));
    // 双端指针推到 N=COUNT（耗尽）
    advance(&mut client_alloc, COUNT);
    advance(&mut server_alloc, COUNT);
    // 配置指针与分配器一致（先推锚再建状态机）
    let mut client =
        otp_handshake::ClientHandshake::new(client_cfg(client_alloc.state().0, COUNT)).unwrap();
    let mut server =
        otp_handshake::ServerHandshake::new(server_cfg(server_alloc.state().0, COUNT)).unwrap();

    let hello = client.start().unwrap();
    let arbitrate = server.on_hello(&hello).unwrap();
    let Message::Arbitrate {
        result,
        server_pointer,
        ..
    } = &arbitrate
    else {
        panic!()
    };
    assert_eq!(*result, ArbitrateResult::Exhausted);
    assert_eq!(server_pointer.get(), COUNT, "EXHAUSTED 时 sp=N");

    let Step::Failed(HandshakeError::Exhausted { next }) =
        client.handle(&arbitrate, &mut client_alloc)
    else {
        panic!()
    };
    assert_eq!(next.get(), COUNT);
    assert_eq!(client.phase(), ClientPhase::Failed);
    // 不耗段：两端分配器状态不动
    assert_eq!(client_alloc.state().0.get(), COUNT);
    assert_eq!(server_alloc.state().0.get(), COUNT);
}

#[test]
fn h5_book_mismatch_detected_before_arbitration_and_issuance() {
    // 规划 §5 场景 2 前半：不同 book_id。
    let (mut client, _server0, mut client_alloc, server_alloc) =
        machines("bm", fill_a(5), fill_a(5));
    // 服务端配置改成另一 book_id（模拟两端错本）
    let other = otp_handshake::ServerConfig {
        version: otp_codec::ProtocolVersion::V2,
        book_id: otp_types::BookId::from_bytes(*b"OTPTERM-OTHERBK1"),
        local_pointer: server_alloc.state().0,
        segment_count: COUNT,
    };
    let mut server = otp_handshake::ServerHandshake::new(other).unwrap();

    let hello = client.start().unwrap();
    let arbitrate = server.on_hello(&hello).unwrap();
    let Message::Arbitrate {
        result,
        server_pointer,
        ..
    } = &arbitrate
    else {
        panic!()
    };
    // BOOK_MISMATCH：先于仲裁（sp 恒 0），未进入 IssueWait
    assert_eq!(*result, ArbitrateResult::BookMismatch);
    assert_eq!(*server_pointer, SegmentIndex::ZERO);
    assert_eq!(server.phase(), ServerPhase::Failed);

    let Step::Failed(HandshakeError::BookMismatch) = client.handle(&arbitrate, &mut client_alloc)
    else {
        panic!()
    };
    assert_eq!(client.phase(), ClientPhase::Failed);
    // 双端零签发、零消耗
    assert_eq!(client_alloc.state().0, SegmentIndex::ZERO);
    assert_eq!(server_alloc.state().0, SegmentIndex::ZERO);
}

// ───────────── 0x0307：ARBITRATE 组合矛盾 ─────────────

fn arbitrate_msg(result: ArbitrateResult, sp: u64, nonce: ServerNonce) -> Message {
    Message::Arbitrate {
        server_nonce: nonce,
        server_pointer: SegmentIndex::new(sp),
        result,
    }
}

#[test]
fn arbitrate_combination_violations_are_0307_fail_closed() {
    let cases: &[(ArbitrateResult, u64)] = &[
        (ArbitrateResult::Ok, 5),          // OK 但 sp≠cp(0)
        (ArbitrateResult::ServerAhead, 0), // sp 不 > cp
        (ArbitrateResult::ServerAhead, 0),
        (ArbitrateResult::ClientAhead, 0), // sp 不 < cp（相等）
        (ArbitrateResult::ClientAhead, 3), // sp > cp
        (ArbitrateResult::Exhausted, COUNT - 1), // sp ≠ N
    ];
    for &(result, sp) in cases {
        let (mut client, _s, mut client_alloc, _sa) = machines("t307", fill_a(6), fill_a(6));
        client.start().unwrap();
        let msg = arbitrate_msg(result, sp, ServerNonce::from_bytes([7; 16]));
        let Step::Failed(err) = client.handle(&msg, &mut client_alloc) else {
            panic!("{result:?}/{sp} 应被拒绝");
        };
        assert_eq!(
            err.code(),
            otp_codec::ErrorCode::ISSUE_POINTER_MISMATCH,
            "{result:?}/{sp}"
        );
        assert_eq!(client.phase(), ClientPhase::Failed);
        assert_eq!(client_alloc.state().0, SegmentIndex::ZERO, "不耗段");
    }
}

// ───────────── 0x0309：消息类型 × 状态非法转移全拒绝 ─────────────

#[test]
fn client_rejects_wrong_message_types_in_every_phase() {
    let wrong_in_hello_sent = [
        MsgType::Hello,
        MsgType::IssueRequest,
        MsgType::ConfirmC2s,
        MsgType::Data,
    ];
    for ty in wrong_in_hello_sent {
        let (mut client, _s, mut ca, _sa) = machines("ord1", fill_a(7), fill_a(7));
        client.start().unwrap();
        let msg = sample_message_of_type(ty);
        let Step::Failed(err) = client.handle(&msg, &mut ca) else {
            panic!("{ty:?} 在 HelloSent 应被拒绝");
        };
        assert_eq!(err.code(), otp_codec::ErrorCode::BAD_ORDER);
        assert_eq!(client.phase(), ClientPhase::Failed);
    }
    // ConfirmSent 阶段：非 CONFIRM_S2C 全拒
    for ty in [
        MsgType::Hello,
        MsgType::Arbitrate,
        MsgType::IssueRequest,
        MsgType::ConfirmC2s,
        MsgType::Data,
    ] {
        let (mut client, _s, mut ca, _sa) = machines("ord2", fill_a(7), fill_a(7));
        let hello = client.start().unwrap();
        let arb = otp_handshake::ServerHandshake::new(server_cfg(SegmentIndex::ZERO, COUNT))
            .unwrap()
            .on_hello(&hello)
            .unwrap();
        let Step::Send(_) = client.handle(&arb, &mut ca) else {
            panic!()
        };
        assert_eq!(client.phase(), ClientPhase::ConfirmSent);
        let msg = sample_message_of_type(ty);
        let Step::Failed(err) = client.handle(&msg, &mut ca) else {
            panic!("{ty:?} 在 ConfirmSent 应被拒绝");
        };
        assert_eq!(err.code(), otp_codec::ErrorCode::BAD_ORDER);
    }
    // Idle（未 start）与 Established：任何消息全拒
    {
        let (mut client, _s, mut ca, _sa) = machines("ord3", fill_a(7), fill_a(7));
        let msg = sample_message_of_type(MsgType::Arbitrate);
        let Step::Failed(err) = client.handle(&msg, &mut ca) else {
            panic!()
        };
        assert_eq!(err.code(), otp_codec::ErrorCode::BAD_ORDER);
    }
    {
        let e = establish("ord4");
        let mut client = e.client;
        let mut ca = e.client_alloc;
        let msg = sample_message_of_type(MsgType::ConfirmS2c);
        let Step::Failed(err) = client.handle(&msg, &mut ca) else {
            panic!("Established 后握手层不再收消息");
        };
        assert_eq!(err.code(), otp_codec::ErrorCode::BAD_ORDER);
    }
}

#[test]
fn server_rejects_wrong_message_types_and_states() {
    // on_hello 非 HELLO / 重复 on_hello
    {
        let (_c, mut server, _ca, _sa) = machines("sord1", fill_a(8), fill_a(8));
        let msg = sample_message_of_type(MsgType::IssueRequest);
        let err = server.on_hello(&msg).unwrap_err();
        assert_eq!(err.code(), otp_codec::ErrorCode::BAD_ORDER);
        assert_eq!(server.phase(), ServerPhase::Failed);
    }
    {
        let (mut client, mut server, _ca, _sa) = machines("sord2", fill_a(8), fill_a(8));
        let hello = client.start().unwrap();
        server.on_hello(&hello).unwrap();
        assert_eq!(server.phase(), ServerPhase::IssueWait);
        let err = server.on_hello(&hello).unwrap_err();
        assert_eq!(err.code(), otp_codec::ErrorCode::BAD_ORDER);
        assert_eq!(server.phase(), ServerPhase::Failed);
    }
    // on_issue_request 在 Idle（未仲裁）应拒绝
    {
        let (mut client, mut server, _ca, mut sa) = machines("sord3", fill_a(8), fill_a(8));
        let hello = client.start().unwrap();
        let req = sample_message_of_type(MsgType::IssueRequest);
        let Step::Failed(err) = server.on_issue_request(&req, &mut sa) else {
            panic!()
        };
        assert_eq!(err.code(), otp_codec::ErrorCode::BAD_ORDER);
        // 尚未消耗任何段
        assert_eq!(sa.state().0, SegmentIndex::ZERO);
        let _ = hello;
    }
    // on_confirm 在 IssueWait（未签发）应拒绝
    {
        let (mut client, mut server, _ca, sa) = machines("sord4", fill_a(8), fill_a(8));
        let hello = client.start().unwrap();
        server.on_hello(&hello).unwrap();
        let confirm = sample_message_of_type(MsgType::ConfirmC2s);
        let Step::Failed(err) = server.on_confirm(&confirm) else {
            panic!()
        };
        assert_eq!(err.code(), otp_codec::ErrorCode::BAD_ORDER);
        assert_eq!(sa.state().0, SegmentIndex::ZERO, "不耗段");
    }
    // Established 后重复 CONFIRM_C2S（重复 sequence 的握手层拒绝）
    {
        let e = establish("sord5");
        let mut server = e.server;
        let confirm = e.confirm_c2s.clone();
        let Step::Failed(err) = server.on_confirm(&confirm) else {
            panic!("Established 后不得再收 CONFIRM");
        };
        assert_eq!(err.code(), otp_codec::ErrorCode::BAD_ORDER);
    }
}

fn sample_message_of_type(ty: MsgType) -> Message {
    let n = ClientNonce::from_bytes([1; 16]);
    let s = ServerNonce::from_bytes([2; 16]);
    match ty {
        MsgType::Hello => Message::Hello {
            book_id: ID,
            client_nonce: n,
            client_pointer: SegmentIndex::ZERO,
            features: Default::default(),
        },
        MsgType::Arbitrate => arbitrate_msg(ArbitrateResult::Ok, 0, s),
        MsgType::IssueRequest => Message::IssueRequest {
            chosen_pointer: SegmentIndex::ZERO,
            client_nonce: n,
            server_nonce: s,
        },
        MsgType::ConfirmC2s => Message::ConfirmC2s {
            segment_index: SegmentIndex::ZERO,
            session_nonce: otp_types::SessionNonce::from_bytes([3; 16]),
            epoch: Epoch::new(0),
            seq: Sequence::ZERO,
            sealed: [0x42; otp_codec::SEALED_LEN],
        },
        MsgType::ConfirmS2c => Message::ConfirmS2c {
            segment_index: SegmentIndex::ZERO,
            session_nonce: otp_types::SessionNonce::from_bytes([3; 16]),
            epoch: Epoch::new(0),
            seq: Sequence::ZERO,
            sealed: [0x42; otp_codec::SEALED_LEN],
        },
        MsgType::Data => Message::Data {
            epoch: Epoch::new(0),
            seq: Sequence::new(1),
            data: vec![0u8; 16],
        },
    }
}

// ───────────── S2 前置校验：不耗段拒绝 ─────────────

#[test]
fn s_issue_pointer_and_nonce_echo_rejected_before_reservation() {
    // chosen ≠ 仲裁约定 i → 0x0307，不耗段
    {
        let (mut client, mut server, _ca, mut sa) = machines("s2a", fill_a(9), fill_a(9));
        let hello = client.start().unwrap();
        let arbitrate = server.on_hello(&hello).unwrap();
        let Message::Arbitrate { server_nonce, .. } = &arbitrate else {
            panic!()
        };
        let Message::Hello { client_nonce, .. } = &hello else {
            panic!()
        };
        let bad = Message::IssueRequest {
            chosen_pointer: SegmentIndex::new(1), // 约定 0
            client_nonce: *client_nonce,
            server_nonce: *server_nonce,
        };
        let Step::Failed(err) = server.on_issue_request(&bad, &mut sa) else {
            panic!()
        };
        assert_eq!(err.code(), otp_codec::ErrorCode::ISSUE_POINTER_MISMATCH);
        assert_eq!(server.phase(), ServerPhase::Failed);
        assert_eq!(sa.state().0, SegmentIndex::ZERO, "预留前拒绝不耗段");
    }
    // client_nonce 回显错 / server_nonce 回显错 → 0x0203，不耗段
    for bad_nonce in [0usize, 1] {
        let (mut client, mut server, _ca, mut sa) = machines("s2b", fill_a(9), fill_a(9));
        let hello = client.start().unwrap();
        let arbitrate = server.on_hello(&hello).unwrap();
        let Message::Arbitrate { server_nonce, .. } = &arbitrate else {
            panic!()
        };
        let Message::Hello { client_nonce, .. } = &hello else {
            panic!()
        };
        let (cn, sn) = if bad_nonce == 0 {
            let mut b = *client_nonce.as_bytes();
            b[0] ^= 1;
            (ClientNonce::from_bytes(b), *server_nonce)
        } else {
            let mut b = *server_nonce.as_bytes();
            b[0] ^= 1;
            (*client_nonce, ServerNonce::from_bytes(b))
        };
        let bad = Message::IssueRequest {
            chosen_pointer: SegmentIndex::ZERO,
            client_nonce: cn,
            server_nonce: sn,
        };
        let Step::Failed(err) = server.on_issue_request(&bad, &mut sa) else {
            panic!()
        };
        assert_eq!(err.code(), otp_codec::ErrorCode::NONCE_MISMATCH); // 0x0203
        assert_eq!(sa.state().0, SegmentIndex::ZERO, "预留前拒绝不耗段");
    }
}

// ───────────── H13/S13：abort ─────────────

#[test]
fn h13_abort_fails_closed_and_burns_pending_session() {
    let e = establish("abort"); // 双端 Established
    let mut client = e.client;
    let mut server = e.server;
    let mut ca = e.client_alloc;
    let sa = e.server_alloc;
    let step = client.abort(otp_codec::ErrorCode::IO_ERROR);
    assert!(matches!(step, Step::Failed(_)));
    assert_eq!(client.phase(), ClientPhase::Failed);
    let step = server.abort(otp_codec::ErrorCode::IO_ERROR);
    assert!(matches!(step, Step::Failed(_)));
    assert_eq!(server.phase(), ServerPhase::Failed);
    // 已消耗段不回收
    assert_eq!(ca.state().0, SegmentIndex::new(1));
    assert_eq!(sa.state().0, SegmentIndex::new(1));
    // 终态后一切输入拒绝
    let Step::Failed(_) = client.handle(&e.confirm_s2c, &mut ca) else {
        panic!()
    };
    let Step::Failed(_) = server.on_confirm(&e.confirm_c2s) else {
        panic!()
    };
}

// ───────────── 标签常量 ─────────────

#[test]
fn confirm_labels_match_wire_spec() {
    assert_eq!(CONFIRM_LABEL_C2S, b"client-confirm");
    assert_eq!(CONFIRM_LABEL_S2C, b"server-confirm");
    let _ = Direction::ClientToServer; // 引用防未用告警
}
