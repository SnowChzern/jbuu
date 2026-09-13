//! 错误路径 fail-closed（任务 #47 验收 ③；规划 §5 场景 2 双向夹具）。
//!
//! 覆盖：CONFIRM 外层字段违规（0x0202/0x0203/0x030A/0x030B）、tag 失败即
//! 关闭（0x0201）、tag 合法但内层副本不符（0x0202/0x0203/0x030A/0x030B）、
//! 重复 sequence 拒绝（握手层状态拒绝 + record 层 0x0204/0x030B）、两端
//! 错本：异 book_id（ARBITRATE 前 0x0100，见 state_machine 测试）与
//! **同 ID 异正文**（最迟 CONFIRM tag 失败，段按规则消耗不降级、不复用）。

#![forbid(unsafe_code)]

mod common;

use common::*;
use otp_codec::{
    ArbitrateResult, ConfirmBody, ErrorCode, Message, MsgType, SEALED_LEN, encode_confirm_body,
};
use otp_handshake::{ClientPhase, ServerPhase, Step};
use otp_session::{CommittedSegment as SessionSegment, MessageType, Session, SessionContext};
use otp_testkit::IssueOracle;
use otp_types::{
    BookId, ClientNonce, Direction, Epoch, Role, SEGMENT_LEN, SegmentIndex, Sequence, ServerNonce,
};

/// 用测试已知的段内容构造一个与真实机器同上下文的会话（仅测试：
/// 用于封装"tag 合法但内文被篡改"或"异正文密钥"的负例）。
fn forged_session(
    segment_bytes: [u8; SEGMENT_LEN],
    segment: SegmentIndex,
    client_nonce: ClientNonce,
    server_nonce: ServerNonce,
    role: Role,
) -> Session {
    Session::new(
        SessionSegment::from_bytes(segment_bytes),
        SessionContext {
            role,
            book_id: ID,
            segment,
            client_nonce,
            server_nonce,
        },
    )
}

/// 合法 C2S 确认副本（与正序机器的期望一致）。
fn legit_c2s_body(hello: &Message, arbitrate: &Message, segment: SegmentIndex) -> ConfirmBody {
    let Message::Hello { client_nonce, .. } = hello else {
        panic!()
    };
    let Message::Arbitrate { server_nonce, .. } = arbitrate else {
        panic!()
    };
    ConfirmBody {
        book_id: ID,
        segment_index: segment,
        client_nonce: *client_nonce,
        server_nonce: *server_nonce,
        direction: Direction::ClientToServer,
        epoch: Epoch::new(0),
        seq: Sequence::ZERO,
        msg_type: MsgType::ConfirmC2s.wire(),
        label: *b"client-confirm",
    }
}

/// 合法 S2C 确认副本。
fn legit_s2c_body(hello: &Message, arbitrate: &Message, segment: SegmentIndex) -> ConfirmBody {
    let mut body = legit_c2s_body(hello, arbitrate, segment);
    body.direction = Direction::ServerToClient;
    body.msg_type = MsgType::ConfirmS2c.wire();
    body.label = *b"server-confirm";
    body
}

/// 以指定段内容封装一条 CONFIRM（外层字段合规；tag 在该内容派生的
/// 密钥下合法——正文/密钥是否匹配真实机器由调用方控制）。
fn forged_confirm(
    hello: &Message,
    arbitrate: &Message,
    segment_bytes: [u8; SEGMENT_LEN],
    body: ConfirmBody,
    role: Role,
) -> Message {
    let Message::Hello { client_nonce, .. } = hello else {
        panic!()
    };
    let Message::Arbitrate { server_nonce, .. } = arbitrate else {
        panic!()
    };
    let mut session = forged_session(
        segment_bytes,
        SegmentIndex::ZERO,
        *client_nonce,
        *server_nonce,
        role,
    );
    let (mt, plain) = match role {
        Role::Client => (
            MessageType::ClientConfirm,
            encode_confirm_body(&body).unwrap(),
        ),
        Role::Server => (
            MessageType::ServerConfirm,
            encode_confirm_body(&body).unwrap(),
        ),
    };
    let record = session.seal(mt, &plain).unwrap();
    let mut sealed = [0u8; SEALED_LEN];
    sealed.copy_from_slice(record.sealed());
    let fields = (
        SegmentIndex::ZERO,
        session.context().session_nonce(),
        Epoch::new(0),
        record.sequence,
        sealed,
    );
    match role {
        Role::Client => {
            let (segment_index, session_nonce, epoch, seq, sealed) = fields;
            Message::ConfirmC2s {
                segment_index,
                session_nonce,
                epoch,
                seq,
                sealed,
            }
        }
        Role::Server => {
            let (segment_index, session_nonce, epoch, seq, sealed) = fields;
            Message::ConfirmS2c {
                segment_index,
                session_nonce,
                epoch,
                seq,
                sealed,
            }
        }
    }
}

/// 正序驱动到服务端 ConfirmWait（客户端已发 ISSUE + CONFIRM_C2S，
/// 服务端已签发）。返回机器/分配器与两条出站消息。
struct AtConfirmWait {
    hello: Message,
    arbitrate: Message,
    confirm_c2s: Message,
    client: otp_handshake::ClientHandshake,
    server: otp_handshake::ServerHandshake,
    client_alloc: otp_allocator::Allocator,
    server_alloc: otp_allocator::Allocator,
}

fn drive_to_confirm_wait(tag: &str) -> AtConfirmWait {
    let (mut client, mut server, mut client_alloc, mut server_alloc) =
        machines(tag, fill_a(0x21), fill_a(0x21));
    let hello = client.start().unwrap();
    let arbitrate = server.on_hello(&hello).unwrap();
    let Step::Send(outbound) = client.handle(&arbitrate, &mut client_alloc) else {
        panic!("{tag}: 客户端应产出 ISSUE+CONFIRM");
    };
    let confirm_c2s = outbound[1].clone();
    let Step::AwaitPeer = server.on_issue_request(&outbound[0], &mut server_alloc) else {
        panic!("{tag}: 服务端应进入 ConfirmWait");
    };
    assert_eq!(server.phase(), ServerPhase::ConfirmWait);
    AtConfirmWait {
        hello,
        arbitrate,
        confirm_c2s,
        client,
        server,
        client_alloc,
        server_alloc,
    }
}

#[test]
fn confirm_outer_field_violations_fail_closed_with_exact_codes() {
    struct Case {
        name: &'static str,
        mutate: fn(&mut Message),
        expect: ErrorCode,
    }
    let cases = [
        Case {
            name: "segment_index != i → 0x0202",
            mutate: |m: &mut Message| {
                if let Message::ConfirmC2s { segment_index, .. } = m {
                    *segment_index = SegmentIndex::new(7);
                }
            },
            expect: ErrorCode::SEGMENT_BINDING,
        },
        Case {
            name: "session_nonce != ζ → 0x0203",
            mutate: |m: &mut Message| {
                if let Message::ConfirmC2s { session_nonce, .. } = m {
                    let mut b = *session_nonce.as_bytes();
                    b[15] ^= 1;
                    *session_nonce = otp_types::SessionNonce::from_bytes(b);
                }
            },
            expect: ErrorCode::NONCE_MISMATCH,
        },
        Case {
            name: "epoch != 0 → 0x030A",
            mutate: |m: &mut Message| {
                if let Message::ConfirmC2s { epoch, .. } = m {
                    *epoch = Epoch::new(1);
                }
            },
            expect: ErrorCode::EPOCH_MISMATCH,
        },
        Case {
            name: "seq != 0 → 0x030B",
            mutate: |m: &mut Message| {
                if let Message::ConfirmC2s { seq, .. } = m {
                    *seq = Sequence::new(1);
                }
            },
            expect: ErrorCode::SEQ_UNEXPECTED,
        },
    ];
    for case in cases {
        let mut at = drive_to_confirm_wait("outer");
        assert_eq!(
            at.server_alloc.state().0,
            SegmentIndex::new(1),
            "已签发消耗"
        );
        let mut confirm = at.confirm_c2s.clone();
        (case.mutate)(&mut confirm);
        let Step::Failed(err) = at.server.on_confirm(&confirm) else {
            panic!("{}: 应失败", case.name)
        };
        assert_eq!(err.code(), case.expect, "{}", case.name);
        assert_eq!(at.server.phase(), ServerPhase::Failed, "{}", case.name);
        // 段已消耗、指针不回退、不复用
        assert_eq!(at.server_alloc.state().0, SegmentIndex::new(1));
        // 终态后重复投递同一消息仍拒绝
        let Step::Failed(_) = at.server.on_confirm(&confirm) else {
            panic!("{}: 终态无出边", case.name)
        };
    }
}

#[test]
fn confirm_tag_failure_closes_immediately() {
    let mut at = drive_to_confirm_wait("tag");
    let mut confirm = at.confirm_c2s.clone();
    if let Message::ConfirmC2s { sealed, .. } = &mut confirm {
        sealed[0] ^= 0x01; // 翻转密文 1 bit
    }
    let Step::Failed(err) = at.server.on_confirm(&confirm) else {
        panic!("tag 篡改必须失败")
    };
    assert_eq!(err.code(), ErrorCode::TAG_INVALID); // 0x0201
    assert_eq!(at.server.phase(), ServerPhase::Failed);
    // tag 失败即关闭：段已消耗，绝不重试同段/降级
    assert_eq!(at.server_alloc.state().0, SegmentIndex::new(1));
    // 客户端尚未收到 CONFIRM_S2C：H13 abort 关闭，其段同样已消耗
    assert!(matches!(
        at.client.abort(ErrorCode::IO_ERROR),
        Step::Failed(_)
    ));
    assert_eq!(at.client.phase(), ClientPhase::Failed);
    assert_eq!(at.client_alloc.state().0, SegmentIndex::new(1));
}

#[test]
fn confirm_body_binding_failures_with_valid_tag() {
    // tag 合法（测试以真实同段内容封装），但内层副本被篡改：最迟 CONFIRM
    // 处拒绝（0x0202/0x0203/0x030A/0x030B），不降级。
    let content = fill_a(0x21)(0); // 与 drive_to_confirm_wait 的书内容一致
    struct Case {
        name: &'static str,
        mutate: fn(&mut ConfirmBody),
        expect: ErrorCode,
    }
    let cases = [
        Case {
            name: "body.segment_index != i → 0x0202",
            mutate: |b: &mut ConfirmBody| b.segment_index = SegmentIndex::new(5),
            expect: ErrorCode::SEGMENT_BINDING,
        },
        Case {
            name: "body.book_id != 会话 book_id → 0x0202",
            mutate: |b: &mut ConfirmBody| b.book_id = BookId::from_bytes(*b"OTPTERM-OTHERBK1"),
            expect: ErrorCode::SEGMENT_BINDING,
        },
        Case {
            name: "body.direction = S2C → 0x0202",
            mutate: |b: &mut ConfirmBody| b.direction = Direction::ServerToClient,
            expect: ErrorCode::SEGMENT_BINDING,
        },
        Case {
            name: "body.msg_type = 0x0005 → 0x0202",
            mutate: |b: &mut ConfirmBody| b.msg_type = MsgType::ConfirmS2c.wire(),
            expect: ErrorCode::SEGMENT_BINDING,
        },
        Case {
            name: "body.label 末字节翻转 → 0x0202",
            mutate: |b: &mut ConfirmBody| b.label[13] ^= 1,
            expect: ErrorCode::SEGMENT_BINDING,
        },
        Case {
            name: "body.client_nonce 回显错 → 0x0203",
            mutate: |b: &mut ConfirmBody| {
                let mut n = *b.client_nonce.as_bytes();
                n[0] ^= 1;
                b.client_nonce = ClientNonce::from_bytes(n)
            },
            expect: ErrorCode::NONCE_MISMATCH,
        },
        Case {
            name: "body.server_nonce 回显错 → 0x0203",
            mutate: |b: &mut ConfirmBody| {
                let mut n = *b.server_nonce.as_bytes();
                n[0] ^= 1;
                b.server_nonce = ServerNonce::from_bytes(n)
            },
            expect: ErrorCode::NONCE_MISMATCH,
        },
        Case {
            name: "body.epoch != 0 → 0x030A",
            mutate: |b: &mut ConfirmBody| b.epoch = Epoch::new(2),
            expect: ErrorCode::EPOCH_MISMATCH,
        },
        Case {
            name: "body.seq != 0 → 0x030B",
            mutate: |b: &mut ConfirmBody| b.seq = Sequence::new(9),
            expect: ErrorCode::SEQ_UNEXPECTED,
        },
    ];
    // 基线：同内容同上下文、未篡改副本的封装必须通过（证明封装夹具合法）
    {
        let mut at = drive_to_confirm_wait("inner-base");
        let body = legit_c2s_body(&at.hello, &at.arbitrate, SegmentIndex::ZERO);
        let forged = forged_confirm(&at.hello, &at.arbitrate, content, body, Role::Client);
        let Step::Established { .. } = at.server.on_confirm(&forged) else {
            panic!("基线：同密钥同副本的 CONFIRM 必须通过")
        };
        assert_eq!(at.server.phase(), ServerPhase::Established);
    }
    for case in cases {
        let mut at = drive_to_confirm_wait("inner");
        let mut body = legit_c2s_body(&at.hello, &at.arbitrate, SegmentIndex::ZERO);
        (case.mutate)(&mut body);
        let forged = forged_confirm(&at.hello, &at.arbitrate, content, body, Role::Client);
        let Step::Failed(err) = at.server.on_confirm(&forged) else {
            panic!("{}: tag 合法但副本错必须拒绝", case.name)
        };
        assert_eq!(err.code(), case.expect, "{}", case.name);
        assert_eq!(at.server.phase(), ServerPhase::Failed, "{}", case.name);
        assert_eq!(
            at.server_alloc.state().0,
            SegmentIndex::new(1),
            "{}: 段已消耗不降级",
            case.name
        );
    }
}

#[test]
fn duplicate_sequence_rejected_at_handshake_and_record_layer() {
    // 握手层：CONFIRM seq≠0 → 0x030B（外层校验，先于 AEAD）；段已消耗
    {
        let mut at = drive_to_confirm_wait("dup");
        let mut confirm = at.confirm_c2s.clone();
        if let Message::ConfirmC2s { seq, .. } = &mut confirm {
            *seq = Sequence::new(1);
        }
        let Step::Failed(err) = at.server.on_confirm(&confirm) else {
            panic!()
        };
        assert_eq!(err.code(), ErrorCode::SEQ_UNEXPECTED); // 0x030B
        assert_eq!(at.server_alloc.state().0, SegmentIndex::new(1), "段已消耗");
    }
    // record 层：DATA 精确重放（重复 seq）→ 0x0204，会话立即焚毁密钥
    {
        let e = establish("dup-rec");
        let (mut cs, mut ss) = (e.client_session, e.server_session);
        let rec1 = cs.seal(MessageType::Data, b"x1").unwrap();
        assert_eq!(rec1.sequence.get(), 1);
        assert!(
            ss.open(MessageType::Data, rec1.sequence, rec1.sealed())
                .is_ok()
        );
        assert!(matches!(
            ss.open(MessageType::Data, rec1.sequence, rec1.sealed()),
            Err(otp_session::SessionError::SequenceReplay)
        ));
        assert!(!ss.is_active(), "重复序号：立即焚毁密钥并终止");
        let rec2 = cs.seal(MessageType::Data, b"x2").unwrap();
        assert!(
            ss.open(MessageType::Data, rec2.sequence, rec2.sealed())
                .is_err()
        );
    }
}

#[test]
fn scenario2_same_book_id_different_body_fails_at_confirm_and_segments_consumed() {
    // 规划 §5 场景 2 后半（双向）：
    // ① 服务端视角：客户端书 A / 服务端书 B（同 ID 异正文）→ 服务端在
    //    CONFIRM tag 处失败，两端段均按规则消耗；
    // ② 客户端视角（对称夹具）：服务端以 B 的密钥封装的 CONFIRM_S2C →
    //    客户端 tag 失败；
    // ③ 段 0 绝不复用：IssueOracle 全局唯一性。
    assert!(fills_differ(0x71), "夹具前提：同 ID 异正文");

    // ① 服务端视角
    let (mut client, mut server, mut client_alloc, mut server_alloc) =
        machines("sc2-srv", fill_a(0x71), fill_b(0x71));
    let hello = client.start().unwrap();
    let arbitrate = server.on_hello(&hello).unwrap();
    let Message::Arbitrate { result, .. } = &arbitrate else {
        panic!()
    };
    assert_eq!(*result, ArbitrateResult::Ok, "同 ID：仲裁照常通过");
    let Step::Send(outbound) = client.handle(&arbitrate, &mut client_alloc) else {
        panic!("客户端本地签发应成功（其本内容自洽）")
    };
    assert_eq!(client.phase(), ClientPhase::ConfirmSent);
    let Step::AwaitPeer = server.on_issue_request(&outbound[0], &mut server_alloc) else {
        panic!("服务端签发应成功（其本内容自洽）")
    };
    assert_eq!(server.phase(), ServerPhase::ConfirmWait);
    // 客户端用 A[0] 封装，服务端持 B[0] 密钥 ⇒ 最迟 CONFIRM tag 失败
    let Step::Failed(err) = server.on_confirm(&outbound[1]) else {
        panic!("同 ID 异正文必须最迟在 CONFIRM tag 处失败")
    };
    assert_eq!(err.code(), ErrorCode::TAG_INVALID);
    assert_eq!(server.phase(), ServerPhase::Failed);
    // 段按规则消耗（两端 next=1，T6/T11 浪费），不降级、不复用、不回退
    assert_eq!(client_alloc.state().0, SegmentIndex::new(1));
    assert_eq!(server_alloc.state().0, SegmentIndex::new(1));

    // ② 客户端视角（对称夹具）：客户端持 A，收到"B 密钥封装"的 CONFIRM_S2C
    let (mut client2, mut server2, mut ca2, mut sa2) =
        machines("sc2-cli", fill_a(0x72), fill_b(0x72));
    let hello2 = client2.start().unwrap();
    let arb2 = server2.on_hello(&hello2).unwrap();
    let Step::Send(out2) = client2.handle(&arb2, &mut ca2) else {
        panic!()
    };
    let Step::AwaitPeer = server2.on_issue_request(&out2[0], &mut sa2) else {
        panic!()
    };
    assert_eq!(client2.phase(), ClientPhase::ConfirmSent);
    // 伪造：服务端身份、B[0] 段内容、合法 S2C 副本（副本对客户端完全正确）
    let bad_content = fill_b(0x72)(0);
    let body = legit_s2c_body(&hello2, &arb2, SegmentIndex::ZERO);
    let forged_s2c = forged_confirm(&hello2, &arb2, bad_content, body, Role::Server);
    let Step::Failed(err2) = client2.handle(&forged_s2c, &mut ca2) else {
        panic!("客户端侧对称夹具：异正文 tag 必失败")
    };
    assert_eq!(err2.code(), ErrorCode::TAG_INVALID);
    assert_eq!(client2.phase(), ClientPhase::Failed);
    assert_eq!(ca2.state().0, SegmentIndex::new(1), "客户端段已消耗");

    // ③ 段 0 绝不复用（模型 oracle：唯一性/不回退）
    let mut oracle = IssueOracle::new(SegmentIndex::ZERO);
    assert!(oracle.observe(SegmentIndex::ZERO), "段 0 只观察一次");
    assert!(!oracle.observe(SegmentIndex::ZERO), "段 0 复用=死刑");
    assert_eq!(oracle.next(), SegmentIndex::new(1));
}

#[test]
fn retry_after_scenario2_failure_uses_next_segment_never_zero() {
    // 场景 2 收尾：失败后（运维换回配对正确的书）重连走全新握手，
    // 从段 1 继续，绝不回到段 0。
    assert!(fills_differ(0x81));
    let (mut client, mut server, mut client_alloc, mut server_alloc) =
        machines("sc2-retry", fill_a(0x81), fill_b(0x81));
    let hello = client.start().unwrap();
    let arbitrate = server.on_hello(&hello).unwrap();
    let Step::Send(outbound) = client.handle(&arbitrate, &mut client_alloc) else {
        panic!()
    };
    let Step::AwaitPeer = server.on_issue_request(&outbound[0], &mut server_alloc) else {
        panic!()
    };
    assert!(matches!(server.on_confirm(&outbound[1]), Step::Failed(_)));
    drop(server);
    drop(client);

    // 运维把服务端书换成与客户端同内容（新分配器；advance 1 模拟段 0 已耗）
    let mut new_server_alloc = open_allocator("sc2-retry-fix", ID, COUNT, fill_a(0x81));
    advance(&mut new_server_alloc, 1);
    let mut client2 =
        otp_handshake::ClientHandshake::new(client_cfg(client_alloc.state().0, COUNT)).unwrap();
    let mut server2 =
        otp_handshake::ServerHandshake::new(server_cfg(new_server_alloc.state().0, COUNT)).unwrap();
    let hello2 = client2.start().unwrap();
    let arb2 = server2.on_hello(&hello2).unwrap();
    let Message::Arbitrate {
        result,
        server_pointer,
        ..
    } = &arb2
    else {
        panic!()
    };
    assert_eq!(*result, ArbitrateResult::Ok, "换对书后指针一致");
    assert_eq!(*server_pointer, SegmentIndex::new(1));
    let Step::Send(out2) = client2.handle(&arb2, &mut client_alloc) else {
        panic!()
    };
    let Step::AwaitPeer = server2.on_issue_request(&out2[0], &mut new_server_alloc) else {
        panic!()
    };
    let Step::Established { segment, .. } = server2.on_confirm(&out2[1]) else {
        panic!("重连必须成功")
    };
    assert_eq!(segment, SegmentIndex::new(1), "使用段 1，绝不回到段 0");
    assert_eq!(client_alloc.state().0, SegmentIndex::new(2));
    assert_eq!(new_server_alloc.state().0, SegmentIndex::new(2));
}
