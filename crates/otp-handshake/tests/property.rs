//! 性质测试（任务 #47）：任意消息流下的状态机不变量。
//!
//! P-NO-PANIC：任意类型的消息以任意顺序注入服务端状态机，绝不 panic
//! （fuzz 前提，WP-14 的状态面子集）。
//! P-FAIL-CLOSED：一旦进入 Failed 终态，任何后续输入都不能使其回到
//! 非终态；哑 issuer（无法产出 CommittedSegment——类型系统不允许伪造）
//! 下永远不可能 Established。
//!
//! 客户端 handle() 需要真实 issuer 才能越过 ARBITRATE，其任意输入面
//! 由 state_machine.rs 的确定性非法转移用例覆盖；真实签发性质由
//! otp-allocator 自身测试与 error_paths.rs 的场景 2 保证。

#![forbid(unsafe_code)]

use otp_codec::{ArbitrateResult, Message, MsgType, ProtocolVersion};
use otp_handshake::{
    ClientConfig, ClientHandshake, ServerConfig, ServerHandshake, ServerPhase, Step,
};
use otp_types::{BookId, ClientNonce, Epoch, SegmentIndex, Sequence, ServerNonce};
use proptest::prelude::*;

/// 确定性伪随机流（测试专用；不涉密）。
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn any_message(rng: &mut Rng) -> Message {
    let c_nonce = |rng: &mut Rng| {
        let mut b = [0u8; 16];
        for byte in b.iter_mut() {
            *byte = rng.next() as u8;
        }
        ClientNonce::from_bytes(b)
    };
    let s_nonce = |rng: &mut Rng| {
        let mut b = [0u8; 16];
        for byte in b.iter_mut() {
            *byte = rng.next() as u8;
        }
        ServerNonce::from_bytes(b)
    };
    let pointer = |rng: &mut Rng| SegmentIndex::new(rng.below(16));
    match rng.below(6) {
        0 => Message::Hello {
            book_id: BookId::from_bytes(*b"OTPTERM-TESTBOOK"),
            client_nonce: c_nonce(rng),
            client_pointer: pointer(rng),
            features: Default::default(),
        },
        1 => Message::Arbitrate {
            server_nonce: s_nonce(rng),
            server_pointer: pointer(rng),
            result: [
                ArbitrateResult::Ok,
                ArbitrateResult::ServerAhead,
                ArbitrateResult::Exhausted,
                ArbitrateResult::BookMismatch,
                ArbitrateResult::ClientAhead,
            ][rng.below(5) as usize],
        },
        2 => Message::IssueRequest {
            chosen_pointer: pointer(rng),
            client_nonce: c_nonce(rng),
            server_nonce: s_nonce(rng),
        },
        3 => Message::ConfirmC2s {
            segment_index: pointer(rng),
            session_nonce: otp_types::SessionNonce::from_bytes([rng.next() as u8; 16]),
            epoch: Epoch::new(rng.next() as u32),
            seq: Sequence::new(rng.next()),
            sealed: [rng.next() as u8; otp_codec::SEALED_LEN],
        },
        4 => Message::ConfirmS2c {
            segment_index: pointer(rng),
            session_nonce: otp_types::SessionNonce::from_bytes([rng.next() as u8; 16]),
            epoch: Epoch::new(rng.next() as u32),
            seq: Sequence::new(rng.next()),
            sealed: [rng.next() as u8; otp_codec::SEALED_LEN],
        },
        _ => Message::Data {
            epoch: Epoch::new(rng.next() as u32),
            seq: Sequence::new(rng.next()),
            data: vec![rng.next() as u8; 16],
        },
    }
}

/// 哑 issuer：无法产出 CommittedSegment（该类型只能由真实 Allocator 构造），
/// 以确定性错误覆盖"签发失败 → fail closed"分支。
struct DumbIssuer;

impl otp_allocator::SegmentIssuer for DumbIssuer {
    fn issue(&mut self) -> Result<otp_allocator::CommittedSegment, otp_allocator::IssueError> {
        Err(otp_allocator::IssueError::LockUnavailable)
    }
}

fn fresh_server() -> ServerHandshake {
    ServerHandshake::new(ServerConfig {
        version: ProtocolVersion::V2,
        book_id: BookId::from_bytes(*b"OTPTERM-TESTBOOK"),
        local_pointer: SegmentIndex::ZERO,
        segment_count: 4,
    })
    .unwrap()
}

fn run_server_case(seed: u64) -> Result<(), TestCaseError> {
    let mut rng = Rng::new(seed);
    let mut server = fresh_server();
    let mut issuer = DumbIssuer;
    let mut terminal = false;
    for _ in 0..24 {
        let msg = any_message(&mut rng);
        let step = match msg.msg_type() {
            MsgType::Hello => {
                let _ = server.on_hello(&msg); // Ok/Err 均合法；不 panic 即可
                None
            }
            MsgType::IssueRequest => Some(server.on_issue_request(&msg, &mut issuer)),
            _ => Some(server.on_confirm(&msg)),
        };
        if let Some(step) = step {
            if let Step::Established { .. } = step {
                // 哑 issuer 无法签发 ⇒ ConfirmWait 不可达 ⇒ Established 不可达
                return Err(TestCaseError::fail("哑 issuer 下不可能 Established"));
            }
            if matches!(step, Step::Failed(_)) || server.phase() == ServerPhase::Failed {
                terminal = true;
            }
        }
        if server.phase() == ServerPhase::Failed || server.phase() == ServerPhase::AheadPending {
            // 终态（AheadPending 对协议输入同样无出边——人工恢复域）：
            // 记录后断言其不再离开
            terminal = true;
        }
        if terminal {
            prop_assert!(
                matches!(
                    server.phase(),
                    ServerPhase::Failed | ServerPhase::AheadPending | ServerPhase::Established
                ),
                "终态后不得回到非终态（当前 {:?}）",
                server.phase()
            );
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn server_survives_arbitrary_message_streams_fail_closed(seed in 0u64..4096) {
        run_server_case(seed)?;
    }
}

// ClientHandshake 构造面独立性质：任意合法配置构造成功、非法版本拒绝。
proptest! {
    #[test]
    fn client_construction_validates_version(version in 0u16..8, pointer in 0u64..16) {
        let cfg = ClientConfig {
            version: ProtocolVersion(version),
            book_id: BookId::from_bytes(*b"OTPTERM-TESTBOOK"),
            local_pointer: SegmentIndex::new(pointer),
            segment_count: 4,
        };
        match ClientHandshake::new(cfg) {
            Ok(_) => prop_assert_eq!(version, 0x0002),
            Err(e) => prop_assert_eq!(e.code(), otp_codec::ErrorCode::BAD_VERSION),
        }
    }
}
