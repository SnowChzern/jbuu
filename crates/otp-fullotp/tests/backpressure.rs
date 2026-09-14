//! backpressure 与协调者测试（任务 #75 验收：数据泵语义，§2.3）。
//!
//! 覆盖：低水位触发 PAD_NEED；服务端唯一协调者（重复 NEED 不重复预取）；
//! ACK 前发送背压（不裸发/不降级）；ACK 后切换（旧 bundle 清零、offset
//! 重置、seq 延续）；记录不跨 bundle（缩短 L）；接收面低水位；offer
//! 基址不符 fail closed；重放/篡改关闭且无明文输出。

use otp_fullotp::{
    BUNDLE_BYTES, FullOtpPump, PadControl, PadSource, PadSourceError, PumpAction, SendOutcome,
};
use otp_types::{Direction, Role};

fn flat_for(base: u64) -> [u8; BUNDLE_BYTES] {
    core::array::from_fn(|i| {
        let seg = base + (i / 64) as u64;
        let j = i % 64;
        ((seg * 64 + j as u64) as u8)
            .wrapping_mul(3)
            .wrapping_add(7)
    })
}

struct Book {
    next_base: u64,
    reserves: usize,
    /// 强制采纳失败（模拟本地指针不符）。
    mismatch: bool,
}

impl Book {
    fn at(base: u64) -> Self {
        Self {
            next_base: base,
            reserves: 0,
            mismatch: false,
        }
    }
}

impl PadSource for Book {
    fn reserve_next_bundle(&mut self) -> Result<(u64, [u8; BUNDLE_BYTES]), PadSourceError> {
        let base = self.next_base;
        self.next_base += 128;
        self.reserves += 1;
        Ok((base, flat_for(base)))
    }
    fn reserve_bundle_at(
        &mut self,
        expected_base: u64,
    ) -> Result<[u8; BUNDLE_BYTES], PadSourceError> {
        if self.mismatch || self.next_base != expected_base {
            return Err(PadSourceError::PointerMismatch {
                local: self.next_base,
                announced: expected_base,
            });
        }
        self.next_base += 128;
        self.reserves += 1;
        Ok(flat_for(expected_base))
    }
}

/// 建立已就绪 bundle 1 的两端（bundle 0 base=1；bundle 1 base=129）。
fn established_pair() -> (FullOtpPump, FullOtpPump, Book, Book) {
    let mut client = FullOtpPump::new(Role::Client, 1, flat_for(1));
    let mut server = FullOtpPump::new(Role::Server, 1, flat_for(1));
    let mut sbook = Book::at(129);
    let mut cbook = Book::at(129);
    let offer = server.on_control(&PadControl::PadNeed, &mut sbook).unwrap();
    assert_eq!(
        offer,
        vec![PumpAction::SendPadOffer {
            bundle_id: 1,
            base_segment: 129
        }]
    );
    let ack = client
        .on_control(
            &PadControl::PadOffer {
                bundle_id: 1,
                base_segment: 129,
            },
            &mut cbook,
        )
        .unwrap();
    assert_eq!(ack, vec![PumpAction::SendPadAck { bundle_id: 1 }]);
    server
        .on_control(&PadControl::PadAck { bundle_id: 1 }, &mut sbook)
        .unwrap();
    (client, server, sbook, cbook)
}

#[test]
fn low_water_triggers_pad_need_flag_exactly_at_boundary() {
    // LOW_WATER=1024（§2.3）：remaining==1024 恰在阈值之上不触发；
    // 再消耗后 remaining=1 < 1024 ⇒ need_pad 置位；耗尽后未就绪 ⇒ 背压
    let mut client = FullOtpPump::new(Role::Client, 1, flat_for(1));
    match client.send(&vec![0u8; 3040]).unwrap() {
        // 32+3040=3072，remaining=1024
        SendOutcome::Record { need_pad, .. } => assert!(!need_pad, "==LOW_WATER 不触发"),
        _ => panic!(),
    }
    assert_eq!(client.remaining(Direction::ClientToServer), 1024);
    match client.send(&vec![0u8; 991]).unwrap() {
        // 32+991=1023，remaining=1
        SendOutcome::Record { need_pad, .. } => assert!(need_pad, "低于低水位必须置位"),
        _ => panic!(),
    }
    assert_eq!(client.remaining(Direction::ClientToServer), 1);
    // 1B 剩余放不下任何记录（<33）⇒ 无下一 bundle 材料 ⇒ 背压
    assert!(matches!(client.send(b"x"), Ok(SendOutcome::Backpressure)));
}

#[test]
fn server_send_backpressure_until_ack_then_switch() {
    let (_client, mut server, sbook, _cbook) = established_pair();
    let _ = sbook;
    // S2C 填满 bundle 0（服务端发送方向）
    match server.send(&vec![0xEE; 4064]).unwrap() {
        SendOutcome::Record { .. } => {}
        _ => panic!(),
    }
    // ACK 已完成（established_pair）⇒ 可切换续发
    match server.send(b"next bundle").unwrap() {
        SendOutcome::Record { record, .. } => {
            assert_eq!(record.bundle_id, 1);
            assert_eq!(record.pad_offset, 0);
            assert_eq!(record.record_seq, 1, "record_seq 跨 bundle 延续");
            assert_eq!(
                record.base_segment,
                129 + 64,
                "S2C 半区基址 = bundle base+64"
            );
        }
        _ => panic!("已 ACK 应可切换"),
    }
    let _ = sbook;
}

#[test]
fn backpressure_before_ack_no_raw_send() {
    // 服务端已预取（offer 未 ACK）：S2C 耗尽 bundle 0 ⇒ 背压（不裸发/不降级）
    let mut server = FullOtpPump::new(Role::Server, 1, flat_for(1));
    let mut sbook = Book::at(129);
    server.on_control(&PadControl::PadNeed, &mut sbook).unwrap(); // 预取 bundle 1（未 ACK）
    match server.send(&vec![0x11; 4064]).unwrap() {
        SendOutcome::Record { .. } => {}
        _ => panic!(),
    }
    assert!(matches!(server.send(b"x"), Ok(SendOutcome::Backpressure)));
    // 背压期间预取不重复（单一未决）
    assert_eq!(server.server_prefetch(&mut sbook).unwrap(), None);
    assert_eq!(sbook.reserves, 1);
}

#[test]
fn duplicate_pad_need_never_duplicates_prefetch() {
    let mut server = FullOtpPump::new(Role::Server, 1, flat_for(1));
    let mut sbook = Book::at(129);
    let a1 = server.on_control(&PadControl::PadNeed, &mut sbook).unwrap();
    assert_eq!(a1.len(), 1);
    let a2 = server.on_control(&PadControl::PadNeed, &mut sbook).unwrap();
    assert!(a2.is_empty(), "已有未决材料：重复 NEED 忽略");
    let a3 = server.on_control(&PadControl::PadNeed, &mut sbook).unwrap();
    assert!(a3.is_empty());
    assert_eq!(sbook.reserves, 1, "协调者只预取一次");
}

#[test]
fn records_shorten_at_tail_and_never_cross_bundle() {
    // 剩余 40B：100B 明文截断为 8B 记录（32+8=40）；随后背压/切换
    let (mut client, _s, _sb, _cb) = established_pair();
    // 精确消耗到剩余 40：4096-40=4056（一条 4024B 记录 = 4056）
    match client.send(&vec![0x77; 4024]).unwrap() {
        SendOutcome::Record { .. } => {}
        _ => panic!(),
    }
    assert_eq!(client.remaining(Direction::ClientToServer), 40);
    match client.send(&[0x99; 100]).unwrap() {
        SendOutcome::Record {
            record,
            consumed_plaintext,
            ..
        } => {
            assert_eq!(consumed_plaintext, 8, "按剩余缩短 L");
            assert_eq!(record.ciphertext.len(), 8);
            assert_eq!(record.pad_offset, 4056, "offset = 消耗 4056 后的 cursor");
        }
        _ => panic!(),
    }
    assert_eq!(client.remaining(Direction::ClientToServer), 0);
    // 已 ACK bundle 1 ⇒ 切换而非背压
    match client.send(&[0x55; 10]).unwrap() {
        SendOutcome::Record { record, .. } => {
            assert_eq!(record.bundle_id, 1);
            assert_eq!(record.pad_offset, 0);
        }
        _ => panic!(),
    }
}

#[test]
fn receive_side_switches_on_next_bundle_record_and_low_water() {
    let (mut client, mut server, _sb, _cb) = established_pair();
    // 服务端 S2C 填满 bundle 0（耗尽即低于低水位）后切 bundle 1 续发；
    // 客户端接收面在首条 bundle 1 记录上自动切换
    match server.send(&vec![1u8; 4064]).unwrap() {
        SendOutcome::Record {
            record, need_pad, ..
        } => {
            assert!(need_pad, "耗尽必低于低水位");
            assert_eq!(recv(&mut client, record.encode()), vec![1u8; 4064]);
        }
        _ => panic!(),
    }
    assert_eq!(client.current_bundle(Direction::ServerToClient), (0, 65));
    match server.send(&vec![2u8; 500]).unwrap() {
        SendOutcome::Record {
            record, need_pad, ..
        } => {
            assert_eq!(record.bundle_id, 1);
            assert!(!need_pad, "bundle 1 剩余 3564 > 1024，不触发");
            assert_eq!(recv(&mut client, record.encode()), vec![2u8; 500]);
        }
        _ => panic!(),
    }
    // 客户端接收面已切到 bundle 1；会话累计 = 4096 + 532
    assert_eq!(client.current_bundle(Direction::ServerToClient), (1, 193));
    assert_eq!(
        client.session_consumed(Direction::ServerToClient),
        4096 + 532
    );
    assert_eq!(client.remaining(Direction::ServerToClient), 4096 - 532);
}

fn recv(pump: &mut FullOtpPump, frame: Vec<u8>) -> Vec<u8> {
    pump.receive(&frame).unwrap().plaintext.as_bytes().to_vec()
}

#[test]
fn offer_pointer_mismatch_fails_closed_and_wastes() {
    let mut client = FullOtpPump::new(Role::Client, 1, flat_for(1));
    let mut cbook = Book::at(129);
    cbook.mismatch = true; // 本地指针不符
    let r = client.on_control(
        &PadControl::PadOffer {
            bundle_id: 1,
            base_segment: 129,
        },
        &mut cbook,
    );
    assert!(matches!(r, Err(otp_fullotp::PumpError::Source(_))));
    assert!(!client.is_active(), "采纳失败 ⇒ fail closed");
    // 材料全浪费：任何后续操作 Closed，且不产生任何记录
    assert!(matches!(
        client.send(b"x"),
        Err(otp_fullotp::SendError::Closed)
    ));
    assert!(matches!(
        client.receive(&[0u8; 60]),
        Err(otp_fullotp::OtpError::Closed)
    ));
}

#[test]
fn offer_with_wrong_bundle_id_fails_closed() {
    let mut client = FullOtpPump::new(Role::Client, 1, flat_for(1));
    let mut cbook = Book::at(129);
    let r = client.on_control(
        &PadControl::PadOffer {
            bundle_id: 2,
            base_segment: 129,
        },
        &mut cbook,
    );
    assert!(matches!(r, Err(otp_fullotp::PumpError::Data(_))));
    assert!(!client.is_active());
    assert_eq!(cbook.reserves, 0, "不预留不匹配范围");
}

#[test]
fn replayed_frame_closes_session_with_no_output() {
    let (mut client, mut server, _sb, _cb) = established_pair();
    let frame = match client.send(b"hello").unwrap() {
        SendOutcome::Record { record, .. } => record.encode(),
        _ => panic!(),
    };
    assert_eq!(recv(&mut server, frame.clone()), b"hello".to_vec());
    // 重放同一帧：seq < expected ⇒ OTP_REPLAY ⇒ 关闭、剩余材料浪费
    assert!(matches!(
        server.receive(&frame),
        Err(otp_fullotp::OtpError::Replay)
    ));
    assert!(!server.is_active());
    assert!(matches!(
        server.receive(&frame),
        Err(otp_fullotp::OtpError::Closed)
    ));
}

#[test]
fn tampered_frame_closes_without_plaintext() {
    let (mut client, mut server, _sb, _cb) = established_pair();
    let mut frame = match client.send(b"payload").unwrap() {
        SendOutcome::Record { record, .. } => record.encode(),
        _ => panic!(),
    };
    frame[40] ^= 0x40; // 翻一位密文
    assert!(matches!(
        server.receive(&frame),
        Err(otp_fullotp::OtpError::Tag)
    ));
    assert!(!server.is_active());
}

#[test]
fn close_control_wastes_everything_idempotent() {
    let (mut client, mut server, _sb, _cb) = established_pair();
    server
        .on_control(&PadControl::Close, &mut Book::at(999))
        .unwrap();
    assert!(!server.is_active());
    // 已关闭后两重复 CLOSE 控制消息：Err(Closed)，不崩溃、不再触碰材料
    assert!(matches!(
        server.on_control(&PadControl::Close, &mut Book::at(999)),
        Err(otp_fullotp::PumpError::Data(otp_fullotp::OtpError::Closed))
    ));
    // 本端 close() 本身幂等
    server.close();
    server.close();
    assert!(
        matches!(client.send(b"x"), Ok(SendOutcome::Record { .. })),
        "对端未收到 CLOSE 前仍可发送（关闭是本端行为）"
    );
}

#[test]
fn client_rejects_pad_need_and_server_rejects_offer_or_ack() {
    let mut client = FullOtpPump::new(Role::Client, 1, flat_for(1));
    let mut cbook = Book::at(129);
    assert!(matches!(
        client.on_control(&PadControl::PadNeed, &mut cbook),
        Err(otp_fullotp::PumpError::Data(_))
    ));
    assert!(!client.is_active());
    let mut server = FullOtpPump::new(Role::Server, 1, flat_for(1));
    let mut sbook = Book::at(129);
    assert!(matches!(
        server.on_control(
            &PadControl::PadOffer {
                bundle_id: 1,
                base_segment: 129
            },
            &mut sbook
        ),
        Err(otp_fullotp::PumpError::Data(_))
    ));
    assert!(!server.is_active());
    let mut server2 = FullOtpPump::new(Role::Server, 1, flat_for(1));
    let mut sbook2 = Book::at(129);
    assert!(matches!(
        server2.on_control(&PadControl::PadAck { bundle_id: 1 }, &mut sbook2),
        Err(otp_fullotp::PumpError::Data(_))
    ));
    assert!(!server2.is_active(), "无未决 offer 的 ACK ⇒ fail closed");
}
