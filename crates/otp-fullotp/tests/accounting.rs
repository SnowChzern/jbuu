//! 段消耗记账测试（任务 #75 验收 2：`sum(L)+32*records` 对账精确）。
//!
//! 口径（fullotp-design §2.1）：每方向独立计费，
//! `consumed = 32*record_count + sum(L_j)`；密文/tag/公开头不消耗 pad；
//! 记录不跨 bundle；`<=32B` 尾部浪费。发送侧与接收侧记账必须逐步相等。

use otp_fullotp::{BUNDLE_BYTES, FullOtpPump, PAD_HALF, seal_record, split_bundle};
use otp_types::{Direction, Role};

fn bundle_flat(seed_base: u64) -> [u8; BUNDLE_BYTES] {
    // 段 i 内容：((i*64+j) ^ (i+seed_base)) & 0xFF —— 逐段可区分
    core::array::from_fn(|i| {
        let seg = seed_base + (i / 64) as u64;
        let j = i % 64;
        ((seg * 64 + j as u64) as u8) ^ (seg as u8)
    })
}

#[test]
fn single_bundle_exact_accounting_both_directions() {
    let flat = bundle_flat(0);
    // C2S 链：长度序列恰耗尽 4096B（33+132+2032+1899 = 4096）
    let c2s_lens = [1usize, 100, 2000, 1867];
    let s2c_lens = [4064usize]; // 单条满记录恰 4096
    for (dir, lens, half_off) in [
        (Direction::ClientToServer, &c2s_lens[..], 0usize),
        (Direction::ServerToClient, &s2c_lens[..], PAD_HALF),
    ] {
        let (mut sender, mut receiver) = {
            let (c1, s1) = split_bundle(0, 1, flat);
            let (c2, s2) = split_bundle(0, 1, flat);
            match dir {
                Direction::ClientToServer => (c1, c2),
                Direction::ServerToClient => (s1, s2),
            }
        };
        let _ = half_off;
        let sender_base = sender.base_segment();
        let mut seq = 0u64;
        let mut accounting_sum = 0usize;
        for &l in lens {
            let pt = vec![(l as u8).wrapping_mul(7); l];
            let rec = seal_record(&mut sender, dir, seq, &pt).unwrap();
            seq += 1;
            accounting_sum += 32 + l;
            assert_eq!(sender.consumed(), accounting_sum, "发送侧第 {seq} 条后");
            // 接收侧对账：pad_offset == 期望 cursor；验证后同额推进
            let frame = rec.encode();
            let got = otp_fullotp::open_record(
                &mut receiver,
                &otp_fullotp::OpenExpectation {
                    direction: dir,
                    bundle_id: 0,
                    base_segment: sender_base,
                    record_seq: seq - 1,
                },
                &frame,
            )
            .unwrap();
            assert_eq!(got.as_bytes(), &pt[..]);
            assert_eq!(receiver.consumed(), accounting_sum, "接收侧第 {seq} 条后");
        }
        assert_eq!(accounting_sum, 32 * lens.len() + lens.iter().sum::<usize>());
        assert_eq!(sender.consumed(), PAD_HALF, "恰耗尽方向流");
        assert_eq!(receiver.consumed(), PAD_HALF);
    }
}

#[test]
fn tail_below_min_record_is_waste_not_partial() {
    // 消耗至 remaining=4（<33）：不可再容纳任何记录；4B 属尾部浪费面
    let flat = bundle_flat(1);
    let (mut sender, _) = split_bundle(0, 0, flat);
    for i in 0..124u64 {
        let rec = seal_record(&mut sender, Direction::ClientToServer, i, b"x").unwrap();
        assert_eq!(rec.pad_offset, (i * 33) as u16);
    }
    assert_eq!(sender.remaining(), 4);
    assert!(!sender.fits(1));
    assert!(matches!(
        seal_record(&mut sender, Direction::ClientToServer, 124, b"x"),
        Err(otp_fullotp::OtpError::DoesNotFit)
    ));
    // 失败不推进游标（记账不被污染）
    assert_eq!(sender.remaining(), 4);
    assert_eq!(sender.consumed(), 124 * 33);
}

#[test]
fn pump_accounting_across_bundle_switch_and_directions() {
    // 双向 + 双 bundle 全链记账：两泵（客户端/服务端）共享同一虚拟密码本
    let flat0 = bundle_flat(1);
    let flat1 = bundle_flat(129);
    let mut client = FullOtpPump::new(Role::Client, 1, flat0);
    let mut server = FullOtpPump::new(Role::Server, 1, flat0);

    // C2S：bundle 0 一条满记录（4096B 消耗）→ 背压 → PAD 流程 → bundle 1
    let big = vec![0xA5u8; 4064];
    let out0 = client.send(&big).unwrap();
    let otp_fullotp::SendOutcome::Record {
        record, need_pad, ..
    } = out0
    else {
        panic!("首条必成");
    };
    assert!(need_pad, "剩余 0 已低于低水位");
    assert_eq!(
        server
            .receive(&record.encode())
            .unwrap()
            .plaintext
            .as_bytes(),
        &big[..]
    );
    assert_eq!(server.session_consumed(Direction::ClientToServer), 4096);

    // 背压：bundle 0 C2S 已耗尽，bundle 1 未就绪
    assert!(matches!(
        client.send(b"more"),
        Ok(otp_fullotp::SendOutcome::Backpressure)
    ));

    // PAD_NEED → 服务端预取 → PAD_OFFER → 客户端采纳 → PAD_ACK
    // （两端各自持有独立指针的同一内容本：生产 = 各自锚/分配器）
    let mut server_book = VirtualBook {
        next_base: 129,
        reserves: 0,
    };
    let mut client_book = VirtualBook {
        next_base: 129,
        reserves: 0,
    };
    let actions = server
        .on_control(&otp_fullotp::PadControl::PadNeed, &mut server_book)
        .unwrap();
    assert_eq!(
        actions,
        vec![otp_fullotp::PumpAction::SendPadOffer {
            bundle_id: 1,
            base_segment: 129
        }]
    );
    let acks = client
        .on_control(
            &otp_fullotp::PadControl::PadOffer {
                bundle_id: 1,
                base_segment: 129,
            },
            &mut client_book,
        )
        .unwrap();
    assert_eq!(
        acks,
        vec![otp_fullotp::PumpAction::SendPadAck { bundle_id: 1 }]
    );
    let _ = flat1;
    server
        .on_control(
            &otp_fullotp::PadControl::PadAck { bundle_id: 1 },
            &mut server_book,
        )
        .unwrap();

    // 续发：bundle 1，pad_offset 重置 0，record_seq 延续（不因 bundle 重置）
    let small = b"after switch";
    let otp_fullotp::SendOutcome::Record {
        record: r1,
        consumed_plaintext,
        ..
    } = client.send(small).unwrap()
    else {
        panic!("ACK 后应可续发");
    };
    assert_eq!(consumed_plaintext, small.len());
    assert_eq!(r1.bundle_id, 1);
    assert_eq!(r1.pad_offset, 0);
    assert_eq!(r1.record_seq, 1);
    assert_eq!(
        server.receive(&r1.encode()).unwrap().plaintext.as_bytes(),
        &small[..]
    );
    // 记账：C2S 总消耗 = 4096(bundle0) + 32+len(bundle1 首条)
    assert_eq!(
        client.session_consumed(Direction::ClientToServer),
        4096 + 32 + small.len()
    );
    assert_eq!(
        server.session_consumed(Direction::ClientToServer),
        client.session_consumed(Direction::ClientToServer)
    );
    // S2C 独立记账（尚未使用）
    assert_eq!(client.session_consumed(Direction::ServerToClient), 0);
    assert_eq!(server.session_consumed(Direction::ServerToClient), 0);
    // 虚拟本指针：两端各自恰预取/采纳一次 bundle 1（129..257）
    assert_eq!(server_book.next_base, 257);
    assert_eq!(client_book.next_base, 257);
    assert_eq!(server_book.reserves, 1, "服务端预取恰一次");
    assert_eq!(client_book.reserves, 1, "客户端采纳恰一次");
}

#[test]
fn record_metadata_reconciliation_formula() {
    // 从线上元数据反推对账：Σ(pad_offset 推进) == 32*records + Σ(ct_len)
    let flat = bundle_flat(2);
    let (mut sender, mut receiver) = {
        let (a, _) = split_bundle(0, 0, flat);
        let (b, _) = split_bundle(0, 0, flat);
        (a, b)
    };
    let lens = [1usize, 5, 64, 512, 1000, 33];
    let mut expected_cursor = 0usize;
    let mut records = 0usize;
    let mut sum_l = 0usize;
    for (i, &l) in lens.iter().enumerate() {
        let rec = seal_record(
            &mut sender,
            Direction::ClientToServer,
            i as u64,
            &vec![0x11; l],
        )
        .unwrap();
        assert_eq!(
            rec.pad_offset as usize, expected_cursor,
            "offset 必须等于期望 cursor"
        );
        expected_cursor += 32 + rec.ciphertext.len();
        records += 1;
        sum_l += rec.ciphertext.len();
        receiver_probe_accept(&mut receiver, rec.encode(), i as u64);
    }
    assert_eq!(expected_cursor, 32 * records + sum_l, "公式对账");
    assert_eq!(sender.consumed(), expected_cursor);
}

fn receiver_probe_accept(receiver: &mut otp_fullotp::PadStream, frame: Vec<u8>, seq: u64) {
    let got = otp_fullotp::open_record(
        receiver,
        &otp_fullotp::OpenExpectation {
            direction: Direction::ClientToServer,
            bundle_id: 0,
            base_segment: 0,
            record_seq: seq,
        },
        &frame,
    )
    .unwrap();
    assert!(!got.as_bytes().is_empty());
}

/// 虚拟密码本（两端同内容同指针演进的夹具源）。
struct VirtualBook {
    next_base: u64,
    reserves: usize,
}

impl otp_fullotp::PadSource for VirtualBook {
    fn reserve_next_bundle(
        &mut self,
    ) -> Result<(u64, [u8; BUNDLE_BYTES]), otp_fullotp::PadSourceError> {
        let base = self.next_base;
        self.next_base += 128;
        self.reserves += 1;
        Ok((base, bundle_flat(base)))
    }

    fn reserve_bundle_at(
        &mut self,
        expected_base: u64,
    ) -> Result<[u8; BUNDLE_BYTES], otp_fullotp::PadSourceError> {
        if self.next_base != expected_base {
            return Err(otp_fullotp::PadSourceError::PointerMismatch {
                local: self.next_base,
                announced: expected_base,
            });
        }
        self.next_base += 128;
        self.reserves += 1;
        Ok(bundle_flat(expected_base))
    }
}
