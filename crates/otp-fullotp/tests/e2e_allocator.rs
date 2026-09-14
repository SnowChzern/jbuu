//! 端到端对账：真实 `reserve_range` 双锚事务 → bundle 切分 → OTP 记录流
//! → 锚指针/密码本字节级对账（任务 #75 验收 2/3 的数据面闭环）。
//!
//! 场景（fullotp-design §2.2/§2.3）：
//! 1. 服务端 `issue()` 取首个握手段（段 0，不属于 bundle）；
//! 2. 服务端 `reserve_range(128)` → bundle 0（段 1..129），PAD_OFFER，
//!    客户端以**自己的分配器**（同一密码本的独立副本锚）`reserve_at` 采纳；
//! 3. 双向记录流跑满 bundle 0，低水位 → PAD_NEED → 服务端 `reserve_range(128)`
//!    → bundle 1（段 129..257）→ ACK → 切换续发；
//! 4. 对账：两端锚 next 相等且 == 1+128+128；bundle 平面字节与密码本
//!    文件字节逐一相等（pad 来源可证）；泵记账 = 32*records+sum(L)。

use std::fs::File;
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::Path;

use otp_allocator::{Allocator, AllocatorConfig, SegmentIssuer};
use otp_anchor_spec::{AnchorRecord, encode_record};
use otp_fullotp::{BUNDLE_BYTES, FullOtpPump, PadControl, PadSource, PadSourceError, SendOutcome};
use otp_types::{BookId, Direction, Role, SEGMENT_LEN};

const ID: BookId = BookId::from_bytes(*b"OTPTERM-FULLOTP1");
const SEGMENTS: u64 = 300;

/// 测试站点目录：仓库 target/tmp 下（Allocator 的 OFD 锁要求受支持文件
/// 系统——ext4 等；/tmp 是 tmpfs 会被 require_supported_filesystem 拒绝，
/// 与 otp-cli 集成测试同口径）。
fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/tmp")
        .join(format!("otp-fullotp-e2e-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn init_site(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let mut anchor = Vec::new();
    encode_record(&AnchorRecord::init(ID), &mut anchor);
    for name in ["a.anchor", "b.anchor"] {
        let f = File::create(dir.join(name)).unwrap();
        (&f).write_all(&anchor).unwrap();
        f.sync_all().unwrap();
    }
    let f = File::create(dir.join("segments.bin")).unwrap();
    let header = otp_book::header::BookHeader::new(ID, SEGMENTS)
        .unwrap()
        .encode();
    (&f).write_all(&header).unwrap();
    for i in 0..SEGMENTS {
        // 段 i 内容：byte j = (i ^ j) ^ (i >> 3)（逐段可区分、逐字节可验）
        let seg: [u8; SEGMENT_LEN] =
            core::array::from_fn(|j| (i as u8 ^ j as u8) ^ ((i >> 3) as u8));
        (&f).write_all(&seg).unwrap();
    }
    f.sync_all().unwrap();
}

fn open_allocator(dir: &Path) -> Allocator {
    Allocator::open(AllocatorConfig {
        book: dir.join("segments.bin"),
        anchor_a: dir.join("a.anchor"),
        anchor_b: dir.join("b.anchor"),
        expected_book_id: ID,
    })
    .unwrap()
}

/// 读密码本文件中段 i 的原始字节（独立于分配器路径的取证通道）。
fn book_segment_bytes(dir: &Path, i: u64) -> [u8; SEGMENT_LEN] {
    let f = File::open(dir.join("segments.bin")).unwrap();
    let mut buf = [0u8; SEGMENT_LEN];
    f.read_exact_at(&mut buf, 128 + i * SEGMENT_LEN as u64)
        .unwrap();
    buf
}

/// 分配器适配到 PadSource（生产接线形态的同构缩微）。
struct AllocSource {
    alloc: Allocator,
    dir: std::path::PathBuf,
}

trait ReserveVia {
    fn reserve_range_via(
        &mut self,
        n: u64,
    ) -> Result<otp_allocator::ReservedRange, otp_allocator::IssueError>;
}
impl ReserveVia for Allocator {
    fn reserve_range_via(
        &mut self,
        n: u64,
    ) -> Result<otp_allocator::ReservedRange, otp_allocator::IssueError> {
        // 显式走 RangeIssuer trait 路径（生产调用形态）
        otp_allocator::RangeIssuer::reserve_range(self, n)
    }
}

impl PadSource for AllocSource {
    fn reserve_next_bundle(&mut self) -> Result<(u64, [u8; BUNDLE_BYTES]), PadSourceError> {
        let range = self.alloc.reserve_range(128).map_err(|e| {
            PadSourceError::Reserve(match e {
                otp_allocator::IssueError::Exhausted { .. } => "exhausted",
                otp_allocator::IssueError::PersistenceUncertain => "persistence-uncertain",
                _ => "io",
            })
        })?;
        // 取证：范围平面 == 密码本文件字节（pad 来源 = 本体）
        verify_flat_against_book(&self.dir, range.base().get(), range.flat_bytes());
        let mut flat = [0u8; BUNDLE_BYTES];
        flat.copy_from_slice(range.flat_bytes());
        Ok((range.base().get(), flat))
    }

    fn reserve_bundle_at(
        &mut self,
        expected_base: u64,
    ) -> Result<[u8; BUNDLE_BYTES], PadSourceError> {
        let (local, _) = self.alloc.state();
        if local.get() != expected_base {
            return Err(PadSourceError::PointerMismatch {
                local: local.get(),
                announced: expected_base,
            });
        }
        let range = self
            .alloc
            .reserve_range_via(128)
            .map_err(|_| PadSourceError::Reserve("reserve-failed"))?;
        if range.base().get() != expected_base {
            return Err(PadSourceError::PointerMismatch {
                local: range.base().get(),
                announced: expected_base,
            });
        }
        verify_flat_against_book(&self.dir, range.base().get(), range.flat_bytes());
        let mut flat = [0u8; BUNDLE_BYTES];
        flat.copy_from_slice(range.flat_bytes());
        Ok(flat)
    }
}

fn verify_flat_against_book(dir: &Path, base: u64, flat: &[u8]) {
    for k in 0..128u64 {
        let expect = book_segment_bytes(dir, base + k);
        let got: &[u8] = &flat[(k as usize) * SEGMENT_LEN..][..SEGMENT_LEN];
        assert_eq!(
            expect, got,
            "bundle 段 {k} 与密码本字节不符（pad 来源取证）"
        );
    }
}

#[test]
fn e2e_reserve_bundle_records_and_anchor_reconciliation() {
    let root = scratch("main");
    let server_dir = root.join("server");
    let client_dir = root.join("client");
    init_site(&server_dir);
    init_site(&client_dir);

    let mut server_src = AllocSource {
        alloc: open_allocator(&server_dir),
        dir: server_dir.clone(),
    };
    let mut client_src = AllocSource {
        alloc: open_allocator(&client_dir),
        dir: client_dir.clone(),
    };

    // 1. 首个握手段（段 0）：两端各自 issue（同构于握手指令流的材料来源）
    let _hs = server_src.alloc.issue().unwrap();
    let _hc = client_src.alloc.issue().unwrap();

    // 2. bundle 0：服务端预留 + 公告；客户端采纳
    let (base0, flat0) = server_src.reserve_next_bundle().unwrap();
    assert_eq!(base0, 1, "bundle 0 从握手段之后开始");
    let flat0_c = client_src.reserve_bundle_at(base0).unwrap();
    assert_eq!(flat0, flat0_c, "两端同范围同字节");

    let mut client = FullOtpPump::new(Role::Client, base0, flat0);
    let mut server = FullOtpPump::new(Role::Server, base0, flat0_c);

    // 3. 双向记录流：C2S 跑满 bundle 0（4064+32=4096）
    let big = vec![0xC3u8; 4064];
    let SendOutcome::Record {
        record: r0,
        need_pad,
        ..
    } = client.send(&big).unwrap()
    else {
        panic!()
    };
    assert!(need_pad);
    assert_eq!(
        server.receive(&r0.encode()).unwrap().plaintext.as_bytes(),
        &big[..]
    );
    assert_eq!(server.session_consumed(Direction::ClientToServer), 4096);

    // 背压 → PAD_NEED → 服务端 reserve_range(128)（bundle 1）→ OFFER → 采纳 → ACK
    assert!(matches!(
        client.send(b"tail"),
        Ok(SendOutcome::Backpressure)
    ));
    let actions = server
        .on_control(&PadControl::PadNeed, &mut server_src)
        .unwrap();
    assert_eq!(actions.len(), 1);
    let PadControl::PadOffer {
        bundle_id: id1,
        base_segment: base1,
    } = decode_offer(&actions[0])
    else {
        panic!()
    };
    assert_eq!((id1, base1), (1, 129));
    let acks = client
        .on_control(
            &PadControl::PadOffer {
                bundle_id: id1,
                base_segment: base1,
            },
            &mut client_src,
        )
        .unwrap();
    assert_eq!(acks.len(), 1);
    let _ = server
        .on_control(&PadControl::PadAck { bundle_id: id1 }, &mut server_src)
        .unwrap();

    // 4. bundle 1 续发（C2S）+ S2C 独立记录
    let small = b"after switch";
    let SendOutcome::Record { record: r1, .. } = client.send(small).unwrap() else {
        panic!()
    };
    assert_eq!(r1.bundle_id, 1);
    assert_eq!(
        server.receive(&r1.encode()).unwrap().plaintext.as_bytes(),
        &small[..]
    );
    let s_out = vec![0x42u8; 2000];
    let SendOutcome::Record { record: s1, .. } = server.send(&s_out).unwrap() else {
        panic!()
    };
    assert_eq!(s1.bundle_id, 0, "S2C 仍在 bundle 0（方向独立推进）");
    assert_eq!(
        client.receive(&s1.encode()).unwrap().plaintext.as_bytes(),
        &s_out[..]
    );

    // 5. 对账：两端锚 next 相等 == 握手段 + 2 bundles；记账公式闭合
    let (snext, _) = server_src.alloc.state();
    let (cnext, _) = client_src.alloc.state();
    assert_eq!(snext.get(), cnext.get(), "两端指针一致");
    assert_eq!(snext.get(), 1 + 128 + 128, "握手 1 段 + 两个 bundle");
    assert_eq!(
        server.session_consumed(Direction::ClientToServer),
        4096 + 32 + small.len()
    );
    assert_eq!(
        server.session_consumed(Direction::ClientToServer),
        client.session_consumed(Direction::ClientToServer)
    );
    assert_eq!(
        client.session_consumed(Direction::ServerToClient),
        32 + 2000
    );

    // 6. 段消耗总量守恒：本体消耗段数 = 锚推进；记录消耗 = 阶段和
    // C2S：bundle0(4096B=64 段) + bundle1 首条(44B)
    // S2C：bundle0 首条(2032B)
    let c2s_bytes = server.session_consumed(Direction::ClientToServer);
    let s2c_bytes = server.session_consumed(Direction::ServerToClient);
    assert!(c2s_bytes + s2c_bytes <= 2 * 4096, "两 bundle 上限");
    assert_eq!(c2s_bytes, 4096 + 44);
    assert_eq!(s2c_bytes, 2032);

    std::fs::remove_dir_all(root).unwrap();
}

fn decode_offer(a: &otp_fullotp::PumpAction) -> PadControl {
    match *a {
        otp_fullotp::PumpAction::SendPadOffer {
            bundle_id,
            base_segment,
        } => PadControl::PadOffer {
            bundle_id,
            base_segment,
        },
        _ => panic!("期望 SendPadOffer"),
    }
}

#[test]
fn client_rejects_offer_when_local_pointer_diverges() {
    // 客户端指针不在公告基址（本地多预留过一段）⇒ 采纳失败 fail closed
    let root = scratch("divergence");
    let server_dir = root.join("s");
    let client_dir = root.join("c");
    init_site(&server_dir);
    init_site(&client_dir);
    let mut server_src = AllocSource {
        alloc: open_allocator(&server_dir),
        dir: server_dir,
    };
    let mut client_src = AllocSource {
        alloc: open_allocator(&client_dir),
        dir: client_dir,
    };

    let _ = server_src.alloc.issue().unwrap();
    let _ = client_src.alloc.issue().unwrap();
    // 客户端额外签发一段（模拟本地状态领先）
    let _ = client_src.alloc.issue().unwrap();
    let (base0, flat0) = server_src.reserve_next_bundle().unwrap();
    let mut client = FullOtpPump::new(Role::Client, base0, flat0);
    let r = client.on_control(
        &PadControl::PadOffer {
            bundle_id: 1,
            base_segment: 129,
        },
        &mut client_src,
    );
    assert!(matches!(
        r,
        Err(otp_fullotp::PumpError::Source(
            PadSourceError::PointerMismatch { .. }
        ))
    ));
    assert!(
        !client.is_active(),
        "指针分歧 ⇒ fail closed（不得回退，§2.3）"
    );
    std::fs::remove_dir_all(root).unwrap();
}
