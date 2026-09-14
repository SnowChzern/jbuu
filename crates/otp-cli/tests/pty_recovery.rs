//! WP-16 恢复语义验收（真实分配器 + 真实 WP-11 握手，loopback 旁录）：
//!
//! - **恢复 = 重新仲裁 + 签发新段**（wp02 §5.3）：每次连接（含恢复）都完成
//!   完整握手，段号互不相同、指针只前进——**旧段零重用**；
//! - **同一 PTY 存活**：恢复连接附着旧句柄，shell 状态可读；
//! - **并发恢复各得不同段 + 单主**：双客户端 barrier 竞争附着，恰一胜者
//!   （另一 `LeaseHeldByOther`），随后断线接管 token 递增
//!   （规划 §5 测试 10 全栈口径）；竞争者各持**独立客户端分配器**
//!   （`Ends::racer_ends`，F6 修复：握手套件不在持跨连接共享锁状态下
//!   做阻塞网络 I/O，见竞争测试处注释）；
//! - **恢复 token 只能是索引/句柄**：句柄恒为注册表计数器（跨会话不变），
//!   与段号推进无关联；
//! - **明文不出传输层**：WireTap 旁录不含终端明文与段正文。

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use otp_anchor_spec::{AnchorRecord, encode_record};
use otp_book::header::BookHeader;
use otp_term_cli::proto::{self, Endpoint};
use otp_terminal::{
    AttachMode, ClientOptions, ServeEnd, ServeSummary, TerminalError, TerminalEvent,
    TerminalHandle, TerminalRegistry, TerminalSession, WindowSize,
};
use otp_transport::{LoopbackTransport, WireTap};
use otp_types::{BookId, SEGMENT_LEN, SegmentIndex};

const ID: BookId = BookId::from_bytes(*b"OTPTERM-TESTBOOK");
const COUNT: u64 = 16;
const LEASE: Duration = Duration::from_secs(5);
const DEADLINE: Duration = Duration::from_secs(30);
const BUDGET: Duration = Duration::from_secs(15);

fn scratch(tag: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/tmp")
        .join(format!("otp-cli-ptyrec-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fill(seed: u8) -> impl Fn(u64) -> [u8; SEGMENT_LEN] {
    move |i| {
        let mut s = [0u8; SEGMENT_LEN];
        for (k, b) in s.iter_mut().enumerate() {
            *b = seed ^ (i as u8).wrapping_add(k as u8).wrapping_mul(7);
        }
        s
    }
}

fn write_test_book(dir: &Path, seed: u8) -> PathBuf {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("book.bin");
    let header = BookHeader::new(ID, COUNT).unwrap();
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(&header.encode()).unwrap();
    let fillfn = fill(seed);
    for i in 0..COUNT {
        f.write_all(&fillfn(i)).unwrap();
    }
    f.sync_all().unwrap();
    drop(f);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn write_init_anchors(dir: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let mut rec = Vec::new();
    encode_record(&AnchorRecord::init(ID), &mut rec);
    let mut paths = Vec::new();
    for copy in ["anchor-a", "anchor-b"] {
        let p = dir.join(format!("{copy}.anchor"));
        std::fs::write(&p, &rec).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        paths.push(p);
    }
    (paths.pop().unwrap(), paths.pop().unwrap())
}

/// 双端共享栈（克隆即共享）：分配器 ×2 + 终端注册表。
#[derive(Clone)]
struct Ends {
    ep: Endpoint,
    server_alloc: Arc<Mutex<otp_allocator::Allocator>>,
    client_alloc: Arc<Mutex<otp_allocator::Allocator>>,
    registry: Arc<TerminalRegistry>,
}

fn make_ends(tag: &str) -> Ends {
    let sdir = scratch(&format!("{tag}-s"));
    let cdir = scratch(&format!("{tag}-c"));
    let s_book = write_test_book(&sdir, 0x11);
    let (s_a, s_b) = write_init_anchors(&sdir);
    let c_book = write_test_book(&cdir, 0x11);
    let (c_a, c_b) = write_init_anchors(&cdir);
    let server_alloc = otp_allocator::Allocator::open(otp_allocator::AllocatorConfig {
        book: s_book,
        anchor_a: s_a,
        anchor_b: s_b,
        expected_book_id: ID,
    })
    .expect("服务端分配器");
    let client_alloc = otp_allocator::Allocator::open(otp_allocator::AllocatorConfig {
        book: c_book,
        anchor_a: c_a,
        anchor_b: c_b,
        expected_book_id: ID,
    })
    .expect("客户端分配器");
    Ends {
        ep: Endpoint {
            book_id: ID,
            segment_count: COUNT,
        },
        server_alloc: Arc::new(Mutex::new(server_alloc)),
        client_alloc: Arc::new(Mutex::new(client_alloc)),
        registry: Arc::new(TerminalRegistry::new(vec!["/bin/sh".into()], LEASE)),
    }
}

fn tapped_pair() -> ((LoopbackTransport, LoopbackTransport), WireTap) {
    LoopbackTransport::new_pair_tapped()
}

/// 竞争者专用端点栈：服务端侧（注册表/服务端分配器/端点参数）保持共享，
/// 客户端侧换成**独立分配器**（独立 book + 初始锚，内容与主客户端本一致）。
///
/// F6 修复（试金 R2）：修复前两个竞争线程共享 `client_alloc` 互斥锁跨
/// 整个阻塞网络握手，与服务端共享 `server_alloc` 交叉调度成 ABBA 四边
/// 互等环——racer_A 持 client_alloc 等对端 serve_A → serve_A 等
/// server_alloc（serve_B 持有跨整个握手）→ serve_B 等 racer_B 的 HELLO
/// → racer_B 等 client_alloc（racer_A 持有）——环上握手全部停滞，30s
/// DEADLINE 破环 → 质量门概率性翻红（f74cad3 上 35 跑 5 红）。
///
/// 独立分配器即真实产品拓扑：并发的第二条恢复连接只能来自另一个客户
/// 端进程——各自持独立锚状态（同机同锚文件会在分配器 OFD 锁上
/// fail-closed，不存在两进程共享同一内存分配器）。换独立分配器后，
/// 客户端侧握手不再持任何跨连接共享锁；唯一跨网络 I/O 的共享锁只剩
/// 服务端分配器——与产品 `serve_one` 同款（F7 观测，串行有界无环）。
/// 竞争者本地锚指针（0）落后于服务端（1/2）→ ARBITRATE SERVER_AHEAD
/// 跳段采纳（wp01 H3 产品正路，h3 状态机测试覆盖）；各连接约定段仍由
/// 共享服务端分配器在锁内串行签发——段号互异不变，恰一主/fencing
/// 断言原样保留。
fn racer_ends(ends: &Ends, tag: &str) -> Ends {
    let mut e = ends.clone();
    let dir = scratch(tag);
    let book = write_test_book(&dir, 0x11);
    let (a, b) = write_init_anchors(&dir);
    e.client_alloc = Arc::new(Mutex::new(
        otp_allocator::Allocator::open(otp_allocator::AllocatorConfig {
            book,
            anchor_a: a,
            anchor_b: b,
            expected_book_id: ID,
        })
        .expect("竞争者分配器"),
    ));
    e
}

/// 服务端连接线程：完整 WP-11 握手（重新仲裁+签发新段）→ WP-16 终端服务。
///
/// 握手期间持共享 `server_alloc`（与产品 `serve_one` 同款：服务端分配
/// 器唯一、握手串行、有界等待）。客户端侧永不阻塞在服务端分配器上
/// （各连接独立客户端分配器，见 `racer_ends`），故无互等环。
fn serve_thread(ends: &Ends, io: LoopbackTransport) -> std::thread::JoinHandle<ServeSummary> {
    let ends = ends.clone();
    std::thread::spawn(move || {
        let mut io = io;
        let (session, _info) = {
            let mut alloc = ends.server_alloc.lock().unwrap();
            proto::server_handshake(&mut io, &mut alloc, ends.ep, DEADLINE).expect("服务端握手")
        };
        otp_terminal::serve_connection(
            &ends.registry,
            io,
            session,
            ends.registry.next_conn(),
            &Default::default(),
        )
    })
}

/// 客户端连接：完整握手（新段）→ 附着。
fn client_attach(
    ends: &Ends,
    io: LoopbackTransport,
    mode: AttachMode,
) -> Result<(TerminalSession<LoopbackTransport>, SegmentIndex), TerminalError> {
    let mut io = io;
    let (session, info) = {
        let mut alloc = ends.client_alloc.lock().unwrap();
        proto::client_handshake(&mut io, &mut alloc, ends.ep, DEADLINE).expect("客户端握手")
    };
    let ts = TerminalSession::attach(
        io,
        session,
        mode,
        &ClientOptions {
            attach_timeout: BUDGET,
        },
    )?;
    Ok((ts, info.segment))
}

/// 收集输出直到 needle（等待期间持续心跳维持租约）。
fn collect_until(ts: &mut TerminalSession<LoopbackTransport>, needle: &str) -> Vec<u8> {
    let deadline = Instant::now() + BUDGET;
    let mut acc = Vec::new();
    loop {
        assert!(Instant::now() < deadline, "等待 {needle:?} 超时");
        match ts.poll_event(Duration::from_millis(200)).unwrap() {
            Some(TerminalEvent::Output(mut b)) => {
                if b.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                    acc.append(&mut b);
                    return acc;
                }
                acc.append(&mut b);
            }
            Some(TerminalEvent::Exit(c)) => panic!("过早退出 {c}"),
            None => {
                let _ = ts.ping();
            }
        }
    }
}

// ───────────────── ① 恢复=新段+同 PTY；旧段零重用 ─────────────────

#[test]
fn recovery_rearbitrates_new_segment_and_attaches_same_pty() {
    let ends = make_ends("rec");
    let mut taps = Vec::new();

    // 第一连接。
    let ((c1, s1), tap1) = tapped_pair();
    taps.push(tap1);
    let server1 = serve_thread(&ends, s1);
    let (mut ts1, seg1) = client_attach(
        &ends,
        c1,
        AttachMode::New {
            window: WindowSize::FALLBACK,
        },
    )
    .expect("附着");
    assert_eq!(seg1, SegmentIndex::new(0), "首会话消耗段 0");
    let handle = ts1.handle();
    let token1 = ts1.token();
    assert_eq!(handle, TerminalHandle(1));
    ts1.send_input(b"REC_STATE=qw-77\n").unwrap();
    collect_until(&mut ts1, "REC_STATE=qw-77");
    std::thread::sleep(Duration::from_millis(150)); // 让 shell 执行赋值
    ts1.close();
    assert_eq!(serve_thread_join(server1).end, ServeEnd::PeerClosed);

    // 断言：两端各前进 1（同段双端签发）。
    assert_eq!(ends.server_alloc.lock().unwrap().state().0.get(), 1);
    assert_eq!(ends.client_alloc.lock().unwrap().state().0.get(), 1);

    // 恢复连接：**重新握手 → 新段**，附着同一 PTY。
    let ((c2, s2), tap2) = tapped_pair();
    taps.push(tap2);
    let server2 = serve_thread(&ends, s2);
    let (mut ts2, seg2) = client_attach(
        &ends,
        c2,
        AttachMode::Recover {
            handle,
            window: WindowSize::FALLBACK,
        },
    )
    .expect("恢复附着");
    assert_ne!(seg1, seg2, "恢复必须签发新段（wp02 §5.3：绝不重用旧段）");
    assert_eq!(seg2, SegmentIndex::new(1), "恢复会话消耗段 1");
    assert_eq!(ts2.handle(), handle, "恢复 token=句柄（索引），跨会话不变");
    assert!(ts2.token() > token1, "接管 token 递增");
    ts2.send_input(b"echo $REC_STATE\n").unwrap();
    let out = collect_until(&mut ts2, "qw-77");
    assert!(out.windows(5).any(|w| w == b"qw-77"), "同一 PTY 存活");
    ts2.send_input(b"exit 0\n").unwrap();
    assert_eq!(ts2.wait_exit(BUDGET, |_| {}).unwrap().code, 0, "退出码回传");
    assert!(matches!(
        serve_thread_join(server2).end,
        ServeEnd::ShellExited { code: 0 }
    ));

    // 指针只前进：两端 next=2（两个会话、两个不同段、零重用）。
    assert_eq!(ends.server_alloc.lock().unwrap().state().0.get(), 2);
    assert_eq!(ends.client_alloc.lock().unwrap().state().0.get(), 2);

    // 明文不出传输层。
    let fillfn = fill(0x11);
    for tap in &taps {
        let wire = tap.snapshot();
        assert!(wire.len() > 100);
        assert!(!wire.windows(9).any(|w| w == b"REC_STATE"));
        assert!(!wire.windows(5).any(|w| w == b"qw-77"));
        for seg in [0u64, 1] {
            let s = fillfn(seg);
            assert!(!wire.windows(SEGMENT_LEN).any(|w| w == s), "段 {seg} 泄露");
        }
    }
}

fn serve_thread_join(h: std::thread::JoinHandle<ServeSummary>) -> ServeSummary {
    h.join().expect("服务线程汇合")
}

// ───────────────── ② 并发恢复竞争（规划 §5 测试 10 全栈口径） ─────────────────

#[test]
fn concurrent_recovery_races_single_master_and_distinct_segments() {
    let ends = make_ends("race");
    let mut taps = Vec::new();

    // holder 建立终端。
    let ((c1, s1), tap1) = tapped_pair();
    taps.push(tap1);
    let server1 = serve_thread(&ends, s1);
    let (mut ts1, seg1) = client_attach(
        &ends,
        c1,
        AttachMode::New {
            window: WindowSize::FALLBACK,
        },
    )
    .unwrap();
    let handle = ts1.handle();
    ts1.send_input(b"RACE_STATE=mk\n").unwrap();
    collect_until(&mut ts1, "RACE_STATE=mk");
    ts1.ping().unwrap();

    // 两个恢复连接：各自**先完成新握手（各签发不同段）**，再 barrier
    // 同放竞争 lease（附着时单主仲裁）。
    //
    // F6 修复：竞争者各持独立客户端分配器（旧夹具两线程共享
    // `client_alloc` 锁跨阻塞握手 → 与服务端 `server_alloc` 成 ABBA
    // 四边互等环，详见 `racer_ends` 注释）。竞争断言语义不变：
    // 恰一主/段号互异/fencing 全部原样。
    let barrier = Arc::new(Barrier::new(2));
    let mut racers = Vec::new();
    for n in 0..2 {
        let ((c, s), tap) = tapped_pair();
        taps.push(tap);
        let server = serve_thread(&ends, s);
        let ends2 = racer_ends(&ends, &format!("race-r{n}"));
        let barrier2 = Arc::clone(&barrier);
        racers.push(std::thread::spawn(move || {
            // 握手先行（新段签发与竞争无关：恢复必先重新仲裁）。
            // `ends2.client_alloc` 为本竞争者独占：持锁跨网络 I/O 不再
            // 与其他连接交叉（F6）。
            let mut c = c;
            let (session, info) = {
                let mut alloc = ends2.client_alloc.lock().unwrap();
                proto::client_handshake(&mut c, &mut alloc, ends2.ep, DEADLINE).expect("竞争者握手")
            };
            barrier2.wait(); // 两端都完成新段签发后同放
            let ts = TerminalSession::attach(
                c,
                session,
                AttachMode::Recover {
                    handle,
                    window: WindowSize::FALLBACK,
                },
                &ClientOptions {
                    attach_timeout: BUDGET,
                },
            );
            (ts, info.segment, server)
        }));
    }
    let mut segments = vec![seg1.get()];
    let mut granted = 0;
    let mut rejected = 0;
    for racer in racers {
        let (ts, seg, server) = racer.join().unwrap();
        segments.push(seg.get());
        match ts {
            Ok(_ts) => granted += 1,
            Err(TerminalError::LeaseHeldByOther { .. }) => rejected += 1,
            Err(other) => panic!("竞争附着意外错误：{other:?}"),
        }
        let summary = serve_thread_join(server);
        if granted == 0 {
            assert_eq!(summary.end, ServeEnd::DeniedBusy, "拒绝者摘要");
        }
    }
    assert_eq!(granted, 0, "holder 活跃期间不得有任何接管");
    assert_eq!(rejected, 2, "并发恢复全部被单主拒绝");
    // 并发恢复各得不同段：三个已签发段互不相同。
    segments.sort_unstable();
    segments.dedup();
    assert_eq!(segments.len(), 3, "各会话段号互异：{segments:?}");
    assert_eq!(segments, vec![0, 1, 2]);

    // holder 断线 → 重试接管：token 递增 + 同一 PTY。
    ts1.close();
    assert_eq!(serve_thread_join(server1).end, ServeEnd::PeerClosed);
    let ((c4, s4), tap4) = tapped_pair();
    taps.push(tap4);
    let server4 = serve_thread(&ends, s4);
    let (mut ts4, seg4) = client_attach(
        &ends,
        c4,
        AttachMode::Recover {
            handle,
            window: WindowSize::FALLBACK,
        },
    )
    .expect("断线后接管");
    assert_eq!(seg4.get(), 3, "第四会话消耗段 3");
    assert!(ts4.token() > 1);
    ts4.send_input(b"echo $RACE_STATE\n").unwrap();
    collect_until(&mut ts4, "mk");
    ts4.send_input(b"exit 0\n").unwrap();
    assert_eq!(ts4.wait_exit(BUDGET, |_| {}).unwrap().code, 0);
    serve_thread_join(server4);

    // 旁录扫描。
    let fillfn = fill(0x11);
    for tap in &taps {
        let wire = tap.snapshot();
        assert!(!wire.windows(10).any(|w| w == b"RACE_STATE"), "明文泄露");
        for seg in 0u64..4 {
            let s = fillfn(seg);
            assert!(!wire.windows(SEGMENT_LEN).any(|w| w == s), "段 {seg} 泄露");
        }
    }
}

// ───────────────── ③ 恢复句柄与段材料零关联（结构性） ─────────────────

#[test]
fn recovery_handle_is_registry_index_not_segment_material() {
    // 句柄在多次会话间保持同一小整数计数器值，而段号随每次握手递增：
    // 恢复 token 与段号/段正文无函数关系（wp02 §5.3：只能是索引/句柄）。
    let ends = make_ends("hnd");
    let ((c1, s1), _tap) = tapped_pair();
    let server1 = serve_thread(&ends, s1);
    let (mut ts1, seg1) = client_attach(
        &ends,
        c1,
        AttachMode::New {
            window: WindowSize::FALLBACK,
        },
    )
    .unwrap();
    let handle = ts1.handle();
    assert_eq!(handle.0, 1, "句柄=注册表计数器初值");
    assert_eq!(seg1.get(), 0);
    ts1.send_input(b"exit 0\n").unwrap();
    ts1.wait_exit(BUDGET, |_| {}).unwrap();
    serve_thread_join(server1);

    // 新开终端：句柄 2，与段推进（1、2…）独立递增。
    let ((c2, s2), _tap2) = tapped_pair();
    let server2 = serve_thread(&ends, s2);
    let (mut ts2, seg2) = client_attach(
        &ends,
        c2,
        AttachMode::New {
            window: WindowSize::FALLBACK,
        },
    )
    .unwrap();
    assert_eq!(ts2.handle().0, 2);
    assert_eq!(seg2.get(), 1);
    assert_ne!(ts2.handle(), TerminalHandle(seg2.get()), "句柄≠段号派生");
    ts2.send_input(b"exit 0\n").unwrap();
    ts2.wait_exit(BUDGET, |_| {}).unwrap();
    serve_thread_join(server2);
}
