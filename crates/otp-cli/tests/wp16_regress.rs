//! WP-16 返工回归（任务 #56）：F1/F2/F4 修复后的**正向**回归——
//! 断言修复后的正确行为（对照件 `shijin_findings.rs`〔试金，任务 #55〕
//! 断言缺陷行为本身，二者互补：缺陷件在修复后应转红）。
//!
//! - F1（严重）纯输出长流：客户端泵按 ping_interval **无条件**发 Ping
//!   （与输出活动解耦）→ 无键入的连续输出超过 lease 也不再被
//!   LeaseExpired 中途逐出。本测试走真实泵（`run_interactive`，静默
//!   stdin——与 `otp-term connect` 管道形态同构）。
//! - F2（阻断）单帧大输入：服务端按 ≤PTY_WRITE_SLICE 分片写 master 并
//!   在片间排空回显 → 回显即时流出（不再楔死）、服务端线程正常终止、
//!   租约锁不被无限持有（并发 acquire 即时返回 Busy）。
//! - F4（一般）PTY 子进程收割：PDEATHSIG(SIGKILL) 锚点 = registry
//!   专用长寿命 spawn 线程——registry 消亡（serve 进程死亡等价物）后
//!   shell 被内核收割（交互式 shell 忽略 SIGTERM，故用 SIGKILL），不
//!   残留 pts 孤儿；hub 自身未被 Drop（排除 kill+reap 路径的干扰）。

#![forbid(unsafe_code)]

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use otp_term_cli::proto::{self, Endpoint};
use otp_terminal::{
    AttachMode, ClientOptions, LeaseDenied, ServeEnd, ServeSummary, TerminalError, TerminalEvent,
    TerminalRegistry, TerminalSession, WindowSize,
};
use otp_transport::LoopbackTransport;

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/tmp")
        .join(format!("otp-cli-reg56-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const ID: otp_types::BookId = otp_types::BookId::from_bytes(*b"OTPTERM-TESTBOOK");
const COUNT: u64 = 24;
const BUDGET: Duration = Duration::from_secs(20);

#[derive(Clone)]
struct Ends {
    ep: Endpoint,
    server_alloc: Arc<Mutex<otp_allocator::Allocator>>,
    client_alloc: Arc<Mutex<otp_allocator::Allocator>>,
    registry: Arc<TerminalRegistry>,
}

fn make_ends(tag: &str, lease: Duration) -> Ends {
    let sdir = scratch(&format!("{tag}-s"));
    let cdir = scratch(&format!("{tag}-c"));
    let mk = |dir: &std::path::Path| {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("book.bin");
        let header = otp_book::header::BookHeader::new(ID, COUNT).unwrap();
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&header.encode()).unwrap();
        for i in 0..COUNT {
            let mut s = [0u8; 64];
            for (k, b) in s.iter_mut().enumerate() {
                *b = 0x5a ^ (i as u8).wrapping_add(k as u8).wrapping_mul(7);
            }
            f.write_all(&s).unwrap();
        }
        f.sync_all().unwrap();
        drop(f);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut rec = Vec::new();
        otp_anchor_spec::encode_record(&otp_anchor_spec::AnchorRecord::init(ID), &mut rec);
        let mut paths = Vec::new();
        for copy in ["anchor-a", "anchor-b"] {
            let p = dir.join(format!("{copy}.anchor"));
            std::fs::write(&p, &rec).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            paths.push(p);
        }
        (paths.pop().unwrap(), paths.pop().unwrap())
    };
    let (s_a, s_b) = mk(&sdir);
    let (c_a, c_b) = mk(&cdir);
    let s_book = sdir.join("book.bin");
    let c_book = cdir.join("book.bin");
    Ends {
        ep: Endpoint {
            book_id: ID,
            segment_count: COUNT,
        },
        server_alloc: Arc::new(Mutex::new(
            otp_allocator::Allocator::open(otp_allocator::AllocatorConfig {
                book: s_book,
                anchor_a: s_a,
                anchor_b: s_b,
                expected_book_id: ID,
            })
            .unwrap(),
        )),
        client_alloc: Arc::new(Mutex::new(
            otp_allocator::Allocator::open(otp_allocator::AllocatorConfig {
                book: c_book,
                anchor_a: c_a,
                anchor_b: c_b,
                expected_book_id: ID,
            })
            .unwrap(),
        )),
        registry: Arc::new(TerminalRegistry::new(vec!["/bin/sh".into()], lease)),
    }
}

fn serve_thread(ends: &Ends, io: LoopbackTransport) -> std::thread::JoinHandle<ServeSummary> {
    let ends = ends.clone();
    std::thread::spawn(move || {
        let mut io = io;
        let (session, _info) = {
            let mut alloc = ends.server_alloc.lock().unwrap();
            proto::server_handshake(&mut io, &mut alloc, ends.ep, Duration::from_secs(30))
                .expect("服务端握手")
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

fn client_attach(ends: &Ends, io: LoopbackTransport) -> TerminalSession<LoopbackTransport> {
    let mut io = io;
    let (session, _info) = {
        let mut alloc = ends.client_alloc.lock().unwrap();
        proto::client_handshake(&mut io, &mut alloc, ends.ep, Duration::from_secs(30))
            .expect("客户端握手")
    };
    TerminalSession::attach(
        io,
        session,
        AttachMode::New {
            window: WindowSize::FALLBACK,
        },
        &ClientOptions {
            attach_timeout: BUDGET,
        },
    )
    .expect("附着")
}

/// 永远静默的 stdin（真实泵在整个纯输出期间零键入——F1 缺陷形态）。
struct SilentStdin;

impl io::Read for SilentStdin {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        // 永久阻塞（无人 unpark）：pump 的输入线程被有意放弃，由进程
        // 退出收割（与 run_interactive 对 tty stdin 的既有语义一致）。
        loop {
            std::thread::park();
        }
    }
}

// ─────────── F1：真实泵在纯输出长流期间保持活性（不再 LeaseExpired） ───────────

#[test]
fn f1_pump_survives_pure_output_beyond_lease() {
    // lease 5s；纯输出流 45×0.2s = 9s（> lease），期间 stdin 零键入。
    let ends = make_ends("f1r", Duration::from_secs(5));
    let ((c, s), _tap) = LoopbackTransport::new_pair_tapped();
    let server = serve_thread(&ends, s);
    let mut ts = client_attach(&ends, c);
    ts.send_input(
        b"for i in $(seq 1 45); do echo F1L-$i; sleep 0.2; done; echo F1-FINISH-MARK; exit 0\n",
    )
    .unwrap();
    let t0 = Instant::now();
    // 真实客户端泵（connect 同构）：静默 stdin + 1s 无条件心跳。
    let mut sink = Vec::new();
    let exit = ts
        .run_interactive(SilentStdin, &mut sink, Duration::from_secs(1), || None)
        .expect("泵应正常完成");
    let dt = t0.elapsed();
    let summary = server.join().unwrap();
    eprintln!(
        "F1R: {dt:?} exit={} 输出 {}B end={:?}",
        exit.code,
        sink.len(),
        summary.end
    );
    assert_eq!(exit.code, 0, "远端应正常退出");
    assert!(
        dt >= Duration::from_secs(8),
        "流必须完整跑完（>8s），实测 {dt:?}"
    );
    let out = String::from_utf8_lossy(&sink);
    assert!(out.contains("F1-FINISH-MARK"), "完成标记必须到达");
    assert!(out.contains("F1L-45"), "末行必须到达（流不得中途截断）");
    assert!(
        matches!(summary.end, ServeEnd::ShellExited { code: 0 }),
        "服务端应以 ShellExited 终止（不得 LeaseExpired/Fenced）：{:?}",
        summary.end
    );
    assert!(summary.output_bytes > 200, "应有可观测输出");
}

// ─────────── F2：单帧大输入 → 回显流出 + 恢复/接管路径可用 ───────────

#[test]
fn f2_large_single_frame_flows_and_lease_paths_stay_alive() {
    let ends = make_ends("f2r", Duration::from_secs(5));
    let ((c, s), _tap) = LoopbackTransport::new_pair_tapped();
    let server = serve_thread(&ends, s);
    let mut ts = client_attach(&ends, c);
    let handle = ts.handle();
    // 与试金复现同负载：单帧 32080B（16×2005B 行，ECHO 开启）。
    let mut sent = Vec::new();
    for i in 0..16u32 {
        sent.extend_from_slice(format!("L{i:02}:{}\n", "x".repeat(2000)).as_bytes());
    }
    let t0 = Instant::now();
    ts.send_input(&sent).unwrap();
    // 楔死观测窗（试金口径：6s 内零输出=缺陷；修复后应持续流出）。
    let mut got = 0usize;
    let mut first_out: Option<Instant> = None;
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        match ts.poll_event(Duration::from_millis(200)) {
            Ok(Some(TerminalEvent::Output(b))) => {
                if first_out.is_none() {
                    first_out = Some(Instant::now());
                }
                got += b.len();
            }
            Ok(Some(TerminalEvent::Exit(_))) => panic!("不应退出"),
            Ok(None) => {
                let _ = ts.ping();
            }
            Err(_) => break,
        }
    }
    eprintln!(
        "F2R: 6s 窗口收到 {got}B，首发于 {:?}",
        first_out.map(|t| t - t0)
    );
    assert!(got > 8_000, "回显必须持续流出（缺陷形态为 0B）：{got}B");
    assert!(
        first_out.is_some_and(|t| (t - t0) < Duration::from_secs(2)),
        "回显应在 2s 内开始（不得楔死）"
    );
    // 并发 acquire 必须即时返回（缺陷形态：lease 锁被楔住的写持有 →
    // acquire 无响应）。holder 活跃 → 预期 Busy。
    let hub = Arc::clone(&ends.registry.find(handle).unwrap());
    let taker = std::thread::spawn(move || hub.acquire(99));
    let takeover = join_timeout(taker, Duration::from_secs(3));
    assert!(
        takeover.is_some(),
        "acquire 必须 3s 内返回（写门不得无限持锁）"
    );
    let busy = matches!(takeover, Some(Err(LeaseDenied::Busy { .. })));
    assert!(
        busy,
        "holder 活跃期间应为 Busy（takeover 返回即证明写门未无限持锁）"
    );
    // 干净收尾：全量回显 + 正常退出 + 服务端线程终止。
    ts.send_input(b"echo F2-DONE\nexit 0\n").unwrap();
    let mut done = false;
    let needle = b"F2-DONE";
    let deadline = Instant::now() + BUDGET;
    while Instant::now() < deadline {
        match ts.poll_event(Duration::from_millis(200)) {
            Ok(Some(TerminalEvent::Output(b))) => {
                if b.windows(needle.len()).any(|w| w == needle) {
                    done = true;
                }
            }
            Ok(Some(TerminalEvent::Exit(code))) => {
                assert_eq!(code, 0);
                break;
            }
            Ok(None) => {
                let _ = ts.ping();
            }
            Err(e) => panic!("收尾不应失败：{e:?}"),
        }
    }
    assert!(done, "F2-DONE 标记必须到达");
    let summary = server.join().unwrap();
    eprintln!(
        "F2R: end={:?} input={}B output={}B",
        summary.end, summary.input_bytes, summary.output_bytes
    );
    assert!(
        matches!(summary.end, ServeEnd::ShellExited { code: 0 }),
        "服务端应以 ShellExited 终止：{:?}",
        summary.end
    );
    assert_eq!(
        summary.input_bytes,
        (sent.len() + b"echo F2-DONE\nexit 0\n".len()) as u64
    );
}

// ─────────── F4：registry（spawn 线程）消亡 → 内核收割 PTY 子进程 ───────────

#[test]
fn f4_registry_death_reaps_pty_child_via_pdeathsig() {
    let registry = Arc::new(TerminalRegistry::new(
        vec!["/bin/sh".into()],
        Duration::from_secs(30),
    ));
    let hub = registry.open(WindowSize::FALLBACK).unwrap();
    // 控制项：registry 存活期间 shell 正常工作（写读回显可用）。
    let grant = hub.acquire(1).unwrap();
    hub.write_input(grant.token(), b"echo F4-ALIVE\n").unwrap();
    let mut acc = Vec::new();
    let mut buf = vec![0u8; 4096];
    let alive = b"F4-ALIVE";
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !acc.windows(alive.len()).any(|w| w == alive) {
        if let otp_platform::pty::PtyRead::Data(n) = hub.drain_output(&mut buf).unwrap() {
            acc.extend_from_slice(&buf[..n]);
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    assert!(
        acc.windows(alive.len()).any(|w| w == alive),
        "registry 存活期间 shell 必须可交互：{:?}",
        String::from_utf8_lossy(&acc)
    );
    drop(grant);
    // serve 硬杀的等价物：spawn 线程随 registry 消亡；hub 仍存活
    // （Arc 在手）——排除 hub Drop kill+reap 路径，只可能是 PDEATHSIG。
    drop(registry);
    let deadline = Instant::now() + Duration::from_secs(10);
    let exit = loop {
        if let Some(e) = hub.poll_exit() {
            break e;
        }
        assert!(Instant::now() < deadline, "spawn 线程消亡后 shell 应被收割");
        std::thread::sleep(Duration::from_millis(20));
    };
    eprintln!("F4R: 收割退出码 {}（SIGKILL=128+9）", exit.code);
    assert_eq!(
        exit.code,
        128 + 9,
        "应为内核投递的 SIGKILL 终止（交互式 shell 忽略 SIGTERM）"
    );
}

/// join 带超时（None = 期限内未返回）。
fn join_timeout<T: Send + 'static>(h: std::thread::JoinHandle<T>, d: Duration) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(h.join().ok());
    });
    rx.recv_timeout(d).unwrap_or_default()
}

// 静默未使用告警：TerminalError 仅出现在文档注释口径中。
const _: fn(TerminalError) -> String = |e| format!("{e}");
