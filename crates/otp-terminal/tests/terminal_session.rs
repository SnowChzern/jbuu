//! 终端会话端到端（WP-16）：loopback 传输 + 直接构造的配对 AEAD 会话 +
//! 真实 PTY（/bin/sh），覆盖：
//!
//! - PTY I/O / 窗口协商 / 退出码经**加密会话**往返（e2e）；
//! - 恢复 = 附着同一 PTY（shell 状态存活）+ 重新仲裁租约（token 递增）；
//! - 未知句柄 → `TerminalGone`；
//! - 单主：活跃 holder 在位时第二连接附着被拒（`LeaseHeldByOther`），
//!   断线后接管（token 递增）；lease 超时接管后旧连接写被 fence；
//! - 传输层明文断言：WireTap 旁录字节不含 PTY 明文与段正文。
//!
//! 段材料口径：本夹具用确定性段内容（0x5A 模式）直接构造会话对，
//! "恢复 = 重新握手 + 新签发段、旧段零重用"的**分配器级**断言在
//! otp-cli 的 pty_recovery.rs（真实 Allocator + 真实握手）覆盖。

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use otp_session::{CommittedSegment, Session, SessionContext};
use otp_terminal::{
    AttachMode, ClientOptions, FencingToken, ServeEnd, ServeOptions, TerminalError, TerminalEvent,
    TerminalHandle, TerminalRegistry, TerminalSession, WindowSize, serve_connection,
};
use otp_transport::LoopbackTransport;
use otp_types::{BookId, ClientNonce, Role, SEGMENT_LEN, SegmentIndex, ServerNonce};

const LEASE_SANE: Duration = Duration::from_secs(8);
const LEASE_SHORT: Duration = Duration::from_millis(350);
const BUDGET: Duration = Duration::from_secs(15);

/// 确定性段内容（secret 扫描口径：0x5A 重复 64B）。
fn segment_bytes() -> [u8; SEGMENT_LEN] {
    [0x5A; SEGMENT_LEN]
}

/// 构造配对会话（客户端/服务端同段同 nonce 副本——与真实握手产物同构）。
///
/// 序号状态对齐：真实 WP-11 握手中双向 CONFIRM 各占 seq=0（wp03 §4.1），
/// DATA 自 1 起。本夹具以合成 CONFIRM 互换推进两侧 seq 状态（丢弃载荷），
/// 与 Established 产物的序号状态完全一致。
fn session_pair() -> (Session, Session) {
    let seg = segment_bytes();
    let ctx = SessionContext {
        role: Role::Client,
        book_id: BookId::from_bytes(*b"OTPTERM-TESTBOOK"),
        segment: SegmentIndex::ZERO,
        client_nonce: ClientNonce::from_bytes([0x11; 16]),
        server_nonce: ServerNonce::from_bytes([0x22; 16]),
    };
    let mut client = Session::new(CommittedSegment::from_bytes(seg), ctx);
    let mut server = Session::new(
        CommittedSegment::from_bytes(seg),
        SessionContext {
            role: Role::Server,
            ..ctx
        },
    );
    use otp_session::MessageType;
    let c_confirm = client
        .seal(MessageType::ClientConfirm, &[0u8; 8])
        .expect("合成 CONFIRM(seq=0)");
    server
        .open(
            MessageType::ClientConfirm,
            c_confirm.sequence,
            c_confirm.sealed(),
        )
        .expect("合成 CONFIRM 互认");
    let s_confirm = server
        .seal(MessageType::ServerConfirm, &[0u8; 8])
        .expect("合成 CONFIRM(seq=0)");
    client
        .open(
            MessageType::ServerConfirm,
            s_confirm.sequence,
            s_confirm.sealed(),
        )
        .expect("合成 CONFIRM 互认");
    (client, server)
}

fn registry(lease: Duration) -> TerminalRegistry {
    TerminalRegistry::new(vec!["/bin/sh".into()], lease)
}

fn serve_opts() -> ServeOptions {
    ServeOptions {
        first_frame_timeout: BUDGET,
        poll_slice: Duration::from_millis(20),
        exit_grace: Duration::from_millis(150),
    }
}

/// 收集输出直到包含 needle（预算内）；超时 panic。
fn collect_until(
    client: &mut TerminalSession<LoopbackTransport>,
    needle: &str,
    budget: Duration,
) -> Vec<u8> {
    let deadline = Instant::now() + budget;
    let mut acc = Vec::new();
    loop {
        assert!(
            Instant::now() < deadline,
            "等待 {needle:?} 超时；已收：{acc:?}"
        );
        match client.poll_event(Duration::from_millis(200)).unwrap() {
            Some(TerminalEvent::Output(mut b)) => {
                if b.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                    acc.append(&mut b);
                    return acc;
                }
                acc.append(&mut b);
            }
            Some(TerminalEvent::Exit(code)) => panic!("过早退出：{code}；已收：{acc:?}"),
            None => {}
        }
    }
}

fn attach(io: LoopbackTransport, mode: AttachMode) -> TerminalSession<LoopbackTransport> {
    let (session, _server_session) = session_pair();
    TerminalSession::attach(
        io,
        session,
        mode,
        &ClientOptions {
            attach_timeout: BUDGET,
        },
    )
    .unwrap()
}

// ───────────────────────── ① PTY I/O / 窗口 / 退出码（e2e） ─────────────────────────

#[test]
fn pty_io_window_and_exit_code_over_encrypted_session() {
    let ((client_io, server_io), tap) = LoopbackTransport::new_pair_tapped();
    let reg = std::sync::Arc::new(registry(LEASE_SANE));
    let sreg = std::sync::Arc::clone(&reg);
    let (_sc, session_server) = session_pair();
    let server = std::thread::spawn(move || {
        let conn = sreg.next_conn();
        serve_connection(&sreg, server_io, session_server, conn, &serve_opts())
    });

    let mut client = attach(
        client_io,
        AttachMode::New {
            window: WindowSize { rows: 24, cols: 80 },
        },
    );
    let handle = client.handle();
    assert_eq!(handle, TerminalHandle(1), "句柄=注册表索引计数器");

    // PTY 输入 → shell → 输出。
    client.send_input(b"echo otp-term-marker-7\n").unwrap();
    collect_until(&mut client, "otp-term-marker-7", BUDGET);

    // 窗口协商：Resize 帧 → TIOCSWINSZ → stty size 反映。
    client
        .resize(WindowSize {
            rows: 33,
            cols: 111,
        })
        .unwrap();
    client.send_input(b"stty size\n").unwrap();
    collect_until(&mut client, "33 111", BUDGET);

    // 退出码回传。
    client.send_input(b"exit 7\n").unwrap();
    let code = client.wait_exit(BUDGET, |_| {}).unwrap();
    assert_eq!(code.code, 7);

    let summary = server.join().unwrap();
    assert_eq!(summary.end, ServeEnd::ShellExited { code: 7 });
    assert_eq!(summary.handle, TerminalHandle(1));
    assert_eq!(summary.token, FencingToken(1));
    assert!(summary.input_bytes > 0 && summary.output_bytes > 0);

    // 传输层明文断言：PTY 明文与段正文均不出现在旁录字节流。
    let wire = tap.snapshot();
    assert!(wire.len() > 100, "旁录应有流量");
    assert!(
        !wire.windows(17).any(|w| w == b"otp-term-marker-7"),
        "PTY 明文出现在传输层"
    );
    let seg = segment_bytes();
    assert!(
        !wire.windows(SEGMENT_LEN).any(|w| w == seg),
        "段正文出现在传输层"
    );
}

// ───────────────────────── ② 恢复：同一 PTY + 重新仲裁租约 ─────────────────────────

#[test]
fn recovery_attaches_same_shell_with_incremented_token() {
    let reg = std::sync::Arc::new(registry(LEASE_SANE));

    // 第一连接：建立终端并留下 shell 状态。
    let handle;
    let token1;
    {
        let ((c1, s1), _tap) = LoopbackTransport::new_pair_tapped();
        let sreg = std::sync::Arc::clone(&reg);
        let (_sc, session_server) = session_pair();
        let server = std::thread::spawn(move || {
            serve_connection(&sreg, s1, session_server, sreg.next_conn(), &serve_opts())
        });
        let mut client = attach(
            c1,
            AttachMode::New {
                window: WindowSize::FALLBACK,
            },
        );
        handle = client.handle();
        token1 = client.token();
        client.send_input(b"RECOVERY_STATE=zz9x\n").unwrap();
        collect_until(&mut client, "RECOVERY_STATE=zz9x", BUDGET);
        // 回显匹配只证明输入已达 PTY 队列；稍候确保 shell 执行赋值后再断线。
        std::thread::sleep(Duration::from_millis(250));
        client.close(); // 断线（服务端据此结束连接并放弃租约）
        let summary = server.join().unwrap();
        assert_eq!(summary.end, ServeEnd::PeerClosed);
    }

    // 恢复连接：附着同一句柄——shell 状态存活证明同一 PTY。
    {
        let ((c2, s2), _tap) = LoopbackTransport::new_pair_tapped();
        let sreg = std::sync::Arc::clone(&reg);
        let (_sc, session_server) = session_pair();
        let server = std::thread::spawn(move || {
            serve_connection(&sreg, s2, session_server, sreg.next_conn(), &serve_opts())
        });
        let mut client = attach(
            c2,
            AttachMode::Recover {
                handle,
                window: WindowSize::FALLBACK,
            },
        );
        assert_eq!(client.handle(), handle, "恢复返回同一句柄");
        assert!(
            client.token() > token1,
            "接管 fencing token 必须递增（{} → {}）",
            token1,
            client.token()
        );
        client.send_input(b"echo $RECOVERY_STATE\n").unwrap();
        let out = collect_until(&mut client, "zz9x", BUDGET);
        assert!(
            out.windows(4).any(|w| w == b"zz9x"),
            "恢复连接附着的是同一 shell（状态存活）"
        );
        client.send_input(b"exit 0\n").unwrap();
        assert_eq!(client.wait_exit(BUDGET, |_| {}).unwrap().code, 0);
        let summary = server.join().unwrap();
        assert_eq!(summary.end, ServeEnd::ShellExited { code: 0 });
    }

    // 退出后的句柄作废：Gone。
    {
        let ((c3, s3), _tap) = LoopbackTransport::new_pair_tapped();
        let sreg = std::sync::Arc::clone(&reg);
        let (_sc, session_server) = session_pair();
        let server = std::thread::spawn(move || {
            serve_connection(&sreg, s3, session_server, sreg.next_conn(), &serve_opts())
        });
        let (session, _ss) = session_pair();
        let err = match TerminalSession::attach(
            c3,
            session,
            AttachMode::Recover {
                handle,
                window: WindowSize::FALLBACK,
            },
            &ClientOptions {
                attach_timeout: BUDGET,
            },
        ) {
            Err(e) => e,
            Ok(_) => panic!("已退出句柄的附着必须被拒绝"),
        };
        assert_eq!(err, TerminalError::TerminalGone);
        assert_eq!(server.join().unwrap().end, ServeEnd::DeniedGone);
    }
}

// ───────────────────────── ③ 单主：并发附着恰一个 writer ─────────────────────────

#[test]
fn dual_attach_while_holder_active_is_rejected_then_takeover() {
    let reg = std::sync::Arc::new(registry(LEASE_SANE));

    // holder 活跃。
    let ((c1, s1), _t1) = LoopbackTransport::new_pair_tapped();
    let sreg = std::sync::Arc::clone(&reg);
    let (_sc, session_server1) = session_pair();
    let server1 = std::thread::spawn(move || {
        serve_connection(&sreg, s1, session_server1, sreg.next_conn(), &serve_opts())
    });
    let mut client1 = attach(
        c1,
        AttachMode::New {
            window: WindowSize::FALLBACK,
        },
    );
    let handle = client1.handle();
    let token1 = client1.token();
    client1.send_input(b"DUAL_STATE=1\n").unwrap();
    collect_until(&mut client1, "DUAL_STATE=1", BUDGET);

    // 并发恢复请求：单主拒绝（Barrier 同放后竞争）。
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut racers = Vec::new();
    for _ in 0..2 {
        let ((c2, s2), _t2) = LoopbackTransport::new_pair_tapped();
        let sreg = std::sync::Arc::clone(&reg);
        let (_sc, session_server) = session_pair();
        let server = std::thread::spawn(move || {
            serve_connection(&sreg, s2, session_server, sreg.next_conn(), &serve_opts())
        });
        let barrier2 = std::sync::Arc::clone(&barrier);
        let racer = std::thread::spawn(move || {
            let (session, _ss) = session_pair();
            barrier2.wait();
            TerminalSession::attach(
                c2,
                session,
                AttachMode::Recover {
                    handle,
                    window: WindowSize::FALLBACK,
                },
                &ClientOptions {
                    attach_timeout: BUDGET,
                },
            )
        });
        racers.push((racer, server));
    }
    let mut rejected = 0;
    let mut granted = Vec::new();
    for (racer, server) in racers {
        match racer.join().unwrap() {
            Err(TerminalError::LeaseHeldByOther { .. }) => rejected += 1,
            Ok(sess) => granted.push(sess),
            Err(other) => panic!("竞争附着意外错误：{other:?}"),
        }
        let summary = server.join().unwrap();
        if summary.end == ServeEnd::DeniedBusy {
            assert_eq!(summary.token, FencingToken::ZERO);
        }
    }
    assert_eq!(granted.len(), 0, "holder 活跃期间不得有任何接管");
    assert_eq!(rejected, 2);

    // holder 断线 → 竞争者重试接管，token 递增，仍是同一 PTY。
    client1.close();
    assert_eq!(server1.join().unwrap().end, ServeEnd::PeerClosed);
    let ((c3, s3), _t3) = LoopbackTransport::new_pair_tapped();
    let sreg = std::sync::Arc::clone(&reg);
    let (_sc, session_server) = session_pair();
    let server = std::thread::spawn(move || {
        serve_connection(&sreg, s3, session_server, sreg.next_conn(), &serve_opts())
    });
    let mut client3 = attach(
        c3,
        AttachMode::Recover {
            handle,
            window: WindowSize::FALLBACK,
        },
    );
    assert!(client3.token() > token1, "接管 token 必须递增");
    client3.send_input(b"echo $DUAL_STATE\n").unwrap();
    collect_until(&mut client3, "1", BUDGET);
    client3.send_input(b"exit 0\n").unwrap();
    assert_eq!(client3.wait_exit(BUDGET, |_| {}).unwrap().code, 0);
    server.join().unwrap();
}

// ───────────────────────── ④ 超时接管后旧连接被 fence ─────────────────────────

#[test]
fn lease_expiry_takeover_fences_stale_connection() {
    let reg = std::sync::Arc::new(registry(LEASE_SHORT));

    let ((c1, s1), _t1) = LoopbackTransport::new_pair_tapped();
    let sreg = std::sync::Arc::clone(&reg);
    let (_sc, session_server1) = session_pair();
    let server1 = std::thread::spawn(move || {
        serve_connection(&sreg, s1, session_server1, sreg.next_conn(), &serve_opts())
    });
    let mut client1 = attach(
        c1,
        AttachMode::New {
            window: WindowSize::FALLBACK,
        },
    );
    let handle = client1.handle();
    let token1 = client1.token();
    client1.send_input(b"echo before-expiry\n").unwrap();
    collect_until(&mut client1, "before-expiry", BUDGET);

    // 静默超过 lease 超时（无心跳）→ 新连接接管。
    std::thread::sleep(LEASE_SHORT * 3);
    let ((c2, s2), _t2) = LoopbackTransport::new_pair_tapped();
    let sreg = std::sync::Arc::clone(&reg);
    let (_sc, session_server2) = session_pair();
    let server2 = std::thread::spawn(move || {
        serve_connection(&sreg, s2, session_server2, sreg.next_conn(), &serve_opts())
    });
    let mut client2 = attach(
        c2,
        AttachMode::Recover {
            handle,
            window: WindowSize::FALLBACK,
        },
    );
    assert!(client2.token() > token1);

    // 旧连接（陈旧 writer）再写：服务端 fence 并关闭其连接。
    let mut fenced = false;
    for _ in 0..50 {
        if client1.send_input(b"echo stale-writer\n").is_err() {
            fenced = true;
            break;
        }
        match client1.poll_event(Duration::from_millis(100)) {
            Err(_) => {
                fenced = true;
                break;
            }
            Ok(Some(TerminalEvent::Exit(_))) => panic!("旧连接不应收到正常退出"),
            _ => {}
        }
    }
    assert!(
        fenced,
        "陈旧 writer 的后续操作必须以错误收场（被 fence/关闭）"
    );
    let summary1 = server1.join().unwrap();
    // 旧连接终止：被接管 fence（takeover 先于自检）或 lease 超时自逐出——
    // 两者都是单主不变量的合法执行（谁先观察到超时取决于时序）；
    // 双主被拒/陈旧 writer 被拒已在 lease_race 与本测试上方确定性覆盖。
    assert!(
        matches!(summary1.end, ServeEnd::Fenced | ServeEnd::LeaseExpired),
        "旧连接应以 fenced/lease-expired 终止，实际：{:?}",
        summary1.end
    );

    // 新 holder 继续正常工作。
    client2.send_input(b"exit 0\n").unwrap();
    assert_eq!(client2.wait_exit(BUDGET, |_| {}).unwrap().code, 0);
    assert_eq!(
        server2.join().unwrap().end,
        ServeEnd::ShellExited { code: 0 }
    );
}

// ───────────────────────── ⑤ 心跳维持租约（超时不误伤活跃连接） ─────────────────────────

#[test]
fn heartbeat_keeps_lease_across_multiple_windows() {
    let reg = std::sync::Arc::new(registry(Duration::from_millis(600)));
    let ((c1, s1), _t1) = LoopbackTransport::new_pair_tapped();
    let sreg = std::sync::Arc::clone(&reg);
    let (_sc, session_server) = session_pair();
    let server = std::thread::spawn(move || {
        serve_connection(&sreg, s1, session_server, sreg.next_conn(), &serve_opts())
    });
    let mut client = attach(
        c1,
        AttachMode::New {
            window: WindowSize::FALLBACK,
        },
    );
    for i in 0..4u32 {
        std::thread::sleep(Duration::from_millis(250));
        client.ping().unwrap();
        client
            .send_input(format!("echo hb-{i}\n").as_bytes())
            .unwrap();
        collect_until(&mut client, &format!("hb-{i}"), BUDGET);
    }
    client.send_input(b"exit 3\n").unwrap();
    assert_eq!(client.wait_exit(BUDGET, |_| {}).unwrap().code, 3);
    assert_eq!(
        server.join().unwrap().end,
        ServeEnd::ShellExited { code: 3 }
    );
}

// ───────────────────────── ⑥ run_interactive（CLI 数据面同构） ─────────────────────────

#[test]
fn run_interactive_pumps_stdin_stdout_and_returns_remote_exit_code() {
    let reg = std::sync::Arc::new(registry(LEASE_SANE));
    let ((c1, s1), _tap) = LoopbackTransport::new_pair_tapped();
    let sreg = std::sync::Arc::clone(&reg);
    let (_sc, session_server) = session_pair();
    let server = std::thread::spawn(move || {
        serve_connection(&sreg, s1, session_server, sreg.next_conn(), &serve_opts())
    });
    let client = attach(
        c1,
        AttachMode::New {
            window: WindowSize::FALLBACK,
        },
    );
    let script: &[u8] = b"echo run-interactive-ok\nexit 5\n";
    let mut stdout = Vec::new();
    let code = client
        .run_interactive(script, &mut stdout, Duration::from_millis(200), || None)
        .unwrap();
    assert_eq!(code.code, 5);
    assert!(
        stdout
            .windows(b"run-interactive-ok".len())
            .any(|w| w == b"run-interactive-ok"),
        "stdout 应含终端输出：{:?}",
        String::from_utf8_lossy(&stdout)
    );
    assert_eq!(
        server.join().unwrap().end,
        ServeEnd::ShellExited { code: 5 }
    );
}
