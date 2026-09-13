//! M1/WP-12 验收：TCP 双进程加密回显（规划 §3 M1、§4 WP-12 行）。
//!
//! 两个独立 OS 进程（本测试二进制自执行，`--exact` 只跑本测试）经
//! localhost TCP 完成握手与 1 MiB 加密回显；中间架设字节中继（录制两
//! 方向全部流经字节）充任"抓取 transport 字节流"观察点：
//! - 回显内容逐字节一致（子进程内逐块断言，非 0 退出即失败）；
//! - 明文标记与会话段正文不出现在 TCP 字节流中；
//! - 会话后双方 next=1。
//!
//! 父子进程经文件通道（`OTP_ECHO_TCP_OUT` 指定的追加写文件）传递
//! `PORT=<n>` / `NEXT=<n>` 行——测试框架会捕获 stdout，管道读行不可靠。

#![forbid(unsafe_code)]

mod common;

use std::io::{Read as _, Write as _};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{
    CHUNKS, ECHO_TOTAL, assert_no_plaintext_in_stream, assert_stream_looks_like_ciphertext,
    client_handshake_over, client_recv_echo, client_send_chunk, echo_chunk, open_allocator,
    server_echo_wire, server_handshake_over,
};
use otp_transport::{FramedStream as _, TcpListener as OtpTcpListener, TcpTransport};

const ROLE_ENV: &str = "OTP_ECHO_TCP_ROLE";
const ADDR_ENV: &str = "OTP_ECHO_TCP_ADDR";
const OUT_ENV: &str = "OTP_ECHO_TCP_OUT";
const TEST_NAME: &str = "tcp_two_process_encrypted_echo";
const DEADLINE: Duration = Duration::from_secs(120);

#[test]
fn tcp_two_process_encrypted_echo() {
    if let Ok(role) = std::env::var(ROLE_ENV) {
        child_main(&role); // 子进程路径：完成任务后 exit(0)
    }
    parent_main();
}

// ───────────────────────────── 子进程 ─────────────────────────────

fn child_main(role: &str) -> ! {
    let code = match role {
        "server" => server_child(),
        "client" => client_child(),
        other => {
            eprintln!("未知角色 {other}");
            3
        }
    };
    std::process::exit(code);
}

/// 向文件通道追加一行（父子进程控制面；内容均为公开元数据）。
fn report(line: &str) {
    let Ok(path) = std::env::var(OUT_ENV) else {
        return;
    };
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{line}");
        let _ = f.sync_all();
    }
}

fn server_child() -> i32 {
    let mut alloc = open_allocator("tcp-s");
    let listener = match OtpTcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(_) => return 4,
    };
    let port = match listener.local_addr() {
        Ok(a) => a.rsplit(':').next().unwrap_or_default().to_string(),
        Err(_) => return 4,
    };
    report(&format!("PORT={port}"));
    let mut io = match listener.accept() {
        Ok(t) => t,
        Err(_) => return 4,
    };
    if io.set_deadline(DEADLINE).is_err() {
        return 4;
    }
    let handshake = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        server_handshake_over(&mut io, &mut alloc)
    }));
    let (mut session, _segment) = match handshake {
        Ok(v) => v,
        Err(_) => return 5,
    };
    // 回显循环：收帧即回显；对端干净关闭（半关闭后 EOF）→ 正常退出
    loop {
        match io.recv_frame() {
            Ok(wire) => {
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    server_echo_wire(&mut session, &mut io, &wire)
                }));
                if r.is_err() {
                    return 5;
                }
            }
            Err(otp_transport::TransportError::ClosedByPeer) => break,
            Err(_) => return 6,
        }
    }
    let _ = io.close();
    report(&format!("NEXT={}", alloc.state().0.get()));
    0
}

fn client_child() -> i32 {
    let addr = match std::env::var(ADDR_ENV) {
        Ok(a) if !a.is_empty() => a,
        _ => return 3,
    };
    let mut alloc = open_allocator("tcp-c");
    let mut io = match TcpTransport::connect(&addr) {
        Ok(t) => t,
        Err(_) => return 4,
    };
    if io.set_deadline(DEADLINE).is_err() {
        return 4;
    }
    let handshake = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client_handshake_over(&mut io, &mut alloc)
    }));
    let mut session = match handshake {
        Ok(s) => s,
        Err(_) => return 5,
    };
    for i in 0..CHUNKS {
        let chunk = echo_chunk(i);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client_send_chunk(&mut session, &mut io, &chunk);
            client_recv_echo(&mut session, &mut io)
        }));
        match outcome {
            Ok(back) if back == chunk => {}
            Ok(_) => return 7, // 回显不一致
            Err(_) => return 5,
        }
    }
    // 半关闭：告知服务端发送完毕
    if io.shutdown_write().is_err() {
        return 6;
    }
    report(&format!("NEXT={}", alloc.state().0.get()));
    0
}

// ───────────────────────────── 中继（抓流观察点） ─────────────────────────────

/// 单向字节泵：src → dst，全部流经字节旁录入 `recording`；EOF 时半关闭 dst。
fn pump(mut src: TcpStream, mut dst: TcpStream, recording: Arc<Mutex<Vec<u8>>>) {
    let mut buf = [0u8; 16384];
    loop {
        match src.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if let Ok(mut rec) = recording.lock() {
                    rec.extend_from_slice(&buf[..n]);
                }
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = dst.shutdown(Shutdown::Write);
}

/// 中继产物：（监听地址， 录制句柄， 完成句柄）。
type Relay = (
    String,
    Arc<Mutex<Vec<u8>>>,
    std::thread::JoinHandle<Option<()>>,
);

/// 起一个中继监听器：受理客户端一条连接，转发到 `server_addr`，录制
/// 两方向全部字节。
fn spawn_relay(server_addr: String) -> Relay {
    let listener = TcpListener::bind("127.0.0.1:0").expect("中继监听");
    let relay_addr = listener.local_addr().expect("中继地址").to_string();
    let recording = Arc::new(Mutex::new(Vec::new()));
    let rec = Arc::clone(&recording);
    let handle = std::thread::spawn(move || {
        let (client_sock, _) = listener.accept().ok()?;
        let server_sock = TcpStream::connect(server_addr).ok()?;
        let c2s_rec = Arc::clone(&rec);
        let s2c_rec = Arc::clone(&rec);
        let (c_rd, c_wr) = (client_sock.try_clone().ok()?, client_sock);
        let (s_rd, s_wr) = (server_sock.try_clone().ok()?, server_sock);
        let t1 = std::thread::spawn(move || pump(c_rd, s_wr, c2s_rec));
        let t2 = std::thread::spawn(move || pump(s_rd, c_wr, s2c_rec));
        t1.join().ok()?;
        t2.join().ok()?;
        Some(())
    });
    (relay_addr, recording, handle)
}

// ───────────────────────────── 父进程 ─────────────────────────────

fn parent_main() {
    let exe = std::env::current_exe().expect("测试二进制路径");
    let ctrl_dir: PathBuf = std::env::temp_dir().join(format!(
        "otp-tp-{}-{}",
        std::process::id(),
        common::unique_tag()
    ));
    std::fs::create_dir_all(&ctrl_dir).expect("控制面目录");
    let server_out = ctrl_dir.join("server.out");
    let client_out = ctrl_dir.join("client.out");

    let mut server = Command::new(&exe)
        .args(["--exact", TEST_NAME, "--test-threads=1"])
        .env(ROLE_ENV, "server")
        .env(OUT_ENV, &server_out)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("拉起服务端子进程");

    let server_port = read_tag_from_file(&server_out, "PORT=", "服务端");
    let server_addr = format!("127.0.0.1:{server_port}");

    let (relay_addr, recording, relay_done) = spawn_relay(server_addr);

    let mut client = Command::new(&exe)
        .args(["--exact", TEST_NAME, "--test-threads=1"])
        .env(ROLE_ENV, "client")
        .env(ADDR_ENV, &relay_addr)
        .env(OUT_ENV, &client_out)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("拉起客户端子进程");

    // 中继转发完成（两方向 EOF）
    let t0 = Instant::now();
    while !relay_done.is_finished() {
        assert!(t0.elapsed() < DEADLINE, "中继转发超时");
        std::thread::sleep(Duration::from_millis(50));
    }
    relay_done
        .join()
        .expect("中继线程汇聚")
        .expect("中继两端连接建立");

    let client_next = read_tag_from_file(&client_out, "NEXT=", "客户端");
    let server_next = read_tag_from_file(&server_out, "NEXT=", "服务端");
    let (c_status, s_status) = (
        wait_with_timeout(&mut client, "客户端"),
        wait_with_timeout(&mut server, "服务端"),
    );
    assert!(
        c_status.success(),
        "客户端子进程应以 0 退出（got {c_status:?}）"
    );
    assert!(
        s_status.success(),
        "服务端子进程应以 0 退出（got {s_status:?}）"
    );

    // M1：会话后双方 next=1（段 0 消耗，指针只前进）
    assert_eq!(client_next, "1");
    assert_eq!(server_next, "1");

    // 抓流断言：中继录制的 TCP 字节流不得含明文/段正文
    let stream = recording.lock().map(|r| r.clone()).unwrap_or_default();
    assert_stream_looks_like_ciphertext(&stream, "tcp-relay");
    assert_no_plaintext_in_stream(&stream, "tcp-relay");
    assert!(
        stream.len() > ECHO_TOTAL,
        "双向字节流应大于单向明文总量（含握手帧与 tag 开销）， got {}",
        stream.len()
    );
    let _ = std::fs::remove_dir_all(&ctrl_dir);
}

/// 从文件通道轮询读出 `tag` 起始行（带超时），返回去标签内容。
fn read_tag_from_file(path: &std::path::Path, tag: &str, who: &str) -> String {
    let t0 = Instant::now();
    loop {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                if let Some(rest) = line.strip_prefix(tag) {
                    return rest.to_string();
                }
            }
        }
        assert!(
            t0.elapsed() < DEADLINE,
            "{who}子进程未在期限内写出 {tag} 行"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_with_timeout(child: &mut std::process::Child, who: &str) -> std::process::ExitStatus {
    let t0 = Instant::now();
    loop {
        match child.try_wait().expect("轮询子进程状态") {
            Some(status) => return status,
            None => {
                assert!(t0.elapsed() < DEADLINE, "{who}子进程等待超时");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// 裸 TCP 中继回归：双向搬运 + 录制语义（不起完整回显的轻量证据）。
#[test]
fn relay_records_both_directions_when_sockets_talk() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let dst_addr = listener.local_addr().unwrap().to_string();
    let (relay_addr, recording, done) = spawn_relay(dst_addr);
    let dst = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 8];
        sock.read_exact(&mut buf).unwrap();
        sock.write_all(&buf).unwrap(); // 回显 8B
    });
    let mut c = TcpStream::connect(relay_addr).unwrap();
    c.write_all(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    let mut back = [0u8; 8];
    c.read_exact(&mut back).unwrap();
    assert_eq!(back, [1, 2, 3, 4, 5, 6, 7, 8]);
    drop(c);
    dst.join().unwrap();
    while !done.is_finished() {
        std::thread::sleep(Duration::from_millis(5));
    }
    done.join().unwrap().unwrap();
    let rec = recording.lock().unwrap().clone();
    assert_eq!(rec.len(), 16, "两方向各 8B 均被旁录");
}
