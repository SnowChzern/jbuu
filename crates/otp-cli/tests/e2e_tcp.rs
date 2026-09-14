//! WP-15 验收 ②④ + WP-16 终端数据面（TCP 半 + doctor/审计面）：**真实
//! `jbuu` 二进制**双进程经 localhost TCP（中继录制全部流经字节）完成
//! 端到端加密**交互式 PTY 终端**会话。
//!
//! 断言（PTY 终端口径，任务 #54）：
//! - 客户端 stdout 含远端 shell 对输入脚本标记的输出（数据面；stdout 只
//!   承载明文，其余输出面一律不含明文）；客户端退出码 = 远端退出码；
//! - 中继录制的 TCP 字节流不含明文标记/段正文（PTY 流全走 record 加密）；
//! - 会话后服务端 next=1（EXIT 行）；SESSION 行含 handle/token/exit；
//! - **恢复 e2e**（wp02 §5.3）：断线（detach）→ `connect --recover <句柄>`
//!   重新握手（消耗下一新段，旧段零重用）→ 附着同一 PTY（shell 状态
//!   存活）→ 退出码回传；
//! - 审计日志（serve+connect 双侧）为白名单 JSONL，secret 扫描通过。
//!
//! doctor 面（验收 ④）：正例（0600+排除标记+swap 覆盖 → exit 0）与反例
//! （0644 权限 → exit 2 拒绝启动；本机未证明加密 swap 且无覆盖 → exit 2）。
//! 锚 inspect：双 INIT 锚 → relation consistent；损坏锚 → 非零退出。
//! 骨架面（验收 ①）：drain/rotate 显式退出码 3。
//! 错本负例（M1 口径）：BOOK_MISMATCH fail closed，段零消耗。

#![forbid(unsafe_code)]

use std::io::{Read as _, Write as _};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use otp_anchor_spec::{AnchorRecord, encode_record};
use otp_book::header::BookHeader;
use otp_types::{BookId, SEGMENT_LEN};

const ID: BookId = BookId::from_bytes(*b"OTPTERM-TESTBOOK");
const OTHER_ID: BookId = BookId::from_bytes(*b"OTPTERM-OTHRBOOK");
const COUNT: u64 = 8;
const CHUNKS: usize = 4; // 256 KiB（二进制 e2e 用量；loopback 侧另有 1 MiB）
const DEADLINE: Duration = Duration::from_secs(180);

fn exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_jbuu"))
}

fn scratch(tag: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/tmp")
        .join(format!("otp-cli-e2e-{}-{}", std::process::id(), tag));
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

fn set_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn set_0644(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

fn write_test_book(dir: &Path, id: BookId, seed: u8) -> PathBuf {
    let path = dir.join("book.bin");
    let header = BookHeader::new(id, COUNT).unwrap();
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(&header.encode()).unwrap();
    let fillfn = fill(seed);
    for i in 0..COUNT {
        f.write_all(&fillfn(i)).unwrap();
    }
    f.sync_all().unwrap();
    drop(f);
    set_0600(&path);
    path
}

fn write_init_anchors(dir: &Path, id: BookId) -> (PathBuf, PathBuf) {
    let mut rec = Vec::new();
    encode_record(&AnchorRecord::init(id), &mut rec);
    let mut paths = Vec::new();
    for copy in ["anchor-a", "anchor-b"] {
        let p = dir.join(format!("{copy}.anchor"));
        std::fs::write(&p, &rec).unwrap();
        set_0600(&p);
        paths.push(p);
    }
    (paths.pop().unwrap(), paths.pop().unwrap())
}

fn write_no_backup_marker(dir: &Path) {
    std::fs::write(dir.join(".jbuu-nobackup"), b"ops marker\n").unwrap();
}

fn marker(i: usize) -> [u8; 16] {
    let mut m = *b"OTPTERM-ECHO-i__";
    m[13] = b'0' + u8::try_from((i / 10) % 10).unwrap();
    m[14] = b'0' + u8::try_from(i % 10).unwrap();
    m[15] = b'|';
    m
}

// ───────────────────────── 中继（录制观察点，WP-12 口径） ─────────────────────────

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

type Relay = (
    String,
    Arc<Mutex<Vec<u8>>>,
    std::thread::JoinHandle<Option<()>>,
);

fn spawn_relay(server_addr: String) -> Relay {
    let listener = TcpListener::bind("127.0.0.1:0").expect("中继监听");
    let relay_addr = listener.local_addr().expect("中继地址").to_string();
    let recording = Arc::new(Mutex::new(Vec::new()));
    let rec = Arc::clone(&recording);
    let handle = std::thread::spawn(move || {
        let (client_sock, _) = listener.accept().ok()?;
        let server_sock = TcpStream::connect(server_addr).ok()?;
        let c2s = Arc::clone(&rec);
        let s2c = Arc::clone(&rec);
        let (c_rd, c_wr) = (client_sock.try_clone().ok()?, client_sock);
        let (s_rd, s_wr) = (server_sock.try_clone().ok()?, server_sock);
        let t1 = std::thread::spawn(move || pump(c_rd, s_wr, c2s));
        let t2 = std::thread::spawn(move || pump(s_rd, c_wr, s2c));
        t1.join().ok()?;
        t2.join().ok()?;
        Some(())
    });
    (relay_addr, recording, handle)
}

// ───────────────────────── 子进程工具 ─────────────────────────

fn wait_with_timeout(child: &mut Child, who: &str) -> std::process::ExitStatus {
    let t0 = Instant::now();
    loop {
        match child.try_wait().expect("轮询子进程状态") {
            Some(status) => return status,
            None => {
                assert!(t0.elapsed() < DEADLINE, "{who}等待超时");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// 一次性子进程：喂 stdin（写线程防 64KiB 管道阻塞），收集 stdout/stderr，
/// 返回 (exit_code, stdout, stderr)。
fn run_to_completion(args: &[&str], stdin_data: Option<&[u8]>) -> (i32, Vec<u8>, Vec<u8>) {
    let mut cmd = Command::new(exe());
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = match stdin_data {
        Some(data) => {
            let mut child = cmd.stdin(Stdio::piped()).spawn().expect("拉起子进程");
            let mut stdin = child.stdin.take().expect("stdin");
            let data = data.to_vec();
            std::thread::spawn(move || {
                let _ = stdin.write_all(&data);
                // 写完 drop → 触发客户端 EOF。
            });
            child
        }
        None => cmd.stdin(Stdio::null()).spawn().expect("拉起子进程"),
    };
    let out = child.stdout.take().expect("stdout");
    let err = child.stderr.take().expect("stderr");
    let obuf = std::thread::spawn(move || {
        let mut o = out;
        let mut b = Vec::new();
        let _ = o.read_to_end(&mut b);
        b
    });
    let ebuf = std::thread::spawn(move || {
        let mut e = err;
        let mut b = Vec::new();
        let _ = e.read_to_end(&mut b);
        b
    });
    let status = wait_with_timeout(&mut child, "子进程");
    (
        status.code().unwrap_or(-1),
        obuf.join().unwrap(),
        ebuf.join().unwrap(),
    )
}

/// 常驻子进程（serve）：读线程持续把 stdout/stderr 汇入共享缓冲，主线程
/// 轮询取行（LISTEN=）并在收尾汇合。
struct LongProc {
    child: Child,
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    readers: Vec<std::thread::JoinHandle<()>>,
}

impl LongProc {
    fn spawn(args: &[&str]) -> Self {
        let mut child = Command::new(exe())
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("拉起常驻子进程");
        let out = child.stdout.take().expect("stdout");
        let err = child.stderr.take().expect("stderr");
        let obuf = Arc::new(Mutex::new(Vec::new()));
        let ebuf = Arc::new(Mutex::new(Vec::new()));
        let o = Arc::clone(&obuf);
        let e = Arc::clone(&ebuf);
        let readers = vec![
            std::thread::spawn(move || {
                let mut pipe = out;
                let mut b = [0u8; 4096];
                loop {
                    match pipe.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if let Ok(mut g) = o.lock() {
                                g.extend_from_slice(&b[..n]);
                            }
                        }
                    }
                }
            }),
            std::thread::spawn(move || {
                let mut pipe = err;
                let mut b = [0u8; 4096];
                loop {
                    match pipe.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if let Ok(mut g) = e.lock() {
                                g.extend_from_slice(&b[..n]);
                            }
                        }
                    }
                }
            }),
        ];
        Self {
            child,
            stdout: obuf,
            stderr: ebuf,
            readers,
        }
    }

    /// 轮询 stderr 直到出现 `tag` 起始行（超时死）。
    fn wait_stderr_tag(&self, tag: &str) -> String {
        let t0 = Instant::now();
        loop {
            let text = String::from_utf8_lossy(&self.stderr.lock().unwrap().clone()).to_string();
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix(tag) {
                    return rest.to_string();
                }
            }
            assert!(
                t0.elapsed() < DEADLINE,
                "常驻子进程未在期限内写出 {tag}；stderr:\n{text}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// 汇合：等退出 + join 读线程，返回 (code, stdout, stderr)。
    fn finish(mut self) -> (i32, Vec<u8>, Vec<u8>) {
        let status = wait_with_timeout(&mut self.child, "常驻子进程");
        for r in self.readers {
            r.join().expect("读线程汇合");
        }
        (
            status.code().unwrap_or(-1),
            self.stdout.lock().unwrap().clone(),
            self.stderr.lock().unwrap().clone(),
        )
    }
}

// ───────────────────────── secret 扫描 ─────────────────────────

fn assert_no_secret_in(label: &str, bytes: &[u8]) {
    for i in 0..CHUNKS {
        let m = marker(i);
        assert!(
            !bytes.windows(m.len()).any(|w| w == m),
            "{label}: 出现第 {i} 块明文标记（明文泄露）"
        );
    }
    let f = fill(0x11);
    for seg in [0u64, 1] {
        let s = f(seg);
        assert!(
            !bytes.windows(s.len()).any(|w| w == s),
            "{label}: 出现段 {seg} 正文（段材料泄露）"
        );
    }
}

// ───────────────────────── ① TCP 端到端（主用例，PTY 终端） ─────────────────────────

/// 终端输入脚本：多行标记命令 + 显式退出（每行 < canonical 上限）。
fn terminal_script() -> Vec<u8> {
    let mut all = Vec::new();
    for i in 0..CHUNKS {
        let pad = "t".repeat(64);
        all.extend_from_slice(
            format!("echo {marker}-{i:02} {pad}\n", marker = marker_str()).as_bytes(),
        );
    }
    all.extend_from_slice(b"exit 7\n");
    all
}

fn marker_str() -> &'static str {
    "OTPTERM-ECHO-i__"
}

#[test]
fn tcp_two_process_cli_end_to_end_encrypted_terminal() {
    let server_dir = scratch("s");
    let client_dir = scratch("c");
    let s_book = write_test_book(&server_dir, ID, 0x11);
    let (s_a, s_b) = write_init_anchors(&server_dir, ID);
    let c_book = write_test_book(&client_dir, ID, 0x11);
    let (c_a, c_b) = write_init_anchors(&client_dir, ID);
    write_no_backup_marker(&server_dir);
    write_no_backup_marker(&client_dir);
    let s_audit = server_dir.join("audit.jsonl");
    let c_audit = client_dir.join("audit.jsonl");

    let server = LongProc::spawn(&[
        "serve",
        "--book",
        s_book.to_str().unwrap(),
        "--anchor-a",
        s_a.to_str().unwrap(),
        "--anchor-b",
        s_b.to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
        "--sessions",
        "1",
        "--shell",
        "/bin/sh",
        "--audit-log",
        s_audit.to_str().unwrap(),
        "--allow-unencrypted-swap",
        "--deadline-secs",
        "120",
    ]);
    let addr = server.wait_stderr_tag("LISTEN=");
    let (relay_addr, recording, relay_done) = spawn_relay(addr);

    let input = terminal_script();
    let (ccode, cout, cerr) = run_to_completion(
        &[
            "connect",
            "--book",
            c_book.to_str().unwrap(),
            "--anchor-a",
            c_a.to_str().unwrap(),
            "--anchor-b",
            c_b.to_str().unwrap(),
            "--target",
            &relay_addr,
            "--audit-log",
            c_audit.to_str().unwrap(),
            "--allow-unencrypted-swap",
            "--deadline-secs",
            "120",
        ],
        Some(&input),
    );
    assert_eq!(
        ccode,
        7,
        "connect 退出码=远端 shell 退出码；stderr:\n{}",
        String::from_utf8_lossy(&cerr)
    );

    while !relay_done.is_finished() {
        std::thread::sleep(Duration::from_millis(5));
    }
    relay_done.join().unwrap().expect("中继两端建立");
    let (scode, sout, serr) = server.finish();
    assert_eq!(
        scode,
        0,
        "serve 应成功退出；stderr:\n{}",
        String::from_utf8_lossy(&serr)
    );

    // ① 数据面：客户端 stdout 含全部标记的 shell 输出（stdout 是唯一明文面）。
    let cout_text = String::from_utf8_lossy(&cout).to_string();
    for i in 0..CHUNKS {
        let m = format!("{}-{:02}", marker_str(), i);
        assert!(
            cout_text.contains(&m),
            "stdout 缺少标记 {m}（PTY 输出未回传）"
        );
    }

    // ② 指针只前进：serve EXIT next=1；connect DONE 行含 next=1 与 exit=7；
    //    SESSION 行含 WP-16 元数据（handle/token/退出码/终止原因）。
    let serr_text = String::from_utf8_lossy(&serr).to_string();
    let cerr_text = String::from_utf8_lossy(&cerr).to_string();
    assert!(
        serr_text.contains("EXIT next=1"),
        "serve stderr:\n{serr_text}"
    );
    assert!(cerr_text.contains("next=1"), "connect stderr:\n{cerr_text}");
    assert!(cerr_text.contains("exit=7"), "connect stderr:\n{cerr_text}");
    assert!(
        cerr_text.contains("TERMINAL handle=1 token=1"),
        "connect stderr:\n{cerr_text}"
    );
    assert!(serr_text.contains("SESSION segment=0 generation=1 handle=1 token=1"));
    assert!(
        serr_text.contains("exit=7 end=shell-exited(7)"),
        "serve stderr:\n{serr_text}"
    );

    // ③ secret 扫描：TCP 字节流 / serve stdout+stderr / connect stderr。
    let stream = recording.lock().unwrap().clone();
    assert!(stream.len() > 1024, "TCP 字节流应有可观流量");
    assert_no_secret_in("tcp-relay-stream", &stream);
    let zeros = stream
        .chunks(64)
        .filter(|c| c.iter().all(|&b| b == 0))
        .count();
    assert_eq!(zeros, 0, "密文形状：无 64B 全零块");
    assert_no_secret_in("serve-stdout", &sout);
    assert_no_secret_in("serve-stderr", &serr);
    assert_no_secret_in("connect-stderr", &cerr);

    // ④ 审计日志：白名单 JSONL + issued/recovered 事件 + secret 扫描。
    for (who, path) in [("serve", &s_audit), ("connect", &c_audit)] {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        assert!(!text.is_empty(), "{who} 审计不应为空");
        for line in text.lines() {
            assert!(
                line.starts_with("{\"book_id\":\""),
                "{who} 审计行非白名单形状：{line}"
            );
            assert!(line.contains(",\"outcome\":\""));
            assert!(line.ends_with("\"}") || line.ends_with("null}"));
        }
        assert!(
            text.contains("\"segment\":0")
                && text.contains("\"generation\":1")
                && text.contains("\"outcome\":\"issued\""),
            "{who} 审计缺少 issued(段0, gen1) 事件：{text}"
        );
        assert_no_secret_in(&format!("{who}-audit"), text.as_bytes());
    }
    let s_audit_text = std::fs::read_to_string(&s_audit).unwrap();
    assert!(s_audit_text.contains("\"outcome\":\"recovered\""));

    let _ = std::fs::remove_dir_all(&server_dir);
    let _ = std::fs::remove_dir_all(&client_dir);
}

// ───────────────────────── ①′ TCP 恢复 e2e（wp02 §5.3 全栈） ─────────────────────────

#[test]
fn tcp_recovery_consumes_new_segment_and_attaches_same_pty() {
    let server_dir = scratch("rs");
    let client_dir = scratch("rc");
    let s_book = write_test_book(&server_dir, ID, 0x11);
    let (s_a, s_b) = write_init_anchors(&server_dir, ID);
    let c_book = write_test_book(&client_dir, ID, 0x11);
    let (c_a, c_b) = write_init_anchors(&client_dir, ID);
    write_no_backup_marker(&server_dir);
    write_no_backup_marker(&client_dir);

    // 3 个会话位：conn1 建立+detach，conn2 恢复+退出，第 3 位兜底。
    let server = LongProc::spawn(&[
        "serve",
        "--book",
        s_book.to_str().unwrap(),
        "--anchor-a",
        s_a.to_str().unwrap(),
        "--anchor-b",
        s_b.to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
        "--sessions",
        "2",
        "--shell",
        "/bin/sh",
        "--allow-unencrypted-swap",
    ]);
    let addr = server.wait_stderr_tag("LISTEN=");

    // conn1：建立终端并留下状态；脚本以 EOF 收尾 → detach（退出码 0）。
    let (code1, out1, err1) = run_to_completion(
        &[
            "connect",
            "--book",
            c_book.to_str().unwrap(),
            "--anchor-a",
            c_a.to_str().unwrap(),
            "--anchor-b",
            c_b.to_str().unwrap(),
            "--target",
            &addr,
            "--allow-unencrypted-swap",
        ],
        Some(b"CLI_REC_STATE=4242; echo SET-OK\n"),
    );
    assert_eq!(
        code1,
        0,
        "detach 语义退出码 0；stderr:\n{}",
        String::from_utf8_lossy(&err1)
    );
    let err1_text = String::from_utf8_lossy(&err1).to_string();
    assert!(
        err1_text.contains("TERMINAL handle=1 token=1"),
        "{err1_text}"
    );
    assert!(
        String::from_utf8_lossy(&out1).contains("SET-OK"),
        "stdout 应含 SET-OK"
    );
    // 等 serve 侧 SESSION 行落盘（conn1 结束）。
    let session1 = server.wait_stderr_tag("SESSION ");
    assert!(session1.contains("handle=1"), "{session1}");
    assert!(session1.contains("end=peer-closed"), "{session1}");

    // conn2：恢复句柄 1——重新握手（新段，旧段零重用）+ 附着同一 PTY。
    let (code2, out2, err2) = run_to_completion(
        &[
            "connect",
            "--book",
            c_book.to_str().unwrap(),
            "--anchor-a",
            c_a.to_str().unwrap(),
            "--anchor-b",
            c_b.to_str().unwrap(),
            "--target",
            &addr,
            "--recover",
            "1",
            "--allow-unencrypted-swap",
        ],
        Some(b"echo REC-MARK=$CLI_REC_STATE\nexit 9\n"),
    );
    assert_eq!(
        code2,
        9,
        "恢复会话退出码=远端 9；stderr:\n{}",
        String::from_utf8_lossy(&err2)
    );
    let out2_text = String::from_utf8_lossy(&out2).to_string();
    assert!(
        out2_text.contains("REC-MARK=4242"),
        "恢复附着的是同一 PTY（shell 状态存活）：\n{out2_text}"
    );
    let err2_text = String::from_utf8_lossy(&err2).to_string();
    assert!(
        err2_text.contains("TERMINAL handle=1 token=2"),
        "接管 token 递增：{err2_text}"
    );
    assert!(err2_text.contains("segment=1"), "恢复签发新段：{err2_text}");

    let (scode, _sout, serr) = server.finish();
    assert_eq!(scode, 0);
    let serr_text = String::from_utf8_lossy(&serr).to_string();
    // 两会话两段：next=2（段 0、段 1 各一次，零重用）；SESSION 行各含段号。
    assert!(
        serr_text.contains("EXIT next=2"),
        "serve stderr:\n{serr_text}"
    );
    assert!(serr_text.contains("SESSION segment=0 generation=1 handle=1 token=1"));
    assert!(serr_text.contains("SESSION segment=1 generation=2 handle=1 token=2"));
    assert!(
        serr_text.contains("exit=9 end=shell-exited(9)"),
        "{serr_text}"
    );

    let _ = std::fs::remove_dir_all(&server_dir);
    let _ = std::fs::remove_dir_all(&client_dir);
}

// ───────────────────────── 错本负例（M1 口径） ─────────────────────────

#[test]
fn wrong_book_fails_closed_without_segment_consumption() {
    let server_dir = scratch("mm-s");
    let client_dir = scratch("mm-c");
    let s_book = write_test_book(&server_dir, ID, 0x11);
    let (s_a, s_b) = write_init_anchors(&server_dir, ID);
    // 客户端持不同 book_id 的另一本。
    let c_book = write_test_book(&client_dir, OTHER_ID, 0x22);
    let (c_a, c_b) = write_init_anchors(&client_dir, OTHER_ID);
    write_no_backup_marker(&server_dir);
    write_no_backup_marker(&client_dir);
    let s_audit = server_dir.join("audit.jsonl");

    let server = LongProc::spawn(&[
        "serve",
        "--book",
        s_book.to_str().unwrap(),
        "--anchor-a",
        s_a.to_str().unwrap(),
        "--anchor-b",
        s_b.to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
        "--sessions",
        "1",
        "--audit-log",
        s_audit.to_str().unwrap(),
        "--allow-unencrypted-swap",
    ]);
    let addr = server.wait_stderr_tag("LISTEN=");

    let (ccode, _cout, cerr) = run_to_completion(
        &[
            "connect",
            "--book",
            c_book.to_str().unwrap(),
            "--anchor-a",
            c_a.to_str().unwrap(),
            "--anchor-b",
            c_b.to_str().unwrap(),
            "--target",
            &addr,
            "--allow-unencrypted-swap",
        ],
        Some(b"x"),
    );
    assert_ne!(ccode, 0, "错本客户端必须失败退出");
    let cerr_text = String::from_utf8_lossy(&cerr).to_string();
    assert!(
        cerr_text.contains("BOOK_MISMATCH"),
        "客户端应报 BOOK_MISMATCH：\n{cerr_text}"
    );
    assert!(cerr_text.contains("category=handshake"));

    let (scode, _sout, serr) = server.finish();
    assert_eq!(scode, 0, "serve 单会话后正常退出");
    let serr_text = String::from_utf8_lossy(&serr).to_string();
    // 预留前拒绝：不耗段（EXIT next=0），审计记 rejected。
    assert!(
        serr_text.contains("EXIT next=0"),
        "错本不得消耗段；serve stderr:\n{serr_text}"
    );
    assert!(serr_text.contains("SESSION-FAILED"));
    let audit = std::fs::read_to_string(&s_audit).unwrap();
    assert!(
        audit.contains("\"outcome\":\"rejected\"")
            && audit.contains("\"error_category\":\"handshake\""),
        "审计应记 rejected/handshake：{audit}"
    );

    let _ = std::fs::remove_dir_all(&server_dir);
    let _ = std::fs::remove_dir_all(&client_dir);
}

// ───────────────────────── doctor 正反用例（验收 ④） ─────────────────────────

#[test]
fn doctor_positive_and_negative_cases() {
    let dir = scratch("doc");
    let book = write_test_book(&dir, ID, 0x11);
    let (a, b) = write_init_anchors(&dir, ID);
    write_no_backup_marker(&dir);

    // 正例：0600 + 标记 + swap 覆盖 → exit 0（本机 swap 为裸分区，无覆盖
    // 必 BLOCK——见下一反例）。
    let (code, out, _err) = run_to_completion(
        &[
            "doctor",
            "--book",
            book.to_str().unwrap(),
            "--anchor-a",
            a.to_str().unwrap(),
            "--anchor-b",
            b.to_str().unwrap(),
            "--allow-unencrypted-swap",
        ],
        None,
    );
    assert_eq!(
        code,
        0,
        "doctor 正例应 exit 0；输出：\n{}",
        String::from_utf8_lossy(&out)
    );
    assert!(String::from_utf8_lossy(&out).contains("结论：无 BLOCK"));

    // 反例 A（权限）：书 0644 → exit 2，输出含 permissions BLOCK。
    set_0644(&book);
    let (code, out, _err) = run_to_completion(
        &[
            "doctor",
            "--book",
            book.to_str().unwrap(),
            "--anchor-a",
            a.to_str().unwrap(),
            "--anchor-b",
            b.to_str().unwrap(),
            "--allow-unencrypted-swap",
        ],
        None,
    );
    assert_eq!(code, 2);
    let text = String::from_utf8_lossy(&out).to_string();
    assert!(text.contains("permissions"));
    assert!(text.contains("BLOCK"));
    assert!(text.contains("拒绝启动"));
    set_0600(&book);

    // 反例 B（swap 无覆盖；本机存在裸分区 swap）：exit 2。
    // （若测试环境无 swap/已加密 swap，此例退化为正例——以输出断言类别。）
    let (code, out, _err) = run_to_completion(
        &[
            "doctor",
            "--book",
            book.to_str().unwrap(),
            "--anchor-a",
            a.to_str().unwrap(),
            "--anchor-b",
            b.to_str().unwrap(),
        ],
        None,
    );
    let text = String::from_utf8_lossy(&out).to_string();
    let swap_line_block = text
        .lines()
        .any(|l| l.contains("swap") && l.contains("[BLOCK]"));
    if swap_line_block {
        assert_eq!(code, 2, "存在 swap BLOCK 时必须拒绝（exit 2）：\n{text}");
    } else {
        assert_eq!(code, 0, "无 swap 风险时正例 exit 0：\n{text}");
    }

    // 反例 C（备份风险）：把书挪进 Dropbox 目录 → BLOCK。
    let sync_dir = dir.join("Dropbox");
    std::fs::create_dir_all(&sync_dir).unwrap();
    let sync_book = sync_dir.join("book.bin");
    std::fs::copy(&book, &sync_book).unwrap();
    set_0600(&sync_book);
    write_no_backup_marker(&sync_dir);
    let (code, out, _err) = run_to_completion(
        &[
            "doctor",
            "--book",
            sync_book.to_str().unwrap(),
            "--anchor-a",
            a.to_str().unwrap(),
            "--anchor-b",
            b.to_str().unwrap(),
            "--allow-unencrypted-swap",
        ],
        None,
    );
    assert_eq!(code, 2);
    assert!(String::from_utf8_lossy(&out).contains("backup-risk"));

    // 反例 D（锚缺失）：exit 2。
    let (code, _out, _err) = run_to_completion(
        &[
            "doctor",
            "--book",
            book.to_str().unwrap(),
            "--anchor-a",
            dir.join("missing-a.anchor").to_str().unwrap(),
            "--anchor-b",
            b.to_str().unwrap(),
            "--allow-unencrypted-swap",
        ],
        None,
    );
    assert_eq!(code, 2);

    // doctor 拒绝启动面（serve 同策略）：0644 的书 → serve exit 2 且不监听。
    set_0644(&book);
    let (code, _out, err) = run_to_completion(
        &[
            "serve",
            "--book",
            book.to_str().unwrap(),
            "--anchor-a",
            a.to_str().unwrap(),
            "--anchor-b",
            b.to_str().unwrap(),
            "--allow-unencrypted-swap",
        ],
        None,
    );
    assert_eq!(code, 2, "高风险必须拒绝启动");
    assert!(
        String::from_utf8_lossy(&err).contains("拒绝启动"),
        "serve stderr：\n{}",
        String::from_utf8_lossy(&err)
    );
    set_0600(&book);

    // doctor JSON 形状。
    let (code, out, _err) = run_to_completion(
        &[
            "doctor",
            "--book",
            book.to_str().unwrap(),
            "--anchor-a",
            a.to_str().unwrap(),
            "--anchor-b",
            b.to_str().unwrap(),
            "--allow-unencrypted-swap",
            "--json",
        ],
        None,
    );
    assert_eq!(code, 0);
    let json = String::from_utf8_lossy(&out).to_string();
    assert!(json.trim_start().starts_with("{\"findings\":["));
    assert!(json.contains("\"category\":\"core-dump\""));
    assert!(json.trim_end().ends_with("}"));

    let _ = std::fs::remove_dir_all(&dir);
}

// ───────────────────────── anchor inspect / 骨架子命令 ─────────────────────────

#[test]
fn anchor_inspect_and_skeleton_subcommands() {
    let dir = scratch("ai");
    let (_book, (a, b)) = {
        let book = write_test_book(&dir, ID, 0x11);
        let anchors = write_init_anchors(&dir, ID);
        (book, anchors)
    };

    // 双 INIT 锚 → consistent，exit 0；输出含 book_id 十六进制。
    let (code, out, _err) = run_to_completion(
        &[
            "anchor",
            "inspect",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, 0);
    let text = String::from_utf8_lossy(&out).to_string();
    assert!(text.contains("4f54505445524d2d54455354424f4f4b"), "{text}");
    assert!(text.contains("relation: consistent"), "{text}");
    assert!(text.contains("next=0"), "{text}");
    assert!(text.contains("payload=init"), "{text}");

    // JSON 形状。
    let (code, out, _err) = run_to_completion(
        &[
            "anchor",
            "inspect",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "--json",
        ],
        None,
    );
    assert_eq!(code, 0);
    assert!(String::from_utf8_lossy(&out).contains("\"relation\":\"consistent\""));

    // 损坏锚 → 非零退出 + FAILED 行。
    let corrupt = dir.join("corrupt.anchor");
    std::fs::write(&corrupt, b"garbage-not-an-anchor").unwrap();
    set_0600(&corrupt);
    let (code, out, _err) =
        run_to_completion(&["anchor", "inspect", corrupt.to_str().unwrap()], None);
    assert_ne!(code, 0);
    assert!(String::from_utf8_lossy(&out).contains("FAILED(corrupt)"));

    // 骨架：drain/rotate → exit 3，明示 WP-17、不改状态。
    let (code, _out, err) = run_to_completion(&["drain"], None);
    assert_eq!(code, 3);
    assert!(String::from_utf8_lossy(&err).contains("WP-17"));

    let (code, _out, err) = run_to_completion(
        &[
            "rotate",
            "--book-id",
            "00112233445566778899aabbccddeeff",
            "--version",
            "2",
            "--authorizer-a",
            "alice",
            "--authorizer-b",
            "bob",
        ],
        None,
    );
    assert_eq!(code, 3);
    assert!(String::from_utf8_lossy(&err).contains("WP-17"));
    assert!(String::from_utf8_lossy(&err).contains("alice"));

    let _ = std::fs::remove_dir_all(&dir);
}
