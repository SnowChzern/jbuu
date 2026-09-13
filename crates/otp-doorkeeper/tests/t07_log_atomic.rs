//! §8 测试 7：日志原子性——并发压测后全文件 JSONL 可解析率 100%（E6 回归）；
//! SIGHUP reopen 后新行落新文件（子进程真实信号路径）。
#![allow(dead_code)]
mod support;

use std::io::Write;
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use support::{DkHandle, EchoUpstream, TempDir, dk_config, parse_log};

/// 32 线程 × 100 连接并发事务后：日志逐行 JSON 解析率 100%，事件覆盖完整
#[test]
fn t07_log_atomicity_under_concurrency() {
    let dir = TempDir::new("t07a");
    let echo = EchoUpstream::spawn(true);
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        echo.addr,
        dir.join("dk.log"),
    ));

    const THREADS: usize = 32;
    const PER_THREAD: usize = 100;
    let mut handles = Vec::new();
    for t in 0..THREADS {
        let addr = dk.addr;
        handles.push(
            std::thread::Builder::new()
                .stack_size(128 * 1024)
                .spawn(move || {
                    for i in 0..PER_THREAD {
                        let mut c = TcpStream::connect(addr).expect("连接失败");
                        let mut warn = [0u8; 101];
                        support::read_exact_into(&mut c, &mut warn);
                        let payload = format!("t{t}-i{i}-payload");
                        c.write_all(payload.as_bytes()).unwrap();
                        let got = support::read_exact_timeout(
                            &mut c,
                            payload.len(),
                            Duration::from_secs(20),
                        )
                        .expect("echo 失败");
                        assert_eq!(got, payload.as_bytes());
                    }
                })
                .unwrap(),
        );
    }
    for h in handles {
        h.join().expect("并发线程 panic");
    }

    // 等最后一个 conn_close 落盘
    support::wait_for_event(&dk.log_path, "conn_close", |_| true);
    assert!(
        support::wait_until(Duration::from_secs(10), || {
            support::events(&dk.log_path, "conn_close").len() >= THREADS * PER_THREAD
        }),
        "conn_close 事件数必须齐全：{}",
        support::events(&dk.log_path, "conn_close").len()
    );

    let lines = parse_log(&dk.log_path);
    assert_eq!(
        lines.len(),
        support::events(&dk.log_path, "listen_start").len()
            + support::events(&dk.log_path, "conn_accept").len()
            + support::events(&dk.log_path, "warn_sent").len()
            + support::events(&dk.log_path, "upstream_connect").len()
            + support::events(&dk.log_path, "client_version").len()
            + support::events(&dk.log_path, "conn_close").len()
    );
    assert_eq!(
        support::events(&dk.log_path, "conn_accept").len(),
        THREADS * PER_THREAD
    );

    // 逐行已由 parse_log 断言（非法行会 panic）——即 100% 可解析率。
    // 额外显式复核：行级完整性（都以 } 结尾、无空行）
    let text = std::fs::read_to_string(&dk.log_path).unwrap();
    for (idx, line) in text.lines().enumerate() {
        assert!(!line.trim().is_empty(), "第 {idx} 行为空（交错损坏）");
        assert!(
            line.starts_with('{') && line.ends_with('}'),
            "第 {idx} 行结构损坏：{line}"
        );
    }
    eprintln!(
        "t07: {} 行 JSONL 全部可解析（{} 连接）",
        lines.len(),
        THREADS * PER_THREAD
    );
}

/// SIGHUP reopen（真实子进程 + kill -HUP）：轮转后新事件落新文件，旧文件冻结
#[test]
fn t07_sighup_reopen_rotates_file() {
    let bin = env!("CARGO_BIN_EXE_jbuu-doorkeeper");
    let dir = TempDir::new("t07b");
    let echo = EchoUpstream::spawn(true);
    let port = support::free_port(false);
    let log_path = dir.join("dk.log");

    let mut child = Command::new(bin)
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--upstream")
        .arg(echo.addr.to_string())
        .arg("--log-file")
        .arg(&log_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("启动门卫子进程失败");
    assert!(
        support::wait_until(Duration::from_secs(5), || {
            TcpStream::connect(("127.0.0.1", port)).is_ok()
        }),
        "门卫子进程未就绪"
    );

    // 一轮连接产生事件
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut c, &mut warn);
    c.write_all(b"before-rotate").unwrap();
    let _ = support::read_exact_timeout(&mut c, b"before-rotate".len(), Duration::from_secs(5))
        .unwrap();
    drop(c);
    support::wait_for_event(&log_path, "conn_close", |_| true);
    let lines_before = parse_log(&log_path).len();

    // logrotate 语义：改名 + HUP
    let rotated = dir.join("dk.log.1");
    std::fs::rename(&log_path, &rotated).unwrap();
    let _ = Command::new("kill")
        .arg("-HUP")
        .arg(child.id().to_string())
        .output()
        .expect("发 SIGHUP 失败");

    // 轮转后新事件必须落「原路径的新文件」
    let mut c2 = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut c2, &mut warn);
    c2.write_all(b"after-rotate").unwrap();
    let _ = support::read_exact_timeout(&mut c2, b"after-rotate".len(), Duration::from_secs(5))
        .unwrap();
    drop(c2);

    let reopened = support::wait_for_event(&log_path, "log_reopened", |_| true);
    assert_eq!(
        reopened["path"].as_str(),
        Some(log_path.display().to_string().as_str())
    );
    // 注意：就绪探测连接吃掉 conn_id 1，首事务是 2，轮转后事务是 3
    support::wait_for_event(&log_path, "conn_close", |v| {
        v["conn_id"].as_u64() == Some(3)
            && v["bytes_c2s"].as_u64() == Some(b"after-rotate".len() as u64)
    });

    // 旧文件冻结在轮转前状态
    assert_eq!(
        parse_log(&rotated).len(),
        lines_before,
        "旧文件不得再有新写入"
    );
    // 新文件包含 reopen 之后的事件链
    assert!(parse_log(&log_path).len() >= 3);

    let _ = child.kill();
    let _ = child.wait();
}
