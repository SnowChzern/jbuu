//! §8 测试 14：重启韧性——压测中 kill 门卫再启动：
//! 旧连接干净消亡、新连接正常、无上游侧残留异常。
#![allow(dead_code)]
mod support;

use std::io::Write;
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use support::{EchoUpstream, TempDir};

/// 子进程形态跑门卫（真实二进制 + 真实 SIGKILL）
#[test]
fn t14_kill_and_restart_under_load() {
    let bin = env!("CARGO_BIN_EXE_jbuu-doorkeeper");
    let dir = TempDir::new("t14");
    let echo = EchoUpstream::spawn(true);
    let port = support::free_port(false);
    let log_path = dir.join("dk.log");

    let spawn_dk = || {
        Command::new(bin)
            .arg("--listen")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--upstream")
            .arg(echo.addr.to_string())
            .arg("--log-file")
            .arg(&log_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("启动门卫子进程失败")
    };

    let mut child = spawn_dk();
    assert!(
        support::wait_until(Duration::from_secs(5), || {
            TcpStream::connect(("127.0.0.1", port)).is_ok()
        }),
        "门卫就绪"
    );

    // 压测负载：若干活跃连接
    let mut live: Vec<TcpStream> = Vec::new();
    for _ in 0..12 {
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut warn = [0u8; 101];
        support::read_exact_into(&mut c, &mut warn);
        c.write_all(b"load").unwrap();
        let _ = support::read_exact_timeout(&mut c, b"load".len(), Duration::from_secs(5)).unwrap();
        live.push(c);
    }

    // kill -9（压测中）
    let _ = Command::new("kill")
        .arg("-9")
        .arg(child.id().to_string())
        .output();
    let _ = child.wait();

    // 旧连接干净消亡：EOF 或错误（不悬挂）
    for c in live.iter_mut() {
        let got = support::read_to_end_timeout(c, Duration::from_secs(5));
        // Err（RST）也算干净消亡
        if let Ok(data) = got {
            assert!(data.is_empty() || data == b"load", "旧连接残留数据异常");
        }
    }

    // 重启：同端口同参数
    let mut child2 = spawn_dk();
    assert!(
        support::wait_until(Duration::from_secs(5), || {
            TcpStream::connect(("127.0.0.1", port)).is_ok()
        }),
        "重启后必须可连"
    );
    let mut fresh = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut fresh, &mut warn);
    assert_eq!(
        warn.as_slice(),
        otp_doorkeeper::warn::default_warn_line().as_slice()
    );
    fresh.write_all(b"reborn").unwrap();
    let got =
        support::read_exact_timeout(&mut fresh, b"reborn".len(), Duration::from_secs(5)).unwrap();
    assert_eq!(got, b"reborn");

    // 上游侧无残留异常：echo 继续服务新连接
    let mut another = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut another, &mut warn);
    another.write_all(b"echo-again").unwrap();
    let got =
        support::read_exact_timeout(&mut another, b"echo-again".len(), Duration::from_secs(5))
            .unwrap();
    assert_eq!(got, b"echo-again");

    // kill 前日志完好（全部行合法 JSON）
    let lines = std::fs::read_to_string(&log_path).unwrap();
    for line in lines.lines() {
        let _: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("重启韧性：kill 前日志行损坏（{e}）：{line}"));
    }

    let _ = child2.kill();
    let _ = child2.wait();
}
