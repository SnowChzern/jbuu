//! §4.2（D6）--warn-mode off 与 §3.2 W6 CLI 拒绝启动（子进程实测开关有效）
#![allow(dead_code)]
mod support;

use std::io::Write;
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use support::{DkHandle, EchoUpstream, TempDir, dk_config};

/// --warn-mode off：纯透传（客户端收到的首字节即 echo 数据，无警告行）
#[test]
fn switches_warn_mode_off() {
    let dir = TempDir::new("sw1");
    let echo = EchoUpstream::spawn(true);
    let mut cfg = dk_config(
        "127.0.0.1:0".parse().unwrap(),
        echo.addr,
        dir.join("dk.log"),
    );
    cfg.warn_mode = otp_doorkeeper::OnOff::Off;
    let dk = DkHandle::start(cfg);

    let mut c = dk.connect();
    let payload = b"no-warn-here";
    c.write_all(payload).unwrap();
    let got = support::read_exact_timeout(&mut c, payload.len(), Duration::from_secs(5)).unwrap();
    assert_eq!(got, payload, "warn off 时不得注入任何字节");
    // 无 warn_sent 事件
    assert!(support::events(&dk.log_path, "warn_sent").is_empty());
}

/// CLI 子进程：--warn-mode off 可正常启动；--warn-line 违规拒绝启动（W6）
#[test]
fn switches_cli_rejection_and_off() {
    let bin = env!("CARGO_BIN_EXE_jbuu-doorkeeper");
    let dir = TempDir::new("sw2");
    let echo = EchoUpstream::spawn(true);
    let port = support::free_port(false);

    // 1) 违规自定义行（SSH- 前缀）→ 拒绝启动 + 明确错误
    let out = Command::new(bin)
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--upstream")
        .arg(echo.addr.to_string())
        .arg("--log-file")
        .arg(dir.join("dk1.log"))
        .arg("--warn-line")
        .arg("SSH-2.0-evil")
        .output()
        .unwrap();
    assert!(!out.status.success(), "W2 违规必须拒绝启动");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("W2"), "错误须点名不变式：{stderr}");

    // 2) 违规（含 CR）→ 拒绝
    let out = Command::new(bin)
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--upstream")
        .arg(echo.addr.to_string())
        .arg("--log-file")
        .arg(dir.join("dk2.log"))
        .arg("--warn-line")
        .arg("line\rwith-cr")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("W3"));

    // 3) 违规（>200B）→ 拒绝
    let out = Command::new(bin)
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--upstream")
        .arg(echo.addr.to_string())
        .arg("--log-file")
        .arg(dir.join("dk3.log"))
        .arg("--warn-line")
        .arg("y".repeat(201))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("W4"));

    // 4) --warn-mode off 正常启动并行为正确
    let mut child = Command::new(bin)
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--upstream")
        .arg(echo.addr.to_string())
        .arg("--log-file")
        .arg(dir.join("dk4.log"))
        .arg("--warn-mode")
        .arg("off")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(support::wait_until(Duration::from_secs(5), || {
        TcpStream::connect(("127.0.0.1", port)).is_ok()
    }));
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.write_all(b"transparent").unwrap();
    let got =
        support::read_exact_timeout(&mut c, b"transparent".len(), Duration::from_secs(5)).unwrap();
    assert_eq!(got, b"transparent");

    // 5) 非法 warn-mode 值 → clap 拒绝
    let out = Command::new(bin)
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--upstream")
        .arg(echo.addr.to_string())
        .arg("--log-file")
        .arg(dir.join("dk5.log"))
        .arg("--warn-mode")
        .arg("maybe")
        .output()
        .unwrap();
    assert!(!out.status.success());

    let _ = child.kill();
    let _ = child.wait();
}
