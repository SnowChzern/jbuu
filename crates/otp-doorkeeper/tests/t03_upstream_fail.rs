//! §8 测试 3：上游死端口——5s 内关闭 + 失败行字节断言 + reason=upstream_unavailable
#![allow(dead_code)]
mod support;

use std::io::Write;
use std::time::{Duration, Instant};

use support::{DkHandle, TempDir, dk_config, events, read_to_end_timeout, wait_for_event};

/// 死端口（ECONNREFUSED）：立即收到 警告行+失败行 后连接关闭，远小于 5s
#[test]
fn t03_upstream_dead_port_refused() {
    let dir = TempDir::new("t03a");
    // 绑一个端口然后立刻释放 → 连接必被拒绝
    let dead = support::free_port(false);
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        format!("127.0.0.1:{dead}").parse().unwrap(),
        dir.join("dk.log"),
    ));

    let t0 = Instant::now();
    let mut client = dk.connect();
    let got = read_to_end_timeout(&mut client, Duration::from_secs(5)).expect("读取失败");
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "关闭必须发生在 5s 内：{elapsed:?}"
    );

    let mut expect = otp_doorkeeper::warn::default_warn_line();
    expect.extend_from_slice(&otp_doorkeeper::warn::failure_line());
    assert_eq!(got, expect, "字节序必须为 警告行+失败行，逐字节一致");

    // 日志
    let _ = wait_for_event(&dk.log_path, "upstream_connect", |v| {
        v["ok"] == serde_json::json!(false)
    });
    let close = wait_for_event(&dk.log_path, "conn_close", |_| true);
    assert_eq!(close["reason"].as_str(), Some("upstream_unavailable"));
}

/// 不可达地址（连接超时路径）：5s connect 超时内关闭（§5.2/§5.3 上游故障路径）
#[test]
fn t03_upstream_unreachable_timeout() {
    let dir = TempDir::new("t03b");
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        "10.255.255.1:2222".parse().unwrap(),
        dir.join("dk.log"),
    ));

    let t0 = Instant::now();
    let mut client = dk.connect();
    let got = read_to_end_timeout(&mut client, Duration::from_secs(20)).expect("读取失败");
    let elapsed = t0.elapsed();
    assert!(
        elapsed >= Duration::from_secs(4) && elapsed <= Duration::from_secs(8),
        "connect 超时应≈5s：{elapsed:?}"
    );
    let mut expect = otp_doorkeeper::warn::default_warn_line();
    expect.extend_from_slice(&otp_doorkeeper::warn::failure_line());
    assert_eq!(got, expect);
    let close = wait_for_event(&dk.log_path, "conn_close", |v| {
        v["reason"].as_str() == Some("upstream_unavailable")
    });
    assert_eq!(close["reason"].as_str(), Some("upstream_unavailable"));
}

/// --failure-line off：死上游只发警告行，无失败行
#[test]
fn t03_failure_line_off_switch() {
    let dir = TempDir::new("t03c");
    let dead = support::free_port(false);
    let mut cfg = dk_config(
        "127.0.0.1:0".parse().unwrap(),
        format!("127.0.0.1:{dead}").parse().unwrap(),
        dir.join("dk.log"),
    );
    cfg.failure_line = otp_doorkeeper::OnOff::Off;
    let dk = DkHandle::start(cfg);

    let mut client = dk.connect();
    let got = read_to_end_timeout(&mut client, Duration::from_secs(5)).unwrap();
    assert_eq!(
        got,
        otp_doorkeeper::warn::default_warn_line(),
        "只应有警告行"
    );
    // 开关写入运行事件不需要；验证行为即可
    let n = events(&dk.log_path, "upstream_connect")
        .iter()
        .filter(|v| v["ok"] == serde_json::json!(false))
        .count();
    assert_eq!(n, 1);
}

/// 回环顺序回退（§1.2）：v4 回环死、v6 回环活 → 走 [::1] 候选成功
#[test]
fn t03_loopback_fallback_candidate() {
    let dir = TempDir::new("t03d");
    let echo = EchoListener::spawn_v6_only();
    // 指向 127.0.0.1:<死端口>（同端口）——v4 侧无监听，应回退到 [::1] 同端口
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        format!("127.0.0.1:{}", echo.port).parse().unwrap(),
        dir.join("dk.log"),
    ));
    let mut client = dk.connect();
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut client, &mut warn);
    client.write_all(b"hello-fallback").unwrap();
    let echo_back =
        support::read_exact_timeout(&mut client, b"hello-fallback".len(), Duration::from_secs(5));
    assert_eq!(
        echo_back.unwrap(),
        b"hello-fallback",
        "必须经 [::1] 回退候选打通"
    );
}

/// 仅 [::1] 监听的极简 echo
struct EchoListener {
    port: u16,
}

impl EchoListener {
    fn spawn_v6_only() -> EchoListener {
        let listener = std::net::TcpListener::bind("[::1]:0").expect("::1 绑定失败");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                std::thread::Builder::new()
                    .stack_size(64 * 1024)
                    .spawn(move || {
                        use std::io::{Read, Write};
                        let mut buf = [0u8; 4096];
                        loop {
                            match stream.read(&mut buf) {
                                Ok(0) | Err(_) => return,
                                Ok(n) => {
                                    if stream.write_all(&buf[..n]).is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    })
                    .ok();
            }
        });
        EchoListener { port }
    }
}
