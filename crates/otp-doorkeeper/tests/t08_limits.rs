//! §8 测试 8：128 并发全通（echo 上游）；第 129 条立即关闭 + conn_refused_over_limit。
//! 本文件单独成测试二进制：fd/线程计量不与其他测试混跑。
#![allow(dead_code)]
mod support;

use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

use support::{DkHandle, EchoUpstream, TempDir, dk_config, events};

#[test]
fn t08_128_concurrent_then_129th_refused() {
    let dir = TempDir::new("t08");
    let echo = EchoUpstream::spawn(true);
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        echo.addr,
        dir.join("dk.log"),
    ));

    let warn_line = otp_doorkeeper::warn::default_warn_line();

    // 128 条并发连接全部保持打开，且每条都完成一次事务
    let mut clients: Vec<TcpStream> = Vec::with_capacity(128);
    for i in 0..128 {
        let mut c = dk.connect();
        let mut warn = [0u8; 101];
        support::read_exact_into(&mut c, &mut warn);
        assert_eq!(&warn, &warn_line[..], "每条连接都应先收到警告行");
        let payload = format!("conn-{i}");
        c.write_all(payload.as_bytes()).unwrap();
        let got =
            support::read_exact_timeout(&mut c, payload.len(), Duration::from_secs(20)).unwrap();
        assert_eq!(got, payload.as_bytes());
        clients.push(c);
    }
    assert_eq!(
        echo.conns_served.load(std::sync::atomic::Ordering::Relaxed),
        128
    );

    // 第 129 条：accept 后立即关闭——不写警告行，读到 EOF
    let mut extra = dk.connect();
    let got = support::read_to_end_timeout(&mut extra, Duration::from_secs(5))
        .expect("超限连接必须立即关闭");
    assert!(
        got.is_empty(),
        "超限连接不得写警告行（上限保护优先于告知），收到 {}B",
        got.len()
    );

    let refused = support::wait_for_event(&dk.log_path, "conn_refused_over_limit", |_| true);
    assert_eq!(refused["cur_conns"].as_u64(), Some(128));
    assert!(refused["src_port"].as_u64().is_some());
    assert!(refused["src_ip"].as_str().is_some());

    // 释放后恢复正常
    drop(clients);
    assert!(
        support::wait_until(Duration::from_secs(10), || {
            events(&dk.log_path, "conn_close")
                .iter()
                .filter(|v| v["reason"].as_str() == Some("normal"))
                .count()
                >= 128
        }),
        "128 条连接都应正常收尾"
    );
    let mut fresh = dk.connect();
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut fresh, &mut warn);
    fresh.write_all(b"after-drain").unwrap();
    let got = support::read_exact_timeout(&mut fresh, b"after-drain".len(), Duration::from_secs(5))
        .unwrap();
    assert_eq!(got, b"after-drain");
}

/// 小规模上限逻辑复核（max_conns=4：第 5 条拒）
#[test]
fn t08_small_limit_logic() {
    let dir = TempDir::new("t08s");
    let echo = EchoUpstream::spawn(true);
    let mut cfg = dk_config(
        "127.0.0.1:0".parse().unwrap(),
        echo.addr,
        dir.join("dk.log"),
    );
    cfg.max_conns = 4;
    let dk = DkHandle::start(cfg);

    let mut held: Vec<TcpStream> = Vec::new();
    for _ in 0..4 {
        let mut c = dk.connect();
        let mut warn = [0u8; 101];
        support::read_exact_into(&mut c, &mut warn);
        held.push(c);
    }
    let mut fifth = dk.connect();
    let got = support::read_to_end_timeout(&mut fifth, Duration::from_secs(5)).unwrap();
    assert!(got.is_empty());
    assert_eq!(events(&dk.log_path, "conn_refused_over_limit").len(), 1);
    drop(held);
    assert!(support::wait_until(Duration::from_secs(5), || {
        events(&dk.log_path, "conn_close").len() >= 4
    }));
}
