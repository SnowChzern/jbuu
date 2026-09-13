//! §8 测试 10/11/12（恶意输入/fuzz 简项）：
//! - 10：连接后不读不写（慢速占位）→ 不阻塞他人；keepalive 配置实测读回；
//!   长空闲存活证明 pipe 阶段无应用层超时（D7）
//! - 11：首包巨型单行（1 MiB 无换行）→ 透传不崩、观察器按窗放弃
//! - 12：客户端 RST 在警告 write 中途 → EPIPE 干净回收（无 panic/无线程泄漏）
#![allow(dead_code)]
mod support;

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rustix::net::sockopt;

use support::{DkHandle, EchoUpstream, TempDir, dk_config, events};

/// keepalive 三参实测读回（§5.2：TCP_KEEPIDLE=600s / INTVL=60s / CNT=5 + SO_KEEPALIVE）
#[test]
fn t10_keepalive_options_readback() {
    // 建一对已连接 socket，应用门卫的套接字策略，读回断言
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || listener.accept().unwrap().0);
    let client = TcpStream::connect(addr).unwrap();
    let server: TcpStream = server.join().unwrap();

    otp_doorkeeper::proxy::sock::apply_keepalive(&client).unwrap();
    otp_doorkeeper::proxy::sock::apply_keepalive(&server).unwrap();

    assert!(
        sockopt::socket_keepalive(&client).unwrap(),
        "SO_KEEPALIVE 必须开启"
    );
    assert_eq!(
        sockopt::tcp_keepidle(&client).unwrap(),
        Duration::from_secs(600),
        "TCP_KEEPIDLE 必须 600s"
    );
    assert_eq!(
        sockopt::tcp_keepintvl(&client).unwrap(),
        Duration::from_secs(60),
        "TCP_KEEPINTVL 必须 60s"
    );
    assert_eq!(
        sockopt::tcp_keepcnt(&client).unwrap(),
        5,
        "TCP_KEEPCNT 必须 5"
    );

    // 发送超时策略：警告阶段 10s → pipe 阶段清除
    otp_doorkeeper::proxy::sock::apply_client_policy(&client).unwrap();
    assert_eq!(
        sockopt::socket_timeout(&client, sockopt::Timeout::Send).unwrap(),
        Some(Duration::from_secs(10)),
        "警告行 write 阶段 SO_SNDTIMEO=10s"
    );
    otp_doorkeeper::proxy::sock::clear_app_timeouts(&client);
    assert_eq!(
        sockopt::socket_timeout(&client, sockopt::Timeout::Send).unwrap(),
        None,
        "pipe 阶段必须无发送超时（D7）"
    );
}

/// 慢速占位连接不阻塞他人 + 长空闲存活（>10s，证明 pipe 阶段无 10s 应用层超时）
#[test]
fn t10_idle_conn_does_not_block_others_and_survives() {
    let dir = TempDir::new("t10a");
    let echo = EchoUpstream::spawn(true);
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        echo.addr,
        dir.join("dk.log"),
    ));

    // 占位连接 A：读走警告行后彻底沉默
    let mut idle = dk.connect();
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut idle, &mut warn);

    // 他人连接 B/C/D 照常工作
    for i in 0..8 {
        let mut c = dk.connect();
        let mut warn = [0u8; 101];
        support::read_exact_into(&mut c, &mut warn);
        let payload = format!("healthy-{i}");
        c.write_all(payload.as_bytes()).unwrap();
        let got =
            support::read_exact_timeout(&mut c, payload.len(), Duration::from_secs(5)).unwrap();
        assert_eq!(got, payload.as_bytes());
    }

    // 空闲 11s（超过警告行 10s 超时与常见短空闲超时）后连接 A 仍活着且可用
    std::thread::sleep(Duration::from_secs(11));
    let payload = b"awake-after-idle";
    idle.write_all(payload).unwrap();
    let got =
        support::read_exact_timeout(&mut idle, payload.len(), Duration::from_secs(5)).unwrap();
    assert_eq!(got, payload, "pipe 阶段不得有应用层空闲超时（D7）");
}

/// 首包巨型单行（1 MiB 无换行）：透传不崩、观察器按窗放弃、字节精确
#[test]
fn t11_mib_single_line_passthrough() {
    let dir = TempDir::new("t11");
    let echo = EchoUpstream::spawn(true);
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        echo.addr,
        dir.join("dk.log"),
    ));

    // 1 MiB 单行：随机字节中的 \n 一律替换（保证无换行，且总量不减）
    let payload: Vec<u8> = support::Rng::new(0x51_0000_0001)
        .bytes(1024 * 1024)
        .into_iter()
        .map(|b| if b == b'\n' { b'~' } else { b })
        .collect();
    assert_eq!(payload.len(), 1024 * 1024);
    assert!(!payload.contains(&b'\n'));

    let mut client = dk.connect();
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut client, &mut warn);
    client.write_all(&payload).unwrap();
    let got =
        support::read_exact_timeout(&mut client, payload.len(), Duration::from_secs(60)).unwrap();
    assert_eq!(
        support::md5_hex(&got),
        support::md5_hex(&payload),
        "1 MiB 巨型单行必须无损"
    );
    drop(client); // client_version/conn_close 在 pipe 收尾时落盘

    let ver = support::wait_for_event(&dk.log_path, "client_version", |_| true);
    assert_eq!(ver["version"], serde_json::json!(null), "观察器按窗放弃");

    // 门卫健康
    let mut probe = dk.connect();
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut probe, &mut warn);
    probe.write_all(b"probe").unwrap();
    let got = support::read_exact_timeout(&mut probe, 5, Duration::from_secs(5)).unwrap();
    assert_eq!(got, b"probe");
}

/// RST 打在警告 write 前后（SO_LINGER=0 立即 RST）：干净回收，无 panic，无线程泄漏
#[test]
fn t12_client_rst_during_warn_write() {
    let dir = TempDir::new("t12");
    let echo = EchoUpstream::spawn(true);
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        echo.addr,
        dir.join("dk.log"),
    ));

    // panic 记录钩子（链接前一个钩子保持默认行为）
    let panics = Arc::new(AtomicUsize::new(0));
    let prev = std::panic::take_hook();
    {
        let panics = panics.clone();
        std::panic::set_hook(Box::new(move |info| {
            panics.fetch_add(1, Ordering::Relaxed);
            eprintln!("（t12）捕获 panic：{info}");
        }));
    }

    let task_base = {
        let _ = &dk;
        std::fs::read_dir("/proc/self/task").unwrap().count()
    };

    for round in 0..300 {
        let mut c = dk.connect();
        // 部分轮次读一半警告行，制造 write 中途 RST
        if round % 3 == 0 {
            let half = [0u8; 50];
            let _ = support::read_exact_timeout(&mut c, 50, Duration::from_millis(300));
            let _ = half;
        }
        if round % 5 == 0 {
            std::thread::sleep(Duration::from_micros(200)); // 命中 write 时序窗口
        }
        // SO_LINGER=0 → close 立即发 RST
        sockopt::set_socket_linger(&c, Some(Duration::ZERO)).unwrap();
        drop(c);
    }

    // 无 panic
    assert_eq!(panics.load(Ordering::Relaxed), 0, "RST 路径不得 panic");
    std::panic::set_hook(prev);

    // 线程回收
    let ok = support::wait_until(Duration::from_secs(15), || {
        std::fs::read_dir("/proc/self/task").unwrap().count() <= task_base + 4
    });
    let task_now = std::fs::read_dir("/proc/self/task").unwrap().count();
    eprintln!("t12 线程：基线 {task_base} → 终态 {task_now}");
    assert!(ok, "RST 后线程必须回收（{task_base} → {task_now}）");

    // 门卫健康 + 收尾事件齐全（warn 阶段错误也记 conn_close）
    let mut probe = dk.connect();
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut probe, &mut warn);
    probe.write_all(b"healthy").unwrap();
    let got = support::read_exact_timeout(&mut probe, 7, Duration::from_secs(5)).unwrap();
    assert_eq!(got, b"healthy");
    let closes = events(&dk.log_path, "conn_close").len();
    assert!(
        closes >= 1,
        "RST 轮次的连接必须记 conn_close（当前 {closes}）"
    );
}
