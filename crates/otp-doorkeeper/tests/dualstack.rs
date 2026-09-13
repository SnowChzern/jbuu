//! D10 佐证（§1.2/E5）：[::] 单套接字双栈（显式 IPV6_V6ONLY=0）——
//! IPv4 连接映射为 v4mapped 接入，IPv6 直连接入。
#![allow(dead_code)]
mod support;

use std::io::Write;

use support::{DkHandle, EchoUpstream, TempDir, dk_config};

#[test]
fn dual_stack_v4mapped_and_v6() {
    // 检查本机 IPv6 可用性：不可用则 SKIP（保留 runbook §7.5 处置路径）
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        eprintln!("SKIP: 本机 IPv6 不可用（runbook §7.5：退回 --listen 0.0.0.0:22）");
        return;
    }
    let dir = TempDir::new("dual");
    let echo = EchoUpstream::spawn(true);
    let dk = DkHandle::start(dk_config(
        "[::]:0".parse().unwrap(),
        echo.addr,
        dir.join("dk.log"),
    ));
    let port = dk.addr.port();
    assert!(dk.addr.is_ipv6());

    // IPv4 连接（经双栈映射进 v6 监听）
    let v4addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut c4 = std::net::TcpStream::connect(v4addr).expect("v4 经双栈接入失败");
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut c4, &mut warn);
    c4.write_all(b"via-v4").unwrap();
    let got = support::read_exact_timeout(&mut c4, 6, std::time::Duration::from_secs(5)).unwrap();
    assert_eq!(got, b"via-v4");

    // IPv6 直连
    let v6addr: std::net::SocketAddr = format!("[::1]:{port}").parse().unwrap();
    let mut c6 = std::net::TcpStream::connect(v6addr).expect("v6 接入失败");
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut c6, &mut warn);
    c6.write_all(b"via-v6").unwrap();
    let got = support::read_exact_timeout(&mut c6, 6, std::time::Duration::from_secs(5)).unwrap();
    assert_eq!(got, b"via-v6");

    // 日志 family 分类：v4mapped / v6（E5：::ffff:127.0.0.1）
    let accept4 = support::wait_for_event(&dk.log_path, "conn_accept", |v| {
        v["conn_id"].as_u64() == Some(1)
    });
    assert_eq!(
        accept4["family"].as_str(),
        Some("v4mapped"),
        "v4 经双栈应记 v4mapped"
    );
    let accept6 = support::wait_for_event(&dk.log_path, "conn_accept", |v| {
        v["conn_id"].as_u64() == Some(2)
    });
    assert_eq!(accept6["family"].as_str(), Some("v6"));

    // 读回 socket 选项佐证显式 V6ONLY=0（D10：不依赖 sysctl net.ipv6.bindv6only）
    let probe =
        otp_doorkeeper::proxy::bind_listener("[::]:0".parse().unwrap()).expect("双栈监听绑定失败");
    assert!(
        !rustix::net::sockopt::ipv6_v6only(&probe).expect("读 IPV6_V6ONLY 失败"),
        "IPV6_V6ONLY 必须显式为 0"
    );
}
