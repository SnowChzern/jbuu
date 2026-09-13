//! §8 测试 6：半关闭——一侧 FIN → 另一侧收到 FIN 传播（socket 测试工装断言）。
#![allow(dead_code)]
mod support;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use support::{DkHandle, EchoUpstream, TempDir, dk_config};

/// 脚本化上游：读到 EOF 记录之，随后写 tail 并 shutdown(Write)
struct UpstreamRig {
    addr: std::net::SocketAddr,
    saw_fin: Arc<AtomicBool>,
    got_bytes: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl UpstreamRig {
    fn spawn() -> UpstreamRig {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let saw_fin = Arc::new(AtomicBool::new(false));
        let got_bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let fin = saw_fin.clone();
        let bytes = got_bytes.clone();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break, // 收到 FIN
                    Ok(n) => bytes.lock().unwrap().extend_from_slice(&buf[..n]),
                    Err(_) => break,
                }
            }
            fin.store(true, Ordering::Release);
            // 上游响应并主动半关闭（FIN 传回客户端方向）
            let _ = stream.write_all(b"upstream-tail");
            let _ = stream.shutdown(std::net::Shutdown::Write);
            // 保持连接直到对端也结束（读侧丢弃）
            let mut sink = [0u8; 1024];
            loop {
                match stream.read(&mut sink) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
        UpstreamRig {
            addr,
            saw_fin,
            got_bytes,
        }
    }
}

/// 客户端 FIN → 门卫传播 → 上游读到 EOF；上游 FIN → 门卫传播 → 客户端读到 EOF
#[test]
fn t06_halfclose_propagates_both_directions() {
    let dir = TempDir::new("t06");
    let rig = UpstreamRig::spawn();
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        rig.addr,
        dir.join("dk.log"),
    ));

    let mut client = dk.connect();
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut client, &mut warn);

    client.write_all(b"payload-before-fin").unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap(); // 客户端 FIN

    // 上游必须看到 FIN（半关闭传播到上游）
    assert!(
        support::wait_until(Duration::from_secs(5), || rig
            .saw_fin
            .load(Ordering::Acquire)),
        "上游必须收到 FIN 传播"
    );
    assert_eq!(*rig.got_bytes.lock().unwrap(), b"payload-before-fin");

    // 上游的 FIN 也传播回客户端：读到 tail 后 EOF
    let mut tail = Vec::new();
    let got = support::read_to_end_timeout(&mut client, Duration::from_secs(5)).unwrap();
    tail.extend_from_slice(&got);
    assert_eq!(
        tail, b"upstream-tail",
        "客户端必须收到上游 FIN 后的剩余字节"
    );
    // read_to_end 已断言最终 EOF（Ok 返回即读到 0）

    let close = support::wait_for_event(&dk.log_path, "conn_close", |_| true);
    assert_eq!(
        close["reason"].as_str(),
        Some("normal"),
        "干净半关闭双向结束属 normal"
    );
}

/// 长空闲 + 单向关闭压力形态：多个连接同时半关闭，全部正确收尾
#[test]
fn t06_halfclose_multiple_conns() {
    let dir = TempDir::new("t06m");
    let echo = EchoUpstream::spawn(true);
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        echo.addr,
        dir.join("dk.log"),
    ));

    let mut clients = Vec::new();
    for i in 0..16 {
        let mut c: TcpStream = dk.connect();
        let mut warn = [0u8; 101];
        support::read_exact_into(&mut c, &mut warn);
        c.write_all(format!("c{i}-data").as_bytes()).unwrap();
        clients.push(c);
    }
    for c in clients.iter_mut() {
        c.shutdown(std::net::Shutdown::Write).unwrap();
    }
    for (i, c) in clients.iter_mut().enumerate() {
        let expect = format!("c{i}-data");
        let got = support::read_to_end_timeout(c, Duration::from_secs(5)).unwrap();
        assert_eq!(got, expect.as_bytes());
    }
}
