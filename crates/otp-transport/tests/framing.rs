//! FramedStream trait 契约矩阵：同一行为断言对 loopback 与 TCP 双实现
//! 逐一执行（任务 #50 验收 ①③：trait 定形 + 超时/对端关闭/半关闭/大帧
//! 分片路径齐全且实现间语义一致）。

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use otp_codec::FRAME_HEADER_LEN;
use otp_transport::{FramedStream, LoopbackTransport, TcpListener, TcpTransport, TransportError};

/// 带自洽长度前缀的测试帧。
fn frame(len: usize) -> Vec<u8> {
    let mut f: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let payload = (len - FRAME_HEADER_LEN) as u32;
    f[4..8].copy_from_slice(&payload.to_be_bytes());
    f
}

/// 一对受测端点。
type Pair = (Box<dyn FramedStream + Send>, Box<dyn FramedStream + Send>);

/// 构造器：给定标签产出受测端点对。
type PairMaker = Box<dyn Fn() -> Pair>;

/// 受测传输对的构造器集合（同一契约跑两种实现）。
fn pairs() -> Vec<(&'static str, PairMaker)> {
    vec![
        (
            "loopback",
            Box::new(|| {
                let (a, b) = LoopbackTransport::new_pair();
                (Box::new(a), Box::new(b))
            }),
        ),
        (
            "tcp",
            Box::new(|| {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let addr = listener.local_addr().unwrap();
                let a = TcpTransport::connect(&addr).unwrap();
                let b = listener.accept().unwrap();
                (Box::new(a), Box::new(b))
            }),
        ),
    ]
}

#[test]
fn contract_roundtrip_and_clean_close_on_both_impls() {
    for (name, make) in pairs() {
        let (mut a, mut b) = make();
        a.set_deadline(Duration::from_secs(30)).unwrap();
        b.set_deadline(Duration::from_secs(30)).unwrap();
        let f = frame(1337);
        a.send_frame(&f).unwrap();
        assert_eq!(b.recv_frame().unwrap(), f, "{name}: 正向帧一致");
        b.send_frame(&f).unwrap();
        assert_eq!(a.recv_frame().unwrap(), f, "{name}: 反向帧一致");
        // 对端关闭 → 干净 ClosedByPeer（帧边界 EOF）
        b.close().unwrap();
        assert_eq!(
            a.recv_frame(),
            Err(TransportError::ClosedByPeer),
            "{name}: 对端关闭"
        );
    }
}

#[test]
fn contract_recv_timeout_on_both_impls() {
    for (name, make) in pairs() {
        let (mut a, _b) = make();
        a.set_deadline(Duration::from_millis(120)).unwrap();
        let t0 = Instant::now();
        assert_eq!(
            a.recv_frame(),
            Err(TransportError::Timeout),
            "{name}: 读超时"
        );
        assert!(
            t0.elapsed() >= Duration::from_millis(100),
            "{name}: 超时应真实等待"
        );
    }
}

#[test]
fn contract_half_close_keeps_reverse_direction_on_both_impls() {
    for (name, make) in pairs() {
        let (mut a, mut b) = make();
        a.set_deadline(Duration::from_secs(30)).unwrap();
        b.set_deadline(Duration::from_secs(30)).unwrap();
        let f = frame(300);
        a.send_frame(&f).unwrap();
        a.shutdown_write().unwrap(); // 半关闭：A 停发
        assert_eq!(b.recv_frame().unwrap(), f, "{name}: 半关闭前排空在途帧");
        assert_eq!(
            b.recv_frame(),
            Err(TransportError::ClosedByPeer),
            "{name}: B 见 A 的写侧 EOF"
        );
        b.send_frame(&f).unwrap(); // 反向不受影响
        assert_eq!(a.recv_frame().unwrap(), f, "{name}: B→A 仍通");
        b.shutdown_write().unwrap();
        assert_eq!(
            a.recv_frame(),
            Err(TransportError::ClosedByPeer),
            "{name}: A 见 B 的写侧 EOF"
        );
    }
}

#[test]
fn contract_max_frame_fragmentation_on_both_impls() {
    for (name, make) in pairs() {
        let (mut a, mut b) = make();
        a.set_deadline(Duration::from_secs(30)).unwrap();
        b.set_deadline(Duration::from_secs(30)).unwrap();
        // 最大协议帧（65576B）经分块路径（WRITE_CHUNK=16 KiB → ≥4 块；
        // loopback 默认容量恰一帧 → 亦构成跨块背压推进）
        let f = frame(otp_transport::MAX_WIRE_FRAME);
        let sent = f.clone();
        let writer = std::thread::spawn(move || a.send_frame(&sent).map_err(|e| e.to_string()));
        let got = b.recv_frame().unwrap();
        writer.join().unwrap().unwrap();
        assert_eq!(got, f, "{name}: 最大帧分片重组后逐字节一致");
    }
}

#[test]
fn contract_backpressure_write_blocks_then_completes_on_both_impls() {
    for (name, make) in pairs() {
        let (mut a, mut b) = make();
        a.set_deadline(Duration::from_secs(30)).unwrap();
        b.set_deadline(Duration::from_secs(30)).unwrap();
        // 双帧排队 > 一帧容量/缓冲：写方必然经历背压等待，读方腾挪后完成
        let f1 = frame(otp_transport::MAX_WIRE_FRAME);
        let f2 = frame(1024);
        let s1 = f1.clone();
        let s2 = f2.clone();
        let writer = std::thread::spawn(move || {
            a.send_frame(&s1).map_err(|e| e.to_string())?;
            a.send_frame(&s2).map_err(|e| e.to_string())
        });
        assert_eq!(b.recv_frame().unwrap(), f1, "{name}: 第一帧");
        assert_eq!(
            b.recv_frame().unwrap(),
            f2,
            "{name}: 第二帧（背压解除后送达）"
        );
        writer.join().unwrap().unwrap();
    }
}

#[test]
fn contract_error_taxonomy_is_uniform() {
    for (name, make) in pairs() {
        let (mut a, _b) = make();
        a.set_deadline(Duration::from_millis(50)).unwrap();
        let e = a.recv_frame().unwrap_err();
        assert_eq!(e, TransportError::Timeout, "{name}");
        assert_eq!(e.code().0, 0x0401, "{name}: Timeout → IO_ERROR");
        assert!(!e.is_peer_condition());
        let peer = TransportError::ClosedByPeer;
        assert_eq!(
            peer.code().0,
            0x0308,
            "{name}: ClosedByPeer → FRAME_TRUNCATED"
        );
        assert!(peer.is_peer_condition());
    }
}

#[test]
fn contract_send_rejects_malformed_frames_before_any_io() {
    for (name, make) in pairs() {
        let (mut a, _b) = make();
        // 短于帧头 / 前缀失配 / 超上界：在任何字节入流之前拒绝
        assert_eq!(
            a.send_frame(&[0u8; 4]),
            Err(TransportError::FrameMalformed),
            "{name}"
        );
        let mut bad = frame(64);
        bad[7] ^= 0xFF; // 破坏长度前缀
        assert_eq!(
            a.send_frame(&bad),
            Err(TransportError::FrameMalformed),
            "{name}"
        );
        let mut over = vec![0u8; FRAME_HEADER_LEN];
        over[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            a.send_frame(&over),
            Err(TransportError::FrameTooLarge {
                len: u32::MAX as usize
            }),
            "{name}"
        );
    }
}
