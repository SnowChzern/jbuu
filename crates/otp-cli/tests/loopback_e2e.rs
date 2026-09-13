//! WP-15 验收 ②（loopback 半）：库层会话驱动在 `LoopbackTransport` 上完成
//! 端到端加密会话 + 回显（WP-12 M1 口径：真实密码本文件 + 真实双 INIT 锚
//! + 真实 `Allocator` 完整 fail-to-waste 事务）。
//!
//! 断言：
//! - 回显逐字节一致；
//! - WireTap 旁录的两方向字节流不含明文标记与段正文（secret 扫描）；
//! - 会话后双方 next=1（段 0 消耗，指针只前进）。

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use otp_anchor_spec::{AnchorRecord, encode_record};
use otp_book::header::BookHeader;
use otp_term_cli::proto;
use otp_transport::{FramedStream as _, LoopbackTransport};
use otp_types::{BookId, SEGMENT_LEN, SegmentIndex};

const ID: BookId = BookId::from_bytes(*b"OTPTERM-TESTBOOK");
const COUNT: u64 = 8;
const CHUNK_LEN: usize = 65536;
const CHUNKS: usize = 16; // 1 MiB（M1 口径）
const DEADLINE: Duration = Duration::from_secs(120);

fn scratch(tag: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/tmp")
        .join(format!("otp-cli-lb-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 确定性段内容（与 secret 扫描断言共享口径）。
fn fill(seed: u8) -> impl Fn(u64) -> [u8; SEGMENT_LEN] {
    move |i| {
        let mut s = [0u8; SEGMENT_LEN];
        for (k, b) in s.iter_mut().enumerate() {
            *b = seed ^ (i as u8).wrapping_add(k as u8).wrapping_mul(7);
        }
        s
    }
}

fn write_test_book(dir: &Path) -> PathBuf {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("book.bin");
    let header = BookHeader::new(ID, COUNT).unwrap();
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(&header.encode()).unwrap();
    let fillfn = fill(0x11);
    for i in 0..COUNT {
        f.write_all(&fillfn(i)).unwrap();
    }
    f.sync_all().unwrap();
    drop(f);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn write_init_anchors(dir: &Path) -> (PathBuf, PathBuf) {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;
    let mut rec = Vec::new();
    encode_record(&AnchorRecord::init(ID), &mut rec);
    let mut paths = Vec::new();
    for copy in ["anchor-a", "anchor-b"] {
        let p = dir.join(format!("{copy}.anchor"));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(&rec).unwrap();
        f.sync_all().unwrap();
        drop(f);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        paths.push(p);
    }
    (paths.pop().unwrap(), paths.pop().unwrap())
}

fn open_allocator(dir: &Path) -> otp_allocator::Allocator {
    let book = write_test_book(dir);
    let (anchor_a, anchor_b) = write_init_anchors(dir);
    otp_allocator::Allocator::open(otp_allocator::AllocatorConfig {
        book,
        anchor_a,
        anchor_b,
        expected_book_id: ID,
    })
    .unwrap()
}

fn endpoint() -> proto::Endpoint {
    proto::Endpoint {
        book_id: ID,
        segment_count: COUNT,
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// 第 i 块明文：16B 可检索标记 + 确定性伪随机字节。
fn echo_chunk(i: usize) -> Vec<u8> {
    let mut chunk = Vec::with_capacity(CHUNK_LEN);
    chunk.extend_from_slice(&marker(i));
    let mut state = (i as u64).wrapping_mul(0x0100_0000_0000_0001) | 1;
    while chunk.len() < CHUNK_LEN {
        chunk.extend_from_slice(&splitmix64(&mut state).to_le_bytes());
    }
    chunk
}

fn marker(i: usize) -> [u8; 16] {
    let mut m = *b"OTPTERM-ECHO-i__";
    m[13] = b'0' + u8::try_from((i / 10) % 10).unwrap();
    m[14] = b'0' + u8::try_from(i % 10).unwrap();
    m[15] = b'|';
    m
}

fn assert_no_secret_in_stream(stream: &[u8], label: &str) {
    for i in 0..CHUNKS {
        let m = marker(i);
        assert!(
            !stream.windows(m.len()).any(|w| w == m),
            "{label}: 第 {i} 块明文标记出现在流中（明文泄露）"
        );
    }
    let f = fill(0x11);
    for seg in [0u64, 1] {
        let s = f(seg);
        assert!(
            !stream.windows(s.len()).any(|w| w == s),
            "{label}: 段 {seg} 正文出现在流中（段材料泄露）"
        );
    }
    // 密文形状粗证：64B 全零块应为 0。
    let zeros = stream
        .chunks(64)
        .filter(|c| c.iter().all(|&b| b == 0))
        .count();
    assert_eq!(zeros, 0, "{label}: 64B 全零块应为 0");
}

#[test]
fn loopback_end_to_end_encrypted_echo_session() {
    let server_dir = scratch("s");
    let client_dir = scratch("c");
    let mut server_alloc = open_allocator(&server_dir);
    let mut client_alloc = open_allocator(&client_dir);

    let ((mut a, mut b), tap) = LoopbackTransport::new_pair_tapped();
    let ep = endpoint();

    // 服务端线程：握手 → 回显循环（对端半关闭即收尾）。
    let server = std::thread::spawn(move || {
        let (mut session, info) =
            proto::server_handshake(&mut a, &mut server_alloc, ep, DEADLINE).expect("服务端握手");
        let bytes = proto::server_echo_loop(&mut a, &mut session).expect("回显循环");
        (info, bytes, server_alloc.state())
    });

    // 客户端：握手 → ping-pong 回显（M1 口径）→ 半关闭。
    let (mut session, info) =
        proto::client_handshake(&mut b, &mut client_alloc, ep, DEADLINE).expect("客户端握手");
    assert_eq!(info.segment, SegmentIndex::ZERO);
    for i in 0..CHUNKS {
        let chunk = echo_chunk(i);
        let echoed = proto::client_roundtrip(&mut b, &mut session, &chunk).expect("回显");
        assert_eq!(echoed, chunk, "第 {i} 块回显不一致");
    }
    b.shutdown_write().expect("客户端半关闭");

    let (server_info, server_bytes, server_state) = server.join().expect("服务端线程");
    let client_state = client_alloc.state();

    // 会话后双方 next=1；段号 0；generation=1（INIT=0 → 一次 issue）。
    assert_eq!(client_state.0.get(), 1);
    assert_eq!(server_state.0.get(), 1);
    assert_eq!(server_state.1.get(), 1);
    assert_eq!(server_info.segment, SegmentIndex::ZERO);
    assert_eq!(
        server_bytes,
        (CHUNKS * CHUNK_LEN) as u64,
        "服务端回显字节数"
    );

    // secret 扫描：旁录字节流（两方向合并）不含明文标记与段正文。
    let stream = tap.snapshot();
    assert!(stream.len() > CHUNKS * CHUNK_LEN, "流应达 MiB 量级");
    assert_no_secret_in_stream(&stream, "loopback-wiretap");

    let _ = std::fs::remove_dir_all(&server_dir);
    let _ = std::fs::remove_dir_all(&client_dir);
}

#[test]
fn failure_maps_to_whitelist_error_code_and_category() {
    // BOOK_MISMATCH（两端错本）：服务端在 HELLO 处即拒，错误码/类别进入
    // 白名单失败结构（§94）。
    let server_dir = scratch("mm-s");
    let client_dir = scratch("mm-c");
    let mut server_alloc = open_allocator(&server_dir);
    let mut client_alloc = open_allocator(&client_dir);
    let ((mut a, mut b), _tap) = LoopbackTransport::new_pair_tapped();

    // 客户端声明一个错误的 book_id。
    let wrong_ep = proto::Endpoint {
        book_id: BookId::from_bytes(*b"OTPTERM-OTHRBOOK"),
        segment_count: COUNT,
    };
    let right_ep = endpoint();

    let server = std::thread::spawn(move || {
        let r = proto::server_handshake(&mut a, &mut server_alloc, right_ep, DEADLINE);
        (r, server_alloc.state())
    });
    let failure = match proto::client_handshake(&mut b, &mut client_alloc, wrong_ep, DEADLINE) {
        Ok(_) => panic!("错本必须失败"),
        Err(e) => e,
    };
    let (server_result, server_state) = server.join().expect("join");

    assert_eq!(failure.code, otp_codec::ErrorCode::BOOK_MISMATCH);
    assert_eq!(failure.category, otp_types::ErrorCategory::Handshake);
    // 线上口径：失败仅含公开元数据（错误码名 + 类别名）。
    assert!(failure.line().contains("BOOK_MISMATCH"));
    assert!(failure.line().contains("handshake"));
    // 服务端同样 fail closed，且段未被消耗（next 仍 0）。
    assert!(server_result.is_err());
    assert_eq!(server_state.0.get(), 0);

    let _ = std::fs::remove_dir_all(&server_dir);
    let _ = std::fs::remove_dir_all(&client_dir);
}
