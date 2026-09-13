//! 集成测试公共设施（WP-12 验收 ②⑤：M1 口径加密回显）。
//!
//! 复用 otp-handshake 集成测试的夹具口径（真实密码本文件 + 真实双 INIT
//! 锚 + 真实 `Allocator` 完整 fail-to-waste 事务——`CommittedSegment` 只能
//! 由它产出，类型系统强制），在其上叠加：
//! - 跨 `FramedStream` 的完整握手驱动（HELLO→ARBITRATE→ISSUE→
//!   CONFIRM_C2S→CONFIRM_S2C，帧经 transport 收发、语义经 codec 编解码）；
//! - 回显载荷构造（确定性伪随机 1 MiB，含每块 16B 可检索标记）；
//! - 明文不可见断言（在旁录字节流中检索明文标记/段正文）。

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use otp_allocator::Allocator;
use otp_anchor_spec::{AnchorRecord, encode_record};
use otp_book::header::BookHeader;
use otp_codec::{Message, ProtocolVersion, decode, encode};
use otp_handshake::{ClientConfig, ClientHandshake, ServerConfig, ServerHandshake, Step};
use otp_session::{MessageType, Record, Session};
use otp_transport::FramedStream;
use otp_types::{BookId, Epoch, Role, SEGMENT_LEN, SegmentIndex};

/// 标准测试 book_id（与握手/分配器测试一致）。
pub const ID: BookId = BookId::from_bytes(*b"OTPTERM-TESTBOOK");
/// 标准测试段数。
pub const COUNT: u64 = 8;
/// 回显总量：1 MiB（规划 §3 M1 验收"至少 1 MiB"）。
pub const ECHO_TOTAL: usize = 1024 * 1024;
/// 单条 DATA 应用明文上限（= codec MAX_APP_PLAINTEXT）。
pub const CHUNK_LEN: usize = 65536;
/// 回显块数。
pub const CHUNKS: usize = ECHO_TOTAL / CHUNK_LEN;

static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn scratch_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp")
}

fn unique_dir(tag: &str) -> PathBuf {
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    scratch_root().join(format!("otp-tp-{}-{}-{}", std::process::id(), tag, n))
}

/// 单调后缀（父进程控制面目录去重用）。
pub fn unique_tag() -> u64 {
    SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// 确定性段内容（seed 参与的连续字节；测试已知，用于断言段正文不出流）。
pub fn fill(seed: u8) -> impl Fn(u64) -> [u8; SEGMENT_LEN] {
    move |i| {
        let mut s = [0u8; SEGMENT_LEN];
        for (k, b) in s.iter_mut().enumerate() {
            *b = seed ^ (i as u8).wrapping_add(k as u8).wrapping_mul(7);
        }
        s
    }
}

fn write_test_book(dir: &Path, book_id: BookId, count: u64) -> PathBuf {
    use std::io::Write as _;
    let path = dir.join("book.bin");
    let header = BookHeader::new(book_id, count).expect("合法测试头");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(&header.encode()).unwrap();
    let fill = fill(0x11);
    for i in 0..count {
        f.write_all(&fill(i)).unwrap();
    }
    f.sync_all().unwrap();
    path
}

fn write_init_anchors(dir: &Path, book_id: BookId) -> (PathBuf, PathBuf) {
    use std::io::Write as _;
    let mut rec = Vec::new();
    encode_record(&AnchorRecord::init(book_id), &mut rec);
    let mut paths = Vec::new();
    for copy in ["anchor-a", "anchor-b"] {
        let p = dir.join(format!("{copy}.anchor"));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(&rec).unwrap();
        f.sync_all().unwrap();
        paths.push(p);
    }
    (paths.pop().unwrap(), paths.pop().unwrap())
}

/// 打开一个指向独立临时目录的真实 Allocator（书 + 双 INIT 锚）。
pub fn open_allocator(tag: &str) -> Allocator {
    let dir = unique_dir(tag);
    std::fs::create_dir_all(&dir).unwrap();
    let book = write_test_book(&dir, ID, COUNT);
    let (anchor_a, anchor_b) = write_init_anchors(&dir, ID);
    Allocator::open(otp_allocator::AllocatorConfig {
        book,
        anchor_a,
        anchor_b,
        expected_book_id: ID,
    })
    .unwrap()
}

pub fn client_cfg(pointer: SegmentIndex) -> ClientConfig {
    ClientConfig {
        version: ProtocolVersion::V2,
        book_id: ID,
        local_pointer: pointer,
        segment_count: COUNT,
    }
}

pub fn server_cfg(pointer: SegmentIndex) -> ServerConfig {
    ServerConfig {
        version: ProtocolVersion::V2,
        book_id: ID,
        local_pointer: pointer,
        segment_count: COUNT,
    }
}

// ── 帧收发助手：transport 只搬帧，语义归 codec ──

pub fn send_msg(io: &mut dyn FramedStream, msg: &Message) {
    let wire = encode(msg).expect("canonical 编码");
    io.send_frame(&wire).expect("transport 完整写");
}

pub fn recv_msg(io: &mut dyn FramedStream, role: Role) -> Message {
    let wire = io.recv_frame().expect("transport 完整读");
    decode(role, &wire).expect("codec 语义判定")
}

// ── 完整握手驱动（在任意 FramedStream 上）──

/// 驱动 HELLO→ARBITRATE→ISSUE_REQUEST→CONFIRM_C2S→CONFIRM_S2C 至
/// Established，返回两端会话与约定段号。任一步失败即 panic（测试口径）。
pub fn drive_handshake(
    client_io: &mut dyn FramedStream,
    server_io: &mut dyn FramedStream,
    client_alloc: &mut Allocator,
    server_alloc: &mut Allocator,
) -> (Session, Session, SegmentIndex) {
    let mut client = ClientHandshake::new(client_cfg(client_alloc.state().0)).unwrap();
    let mut server = ServerHandshake::new(server_cfg(server_alloc.state().0)).unwrap();

    // H1：HELLO
    send_msg(client_io, &client.start().unwrap());
    // S1：ARBITRATE
    let arbitrate = server.on_hello(&recv_msg(server_io, Role::Server)).unwrap();
    send_msg(server_io, &arbitrate);
    // H2+H6：客户端自传输层收 ARBITRATE → 本地签发 + ISSUE_REQUEST + CONFIRM_C2S
    let arbitrate_in = recv_msg(client_io, Role::Client);
    match client.handle(&arbitrate_in, client_alloc) {
        Step::Send(outbox) => {
            assert_eq!(outbox.len(), 2);
            for m in &outbox {
                send_msg(client_io, m);
            }
        }
        _ => panic!("客户端应产出 ISSUE_REQUEST+CONFIRM_C2S， got 非预期 Step"),
    }
    // S2：签发 → 等确认
    let issue_request = recv_msg(server_io, Role::Server);
    match server.on_issue_request(&issue_request, server_alloc) {
        Step::AwaitPeer => {}
        _ => panic!("服务端应等待确认， got 非预期 Step"),
    }
    // S4：验证 CONFIRM_C2S → CONFIRM_S2C + Established
    let confirm_c2s = recv_msg(server_io, Role::Server);
    let (server_session, segment) = match server.on_confirm(&confirm_c2s) {
        Step::Established {
            outbox,
            session,
            segment,
        } => {
            assert_eq!(outbox.len(), 1);
            send_msg(server_io, &outbox[0]);
            (session, segment)
        }
        _ => panic!("服务端应 Established， got 非预期 Step"),
    };
    // H8：验证 CONFIRM_S2C → Established
    let confirm_s2c = recv_msg(client_io, Role::Client);
    let client_session = match client.handle(&confirm_s2c, client_alloc) {
        Step::Established {
            session,
            segment: s,
            ..
        } => {
            assert_eq!(s, segment);
            session
        }
        _ => panic!("客户端应 Established， got 非预期 Step"),
    };
    (client_session, server_session, segment)
}

// ── 单侧握手驱动（双进程回显：各端各自驱动自己的状态机）──

/// 客户端侧：HELLO → (收 ARBITRATE → ISSUE_REQUEST + CONFIRM_C2S) →
/// (收 CONFIRM_S2C) → Established。
pub fn client_handshake_over(io: &mut dyn FramedStream, alloc: &mut Allocator) -> Session {
    let mut client = ClientHandshake::new(client_cfg(alloc.state().0)).unwrap();
    send_msg(io, &client.start().unwrap());
    let arbitrate = recv_msg(io, Role::Client);
    match client.handle(&arbitrate, alloc) {
        Step::Send(outbox) => {
            assert_eq!(outbox.len(), 2);
            for m in &outbox {
                send_msg(io, m);
            }
        }
        _ => panic!("客户端应产出 ISSUE_REQUEST+CONFIRM_C2S， got 非预期 Step"),
    }
    let confirm_s2c = recv_msg(io, Role::Client);
    match client.handle(&confirm_s2c, alloc) {
        Step::Established { session, .. } => session,
        _ => panic!("客户端应 Established， got 非预期 Step"),
    }
}

/// 服务端侧：(收 HELLO → ARBITRATE) → (收 ISSUE_REQUEST) →
/// (收 CONFIRM_C2S → CONFIRM_S2C) → Established。
pub fn server_handshake_over(
    io: &mut dyn FramedStream,
    alloc: &mut Allocator,
) -> (Session, SegmentIndex) {
    let mut server = ServerHandshake::new(server_cfg(alloc.state().0)).unwrap();
    let hello = recv_msg(io, Role::Server);
    let arbitrate = server.on_hello(&hello).unwrap();
    send_msg(io, &arbitrate);
    let issue_request = recv_msg(io, Role::Server);
    match server.on_issue_request(&issue_request, alloc) {
        Step::AwaitPeer => {}
        _ => panic!("服务端应等待确认， got 非预期 Step"),
    }
    let confirm_c2s = recv_msg(io, Role::Server);
    match server.on_confirm(&confirm_c2s) {
        Step::Established {
            outbox,
            session,
            segment,
        } => {
            assert_eq!(outbox.len(), 1);
            for m in &outbox {
                send_msg(io, m);
            }
            (session, segment)
        }
        _ => panic!("服务端应 Established， got 非预期 Step"),
    }
}

// ── 回显载荷与 DATA 封装 ──

/// SplitMix64 确定性伪随机流（测试载荷；非秘密、可复现）。
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// 第 i 块回显载荷（64 KiB）：前 16B 为可检索明文标记，其余为确定性
/// 伪随机字节。
pub fn echo_chunk(i: usize) -> Vec<u8> {
    let mut chunk = Vec::with_capacity(CHUNK_LEN);
    chunk.extend_from_slice(&plaintext_marker(i));
    let mut state = (i as u64).wrapping_mul(0x0100_0000_0000_0001) | 1;
    while chunk.len() < CHUNK_LEN {
        chunk.extend_from_slice(&splitmix64(&mut state).to_le_bytes());
    }
    chunk
}

/// 第 i 块的 16B 明文标记（明文不可见断言的检索锚点）。
pub fn plaintext_marker(i: usize) -> [u8; 16] {
    let mut m = *b"OTPTERM-ECHO-i__";
    m[13] = b'0' + u8::try_from((i / 10) % 10).unwrap();
    m[14] = b'0' + u8::try_from(i % 10).unwrap();
    m[15] = b'|';
    m
}

/// 回显几何常量（总量， 块长， 块数）。
pub fn chunk_len_info() -> (usize, usize, usize) {
    (ECHO_TOTAL, CHUNK_LEN, CHUNKS)
}

/// 会话段 i 的 64B 正文（本夹具确定性填充；断言段不出流用）。
pub fn segment_bytes(i: u64) -> [u8; SEGMENT_LEN] {
    fill(0x11)(i)
}

fn data_message(record: &Record) -> Message {
    Message::Data {
        epoch: Epoch::new(0),
        seq: record.sequence,
        data: record.sealed().to_vec(),
    }
}

/// 客户端方向：封装并发送一块明文。
pub fn client_send_chunk(session: &mut Session, io: &mut dyn FramedStream, plain: &[u8]) {
    let record = session.seal(MessageType::Data, plain).expect("seal");
    send_msg(io, &data_message(&record));
}

/// 服务端方向：收一块 → 解封 → 原文加密回显。
pub fn server_echo_once(session: &mut Session, io: &mut dyn FramedStream) {
    let wire = io.recv_frame().expect("transport 完整读");
    server_echo_wire(session, io, &wire);
}

/// 服务端方向：对已收到的帧字节解封并原文加密回显（双进程回显循环用：
/// 帧收发与 EOF 判定由调用方控制）。
pub fn server_echo_wire(session: &mut Session, io: &mut dyn FramedStream, wire: &[u8]) {
    let msg = decode(Role::Server, wire).expect("codec 语义判定");
    let Message::Data { seq, data, .. } = msg else {
        panic!("回显阶段只接受 DATA， got {msg:?}");
    };
    let plain = session
        .open(MessageType::Data, seq, &data)
        .expect("tag 验证通过");
    let record = session
        .seal(MessageType::Data, plain.as_bytes())
        .expect("seal echo");
    send_msg(io, &data_message(&record));
}

/// 客户端方向：收一块回显并返回明文（逐字节比对口径）。
pub fn client_recv_echo(session: &mut Session, io: &mut dyn FramedStream) -> Vec<u8> {
    let msg = recv_msg(io, Role::Client);
    let Message::Data { seq, data, .. } = msg else {
        panic!("回显阶段只接受 DATA， got {msg:?}");
    };
    let plain = session
        .open(MessageType::Data, seq, &data)
        .expect("回显 tag 验证通过");
    plain.as_bytes().to_vec()
}

/// 在旁录字节流中断言"明文不出传输层"：
/// - 任一块的 16B 明文标记不得出现；
/// - 会话段 64B 正文不得出现。
pub fn assert_no_plaintext_in_stream(stream: &[u8], label: &str) {
    for i in 0..CHUNKS {
        let marker = plaintext_marker(i);
        assert!(
            !stream.windows(marker.len()).any(|w| w == marker),
            "{label}: 第 {i} 块明文标记出现在字节流中（明文泄露）"
        );
    }
    let seg = segment_bytes(0);
    assert!(
        !stream.windows(seg.len()).any(|w| w == seg),
        "{label}: 段 0 正文出现在字节流中（段材料泄露）"
    );
}

/// 断言字节流确实在搬运密文（容量/熵的粗证：不含全零长串）。
pub fn assert_stream_looks_like_ciphertext(stream: &[u8], label: &str) {
    assert!(
        stream.len() > ECHO_TOTAL / 2,
        "{label}: 字节流应达 MiB 量级"
    );
    let zeros = stream
        .chunks(64)
        .filter(|c| c.iter().all(|&b| b == 0))
        .count();
    assert_eq!(zeros, 0, "{label}: 64B 全零块应为 0（密文不应有长零串）");
}
