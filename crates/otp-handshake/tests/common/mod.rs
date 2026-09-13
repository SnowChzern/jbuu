//! 集成测试公共设施：真实密码本 + 真实双锚分配器夹具。
//!
//! `CommittedSegment` 只能由真实 `Allocator::issue()` 产出（类型系统强制，
//! 任务 #45 E0624 夹具），因此握手层测试全部走**真实文件 + 完整
//! fail-to-waste 事务**，不做任何 mock 段签发。密码本内容按确定性
//! 填充函数构造（测试已知内容，便于构造"同 ID 异正文"负例）。

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use otp_allocator::SegmentIssuer as _;
use otp_anchor_spec::{AnchorRecord, encode_record};
use otp_book::header::BookHeader;
use otp_codec::{Message, ProtocolVersion};
use otp_handshake::{
    ClientConfig, ClientHandshake, ClientPhase, ServerConfig, ServerHandshake, ServerPhase, Step,
};
use otp_session::Session;
use otp_types::{BookId, SEGMENT_LEN, SegmentIndex};

/// 标准测试 book_id（与 otp-book/allocator 测试一致）。
pub const ID: BookId = BookId::from_bytes(*b"OTPTERM-TESTBOOK");
/// 标准测试段数。
pub const COUNT: u64 = 8;

static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 测试夹具根目录：workspace 的 target/tmp（编译期由 CARGO_MANIFEST_DIR
/// 推导，稳定可写）。otp-platform 对 tmpfs 等易失文件系统 fail-closed 拒绝
/// OFD 锁，而部分环境 /tmp 为 tmpfs，故不使用 temp_dir。
fn scratch_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp")
}

fn unique_dir(tag: &str) -> PathBuf {
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    scratch_root().join(format!("otp-hs-{}-{}-{}", std::process::id(), tag, n))
}

/// 写测试密码本：段 i 内容 = fill(i)。返回文件路径。
pub fn write_test_book(
    dir: &Path,
    book_id: BookId,
    count: u64,
    fill: impl Fn(u64) -> [u8; SEGMENT_LEN],
) -> PathBuf {
    use std::io::Write;
    let path = dir.join("book.bin");
    let header = BookHeader::new(book_id, count).expect("合法测试头");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(&header.encode()).unwrap();
    for i in 0..count {
        f.write_all(&fill(i)).unwrap();
    }
    f.sync_all().unwrap();
    path
}

/// 写一对 INIT 锚（wp02 §2.5 首启形态：双锚一致 INIT 记录）。
pub fn write_init_anchors(dir: &Path, book_id: BookId) -> (PathBuf, PathBuf) {
    use std::io::Write;
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
pub fn open_allocator(
    tag: &str,
    book_id: BookId,
    count: u64,
    fill: impl Fn(u64) -> [u8; SEGMENT_LEN],
) -> otp_allocator::Allocator {
    let dir = unique_dir(tag);
    std::fs::create_dir_all(&dir).unwrap();
    let book = write_test_book(&dir, book_id, count, fill);
    let (anchor_a, anchor_b) = write_init_anchors(&dir, book_id);
    otp_allocator::Allocator::open(otp_allocator::AllocatorConfig {
        book,
        anchor_a,
        anchor_b,
        expected_book_id: book_id,
    })
    .unwrap()
}

/// 确定性段内容 A：seed 参与异或的连续字节。
pub fn fill_a(seed: u8) -> impl Fn(u64) -> [u8; SEGMENT_LEN] {
    move |i| {
        let mut s = [0u8; SEGMENT_LEN];
        for (k, b) in s.iter_mut().enumerate() {
            *b = seed ^ (i as u8).wrapping_add(k as u8).wrapping_mul(7);
        }
        s
    }
}

/// 确定性段内容 B（与 A 同参数时内容不同——"同 ID 异正文"负例用）。
pub fn fill_b(seed: u8) -> impl Fn(u64) -> [u8; SEGMENT_LEN] {
    move |i| {
        let mut s = [0u8; SEGMENT_LEN];
        for (k, b) in s.iter_mut().enumerate() {
            *b = seed
                ^ 0x5A
                ^ (i as u8)
                    .wrapping_mul(31)
                    .wrapping_add((k as u8).wrapping_mul(13));
        }
        s
    }
}

/// 证明两种填充在同一 (seed, i) 下产生不同正文（负例夹具前提）。
pub fn fills_differ(seed: u8) -> bool {
    let (a, b) = (fill_a(seed), fill_b(seed));
    (0..COUNT).any(|i| a(i) != b(i))
}

/// 预推进分配器：issue 并丢弃 k 段（完整事务，指针前移 k）。
pub fn advance(alloc: &mut otp_allocator::Allocator, k: u64) {
    for _ in 0..k {
        alloc.issue().unwrap();
    }
}

pub fn client_cfg(pointer: SegmentIndex, count: u64) -> ClientConfig {
    ClientConfig {
        version: ProtocolVersion::V2,
        book_id: ID,
        local_pointer: pointer,
        segment_count: count,
    }
}

pub fn server_cfg(pointer: SegmentIndex, count: u64) -> ServerConfig {
    ServerConfig {
        version: ProtocolVersion::V2,
        book_id: ID,
        local_pointer: pointer,
        segment_count: count,
    }
}

/// 构造两端真实分配器 + 两端状态机（未 start）。允许分别指定两端密码本
/// 内容（"同 ID 异正文"负例用：内容不同 ⇒ 密钥不同 ⇒ tag 必失败）。
pub fn machines(
    tag: &str,
    client_fill: impl Fn(u64) -> [u8; SEGMENT_LEN],
    server_fill: impl Fn(u64) -> [u8; SEGMENT_LEN],
) -> (
    ClientHandshake,
    ServerHandshake,
    otp_allocator::Allocator,
    otp_allocator::Allocator,
) {
    let client_alloc = open_allocator(&format!("{tag}-c"), ID, COUNT, client_fill);
    let server_alloc = open_allocator(&format!("{tag}-s"), ID, COUNT, server_fill);
    let client = ClientHandshake::new(client_cfg(client_alloc.state().0, COUNT)).unwrap();
    let server = ServerHandshake::new(server_cfg(server_alloc.state().0, COUNT)).unwrap();
    (client, server, client_alloc, server_alloc)
}

/// 正序驱动到 Established 的产物。
pub struct Established {
    pub client: ClientHandshake,
    pub server: ServerHandshake,
    pub client_alloc: otp_allocator::Allocator,
    pub server_alloc: otp_allocator::Allocator,
    pub client_session: Session,
    pub server_session: Session,
    pub segment: SegmentIndex,
    /// 客户端 HELLO（供负例复用其 nonce 字段）。
    pub hello: Message,
    /// 服务端 ARBITRATE（供负例复用其 nonce 字段）。
    pub arbitrate: Message,
    /// 客户端发出的 ISSUE_REQUEST 与 CONFIRM_C2S。
    pub issue_request: Message,
    pub confirm_c2s: Message,
    /// 服务端已发 CONFIRM_S2C（供客户端侧负例复用）。
    pub confirm_s2c: Message,
}

/// 完整正序：HELLO→ARBITRATE→ISSUE→CONFIRM_C2S→CONFIRM_S2C→Established。
/// 两端使用**相同内容**密码本。
pub fn establish(tag: &str) -> Established {
    let (mut client, mut server, mut client_alloc, mut server_alloc) =
        machines(tag, fill_a(0x11), fill_a(0x11));

    // H1：HELLO
    let hello = client.start().unwrap();
    assert_eq!(client.phase(), ClientPhase::HelloSent);
    // S1：ARBITRATE
    let arbitrate = server.on_hello(&hello).unwrap();
    assert_eq!(server.phase(), ServerPhase::IssueWait);
    // H2+H6：客户端本地签发 + ISSUE_REQUEST + CONFIRM_C2S
    let Step::Send(outbound) = client.handle(&arbitrate, &mut client_alloc) else {
        panic!("{tag}: 正序驱动：客户端应产出待发消息");
    };
    assert_eq!(client.phase(), ClientPhase::ConfirmSent);
    assert_eq!(outbound.len(), 2);
    let issue_request = outbound[0].clone();
    let confirm_c2s = outbound[1].clone();
    // S2：签发 → 等确认
    let Step::AwaitPeer = server.on_issue_request(&issue_request, &mut server_alloc) else {
        panic!("{tag}: 正序驱动：服务端应进入等待确认");
    };
    assert_eq!(server.phase(), ServerPhase::ConfirmWait);
    // S4：验证 CONFIRM_C2S → 发 CONFIRM_S2C + Established
    let (server_session, confirm_s2c, segment) = match server.on_confirm(&confirm_c2s) {
        Step::Established {
            outbox,
            session,
            segment,
        } => {
            assert_eq!(outbox.len(), 1);
            assert_eq!(server.phase(), ServerPhase::Established);
            (session, outbox[0].clone(), segment)
        }
        _ => panic!("{tag}: 正序驱动：服务端应 Established"),
    };
    // H8：客户端验证 CONFIRM_S2C → Established
    let client_session = match client.handle(&confirm_s2c, &mut client_alloc) {
        Step::Established {
            session,
            segment: s,
            ..
        } => {
            assert_eq!(s, segment);
            session
        }
        _ => panic!("{tag}: 正序驱动：客户端应 Established"),
    };
    assert_eq!(client.phase(), ClientPhase::Established);
    Established {
        client,
        server,
        client_alloc,
        server_alloc,
        client_session,
        server_session,
        segment,
        hello,
        arbitrate,
        issue_request,
        confirm_c2s,
        confirm_s2c,
    }
}
