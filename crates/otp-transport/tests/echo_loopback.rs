//! M1 验收（规划 §3/WP-12 行）：loopback 加密回显 1 MiB。
//!
//! 两端真实 Allocator（相同内容测试密码本 + 双 INIT 锚）经
//! `LoopbackTransport` 完成完整握手，随后客户端以 16 × 64 KiB DATA record
//! 发送 1 MiB 确定性伪随机明文，服务端逐块加密回显，客户端逐字节比对。
//! 旁路 `WireTap` 记录两方向全部流经字节：
//! - 明文标记与会话段正文不得出现在字节流中（明文不出传输层）；
//! - 会话后两端 next=1（段 0 已消耗，指针只前进）。

#![forbid(unsafe_code)]

mod common;

use common::{
    CHUNK_LEN, CHUNKS, ECHO_TOTAL, assert_no_plaintext_in_stream,
    assert_stream_looks_like_ciphertext, chunk_len_info, client_recv_echo, client_send_chunk,
    drive_handshake, echo_chunk, open_allocator, server_echo_once,
};
use otp_transport::{FramedStream as _, LoopbackTransport};
use std::time::Duration;

#[test]
fn loopback_encrypted_echo_1mib() {
    let ((mut client_io, mut server_io), tap) = LoopbackTransport::new_pair_tapped();
    client_io.set_deadline(Duration::from_secs(60)).unwrap();
    server_io.set_deadline(Duration::from_secs(60)).unwrap();

    let mut client_alloc = open_allocator("echo-lb-c");
    let mut server_alloc = open_allocator("echo-lb-s");
    let c0 = client_alloc.state().0;
    let s0 = server_alloc.state().0;

    let (mut client_session, mut server_session, segment) = drive_handshake(
        &mut client_io,
        &mut server_io,
        &mut client_alloc,
        &mut server_alloc,
    );
    assert_eq!(segment.get(), 0, "双端同书同指针：约定段 0");

    // 1 MiB 加密回显（ping-pong：默认容量恰容纳单最大帧，天然逐块推进）
    let mut sent_total = 0usize;
    for i in 0..CHUNKS {
        let chunk = echo_chunk(i);
        client_send_chunk(&mut client_session, &mut client_io, &chunk);
        server_echo_once(&mut server_session, &mut server_io);
        let back = client_recv_echo(&mut client_session, &mut client_io);
        assert_eq!(back.len(), CHUNK_LEN, "第 {i} 块回显长度一致");
        assert_eq!(back, chunk, "第 {i} 块回显逐字节一致");
        sent_total += chunk.len();
    }
    assert_eq!(sent_total, ECHO_TOTAL, "回显总量 = 1 MiB");

    // 会话后指针：双方 next=1（M1 验收"会话后双方 next=1"）
    assert_eq!(client_alloc.state().0.get(), c0.get() + 1);
    assert_eq!(server_alloc.state().0.get(), s0.get() + 1);

    // 抓流断言：明文与段正文不出现在 transport 字节流
    let stream = tap.snapshot();
    assert_stream_looks_like_ciphertext(&stream, "loopback");
    assert_no_plaintext_in_stream(&stream, "loopback");

    // 干净收尾：客户端半关闭 → 服务端见 ClosedByPeer → 服务端关闭
    client_io.shutdown_write().unwrap();
    assert!(matches!(
        server_io.recv_frame(),
        Err(otp_transport::TransportError::ClosedByPeer)
    ));
    server_io.close().unwrap();
    assert!(matches!(
        client_io.recv_frame(),
        Err(otp_transport::TransportError::ClosedByPeer)
    ));
}

#[test]
fn loopback_tampered_stream_fails_authentication_and_closes() {
    // M1 验收："篡改任一 bit 必须认证失败并关闭"——在旁路层模拟线路翻转：
    // 客户端发送的 DATA 帧在写入管道后、服务端读取前被翻转 1 bit。
    use otp_codec::{Message, decode, encode};
    use otp_session::MessageType;
    use otp_types::Role;

    let ((mut client_io, mut server_io), _tap) = LoopbackTransport::new_pair_tapped();
    client_io.set_deadline(Duration::from_secs(60)).unwrap();
    server_io.set_deadline(Duration::from_secs(60)).unwrap();
    let mut client_alloc = open_allocator("tamper-c");
    let mut server_alloc = open_allocator("tamper-s");
    let (mut client_session, mut server_session, _seg) = drive_handshake(
        &mut client_io,
        &mut server_io,
        &mut client_alloc,
        &mut server_alloc,
    );

    // 构造一条合法 DATA 帧，翻转密文区 1 bit 后注入服务端方向
    let record = client_session
        .seal(MessageType::Data, &echo_chunk(0))
        .unwrap();
    let msg = Message::Data {
        epoch: otp_types::Epoch::new(0),
        seq: record.sequence,
        data: record.sealed().to_vec(),
    };
    let mut wire = encode(&msg).unwrap();
    let flip_at = wire.len() - 5; // 密文/tag 区内
    wire[flip_at] ^= 0x01;
    client_io.send_frame(&wire).unwrap();

    let got = server_io.recv_frame().unwrap();
    let decoded = decode(Role::Server, &got).unwrap();
    let Message::Data { seq, data, .. } = decoded else {
        unreachable!()
    };
    let outcome = server_session.open(MessageType::Data, seq, &data);
    assert!(
        matches!(
            outcome,
            Err(otp_session::SessionError::AuthenticationFailed)
        ),
        "篡改 1 bit 必须 tag 认证失败"
    );
    // fail closed：会话焚毁，后续 seal/open 均拒绝
    let after = server_session.seal(MessageType::Data, b"x");
    assert!(matches!(after, Err(otp_session::SessionError::Closed)));
}

#[test]
fn chunk_geometry_matches_m1() {
    // 16 × 64 KiB = 1 MiB；标记互不相同
    assert_eq!(CHUNKS, 16);
    assert_eq!(CHUNK_LEN, 65536);
    assert_eq!(chunk_len_info(), (ECHO_TOTAL, CHUNK_LEN, CHUNKS));
    let m0 = common::plaintext_marker(0);
    let m15 = common::plaintext_marker(15);
    assert_ne!(m0, m15);
}
