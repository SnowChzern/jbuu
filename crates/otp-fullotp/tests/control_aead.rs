//! PAD 控制面 × 现有 AEAD 控制通道集成测试（设计书 §1.3/FOD-4）。
//!
//! 实证三件事：
//! 1. **承载路径**：PAD_* payload 以现有 `otp-session` 的 DATA record
//!    （ChaCha20-Poly1305）封装、经 `otp-codec` v2 帧编解码往返成功——
//!    full-OTP 数据面不另建控制加密通道；
//! 2. **序号空间分离**：控制面用 AEAD session 的 seq（CONFIRM 占 0、
//!    DATA 自 1 起严格 +1），OTP 数据用每方向 `record_seq`（从 0 起）；
//!    两套计数器互不相干（同一连接同时推进两者互不干扰）；
//! 3. **禁止承载终端字符**：控制 payload 为定长元数据，解码器对一切
//!    附加字节 fail closed；本测试同时注入结构上不可能的\"数据逃逸\"
//!    （多余字节）验证拒绝。

use otp_codec::{Message, decode, encode};
use otp_fullotp::{PadControl, decode_control};
use otp_session::{CommittedSegment, MessageType, Session, SessionContext};
use otp_types::{BookId, ClientNonce, Role, SegmentIndex, ServerNonce, TAG_LEN};

fn ctx(role: Role) -> SessionContext {
    SessionContext {
        role,
        book_id: BookId::from_bytes([0x50; 16]),
        segment: SegmentIndex::ZERO,
        client_nonce: ClientNonce::from_bytes([0x11; 16]),
        server_nonce: ServerNonce::from_bytes([0x22; 16]),
    }
}

/// 从共享 64B 段建立客户端/服务端 AEAD 控制通道（与握手层同构）。
fn control_pair() -> (Session, Session) {
    let mut seg = [0u8; 64];
    for (i, b) in seg.iter_mut().enumerate() {
        *b = i as u8;
    }
    // 两端各持同一材料副本（两端共享密码本）
    let seg2 = seg;
    let (mut c, mut s) = (
        Session::new(CommittedSegment::from_bytes(seg), ctx(Role::Client)),
        Session::new(CommittedSegment::from_bytes(seg2), ctx(Role::Server)),
    );
    // 双 CONFIRM 占 seq=0（WP-03 §4.1）
    let c_confirm = c
        .seal(MessageType::ClientConfirm, b"client-confirm-body")
        .unwrap();
    let s_confirm = s
        .seal(MessageType::ServerConfirm, b"server-confirm-body")
        .unwrap();
    s.open(
        MessageType::ClientConfirm,
        c_confirm.sequence,
        c_confirm.sealed(),
    )
    .unwrap();
    c.open(
        MessageType::ServerConfirm,
        s_confirm.sequence,
        s_confirm.sealed(),
    )
    .unwrap();
    (c, s)
}

/// 控制面一跳：发送方 AEAD 封装 → v2 帧 → 接收方帧解码 → AEAD 解封 → payload 解码。
fn send_control(
    from: &mut Session,
    to: &mut Session,
    msg: &PadControl,
) -> Result<PadControl, &'static str> {
    let record = from
        .seal(MessageType::Data, &msg.encode())
        .map_err(|_| "seal")?;
    let frame = encode(&Message::Data {
        epoch: otp_types::Epoch::new(0),
        seq: record.sequence,
        data: record.sealed().to_vec(),
    })
    .map_err(|_| "encode")?;
    let decoded = match decode(to.role(), &frame) {
        Ok(Message::Data { seq, data, .. }) => (seq, data),
        _ => return Err("decode"),
    };
    let payload = to
        .open(MessageType::Data, decoded.0, &decoded.1)
        .map_err(|_| "open")?;
    decode_control(payload.as_bytes()).map_err(|_| "payload")
}

#[test]
fn all_four_pad_messages_roundtrip_over_aead_control_channel() {
    let (mut client, mut server) = control_pair();
    // S→C：PAD_OFFER（服务端协调者公告）
    let offer = PadControl::PadOffer {
        bundle_id: 1,
        base_segment: 129,
    };
    assert_eq!(
        send_control(&mut server, &mut client, &offer).unwrap(),
        offer
    );
    // C→S：PAD_ACK / PAD_NEED / CLOSE
    for msg in [
        PadControl::PadAck { bundle_id: 1 },
        PadControl::PadNeed,
        PadControl::Close,
    ] {
        assert_eq!(send_control(&mut client, &mut server, &msg).unwrap(), msg);
    }
    // AEAD 序号空间：DATA 严格 +1（CONFIRM 占 0）——客户端发 3 条、服务端发 1 条
    assert_eq!(client.next_send_sequence().get(), 4);
    assert_eq!(server.next_send_sequence().get(), 2);
}

#[test]
fn control_and_otp_data_sequence_spaces_are_independent() {
    // 同一\"连接\"上：OTP record_seq（每方向从 0）与 AEAD 控制 seq 并行推进，
    // 互不重置/互不影响（fullotp 泵的 record_seq 由泵自持，本测试实证
    // AEAD 侧约束不泄漏到数据面计数器）
    let (mut client, mut server) = control_pair();
    // 控制面先跑 3 条
    for msg in [
        PadControl::PadNeed,
        PadControl::PadAck { bundle_id: 0 },
        PadControl::Close,
    ] {
        send_control(&mut client, &mut server, &msg).unwrap();
    }
    assert_eq!(client.next_send_sequence().get(), 4, "AEAD DATA seq=1..3");
    // OTP 数据面 record_seq 独立：用泵再发一条数据记录（bundle 0 base=1）
    let flat = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(1));
    let mut pump_client = otp_fullotp::FullOtpPump::new(Role::Client, 1, flat);
    let mut pump_server = otp_fullotp::FullOtpPump::new(Role::Server, 1, flat);
    let out = pump_client.send(b"term").unwrap();
    let otp_fullotp::SendOutcome::Record { record, .. } = out else {
        panic!()
    };
    assert_eq!(
        record.record_seq, 0,
        "OTP record_seq 从 0 起，与 AEAD seq 无关"
    );
    assert_eq!(record.bundle_id, 0);
    assert_eq!(
        pump_server
            .receive(&record.encode())
            .unwrap()
            .plaintext
            .as_bytes(),
        b"term"
    );
    // AEAD 侧计数不受影响
    assert_eq!(client.next_send_sequence().get(), 4);
}

#[test]
fn control_payload_extra_bytes_are_rejected_fail_closed() {
    // \"控制面不得承载终端字符\"的结构投影：一切非冻结格式字节即拒
    let (mut client, mut server) = control_pair();
    let mut evil = PadControl::PadNeed.encode();
    evil.extend_from_slice(b"secret-terminal-bytes");
    let record = client.seal(MessageType::Data, &evil).unwrap();
    let frame = encode(&Message::Data {
        epoch: otp_types::Epoch::new(0),
        seq: record.sequence,
        data: record.sealed().to_vec(),
    })
    .unwrap();
    let Message::Data { seq, data, .. } = decode(server.role(), &frame).unwrap() else {
        panic!()
    };
    let payload = server.open(MessageType::Data, seq, &data).unwrap();
    assert!(
        decode_control(payload.as_bytes()).is_err(),
        "载荷级 fail closed"
    );
}

#[test]
fn control_replay_is_caught_by_aead_layer() {
    // 控制面重放由 AEAD session 序号纪律拒绝（PAD 层无需自带窗口）
    let (mut client, mut server) = control_pair();
    let msg = PadControl::PadAck { bundle_id: 3 };
    let record = client.seal(MessageType::Data, &msg.encode()).unwrap();
    let frame = encode(&Message::Data {
        epoch: otp_types::Epoch::new(0),
        seq: record.sequence,
        data: record.sealed().to_vec(),
    })
    .unwrap();
    let Message::Data { seq, data, .. } = decode(server.role(), &frame).unwrap() else {
        panic!()
    };
    assert!(server.open(MessageType::Data, seq, &data).is_ok());
    // 重放同一 AEAD record ⇒ SEQ_REPLAY，会话终止（fail-to-waste 归 session 层）
    assert!(matches!(
        server.open(MessageType::Data, seq, &data),
        Err(otp_session::SessionError::SequenceReplay)
    ));
    let _ = TAG_LEN;
}
