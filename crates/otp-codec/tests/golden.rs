//! WP-01 §6 golden vectors 全量测试（38 条：正 12 + 负 26）。
//!
//! - 正例：`decode` 成功、字段值与 §6 表一致、`encode(decode(x)) == x`
//!   （§3.1 规则 5），并核对方向约束（§2.3）。
//! - codec 层负例：断言**确定错误码**（§3.2 顺序锁定）。
//! - 标 [state]/[record] 的负例：codec 层**必须放行**（负例不得在 codec
//!   被拦截）；上层行为断言归 WP-10/11/14。
//!
//! 向量 hex 均为规格 v1.1 原文逐字节转写；开发期已用独立脚本
//! （evidence/wp05-verify-vectors.py）核对长度与变异位点一致性。

mod common;

use common::{BOOK_ID, CLIENT_NONCE, SERVER_NONCE, SESSION_NONCE, h};
use otp_codec::{
    ArbitrateResult, ErrorCode, FeatureFlags, Message, decode, decode_confirm_body, encode,
};
use otp_types::{
    BookId, ClientNonce, Epoch, Role, SegmentIndex, Sequence, ServerNonce, SessionNonce,
};

fn fid_book() -> BookId {
    let b = h(BOOK_ID);
    BookId::from_bytes(b.try_into().unwrap())
}
fn fid_client_nonce() -> ClientNonce {
    ClientNonce::from_bytes(h(CLIENT_NONCE).try_into().unwrap())
}
fn fid_server_nonce() -> ServerNonce {
    ServerNonce::from_bytes(h(SERVER_NONCE).try_into().unwrap())
}
fn fid_session_nonce() -> SessionNonce {
    SessionNonce::from_bytes(h(SESSION_NONCE).try_into().unwrap())
}

// ---------- §6.3 HELLO ----------

/// HELLO-POS-001（52B）。
#[test]
fn hello_pos_001() {
    let raw = h(
        "000200010000002c00112233445566778899aabbccddeeff101112131415161718191a1b1c1d1e1f000000000000000000000000",
    );
    assert_eq!(raw.len(), 52);
    let msg = decode(Role::Server, &raw).expect("C→S 消息由 server 解码");
    let Message::Hello {
        book_id,
        client_nonce,
        client_pointer,
        features,
    } = &msg
    else {
        panic!("expected Hello, got {msg:?}")
    };
    assert_eq!(*book_id, fid_book());
    assert_eq!(client_nonce, &fid_client_nonce());
    assert_eq!(*client_pointer, SegmentIndex::ZERO);
    assert_eq!(*features, FeatureFlags(0));
    // §3.1 规则 5：再编码恒等
    assert_eq!(encode(&msg).unwrap(), raw);
    // §2.3：方向不符 → 0x0306
    assert_eq!(decode(Role::Client, &raw), Err(ErrorCode::WRONG_DIRECTION));
}

// ---------- §6.4 ARBITRATE（正例覆盖全部 5 种 result）----------

#[test]
fn arbitrate_pos_all_results() {
    // (向量名, hex, result, server_pointer)
    let cases: &[(&str, &str, ArbitrateResult, u64)] = &[
        (
            "ARBITRATE-POS-001",
            "0002000200000019202122232425262728292a2b2c2d2e2f000000000000000000",
            ArbitrateResult::Ok,
            0,
        ),
        (
            "ARBITRATE-POS-002",
            "0002000200000019202122232425262728292a2b2c2d2e2f000000000000000501",
            ArbitrateResult::ServerAhead,
            5,
        ),
        (
            "ARBITRATE-POS-003",
            "0002000200000019202122232425262728292a2b2c2d2e2f000000000000000302",
            ArbitrateResult::Exhausted,
            3,
        ),
        (
            "ARBITRATE-POS-004",
            "0002000200000019202122232425262728292a2b2c2d2e2f000000000000000003",
            ArbitrateResult::BookMismatch,
            0,
        ),
        (
            "ARBITRATE-POS-005",
            "0002000200000019202122232425262728292a2b2c2d2e2f000000000000000204",
            ArbitrateResult::ClientAhead,
            2,
        ),
    ];
    for (name, hex, want_result, want_sp) in cases {
        let raw = h(hex);
        assert_eq!(raw.len(), 33, "{name}");
        let msg = decode(Role::Client, &raw).unwrap_or_else(|e| panic!("{name}: {e}"));
        let Message::Arbitrate {
            server_nonce,
            server_pointer,
            result,
        } = &msg
        else {
            panic!("{name}: expected Arbitrate, got {msg:?}")
        };
        assert_eq!(server_nonce, &fid_server_nonce(), "{name}");
        assert_eq!(result, want_result, "{name}");
        assert_eq!(server_pointer.get(), *want_sp, "{name}");
        assert_eq!(encode(&msg).unwrap(), raw, "{name} 再编码恒等");
        assert_eq!(
            decode(Role::Server, &raw),
            Err(ErrorCode::WRONG_DIRECTION),
            "{name} S→C 消息不由 server 解码"
        );
    }
}

// ---------- §6.5 ISSUE_REQUEST ----------

#[test]
fn issue_pos_001() {
    let raw = h(
        "00020003000000280000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
    );
    assert_eq!(raw.len(), 48);
    let msg = decode(Role::Server, &raw).expect("ISSUE 由 server 解码");
    let Message::IssueRequest {
        chosen_pointer,
        client_nonce,
        server_nonce,
    } = &msg
    else {
        panic!("expected IssueRequest, got {msg:?}")
    };
    assert_eq!(*chosen_pointer, SegmentIndex::ZERO);
    assert_eq!(client_nonce, &fid_client_nonce());
    assert_eq!(server_nonce, &fid_server_nonce());
    assert_eq!(encode(&msg).unwrap(), raw);
    assert_eq!(decode(Role::Client, &raw), Err(ErrorCode::WRONG_DIRECTION));
}

// ---------- §6.6 CONFIRM 内层 body ----------

#[test]
fn confirm_body_pos() {
    // (向量名, hex, direction 线上值, msg_type)
    let cases: &[(&str, &str, u8, u16)] = &[
        (
            "CONFIRM-BODY-POS-001",
            "000200112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f010000000000000000000000000004636c69656e742d636f6e6669726d",
            0x01,
            0x0004,
        ),
        (
            "CONFIRM-BODY-POS-002",
            "000200112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f0200000000000000000000000000057365727665722d636f6e6669726d",
            0x02,
            0x0005,
        ),
    ];
    for (name, hex, want_dir, want_mt) in cases {
        let raw = h(hex);
        assert_eq!(raw.len(), 87, "{name}");
        let body = decode_confirm_body(&raw).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(body.book_id, fid_book(), "{name}");
        assert_eq!(body.segment_index, SegmentIndex::ZERO, "{name}");
        assert_eq!(body.client_nonce, fid_client_nonce(), "{name}");
        assert_eq!(body.server_nonce, fid_server_nonce(), "{name}");
        assert_eq!(
            otp_codec::body_direction_wire(body.direction),
            *want_dir,
            "{name}"
        );
        assert_eq!(body.epoch, Epoch::new(0), "{name}");
        assert_eq!(body.seq, Sequence::ZERO, "{name}");
        assert_eq!(body.msg_type, *want_mt, "{name}");
        // label 对 codec 不透明：逐字节核对夹具值即可
        assert_eq!(&body.label, &raw[73..87], "{name}");
        assert_eq!(
            otp_codec::encode_confirm_body(&body).unwrap(),
            raw,
            "{name}"
        );
    }
}

// ---------- §6.6 CONFIRM 外层帧 ----------

#[test]
fn confirm_c2s_pos_001() {
    let raw = h(
        "000200040000008b000000000000000030303030303030303030303030303030000000000000000000000000695e7cc81339fc2f4b06f6b619afdbcffe0e3f40ceb1fc75453aa5393bfd8b1fc53af413a9e0b29e3f57cb0584c08eebe3d96d5aa34078184a14114e6f172f791fd260bac23a892d791349a4d4e9233beb6f16d059e4cb6b0437744ffbe65360b787bee49e7980",
    );
    assert_eq!(raw.len(), 147);
    let msg = decode(Role::Server, &raw).expect("CONFIRM_C2S 由 server 解码");
    let Message::ConfirmC2s {
        segment_index,
        session_nonce,
        epoch,
        seq,
        sealed,
    } = &msg
    else {
        panic!("expected ConfirmC2s, got {msg:?}")
    };
    assert_eq!(*segment_index, SegmentIndex::ZERO);
    assert_eq!(session_nonce, &fid_session_nonce());
    assert_eq!(*epoch, Epoch::new(0));
    assert_eq!(*seq, Sequence::ZERO);
    assert_eq!(
        sealed.as_slice(),
        &raw[44..147],
        "sealed = 帧尾 103B 不透明字节"
    );
    assert_eq!(encode(&msg).unwrap(), raw);
    assert_eq!(decode(Role::Client, &raw), Err(ErrorCode::WRONG_DIRECTION));
}

#[test]
fn confirm_s2c_pos_001() {
    let raw = h(
        "000200050000008b0000000000000000303030303030303030303030303030300000000000000000000000005355daa73436835bdc777c47861cc3453ed181caf8be66cfdfacb1cebf131df844de12fcb2e41a07e1259981a1f0f890dc556ff1bc52050861ffa54c184d9a2ad47903f6714aa8247b01b7446afc3c8d440cbf42a2d34002fe639321af7066c91ea6649cd7a96c",
    );
    assert_eq!(raw.len(), 147);
    let msg = decode(Role::Client, &raw).expect("CONFIRM_S2C 由 client 解码");
    let Message::ConfirmS2c {
        segment_index,
        session_nonce,
        epoch,
        seq,
        sealed,
    } = &msg
    else {
        panic!("expected ConfirmS2c, got {msg:?}")
    };
    assert_eq!(*segment_index, SegmentIndex::ZERO);
    assert_eq!(session_nonce, &fid_session_nonce());
    assert_eq!(*epoch, Epoch::new(0));
    assert_eq!(*seq, Sequence::ZERO);
    assert_eq!(sealed.as_slice(), &raw[44..147]);
    assert_eq!(encode(&msg).unwrap(), raw);
    assert_eq!(decode(Role::Server, &raw), Err(ErrorCode::WRONG_DIRECTION));
}

// ---------- §6.7 DATA ----------

#[test]
fn data_pos_001() {
    let raw = h(
        "000200060000003000000000000000000000000100000020213910b55e2698155901535bd6667a33091b6d2fc46bf7ad65c94fdc39f26483",
    );
    assert_eq!(raw.len(), 56);
    // DATA 双向：两个角色都必须解码成功（§2.2）
    for role in [Role::Client, Role::Server] {
        let msg = decode(role, &raw).expect("DATA 双向");
        let Message::Data { epoch, seq, data } = &msg else {
            panic!("expected Data, got {msg:?}")
        };
        assert_eq!(*epoch, Epoch::new(0));
        assert_eq!(
            *seq,
            Sequence::new(1),
            "§4.5：DATA 自 seq=1 起（record 层判定，codec 只透传）"
        );
        assert_eq!(data.as_slice(), &raw[24..56], "data = 密文16B‖tag16B");
        assert_eq!(encode(&msg).unwrap(), raw);
    }
}

// ---------- codec 层负例：确定错误码（§6.8 转换表第 2 行）----------

/// (向量名, hex, 解码角色, 期望错误码)
#[test]
fn codec_layer_negatives_exact_codes() {
    let cases: &[(&str, &str, Role, ErrorCode)] = &[
        // HELLO
        (
            "HELLO-NEG-001",
            "000300010000002c00112233445566778899aabbccddeeff101112131415161718191a1b1c1d1e1f000000000000000000000000",
            Role::Server,
            ErrorCode::BAD_VERSION,
        ),
        (
            "HELLO-NEG-002",
            "000200010000002c00112233445566778899aabbccddeeff101112131415161718191a1b1c1d1e1f0000000000000000000000",
            Role::Server,
            ErrorCode::FRAME_TRUNCATED,
        ),
        (
            "HELLO-NEG-003",
            "000200010000002d00112233445566778899aabbccddeeff101112131415161718191a1b1c1d1e1f000000000000000000000000",
            Role::Server,
            ErrorCode::BAD_LENGTH,
        ),
        (
            "HELLO-NEG-004",
            "000200010000002c00112233445566778899aabbccddeeff101112131415161718191a1b1c1d1e1f00000000000000000000000000",
            Role::Server,
            ErrorCode::TRAILING_BYTES,
        ),
        // ARBITRATE
        (
            "ARBITRATE-NEG-001",
            "0002000200000019202122232425262728292a2b2c2d2e2f000000000000000005",
            Role::Client,
            ErrorCode::BAD_ENUM,
        ),
        (
            "ARBITRATE-NEG-002",
            "0002000200000019202122232425262728292a2b2c2d2e2f0000000000000000",
            Role::Client,
            ErrorCode::FRAME_TRUNCATED,
        ),
        (
            "ARBITRATE-NEG-003",
            "0002000200000019202122232425262728292a2b2c2d2e2f000000000000000000",
            Role::Server,
            ErrorCode::WRONG_DIRECTION,
        ),
        (
            "ARBITRATE-NEG-004",
            "0002000200000019202122232425262728292a2b2c2d2e2f000000000000000103",
            Role::Client,
            ErrorCode::BAD_ENUM,
        ),
        // ISSUE_REQUEST
        (
            "ISSUE-NEG-002",
            "00020003000000270000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            Role::Server,
            ErrorCode::BAD_LENGTH,
        ),
        (
            "ISSUE-NEG-003",
            "00020003000000280000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e",
            Role::Server,
            ErrorCode::FRAME_TRUNCATED,
        ),
        // CONFIRM 外层
        (
            "CONFIRM_C2S-NEG-002",
            "000200040000008c000000000000000030303030303030303030303030303030000000000000000000000000695e7cc81339fc2f4b06f6b619afdbcffe0e3f40ceb1fc75453aa5393bfd8b1fc53af413a9e0b29e3f57cb0584c08eebe3d96d5aa34078184a14114e6f172f791fd260bac23a892d791349a4d4e9233beb6f16d059e4cb6b0437744ffbe65360b787bee49e7980",
            Role::Server,
            ErrorCode::BAD_LENGTH,
        ),
        (
            "CONFIRM_C2S-NEG-003",
            "000200040000008b000000000000000030303030303030303030303030303030000000000000000000000000695e7cc81339fc2f4b06f6b619afdbcffe0e3f40ceb1fc75453aa5393bfd8b1fc53af413a9e0b29e3f57cb0584c08eebe3d96d5aa34078184a14114e6f172f791fd260bac23a892d791349a4d4e9233beb6f16d059e4cb6b0437744ffbe65360b787bee49e79",
            Role::Server,
            ErrorCode::FRAME_TRUNCATED,
        ),
        (
            "CONFIRM_S2C-NEG-002",
            "000200050000008b0000000000000000303030303030303030303030303030300000000000000000000000005355daa73436835bdc777c47861cc3453ed181caf8be66cfdfacb1cebf131df844de12fcb2e41a07e1259981a1f0f890dc556ff1bc52050861ffa54c184d9a2ad47903f6714aa8247b01b7446afc3c8d440cbf42a2d34002fe639321af7066c91ea6649cd7a9",
            Role::Client,
            ErrorCode::FRAME_TRUNCATED,
        ),
        // DATA
        (
            "DATA-NEG-001",
            "000200060000003000000000000000000000000100000021213910b55e2698155901535bd6667a33091b6d2fc46bf7ad65c94fdc39f26483",
            Role::Server,
            ErrorCode::BAD_LENGTH,
        ),
        (
            "DATA-NEG-003",
            "000200060000003000000000000000000000000100000020213910b55e2698155901535bd6667a33091b6d2fc46bf7ad65c94fdc39f264",
            Role::Server,
            ErrorCode::FRAME_TRUNCATED,
        ),
    ];
    for (name, hex, role, want) in cases {
        assert_eq!(decode(*role, &h(hex)), Err(*want), "向量 {name}");
    }
    // 内层 body 负例（codec 层）：body≠87B → 0x0302
    assert_eq!(
        decode_confirm_body(&h(
            "000200112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f010000000000000000000000000004636c69656e742d636f6e666972"
        )),
        Err(ErrorCode::BAD_LENGTH),
        "向量 CONFIRM-BODY-NEG-003"
    );
}

// ---------- [state]/[record] 负例：codec 层必须放行（§6.8 转换表第 3 行）----------

#[test]
fn state_layer_negatives_pass_codec() {
    // ISSUE-NEG-001：chosen 0→1 —— codec Ok（chosen 任意 u64）；0x0307 归 state 层
    let raw = h(
        "00020003000000280000000000000001101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
    );
    let msg = decode(Role::Server, &raw).expect("ISSUE-NEG-001 codec 必须放行");
    let Message::IssueRequest { chosen_pointer, .. } = &msg else {
        panic!("expected IssueRequest")
    };
    assert_eq!(chosen_pointer.get(), 1);

    // CONFIRM-BODY-NEG-001：S2C body 的 direction 02→01 —— 枚举仍合法，codec Ok
    let raw = h(
        "000200112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f0100000000000000000000000000057365727665722d636f6e6669726d",
    );
    let body = decode_confirm_body(&raw).expect("CONFIRM-BODY-NEG-001 codec 必须放行");
    assert_eq!(otp_codec::body_direction_wire(body.direction), 0x01);
    assert_eq!(
        body.msg_type, 0x0005,
        "msg_type/label/direction 交叉不一致归 state 层"
    );

    // CONFIRM-BODY-NEG-002：label 末字符 6D→6E —— label 不透明，codec Ok
    let raw = h(
        "000200112233445566778899aabbccddeeff0000000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f010000000000000000000000000004636c69656e742d636f6e6669726e",
    );
    let body = decode_confirm_body(&raw).expect("CONFIRM-BODY-NEG-002 codec 必须放行");
    assert_eq!(body.label[13], 0x6E);

    // CONFIRM_C2S-NEG-001：tag 末位 80→81 —— sealed 不透明，codec Ok；0x0201 归 record 层
    let raw = h(
        "000200040000008b000000000000000030303030303030303030303030303030000000000000000000000000695e7cc81339fc2f4b06f6b619afdbcffe0e3f40ceb1fc75453aa5393bfd8b1fc53af413a9e0b29e3f57cb0584c08eebe3d96d5aa34078184a14114e6f172f791fd260bac23a892d791349a4d4e9233beb6f16d059e4cb6b0437744ffbe65360b787bee49e7981",
    );
    let msg = decode(Role::Server, &raw).expect("CONFIRM_C2S-NEG-001 codec 必须放行");
    let Message::ConfirmC2s { sealed, .. } = &msg else {
        panic!("expected ConfirmC2s")
    };
    assert_eq!(sealed[102], 0x81, "被篡改的 tag 字节原样透传给 record 层");

    // CONFIRM_C2S-NEG-004：session_nonce 首字节 30→31 —— codec Ok；0x0203 归 state 层
    let raw = h(
        "000200040000008b000000000000000031303030303030303030303030303030000000000000000000000000695e7cc81339fc2f4b06f6b619afdbcffe0e3f40ceb1fc75453aa5393bfd8b1fc53af413a9e0b29e3f57cb0584c08eebe3d96d5aa34078184a14114e6f172f791fd260bac23a892d791349a4d4e9233beb6f16d059e4cb6b0437744ffbe65360b787bee49e7980",
    );
    let msg = decode(Role::Server, &raw).expect("CONFIRM_C2S-NEG-004 codec 必须放行");
    let Message::ConfirmC2s { session_nonce, .. } = &msg else {
        panic!("expected ConfirmC2s")
    };
    assert_eq!(session_nonce.as_bytes()[0], 0x31);

    // CONFIRM_C2S-NEG-005：epoch 低字节 00→01 —— codec Ok（epoch 任意 u32）；0x030A 归 state 层
    let raw = h(
        "000200040000008b000000000000000030303030303030303030303030303030000000010000000000000000695e7cc81339fc2f4b06f6b619afdbcffe0e3f40ceb1fc75453aa5393bfd8b1fc53af413a9e0b29e3f57cb0584c08eebe3d96d5aa34078184a14114e6f172f791fd260bac23a892d791349a4d4e9233beb6f16d059e4cb6b0437744ffbe65360b787bee49e7980",
    );
    let msg = decode(Role::Server, &raw).expect("CONFIRM_C2S-NEG-005 codec 必须放行");
    let Message::ConfirmC2s { epoch, .. } = &msg else {
        panic!("expected ConfirmC2s")
    };
    assert_eq!(*epoch, Epoch::new(1));

    // CONFIRM_S2C-NEG-001：tag 末位 6C→6D —— codec Ok；0x0201 归 record 层
    let raw = h(
        "000200050000008b0000000000000000303030303030303030303030303030300000000000000000000000005355daa73436835bdc777c47861cc3453ed181caf8be66cfdfacb1cebf131df844de12fcb2e41a07e1259981a1f0f890dc556ff1bc52050861ffa54c184d9a2ad47903f6714aa8247b01b7446afc3c8d440cbf42a2d34002fe639321af7066c91ea6649cd7a96d",
    );
    assert!(matches!(
        decode(Role::Client, &raw),
        Ok(Message::ConfirmS2c { .. })
    ));

    // DATA-NEG-002：密文首字节 21→20 —— data 不透明，codec Ok；0x0201 归 record 层
    let raw = h(
        "000200060000003000000000000000000000000100000020203910b55e2698155901535bd6667a33091b6d2fc46bf7ad65c94fdc39f26483",
    );
    let msg = decode(Role::Server, &raw).expect("DATA-NEG-002 codec 必须放行");
    let Message::Data { data, .. } = &msg else {
        panic!("expected Data")
    };
    assert_eq!(data[0], 0x20);

    // DATA-NEG-004：seq 低字节 01→05 —— codec Ok（seq 任意 u64）；0x030B 归 record 层
    let raw = h(
        "000200060000003000000000000000000000000500000020213910b55e2698155901535bd6667a33091b6d2fc46bf7ad65c94fdc39f26483",
    );
    let msg = decode(Role::Server, &raw).expect("DATA-NEG-004 codec 必须放行");
    let Message::Data { seq, .. } = &msg else {
        panic!("expected Data")
    };
    assert_eq!(*seq, Sequence::new(5));

    // DATA-NEG-005：原样重发（重放）—— codec 每次都能解码；0x0204 归 record 层
    let raw = h(
        "000200060000003000000000000000000000000100000020213910b55e2698155901535bd6667a33091b6d2fc46bf7ad65c94fdc39f26483",
    );
    let first = decode(Role::Server, &raw).expect("首次接收");
    let second = decode(Role::Server, &raw).expect("重放同一字节串 codec 同样放行");
    assert_eq!(first, second);
}
