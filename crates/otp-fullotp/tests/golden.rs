//! Golden vectors：OTP_DATA 线格式 + 一次性 Poly1305（任务 #75 验收 1）。
//!
//! 冻结口径：
//! - bundle 夹具：`flat[i] = (i*31+17) & 0xFF`（8192B；C2S 半区 = flat[0..4096]，
//!   S2C 半区 = flat[4096..8192]）；
//! - 向量值由本仓实现产出后**冻结为常量**；测试同时做三重独立校验：
//!   ① 逐字节头布局（§3.1 表）；
//!   ② `ciphertext == plaintext ⊕ pad[cursor+32 .. cursor+32+L]`（§2.1）；
//!   ③ `tag == Poly1305(pad[cursor..cursor+32], DOMSEP‖BE16(25)‖header‖ct)`
//!   （header 与 MAC 输入在测试内按规格表独立拼装，不复用生产代码路径）；
//! - RFC 8439 §2.5.2 KAT 先行钉死"独立一次性 key API = 标准 Poly1305"
//!   （设计书 §5.2 限制条款：必须使用经审计、支持独立 one-time key 的 API）。

use otp_fullotp::{
    DOMAIN_SEPARATOR, MODE_FULL_OTP_POLY1305, MSG_TYPE_OTP_DATA, OTP_VERSION, decode_control,
    seal_record, split_bundle,
};
use otp_types::Direction;
use poly1305::Key;
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit;

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .flat_map(|p| {
            (0..p.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&p[i..i + 2], 16).unwrap())
        })
        .collect()
}

fn golden_bundle_flat() -> [u8; 8192] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(17))
}

/// 测试内独立拼装的 canonical header（§3.1 表逐字段，不复用生产实现）。
fn header_manual(
    direction: u8,
    bundle_id: u64,
    base_segment: u64,
    record_seq: u64,
    pad_offset: u16,
    ct_len: u16,
) -> [u8; 34] {
    let mut h = [0u8; 34];
    h[0..2].copy_from_slice(&OTP_VERSION.to_be_bytes());
    h[2..4].copy_from_slice(&MSG_TYPE_OTP_DATA.to_be_bytes());
    h[4] = MODE_FULL_OTP_POLY1305;
    h[5] = direction;
    h[6..14].copy_from_slice(&bundle_id.to_be_bytes());
    h[14..22].copy_from_slice(&base_segment.to_be_bytes());
    h[22..30].copy_from_slice(&record_seq.to_be_bytes());
    h[30..32].copy_from_slice(&pad_offset.to_be_bytes());
    h[32..34].copy_from_slice(&ct_len.to_be_bytes());
    h
}

/// 独立重算一次性 Poly1305 tag（MAC 输入按 crate 文档冻结布局手工拼装）。
fn tag_manual(key: &[u8; 32], header: &[u8; 34], ct: &[u8]) -> [u8; 16] {
    let mut input = Vec::with_capacity(DOMAIN_SEPARATOR.len() + 2 + 34 + ct.len());
    input.extend_from_slice(DOMAIN_SEPARATOR);
    input.extend_from_slice(&25u16.to_be_bytes());
    input.extend_from_slice(header);
    input.extend_from_slice(ct);
    let tag = Poly1305::new(Key::from_slice(key)).compute_unpadded(&input);
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_slice());
    out
}

#[test]
fn rfc8439_poly1305_kat_pins_the_one_time_key_api() {
    // RFC 8439 §2.5.2：key/tag 固定向量（证明 clamp/padding 语义 = 标准 Poly1305）
    let key: [u8; 32] = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ];
    let tag = Poly1305::new(Key::from_slice(&key))
        .compute_unpadded(b"Cryptographic Forum Research Group");
    let mut got = [0u8; 16];
    got.copy_from_slice(tag.as_slice());
    assert_eq!(
        got,
        [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9
        ]
    );
}

/// 冻结向量的公共三重校验参数。
struct VectorCase<'a> {
    wire_hex: &'a str,
    dir_wire: u8,
    bundle_id: u64,
    base_segment: u64,
    record_seq: u64,
    pad_offset: u16,
    /// 该方向的 4096B pad 流（原始未消费状态）。
    half: &'a [u8],
    plaintext: &'a [u8],
}

/// 冻结向量的公共三重校验：整帧冻结字节 + 头布局 + XOR/OTP + 独立 tag。
fn check_vector(case: &VectorCase) {
    let VectorCase {
        wire_hex,
        dir_wire,
        bundle_id,
        base_segment,
        record_seq,
        pad_offset,
        half,
        plaintext,
    } = case;
    let direction = if *dir_wire == 0x01 {
        Direction::ClientToServer
    } else {
        Direction::ServerToClient
    };
    let (dir_wire, bundle_id, base_segment, record_seq, pad_offset) = (
        *dir_wire,
        *bundle_id,
        *base_segment,
        *record_seq,
        *pad_offset,
    );
    let want = hex(wire_hex);
    let flat = rebuild_flat(dir_wire, half);
    let sender = &mut send_stream(dir_wire, bundle_id, base_segment, flat);
    let rec = seal_record(sender, direction, record_seq, plaintext).unwrap();
    let got = rec.encode();
    assert_eq!(got, want, "整帧字节不符（冻结向量）");
    // 头布局逐字段
    assert_eq!(&got[0..2], &OTP_VERSION.to_be_bytes());
    assert_eq!(&got[2..4], &MSG_TYPE_OTP_DATA.to_be_bytes());
    assert_eq!(got[4], MODE_FULL_OTP_POLY1305);
    assert_eq!(got[5], dir_wire);
    assert_eq!(&got[6..14], &bundle_id.to_be_bytes());
    assert_eq!(&got[14..22], &base_segment.to_be_bytes());
    assert_eq!(&got[22..30], &record_seq.to_be_bytes());
    let l = plaintext.len();
    assert_eq!(&got[32..34], &(l as u16).to_be_bytes());
    assert_eq!(got.len(), 34 + l + 16);
    // 独立校验 ②：密文 = 明文 ⊕ pad[cursor+32 .. cursor+32+l]
    let cursor = pad_offset as usize;
    let ct = &got[34..34 + l];
    for i in 0..l {
        assert_eq!(
            ct[i],
            plaintext[i] ^ half[cursor + 32 + i],
            "密文第 {i} 字节与 OTP XOR 不符"
        );
    }
    // 独立校验 ③：tag = Poly1305(pad[cursor..cursor+32), DOMSEP‖len‖header‖ct)
    let key: [u8; 32] = half[cursor..cursor + 32].try_into().unwrap();
    let header: [u8; 34] = got[..34].try_into().unwrap();
    assert_eq!(
        &header_manual(
            dir_wire,
            bundle_id,
            base_segment,
            record_seq,
            pad_offset,
            l as u16
        ),
        &header[..]
    );
    let tag_wire: [u8; 16] = got[got.len() - 16..].try_into().unwrap();
    assert_eq!(
        tag_wire,
        tag_manual(&key, &header, ct),
        "一次性 Poly1305 tag 不符"
    );
}

/// 由半区还原完整 bundle 平面（另一方向内容与本向量无关，补零）。
fn rebuild_flat(dir_wire: u8, half: &[u8]) -> [u8; 8192] {
    let mut flat = [0u8; 8192];
    let off = if dir_wire == 0x01 { 0usize } else { 4096 };
    flat[off..off + 4096].copy_from_slice(half);
    flat
}

/// 构造该方向的发送流（半区基址：C2S = base，S2C = base+64）。
fn send_stream(
    dir_wire: u8,
    bundle_id: u64,
    base_segment: u64,
    flat: [u8; 8192],
) -> otp_fullotp::PadStream {
    let (c2s, s2c) = split_bundle(bundle_id, base_segment, flat);
    match dir_wire {
        0x01 => c2s,
        _ => s2c,
    }
}

#[test]
fn golden_v1_minimal_record_c2s_fresh_bundle() {
    // 1B 记录：消耗 33B（32B key + 1B pad），§2.1 示例"1 个字符立即发送消耗 33B"
    check_vector(&VectorCase {
        wire_hex: "00030010 01 01 0000000000000000 0000000000000001 \
                   0000000000000000 0000 0001 bb \
                   19cbcfff1bfa388e510b764fbe7868be",
        dir_wire: 0x01,
        bundle_id: 0,
        base_segment: 1,
        record_seq: 0,
        pad_offset: 0,
        half: &golden_bundle_flat()[..4096],
        plaintext: b"J",
    });
}

#[test]
fn golden_v2_mid_bundle_record_s2c() {
    // S2C 半区、bundle 2、base=321、seq=7、offset=33（前一条 1B 记录已耗 33B）、L=100
    let pt: Vec<u8> = (0..100u32).map(|i| (i * 7 + 5) as u8).collect();
    let wire = hex(
        "00030010 01 02 0000000000000002 0000000000000141 0000000000000007 0021 0064 f5033d574da385ffd5436d173de3c5af95839db7cde3051f7543adf79da3456f3503fdd74d6385bfd5c32d177d23c5ef95839d774d23051f35436db79de3c52f75033dd7cda3857f55c3ed173d6345af95839db74d63051ff5c3ad779da3c5ef35037d57 5949f18bc46426f492513fc4d55fbd1f",
    );
    // 先按冻结前导消耗一条 1B 记录（seq=6, offset=0），再校验目标向量
    let flat = golden_bundle_flat();
    let (_, mut s2c) = split_bundle(2, 257, flat);
    let _lead = otp_fullotp::seal_record(&mut s2c, Direction::ServerToClient, 6, b"K").unwrap();
    let rec = otp_fullotp::seal_record(&mut s2c, Direction::ServerToClient, 7, &pt).unwrap();
    assert_eq!(rec.encode(), wire);
    // 独立三重校验（直接以本向量口径）
    let half = &flat[4096..];
    let header: [u8; 34] = wire[..34].try_into().unwrap();
    let ct = &wire[34..134];
    for i in 0..100 {
        assert_eq!(ct[i], pt[i] ^ half[33 + 32 + i]);
    }
    let key: [u8; 32] = half[33..65].try_into().unwrap();
    let tag: [u8; 16] = wire[wire.len() - 16..].try_into().unwrap();
    assert_eq!(tag, tag_manual(&key, &header, ct));
}

#[test]
fn golden_v3_full_bundle_filling_record() {
    // L=4064 恰耗尽方向流（32+4064=4096；§2.1"4064B 满记录消耗 4096B"）
    let pt: Vec<u8> = (0..4064u32).map(|i| (i * 11 + 3) as u8).collect();
    let flat = golden_bundle_flat();
    let (mut c2s, _) = split_bundle(0, 128, flat);
    let rec = seal_record(&mut c2s, Direction::ClientToServer, 0, &pt).unwrap();
    let wire = rec.encode();
    assert_eq!(wire.len(), 4114);
    // 独立校验
    let half = &flat[..4096];
    let header: [u8; 34] = wire[..34].try_into().unwrap();
    let ct = &wire[34..34 + 4064];
    for i in 0..4064 {
        assert_eq!(ct[i], pt[i] ^ half[32 + i]);
    }
    let key: [u8; 32] = half[..32].try_into().unwrap();
    let tag: [u8; 16] = wire[wire.len() - 16..].try_into().unwrap();
    assert_eq!(tag, tag_manual(&key, &header, ct));
    assert_eq!(header_manual(0x01, 0, 128, 0, 0, 4064), header);
}

#[test]
fn frozen_control_payloads_roundtrip() {
    // PAD 控制面 payload 冻结字节（防未来无意改动）
    use otp_fullotp::PadControl;
    assert_eq!(
        PadControl::PadOffer {
            bundle_id: 1,
            base_segment: 256
        }
        .encode(),
        vec![0x01, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0]
    );
    assert_eq!(
        decode_control(&[0x02, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap(),
        PadControl::PadAck { bundle_id: 1 }
    );
    assert_eq!(decode_control(&[0x03]).unwrap(), PadControl::PadNeed);
    assert_eq!(decode_control(&[0x04]).unwrap(), PadControl::Close);
}
