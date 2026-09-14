//! OTP_DATA 记录封装/解封：一次性 Poly1305 认证 + OTP XOR（设计书 §3/§5.2）。
//!
//! - [`seal_record`]：发送侧。按 §2.1 切出 `32B key ‖ L B pad`（原位清零，
//!   用后即弃），`C = P ⊕ Q`，`tag = Poly1305(key, MAC_INPUT)`。游标推进
//!   在记录构造前完成（§3.2 原子消费规则：传输短写/取消/崩溃不重试这些
//!   字节——重发同一 wire record 即重放歧义，协议禁止应用层重发）。
//! - [`open_record`]：接收侧。判定顺序严格按 §3.2：格式/长度界限 → 方向与
//!   bundle → `seq` → `offset==cursor` → 取一次性 key 验 tag（常量时间）→
//!   验证成功后 XOR 一次性交付完整明文 → 推进 cursor。任何失败不输出任何
//!   明文，调用方必须立即关闭并浪费当前+预取 bundle 尾部。
//!
//! Poly1305 路径（§5.2 限制条款）：RustCrypto `poly1305` 独立一次性 key API
//! （NCC Group 审计实现；clamp 在 `KeyInit::new` 内部，非密钥派生）；一次性
//! key 直接取 pad 32B，无 KDF/哈希/跨记录/跨方向复用；与现有
//! ChaCha20-Poly1305 AEAD **不是同一 key 或同一构造**。MAC 输入为带长度域
//! 分隔的定序拼接（见 crate 文档），`compute_unpadded` 即 RFC 8439 §2.5
//! 标准 Poly1305（KAT 见 `tests/golden.rs`）。

use otp_types::{Direction, TAG_LEN};
use poly1305::Key;
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit;
use zeroize::Zeroizing;

use crate::error::OtpError;
use crate::pad::PadStream;
use crate::wire::{self, OtpDataRecord};

/// 解密后的明文载荷：Drop 清零（§9.1.8 类型义务），只能经
/// [`OtpPayload::as_bytes`] 读取；MAC 成功前绝不构造本类型。
#[derive(zeroize::ZeroizeOnDrop)]
pub struct OtpPayload(Vec<u8>);

impl OtpPayload {
    /// 明文字节视图（存活期间由调用方负责不落日志）。
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for OtpPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 明文整 body 均为禁止日志面（§5.3），只打印长度
        write!(f, "OtpPayload({}B redacted)", self.0.len())
    }
}

/// 组装一次性 Poly1305 的 MAC 输入（crate 文档冻结布局）：
/// `DOMAIN_SEP ‖ BE16(len(DOMAIN_SEP)) ‖ canonical_header ‖ ciphertext`。
///
/// 缓冲只含公开字节（域分隔/头/密文），无 pad/key/明文。
fn mac_input(header: &[u8; wire::HEADER_LEN], ciphertext: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut buf = Zeroizing::new(Vec::with_capacity(
        crate::DOMAIN_SEPARATOR.len() + 2 + wire::HEADER_LEN + ciphertext.len(),
    ));
    buf.extend_from_slice(crate::DOMAIN_SEPARATOR);
    buf.extend_from_slice(&(crate::DOMAIN_SEPARATOR.len() as u16).to_be_bytes());
    buf.extend_from_slice(header);
    buf.extend_from_slice(ciphertext);
    buf
}

/// 常量时间 16B 比较（无 subtle 直接依赖；逐字节 OR 折叠，无短路分支）。
fn ct_eq_16(a: &[u8; TAG_LEN], b: &[u8; TAG_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..TAG_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// 封装一条 OTP_DATA 记录（发送侧）。
///
/// - `stream`：本端发送方向的当前 pad 流（记录不跨 bundle：`l <=
///   stream.max_record_len()` 由调用方保证，内部仍防御性判定）；
/// - `record_seq`：本方向严格 +1 的记录序号（调用方分配）。
///
/// 游标推进发生在记录构造前（§3.2）；一次性 key 用后即弃（类型 Drop 清零，
/// 源区已原位清零）。
///
/// # Errors
/// - [`OtpError::DoesNotFit`]：明文放不进当前 bundle（调用方应缩短 L、切换
///   bundle 或背压，见 [`crate::pump`]）；
/// - [`OtpError::Closed`] 等不会在此出现（会话状态归 pump）。
pub fn seal_record(
    stream: &mut PadStream,
    direction: Direction,
    record_seq: u64,
    plaintext: &[u8],
) -> Result<OtpDataRecord, OtpError> {
    let l = plaintext.len();
    if l == 0 {
        return Err(OtpError::DoesNotFit); // §3.1：ciphertext_len ∈ 1..=4064
    }
    if !stream.fits(l) {
        return Err(OtpError::DoesNotFit);
    }
    let bundle_id = stream.bundle_id();
    let base_segment = stream.base_segment();
    let pad_offset = stream.consumed().min(u16::MAX as usize) as u16;

    // §3.2：构造记录前即标记已消费（切材料 + 推进；此后绝不重试这些字节）
    let key = stream.take_mac_key();
    let mut ciphertext = Zeroizing::new(plaintext.to_vec());
    stream.xor_burn_pad(&mut ciphertext);
    stream.advance(l);

    let header = wire::canonical_header(
        direction,
        bundle_id,
        base_segment,
        record_seq,
        pad_offset,
        l,
    );
    let computed = Poly1305::new(Key::from_slice(key.as_array()))
        .compute_unpadded(&mac_input(&header, &ciphertext));
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(computed.as_slice());

    Ok(OtpDataRecord {
        direction,
        bundle_id,
        base_segment,
        record_seq,
        pad_offset,
        ciphertext: ciphertext.to_vec(),
        tag,
    })
}

/// 接收侧期望上下文（由 pump 从会话状态导出）。
#[derive(Clone, Copy, Debug)]
pub struct OpenExpectation {
    /// 本端接收流方向（记录 direction 必须与之相符，否则跨方向搬运）。
    pub direction: Direction,
    /// 当前 bundle 分配序号。
    pub bundle_id: u64,
    /// 当前 bundle 公开基址。
    pub base_segment: u64,
    /// 本方向下一期望 record_seq。
    pub record_seq: u64,
}

/// 解封并验证一条 OTP_DATA 记录（接收侧，判定顺序冻结于 §3.2）。
///
/// 任何 [`Err`] ⇒ 调用方必须立即关闭会话并浪费全部 bundle 尾部；本函数
/// 绝不返回部分明文。tag 验证成功前不构造 [`OtpPayload`]、不推进游标。
///
/// # Errors
/// 按 §3.2 顺序：[`OtpError::Wire`]（格式/长度）→ [`OtpError::Direction`] →
/// [`OtpError::Bundle`] → [`OtpError::Replay`]/[`OtpError::Gap`] →
/// [`OtpError::Offset`] → [`OtpError::Tag`]。
pub fn open_record(
    stream: &mut PadStream,
    expect: &OpenExpectation,
    frame: &[u8],
) -> Result<OtpPayload, OtpError> {
    // 1. 格式/长度界限
    let rec = wire::decode(frame)?;
    // 2. 方向与 bundle（MAC 亦绑定方向，此处先做结构前置判；tag 终判）
    if rec.direction != expect.direction {
        return Err(OtpError::Direction);
    }
    if rec.bundle_id != expect.bundle_id || rec.base_segment != expect.base_segment {
        return Err(OtpError::Bundle);
    }
    // 3. seq（接收窗口恒为 1，§6）
    if rec.record_seq < expect.record_seq {
        return Err(OtpError::Replay);
    }
    if rec.record_seq > expect.record_seq {
        return Err(OtpError::Gap);
    }
    // 4. offset == cursor
    if usize::from(rec.pad_offset) != stream.consumed() {
        return Err(OtpError::Offset);
    }
    let l = rec.ciphertext.len();
    if !stream.fits(l) {
        return Err(OtpError::Offset); // offset 已等于 cursor 但剩余不足 ⇒ 结构矛盾
    }
    // 5. 取一次性 key（源区清零；cursor 不动——验证成功才推进，§3.2）
    let key = stream.take_mac_key();
    let header = wire::canonical_header(
        rec.direction,
        rec.bundle_id,
        rec.base_segment,
        rec.record_seq,
        rec.pad_offset,
        l,
    );
    // tag 终判使用线上字节重组的 header（字段已逐一校验相等）
    let computed_tag = Poly1305::new(Key::from_slice(key.as_array()))
        .compute_unpadded(&mac_input(&header, &rec.ciphertext));
    let mut computed = [0u8; TAG_LEN];
    computed.copy_from_slice(computed_tag.as_slice());
    if !ct_eq_16(&computed, &rec.tag) {
        return Err(OtpError::Tag);
    }
    // 6. 验证成功：XOR 一次性交付完整明文，推进 cursor
    let mut plaintext = Zeroizing::new(rec.ciphertext.clone());
    stream.xor_burn_pad(&mut plaintext);
    stream.advance(l);
    Ok(OtpPayload(plaintext.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pad::split_bundle;

    fn streams() -> (PadStream, PadStream) {
        let mut flat = [0u8; crate::pad::BUNDLE_BYTES];
        for (i, b) in flat.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(17);
        }
        split_bundle(0, 1, flat)
    }

    /// 同一方向的两份相同材料（两端共享密码本：接收方持有同方向半区的副本）。
    fn pair_for(dir: Direction) -> (PadStream, PadStream) {
        let (c1, s1) = streams();
        let (c2, s2) = streams();
        match dir {
            Direction::ClientToServer => (c1, c2),
            Direction::ServerToClient => (s1, s2),
        }
    }

    #[test]
    fn seal_open_roundtrip_both_directions() {
        for (dir, seq) in [
            (Direction::ClientToServer, 0u64),
            (Direction::ServerToClient, 41),
        ] {
            let (mut sender, mut receiver) = pair_for(dir);
            let base = receiver.base_segment();
            let pt = b"hello full-otp".to_vec();
            let rec = seal_record(&mut sender, dir, seq, &pt).unwrap();
            let expect = OpenExpectation {
                direction: dir,
                bundle_id: 0,
                base_segment: base,
                record_seq: seq,
            };
            let out = open_record(&mut receiver, &expect, &rec.encode()).unwrap();
            assert_eq!(out.as_bytes(), &pt[..]);
            assert_eq!(sender.consumed(), receiver.consumed());
        }
    }

    #[test]
    fn any_tamper_is_rejected_without_output() {
        let dir = Direction::ClientToServer;
        let (mut sender, _) = pair_for(dir);
        let rec = seal_record(&mut sender, dir, 0, &[0x42u8; 77]).unwrap();
        let frame = rec.encode();
        let expect = |seq: u64| OpenExpectation {
            direction: dir,
            bundle_id: 0,
            base_segment: 1,
            record_seq: seq,
        };
        // 每个用例用全新接收方（避免游标污染交叉断言）
        let mut t = frame.clone();
        t[40] ^= 0x01; // 密文翻一位
        assert!(matches!(
            open_record(&mut pair_for(dir).1, &expect(0), &t),
            Err(OtpError::Tag)
        ));
        let mut t = frame.clone();
        let n = t.len();
        t[n - 1] ^= 0x80; // tag 翻一位
        assert!(matches!(
            open_record(&mut pair_for(dir).1, &expect(0), &t),
            Err(OtpError::Tag)
        ));
        let mut t = frame.clone();
        t[13] ^= 0x01; // bundle_id
        assert!(matches!(
            open_record(&mut pair_for(dir).1, &expect(0), &t),
            Err(OtpError::Bundle)
        ));
        let mut t = frame.clone();
        t[21] ^= 0x01; // base_segment
        assert!(matches!(
            open_record(&mut pair_for(dir).1, &expect(0), &t),
            Err(OtpError::Bundle)
        ));
        let mut t = frame.clone();
        t[5] = 0x02; // direction 改 S2C
        assert!(matches!(
            open_record(&mut pair_for(dir).1, &expect(0), &t),
            Err(OtpError::Direction)
        ));
        // seq 跳号 → Gap；回退 → Replay；offset 不符 → Offset（均在 tag 判定前）
        let mut t = frame.clone();
        t[29] = 0x02; // record_seq=2 > 期望 0
        assert!(matches!(
            open_record(&mut pair_for(dir).1, &expect(0), &t),
            Err(OtpError::Gap)
        ));
        assert!(matches!(
            open_record(&mut pair_for(dir).1, &expect(5), &frame),
            Err(OtpError::Replay)
        ));
        let mut t = frame.clone();
        t[31] = 0x01; // pad_offset=1 ≠ cursor=0
        assert!(matches!(
            open_record(&mut pair_for(dir).1, &expect(0), &t),
            Err(OtpError::Offset)
        ));
        // 截断
        assert!(matches!(
            open_record(&mut pair_for(dir).1, &expect(0), &frame[..frame.len() - 1]),
            Err(OtpError::Wire(_))
        ));
    }

    #[test]
    fn wrong_direction_or_empty_plaintext_rejected() {
        let (mut sender, _) = streams();
        assert!(matches!(
            seal_record(&mut sender, Direction::ClientToServer, 0, b""),
            Err(OtpError::DoesNotFit)
        ));
        let rec = seal_record(&mut sender, Direction::ClientToServer, 0, b"x").unwrap();
        let wrong_dir = OpenExpectation {
            direction: Direction::ServerToClient,
            bundle_id: 0,
            base_segment: 1,
            record_seq: 0,
        };
        assert!(matches!(
            open_record(
                &mut pair_for(Direction::ServerToClient).1,
                &wrong_dir,
                &rec.encode()
            ),
            Err(OtpError::Direction)
        ));
    }

    #[test]
    fn consumed_material_never_reusable() {
        // 同序号同明文再封一条：游标已推进 ⇒ pad 不同 ⇒ 密文不同
        let (mut sender, _) = streams();
        let r1 = seal_record(&mut sender, Direction::ClientToServer, 0, b"A").unwrap();
        let r2 = seal_record(&mut sender, Direction::ClientToServer, 1, b"A").unwrap();
        assert_ne!(r1.ciphertext, r2.ciphertext);
        assert_ne!(r1.tag, r2.tag);
        assert_eq!(r1.pad_offset, 0);
        assert_eq!(r2.pad_offset, 33);
    }
}
