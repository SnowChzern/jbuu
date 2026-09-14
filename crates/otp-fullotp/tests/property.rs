//! 性质测试（fullotp-design §10"性质测试"项的批 1+批 2 子集）：
//! 1. 任意合法记录长度序列：消费切片严格相邻不重叠（§9.1.1），记账
//!    `consumed == 32*records + sum(L)` 恒成立，收发两侧逐步相等；
//! 2. 任意单字节篡改（均匀覆盖头/密文/tag）⇒ 必被拒绝、零明文、
//!    接收游标零推进（§3.2/§6：MAC 成功前不输出任何明文）；
//! 3. 任意结构合法记录 encode/decode 无损往返（canonical）。

use otp_fullotp::{
    OpenExpectation, OtpDataRecord, PAD_HALF, decode_frame, open_record, seal_record, split_bundle,
};
use otp_types::Direction;
use proptest::prelude::*;

fn flat_of(seed: u64) -> [u8; 8192] {
    core::array::from_fn(|i| ((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ seed) as u8)
}

fn expect(seq: u64) -> OpenExpectation {
    OpenExpectation {
        direction: Direction::ClientToServer,
        bundle_id: 0,
        base_segment: 1,
        record_seq: seq,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// 性质 1：任意长度序列的切片纪律与记账闭合（§2.1/§9.1.1）。
    #[test]
    fn record_sequences_never_overlap_and_account(
        lens in prop::collection::vec(1usize..=4064, 0..24),
        seed in any::<u64>(),
    ) {
        let flat = flat_of(seed);
        let (mut sender, mut receiver) = {
            let (a, _) = split_bundle(0, 1, flat);
            let (b, _) = split_bundle(0, 1, flat);
            (a, b)
        };
        let mut sum_l = 0usize;
        let mut records = 0usize;
        for (i, &l) in lens.iter().enumerate() {
            // 放不下即止（记录不跨 bundle 是硬约束；后续长度留给下一 bundle）
            if !sender.fits(l) {
                break;
            }
            let pt: Vec<u8> = (0..l)
                .map(|j| (j as u8).wrapping_mul(13).wrapping_add(i as u8))
                .collect();
            let rec = seal_record(&mut sender, Direction::ClientToServer, i as u64, &pt)
                .unwrap();
            // pad_offset 必须等于已消费量（切片严格相邻 ⇒ 不重叠不复用）
            prop_assert_eq!(rec.pad_offset as usize, 32 * records + sum_l);
            sum_l += l;
            records += 1;
            prop_assert_eq!(sender.consumed(), 32 * records + sum_l);
            let got = open_record(&mut receiver, &expect(i as u64), &rec.encode()).unwrap();
            prop_assert_eq!(got.as_bytes(), &pt[..]);
            prop_assert_eq!(receiver.consumed(), sender.consumed());
        }
        prop_assert!(sender.consumed() <= PAD_HALF);
    }

    /// 性质 2：任意单字节篡改 ⇒ 拒绝且零明文、零游标推进（§3.2/§6）。
    #[test]
    fn any_single_byte_flip_yields_no_plaintext(
        l in 1usize..=4064,
        seed in any::<u64>(),
    ) {
        let flat = flat_of(seed);
        let (mut sender, mut receiver) = {
            let (a, _) = split_bundle(0, 1, flat);
            let (b, _) = split_bundle(0, 1, flat);
            (a, b)
        };
        let pt: Vec<u8> = (0..l).map(|j| (j as u8).wrapping_mul(29).wrapping_add(3)).collect();
        let rec = seal_record(&mut sender, Direction::ClientToServer, 0, &pt).unwrap();
        let frame = rec.encode();
        let flip_pos = (seed as usize) % frame.len();
        let mut evil = frame.clone();
        evil[flip_pos] ^= 0x01;
        let before = receiver.consumed();
        let outcome = open_record(&mut receiver, &expect(0), &evil);
        prop_assert!(outcome.is_err(), "翻转位置 {flip_pos} 后的帧必须被拒绝");
        prop_assert_eq!(
            receiver.consumed(), before,
            "被拒帧不得推进接收游标（零明文交付面）"
        );
    }

    /// 性质 3：canonical 编解码无损往返（结构合法输入）。
    #[test]
    fn wire_roundtrip_is_lossless(
        bundle_id in any::<u64>(),
        base in any::<u64>(),
        seq in any::<u64>(),
        offset in 0u16..=4064,
        l in 1usize..=4064,
        dir_wire in 1u8..=2,
    ) {
        // 结构界限：offset + 32 + l <= 4096（§3.1）
        let max_l = (PAD_HALF - 32 - offset as usize).min(4064);
        let l = l.min(max_l).max(1);
        let rec = OtpDataRecord {
            direction: if dir_wire == 1 {
                Direction::ClientToServer
            } else {
                Direction::ServerToClient
            },
            bundle_id,
            base_segment: base,
            record_seq: seq,
            pad_offset: offset,
            ciphertext: vec![0x5C; l],
            tag: [0x3D; 16],
        };
        let wire = rec.encode();
        let back = decode_frame(&wire).unwrap();
        prop_assert_eq!(back.bundle_id, bundle_id);
        prop_assert_eq!(back.base_segment, base);
        prop_assert_eq!(back.record_seq, seq);
        prop_assert_eq!(back.pad_offset, offset);
        prop_assert_eq!(back.ciphertext.len(), l);
        prop_assert_eq!(back.tag, [0x3D; 16]);
        prop_assert_eq!(back.encode(), wire, "canonical：再编码逐字节一致");
    }
}
