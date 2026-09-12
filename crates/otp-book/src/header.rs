//! 密码本文件头：128 B 定长大端布局（WP-06 定稿冻结，供 WP-07 allocator 与
//! WP-15 CLI 机械对照）。
//!
//! 设计书 v2 §3 只固定了字段集合（版本、密码本 ID、段长 64、总段数、校验
//! 元数据），未固定字节布局；本模块按 WP-02 锚记录同款风格（magic + 版本 +
//! 定长字段 + 保留区全零 + SHA-256 完整性）落成可机械核对的格式：
//!
//! ```text
//! 偏移   长度   字段           约束（违反即 InvalidHeader，fail-closed）
//! 0      4      magic          "OTPB"
//! 4      2      version        0x0001（BE；不识别即拒绝，无协商）
//! 6      4      segment_len    必须为 64（BE u32）
//! 10     8      segment_count  1..=2^40-1（BE u64；上限=WP-02 §0 协议段号上限）
//! 18     16     book_id        与锚记录/对端配置绑定（公开，非秘密）
//! 34     2      reserved0      必须为 0x0000
//! 36     60     reserved_pad   60×0x00（前向兼容保留；任一非零即拒绝，不猜）
//! 96     32     header_hash    SHA-256(header[0:96])（校验元数据，设计书 §3）
//! —— 头总长 128 B；段 i 正文位于偏移 128 + i*64（128=2×64，段边界全程 64B 对齐）
//! ```
//!
//! 文件头不含任何可推导秘密的内容（设计书 §3）；`book_id` 可公开。

#![forbid(unsafe_code)]

use otp_types::{BookId, SEGMENT_LEN};
use sha2::{Digest, Sha256};

/// 文件魔数。
pub const BOOK_MAGIC: [u8; 4] = *b"OTPB";
/// 本 crate 支持的文件格式版本；不识别的版本一律拒绝（无协商）。
pub const BOOK_VERSION: u16 = 0x0001;
/// 文件头定长（含 32 B 完整性哈希）。
pub const HEADER_LEN: usize = 128;
/// 段正文区起始偏移（= 128，见模块文档）。
pub const SEGMENT_AREA_OFFSET: u64 = HEADER_LEN as u64;
/// 协议段号/总段数上限 2^40−1（WP-02 §0：SegmentIndex 协议上限 POINTER_CAP）。
pub const MAX_SEGMENT_COUNT: u64 = (1u64 << 40) - 1;
/// `header_hash` 覆盖的头前缀长度。
const HASHED_PREFIX_LEN: usize = 96;
/// 保留区总长（reserved0 2 B + reserved_pad 60 B）。
const RESERVED_LEN: usize = 2 + 60;

/// 密码本文件头（设计书 §3：版本、密码本 ID、段长 64、总段数、校验元数据）。
///
/// `header_hash` 不作为字段保存：它由 [`BookHeader::encode`] 计算、由
/// [`BookHeader::decode`] 复核。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BookHeader {
    /// 文件格式版本。
    pub version: u16,
    /// 密码本 ID（绑定两端配置，防错拿另一套本体）。
    pub book_id: BookId,
    /// 段长（必须为 64）。
    pub segment_len: u32,
    /// 总段数。
    pub segment_count: u64,
}

impl BookHeader {
    /// 构造并校验（生成工具入口）：字段必须满足全部格式不变量。
    pub fn new(book_id: BookId, segment_count: u64) -> Result<Self, &'static str> {
        let h = Self {
            version: BOOK_VERSION,
            book_id,
            segment_len: SEGMENT_LEN as u32,
            segment_count,
        };
        h.validate()?;
        Ok(h)
    }

    /// 全部格式不变量（不含文件长度一致性——那需要 stat，归 [`super::Book::open`]）。
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != BOOK_VERSION {
            return Err("unsupported-version");
        }
        if self.segment_len as usize != SEGMENT_LEN {
            return Err("segment-len-not-64");
        }
        if self.segment_count == 0 || self.segment_count > MAX_SEGMENT_COUNT {
            return Err("segment-count-out-of-range");
        }
        Ok(())
    }

    /// canonical 编码为 128 B（含末尾 SHA-256 完整性元数据）。
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&BOOK_MAGIC);
        out[4..6].copy_from_slice(&self.version.to_be_bytes());
        out[6..10].copy_from_slice(&self.segment_len.to_be_bytes());
        out[10..18].copy_from_slice(&self.segment_count.to_be_bytes());
        out[18..34].copy_from_slice(self.book_id.as_bytes());
        // out[34..96] 保留区保持全零
        let hash = Sha256::digest(&out[..HASHED_PREFIX_LEN]);
        out[HASHED_PREFIX_LEN..].copy_from_slice(&hash);
        out
    }

    /// 严格解码：长度必须恰为 [`HEADER_LEN`]；magic/版本/段长/段数/保留区/
    /// SHA-256 任一不符即拒绝（fail-closed，不猜、无默认值）。
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != HEADER_LEN {
            return Err("header-length");
        }
        if bytes[0..4] != BOOK_MAGIC {
            return Err("magic");
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != BOOK_VERSION {
            return Err("unsupported-version");
        }
        let segment_len = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        if segment_len as usize != SEGMENT_LEN {
            return Err("segment-len-not-64");
        }
        let segment_count = u64::from_be_bytes(bytes[10..18].try_into().unwrap());
        if segment_count == 0 || segment_count > MAX_SEGMENT_COUNT {
            return Err("segment-count-out-of-range");
        }
        let mut book_id_bytes = [0u8; 16];
        book_id_bytes.copy_from_slice(&bytes[18..34]);
        if bytes[34..HASHED_PREFIX_LEN] != [0u8; RESERVED_LEN] {
            return Err("reserved-not-zero");
        }
        let expect_hash = Sha256::digest(&bytes[..HASHED_PREFIX_LEN]);
        if bytes[HASHED_PREFIX_LEN..] != expect_hash[..] {
            return Err("header-hash-mismatch");
        }
        Ok(Self {
            version,
            book_id: BookId::from_bytes(book_id_bytes),
            segment_len,
            segment_count,
        })
    }

    /// 段区预期文件长度（checked；`segment_count` 已受 [`MAX_SEGMENT_COUNT`]
    /// 约束，此处的 checked 仅为纵深防御）。
    pub const fn expected_file_size(&self) -> Option<u64> {
        match self.segment_count.checked_mul(SEGMENT_LEN as u64) {
            Some(body) => SEGMENT_AREA_OFFSET.checked_add(body),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// golden 向量：version=1 / 段长 64 / 3 段 / book_id="OTPTERM-TESTBOOK"。
    /// 前缀与 SHA-256 均由独立实现（python hashlib）预计算，防自证循环。
    #[test]
    fn golden_header_bytes() {
        let h = BookHeader::new(BookId::from_bytes(*b"OTPTERM-TESTBOOK"), 3).unwrap();
        let bytes = h.encode();
        // 192 个十六进制字符（96 B 前缀），来自独立实现（python hashlib）。
        let expect_prefix_hex = "4f54504200010000004000000000000000034f54505445524d2d54455354424f4f4b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(expect_prefix_hex.len(), HASHED_PREFIX_LEN * 2);
        let expect_prefix = hex_to_bytes(expect_prefix_hex);
        assert_eq!(&bytes[..HASHED_PREFIX_LEN], &expect_prefix[..]);
        assert_eq!(
            hex::bytes_to_hex(&bytes[HASHED_PREFIX_LEN..]),
            "6b25e3aa0d7c631a64f3dab6d125a564bcff14a3c1db319fcd073481d8e7a8e8"
        );
        // 编码-解码往返全等
        assert_eq!(BookHeader::decode(&bytes).unwrap(), h);
    }

    #[test]
    fn decode_rejects_malformed() {
        let good = BookHeader::new(BookId::from_bytes([7; 16]), 5)
            .unwrap()
            .encode();

        // 长度不是恰 128
        assert_eq!(BookHeader::decode(&good[..127]), Err("header-length"));
        assert_eq!(
            BookHeader::decode(&[good.as_slice(), &[0u8]].concat()),
            Err("header-length")
        );

        let mut b;
        macro_rules! mut_case {
            ($name:ident, $err:literal, $body:expr) => {{
                b = good;
                $body(&mut b);
                assert_eq!(BookHeader::decode(&b), Err($err), stringify!($name));
            }};
        }
        mut_case!(bad_magic, "magic", |b: &mut [u8; 128]| b[0] = b'X');
        mut_case!(version0, "unsupported-version", |b: &mut [u8; 128]| {
            b[4..6].copy_from_slice(&0u16.to_be_bytes())
        });
        mut_case!(version2, "unsupported-version", |b: &mut [u8; 128]| {
            b[4..6].copy_from_slice(&2u16.to_be_bytes())
        });
        mut_case!(seglen63, "segment-len-not-64", |b: &mut [u8; 128]| {
            b[6..10].copy_from_slice(&63u32.to_be_bytes())
        });
        mut_case!(seglen32, "segment-len-not-64", |b: &mut [u8; 128]| {
            b[6..10].copy_from_slice(&32u32.to_be_bytes())
        });
        mut_case!(count0, "segment-count-out-of-range", |b: &mut [u8; 128]| {
            b[10..18].copy_from_slice(&0u64.to_be_bytes())
        });
        mut_case!(
            count_over_cap,
            "segment-count-out-of-range",
            |b: &mut [u8; 128]| {
                b[10..18].copy_from_slice(&(MAX_SEGMENT_COUNT + 1).to_be_bytes())
            }
        );
        mut_case!(
            count_u64_max,
            "segment-count-out-of-range",
            |b: &mut [u8; 128]| { b[10..18].copy_from_slice(&u64::MAX.to_be_bytes()) }
        );
        mut_case!(reserved0, "reserved-not-zero", |b: &mut [u8; 128]| b[35] =
            1);
        mut_case!(pad_tail, "reserved-not-zero", |b: &mut [u8; 128]| b[95] =
            0xFF);
        mut_case!(hash_bit, "header-hash-mismatch", |b: &mut [u8; 128]| b
            [96] ^=
            1);
        mut_case!(
            book_id_change,
            "header-hash-mismatch",
            |b: &mut [u8; 128]| b[18] ^= 1
        );
    }

    #[test]
    fn constructor_rejects_invalid() {
        let id = BookId::from_bytes([0; 16]);
        assert_eq!(
            BookHeader::new(id, 0).unwrap_err(),
            "segment-count-out-of-range"
        );
        assert_eq!(
            BookHeader::new(id, MAX_SEGMENT_COUNT + 1).unwrap_err(),
            "segment-count-out-of-range"
        );
        assert!(BookHeader::new(id, 1).is_ok());
        assert!(BookHeader::new(id, MAX_SEGMENT_COUNT).is_ok());
        // 段区大小不回卷：上限段数 × 64 + 128 仍远小于 2^64
        assert_eq!(
            BookHeader::new(id, MAX_SEGMENT_COUNT)
                .unwrap()
                .expected_file_size(),
            Some(HEADER_LEN as u64 + MAX_SEGMENT_COUNT * 64)
        );
    }

    /// 测试专用十六进制工具（不引入依赖）。
    mod hex {
        pub fn bytes_to_hex(bytes: &[u8]) -> String {
            let mut s = String::with_capacity(bytes.len() * 2);
            for b in bytes {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
            }
            s
        }
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
