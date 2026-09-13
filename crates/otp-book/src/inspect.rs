//! 密码本检查工具（规划 §5 测试 1 / 设计书 §9 测试项 1）。
//!
//! **唯一被允许全本顺序读取的路径**（离线检查工具；与生产读取路径
//! [`crate::Book::read_segment`] 完全分离——生产路径不预读、不缓存、
//! 只按索引单段读）。检查项：
//!
//! - 文件头与文件长度验证（复用与生产同一条 [`crate::Book::open`] 验证路径）；
//! - 全段 SHA-256 去重：任一重复段 ⇒ 检查失败（注入重复段必检出）；
//! - 全零段检测：任一 64 B 全零段 ⇒ 检查失败；
//! - 字节频数表与全本 bit=1 比例：仅作健康告警（如比例明显偏离 0.5），
//!   **不宣称随机性证明**（规划 §5 测试 1 通过标准的原话）。
//!
//! 报告只含公开元数据（段号、计数、比例）；不含段正文、不落任何段哈希，
//! 可安全进入 evidence/。

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use super::header::{BookHeader, HEADER_LEN};
use super::{BookError, open_validated};
use otp_types::{BookId, SEGMENT_LEN};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// 报告中最多列出的重复段对数 / 全零段号数（完整计数另有字段）。
const MAX_LISTED: usize = 16;
/// bit=1 比例健康告警带宽（仅告警，不影响 ok；±2%）。
const ONES_RATIO_BAND: f64 = 0.02;

/// 一对内容相同的段（首次出现号，重复出现号）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DuplicatePair {
    /// 首次出现的段号。
    pub first: u64,
    /// 与之内容相同的后续段号。
    pub other: u64,
}

/// 检查报告（公开元数据，可序列化入 evidence）。
#[derive(Clone, Debug)]
pub struct InspectReport {
    /// 文件头（已通过全部校验）。
    pub header: BookHeader,
    /// 实际文件字节数。
    pub file_size: u64,
    /// 多余的重复出现总次数（每个段的首次出现不计）。
    pub duplicate_count: u64,
    /// 前 [`MAX_LISTED`] 对重复段（完整判定看 `duplicate_count`）。
    pub duplicates: Vec<DuplicatePair>,
    /// 全零段总数。
    pub zero_segment_count: u64,
    /// 前 [`MAX_LISTED`] 个全零段号。
    pub zero_segments: Vec<u64>,
    /// 256 桶字节频数。
    pub byte_freq: [u64; 256],
    /// 全本 bit=1 比例（健康指标，非随机性证明）。
    pub ones_ratio: f64,
    /// 健康告警（统计类；不影响 ok 判定）。
    pub warnings: Vec<&'static str>,
    /// 综合判定：无重复段且无全零段（头/长度已在打开时强制通过）。
    pub ok: bool,
}

impl InspectReport {
    /// book_id（便捷访问）。
    pub fn book_id(&self) -> BookId {
        self.header.book_id
    }

    /// 人类可读摘要（不含任何秘密）。
    pub fn summary(&self) -> String {
        let mut s = String::new();
        use std::fmt::Write as _;
        let _ = writeln!(
            s,
            "book_id        : {:02x?}",
            self.header.book_id.as_bytes()
        );
        let _ = writeln!(s, "version        : {}", self.header.version);
        let _ = writeln!(s, "segment_len    : {}", self.header.segment_len);
        let _ = writeln!(s, "segment_count  : {}", self.header.segment_count);
        let _ = writeln!(s, "file_size      : {}", self.file_size);
        let _ = writeln!(s, "ones_ratio     : {:.6}", self.ones_ratio);
        let (mut min_b, mut max_b) = ((0usize, u64::MAX), (0usize, 0u64));
        for (i, c) in self.byte_freq.iter().enumerate() {
            if *c < min_b.1 {
                min_b = (i, *c);
            }
            if *c > max_b.1 {
                max_b = (i, *c);
            }
        }
        if self.file_size_sans_header() > 0 {
            let expect = self.file_size_sans_header() as f64 / 256.0;
            let _ = writeln!(
                s,
                "byte_freq min  : 0x{:02x} × {}（期望≈{:.0}）",
                min_b.0, min_b.1, expect
            );
            let _ = writeln!(
                s,
                "byte_freq max  : 0x{:02x} × {}（期望≈{:.0}）",
                max_b.0, max_b.1, expect
            );
        }
        let _ = writeln!(s, "duplicate_count: {}", self.duplicate_count);
        for d in &self.duplicates {
            let _ = writeln!(s, "  重复段: {} == {}", d.first, d.other);
        }
        let _ = writeln!(s, "zero_segments  : {}", self.zero_segment_count);
        for z in &self.zero_segments {
            let _ = writeln!(s, "  全零段: {z}");
        }
        for w in &self.warnings {
            let _ = writeln!(s, "WARN: {w}");
        }
        let _ = writeln!(s, "ok             : {}", self.ok);
        s
    }

    fn file_size_sans_header(&self) -> u64 {
        self.file_size.saturating_sub(HEADER_LEN as u64)
    }

    /// 机器可读 JSON（数值/布尔/字符串，无秘密字段）。
    pub fn to_json(&self) -> String {
        let mut s = String::from("{\n");
        use std::fmt::Write as _;
        let _ = writeln!(
            s,
            "  \"book_id\": \"{}\"",
            self.header
                .book_id
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let _ = writeln!(s, "  \"version\": {},", self.header.version);
        let _ = writeln!(s, "  \"segment_len\": {},", self.header.segment_len);
        let _ = writeln!(s, "  \"segment_count\": {},", self.header.segment_count);
        let _ = writeln!(s, "  \"file_size\": {},", self.file_size);
        let _ = writeln!(s, "  \"ones_ratio\": {:.6},", self.ones_ratio);
        let _ = writeln!(s, "  \"duplicate_count\": {},", self.duplicate_count);
        let dups: Vec<String> = self
            .duplicates
            .iter()
            .map(|d| format!("{{\"first\": {}, \"other\": {}}}", d.first, d.other))
            .collect();
        let _ = writeln!(s, "  \"duplicates\": [{}],", dups.join(", "));
        let _ = writeln!(s, "  \"zero_segment_count\": {},", self.zero_segment_count);
        let zeros: Vec<String> = self.zero_segments.iter().map(|z| z.to_string()).collect();
        let _ = writeln!(s, "  \"zero_segments\": [{}],", zeros.join(", "));
        let freq: Vec<String> = self.byte_freq.iter().map(|c| c.to_string()).collect();
        let _ = writeln!(s, "  \"byte_freq\": [{}],", freq.join(","));
        let warns: Vec<String> = self.warnings.iter().map(|w| format!("\"{w}\"")).collect();
        let _ = writeln!(s, "  \"warnings\": [{}],", warns.join(", "));
        let _ = writeln!(s, "  \"ok\": {}", self.ok);
        s.push('}');
        s
    }
}

/// 全本检查：头校验（复用生产路径）+ 逐段流式读 + 哈希去重 + 统计。
pub fn inspect_book(path: &Path) -> Result<InspectReport, BookError> {
    let (fd, header) = open_validated(path)?;
    let file_size =
        (HEADER_LEN as u64).saturating_add(header.segment_count.saturating_mul(SEGMENT_LEN as u64));

    let file = std::fs::File::from(fd.try_clone().map_err(|_| BookError::Io)?);
    drop(fd);
    let mut reader = std::io::BufReader::with_capacity(64 * 1024, file);
    // 跳过文件头（头校验已由 open_validated 完成）
    let mut head = Zeroizing::new([0u8; HEADER_LEN]);
    reader.read_exact(&mut *head).map_err(|_| BookError::Io)?;

    let mut first_seen: HashMap<
        [u8; 32],
        u64,
        std::hash::BuildHasherDefault<std::collections::hash_map::DefaultHasher>,
    > = HashMap::with_capacity_and_hasher(
        header.segment_count.min(1 << 20) as usize,
        std::hash::BuildHasherDefault::default(),
    );
    let mut duplicates = Vec::new();
    let mut duplicate_count = 0u64;
    let mut zero_segments = Vec::new();
    let mut zero_segment_count = 0u64;
    let mut byte_freq = [0u64; 256];
    let mut ones: u64 = 0;

    let mut seg = Zeroizing::new([0u8; SEGMENT_LEN]);
    for i in 0..header.segment_count {
        reader.read_exact(&mut *seg).map_err(|_| BookError::Io)?; // EOF/短读：fail-closed（长度已校验）
        for b in seg.iter() {
            byte_freq[*b as usize] += 1;
            ones += b.count_ones() as u64;
        }
        if seg.iter().all(|&b| b == 0) {
            zero_segment_count += 1;
            if zero_segments.len() < MAX_LISTED {
                zero_segments.push(i);
            }
        }
        let hash: [u8; 32] = Sha256::digest(*seg).into();
        match first_seen.get(&hash) {
            Some(&first) => {
                duplicate_count += 1;
                if duplicates.len() < MAX_LISTED {
                    duplicates.push(DuplicatePair { first, other: i });
                }
            }
            None => {
                first_seen.insert(hash, i);
            }
        }
    }
    drop(first_seen); // 段哈希表在返回前释放（虽属公开可推导，仍不留存）

    let total_bits = header.segment_count * 64 * 8;
    let ones_ratio = if total_bits == 0 {
        0.0
    } else {
        ones as f64 / total_bits as f64
    };

    let mut warnings = Vec::new();
    if duplicate_count > 0 {
        warnings.push("duplicate-segments（内容重复段：健康检查失败项）");
    }
    if zero_segment_count > 0 {
        warnings.push("all-zero-segments（全零段：健康检查失败项）");
    }
    if !(0.5 - ONES_RATIO_BAND..=0.5 + ONES_RATIO_BAND).contains(&ones_ratio) {
        warnings.push(
            "ones-ratio-out-of-band（bit=1 比例偏离 0.5±0.02：仅统计告警，不构成随机性证明）",
        );
    }

    let ok = duplicate_count == 0 && zero_segment_count == 0;
    Ok(InspectReport {
        header,
        file_size,
        duplicate_count,
        duplicates,
        zero_segment_count,
        zero_segments,
        byte_freq,
        ones_ratio,
        warnings,
        ok,
    })
}

#[cfg(test)]
mod tests {
    use super::super::test_support::temp_path;
    use super::super::{Book, BookError};
    use super::*;
    use otp_types::BookId;
    use std::io::{Seek, SeekFrom, Write};

    const ID: BookId = BookId::from_bytes(*b"OTPTERM-TESTBOOK");

    /// 生成确定内容小本并按需改写段。
    fn book_with(tag: &str, segments: u64) -> std::path::PathBuf {
        let p = temp_path(tag);
        crate::test_support::write_test_book(&p, ID, segments).unwrap();
        p
    }

    fn overwrite_segment(p: &Path, index: u64, bytes: &[u8; 64]) {
        let mut f = std::fs::OpenOptions::new().write(true).open(p).unwrap();
        f.seek(SeekFrom::Start(HEADER_LEN as u64 + index * 64))
            .unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
    }

    #[test]
    fn inspect_clean_book_ok() {
        let p = book_with("insp-clean", 512);
        let rep = inspect_book(&p).unwrap();
        assert!(rep.ok, "{}", rep.summary());
        assert_eq!(rep.duplicate_count, 0);
        assert_eq!(rep.zero_segment_count, 0);
        assert_eq!(rep.header.segment_count, 512);
        assert!((0.49..=0.51).contains(&rep.ones_ratio));
        assert!(rep.warnings.is_empty());
        // JSON 可整体生成
        assert!(rep.to_json().contains("\"ok\": true"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn inspect_detects_injected_duplicate() {
        // 设计书 §9 测试项 1：人工复制一个 64B 段后检测必失败
        let p = book_with("insp-dup", 64);
        let book = Book::open(&p).unwrap();
        let seg0 = *book
            .read_segment(otp_types::SegmentIndex::new(0))
            .unwrap()
            .as_bytes();
        drop(book);
        overwrite_segment(&p, 17, &seg0);

        let rep = inspect_book(&p).unwrap();
        assert!(!rep.ok);
        assert_eq!(rep.duplicate_count, 1);
        assert_eq!(
            rep.duplicates.first(),
            Some(&DuplicatePair {
                first: 0,
                other: 17
            })
        );
        assert!(rep.summary().contains("0 == 17"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn inspect_detects_all_zero_segment() {
        let p = book_with("insp-zero", 32);
        overwrite_segment(&p, 5, &[0u8; 64]);
        let rep = inspect_book(&p).unwrap();
        assert!(!rep.ok);
        assert_eq!(rep.zero_segment_count, 1);
        assert_eq!(rep.zero_segments, vec![5u64]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn inspect_rejects_malformed_header_via_shared_path() {
        // 头校验与生产 open 同路径：畸形头在 inspect 侧同样被拒绝
        let p = temp_path("insp-bad");
        std::fs::write(&p, [0u8; 64]).unwrap();
        assert!(matches!(
            inspect_book(&p),
            Err(BookError::InvalidHeader { .. })
        ));
        std::fs::remove_file(&p).ok();
    }
}
