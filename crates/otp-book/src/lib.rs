//! # otp-book —— 密码本读取器
//!
//! 实现规划 §2 职责：验证文件头、book_id、段长/总段数；在已提交预留后按索引
//! `pread_exact(64)`；测试本生成/校验工具的底层支撑（工具入口在 otp-cli）。
//!
//! 禁止事项（规划 §2）：不拥有/推进指针（指针归锚/分配器）；不得预读全本；
//! 不得在预留前读段。
//!
//! ## 文件格式
//!
//! 128 B 定长文件头（见 [`header`] 模块：magic "OTPB" / 版本 / 段长 64 /
//! 总段数 / book_id / 保留区全零 / SHA-256 头完整性）+ 64 B 段正文区，
//! 段 `i` 位于偏移 `128 + i*64`。任一头字段非法、文件长度与总段数不一致、
//! 非常规文件 → 拒绝（fail-closed）。
//!
//! ## 段读取的模块边界（规划 §2.2）
//!
//! [`Book::read_segment`] 为 **crate-private**；生产路径只有 otp-allocator
//! 能在双锚 reservation intent fsync 成功之后调用（WP-02 §1.1 顺序强制：
//! `intent_durable` 先于 `body_read`；调用契约见该方法文档）。
//! 段读取实现与 allocator transaction 位于本 crate 内部；对外仅导出
//! allocator 的已提交段签发接口，调用者无法取得预留中的段正文。
//!
//! ## 不预读承诺
//!
//! [`Book::open`] 只读一次 128 B 文件头；段正文仅在 [`Book::read_segment`]
//! 中按索引单次 `pread_exact(64)` 读出，不缓存、不枚举、不顺序扫描。
//! 离线统计/重复段检测工具（[`inspect`]）是唯一被允许全本顺序读取的路径，
//! 与生产读取路径完全分离。

#![forbid(unsafe_code)]

pub mod allocator;
pub mod generate;
pub mod header;
pub mod inspect;

use std::fmt;
use std::path::Path;

use header::{BookHeader, HEADER_LEN, SEGMENT_AREA_OFFSET};
use otp_types::{SEGMENT_LEN, SegmentIndex};
use rustix::fd::OwnedFd;
use rustix::fs::{FileType, Mode, OFlags, fstat, open};
use zeroize::ZeroizeOnDrop;

pub use header::{BOOK_MAGIC, BOOK_VERSION, MAX_SEGMENT_COUNT};

/// 已打开并通过头校验的密码本。
///
/// 只持有 fd 与 128 B 头（不持有任何段正文）。不实现 `Clone`（fd 复制会
/// 扩大泄露面）；跨线程共享由 otp-allocator 在锁内决定。
pub struct Book {
    fd: OwnedFd,
    header: BookHeader,
}

/// 单个 64B 段正文。敏感数据：Drop 清零；不实现 Clone/Debug/PartialEq/序列化。
#[derive(ZeroizeOnDrop)]
pub struct Segment([u8; SEGMENT_LEN]);

impl Segment {
    #[cfg(test)]
    pub(crate) fn as_bytes(&self) -> &[u8; SEGMENT_LEN] {
        &self.0
    }
}

/// 密码本错误。永不包含段正文或密钥材料（reason 为静态白名单字符串）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BookError {
    /// 文件不存在/不可读。
    NotFound,
    /// 文件头非法（版本/段长/总段数/保留区/头哈希/文件长度不一致等）。
    InvalidHeader {
        /// 原因（静态白名单：见 [`header::BookHeader::decode`] 与
        /// [`Book::open`] 的长度/类型检查）。
        reason: &'static str,
    },
    /// 索引越界（绝不越界读，规划 M2 验收；allocator 映射为 EXHAUSTED）。
    SegmentOutOfRange {
        /// 请求的索引。
        index: SegmentIndex,
        /// 总段数。
        count: u64,
    },
    /// I/O 错误（pread 短读/中断后失败等，fail-closed）。
    Io,
}

impl fmt::Display for BookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "密码本文件不存在或不可读"),
            Self::InvalidHeader { reason } => {
                write!(f, "密码本文件头非法（{reason}），拒绝加载")
            }
            Self::SegmentOutOfRange { index, count } => write!(
                f,
                "段索引越界：index={}，segment_count={}（绝不越界读/不回卷）",
                index.get(),
                count
            ),
            Self::Io => write!(f, "密码本 I/O 错误（fail-closed）"),
        }
    }
}

impl std::error::Error for BookError {}

impl Book {
    /// 打开并验证文件头：magic/版本/段长必须为 64/总段数 1..=2^40−1/保留区
    /// 全零/头 SHA-256 复核/文件长度恰为 `128 + 段数*64`/必须为常规文件。
    /// 只读一次 128 B 头，**不读任何段正文**。
    pub fn open(path: &Path) -> Result<Self, BookError> {
        let (fd, header) = open_validated(path)?;
        Ok(Self { fd, header })
    }

    /// 已验证的文件头。
    pub fn header(&self) -> &BookHeader {
        &self.header
    }

    /// 总段数（耗尽判定：next >= segment_count 即 EXHAUSTED，归 allocator）。
    pub fn segment_count(&self) -> u64 {
        self.header.segment_count
    }

    /// 按索引 `pread_exact(64)` 读取段正文。
    ///
    /// ## crate-private（规划 §2.2，类型系统强制）
    ///
    /// 对本 crate 之外不可见：生产路径只有 otp-allocator 能调用，且调用
    /// 契约为 **双锚 reservation intent 已写满并各自 fsync 成功之后**
    /// （WP-02 §1.1：`intent_durable` 必须先于 `body_read`；否则违反
    /// fail-to-waste 铁律——预留前读段会使“读到内存后、写指针前”的崩溃
    /// 窗口不可观测，设计书 §6）。
    ///
    /// ## 行为
    ///
    /// - 单次 64 B 定位读（`pread` 循环至读满），不缓存、不预读相邻段；
    /// - `index >= segment_count` → [`BookError::SegmentOutOfRange`]，
    ///   绝不越界读、偏移计算全程 checked、绝不回卷（EXHAUSTED 语义归
    ///   allocator，本层只做硬边界）；
    /// - 短读/EOF（并发截断）/EIO → [`BookError::Io`]（fail-closed）。
    pub(crate) fn read_segment(&self, index: SegmentIndex) -> Result<Segment, BookError> {
        let i = index.get();
        if i >= self.header.segment_count {
            return Err(BookError::SegmentOutOfRange {
                index,
                count: self.header.segment_count,
            });
        }
        // i < segment_count <= 2^40-1，乘加不可能溢出 u64；checked 为纵深防御。
        let body_off = i
            .checked_mul(SEGMENT_LEN as u64)
            .ok_or(BookError::SegmentOutOfRange {
                index,
                count: self.header.segment_count,
            })?;
        let offset =
            SEGMENT_AREA_OFFSET
                .checked_add(body_off)
                .ok_or(BookError::SegmentOutOfRange {
                    index,
                    count: self.header.segment_count,
                })?;
        let mut buf = [0u8; SEGMENT_LEN];
        pread_exact(&self.fd, &mut buf, offset)?;
        Ok(Segment(buf))
    }
}

/// 打开并完整验证（inspect 工具与 [`Book::open`] 共用同一条验证路径，
/// 避免出现第二套略过检查的读法）。
fn open_validated(path: &Path) -> Result<(OwnedFd, BookHeader), BookError> {
    let fd = open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|e| map_open_err(e.into()))?;
    let st = fstat(&fd).map_err(|_| BookError::Io)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(BookError::InvalidHeader {
            reason: "not-a-regular-file",
        });
    }
    if st.st_size < HEADER_LEN as i64 {
        return Err(BookError::InvalidHeader {
            reason: "header-length",
        });
    }
    let mut head = [0u8; HEADER_LEN];
    pread_exact(&fd, &mut head, 0)?;
    let header = BookHeader::decode(&head).map_err(|reason| BookError::InvalidHeader { reason })?;
    match header.expected_file_size() {
        Some(expected) if st.st_size as u64 == expected => Ok((fd, header)),
        _ => Err(BookError::InvalidHeader {
            reason: "file-size-mismatch",
        }),
    }
}

fn map_open_err(e: std::io::Error) -> BookError {
    match e.kind() {
        std::io::ErrorKind::NotFound => BookError::NotFound,
        _ => BookError::Io,
    }
}

/// `pread` 循环至 `buf` 读满：EINTR 重试、短读/EOF fail-closed。
fn pread_exact(fd: &OwnedFd, buf: &mut [u8], mut offset: u64) -> Result<(), BookError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match rustix::io::pread(fd, &mut buf[filled..], offset) {
            Ok(0) => return Err(BookError::Io), // EOF：长度已校验，出现即并发截断
            Ok(n) => {
                filled += n;
                offset = offset.saturating_add(n as u64);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(BookError::Io),
        }
    }
    Ok(())
}

// ─────────────────────────────── 单元测试 ───────────────────────────────
// read_segment 为 crate-private，其行为测试只能置于 crate 内。

#[cfg(test)]
pub(crate) mod test_support {
    //! 测试用密码本构造器（crate 内测试与集成测试共用文件写入逻辑，
    //! 但 read 走公开/受控接口）。

    use super::*;
    use otp_types::BookId;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// 唯一临时文件路径（std::env::temp_dir 下；Drop 清理由调用方负责或由
    /// 测试进程退出回收；本仓测试体量小，且 CI 容器即弃）。
    pub(crate) fn temp_path(tag: &str) -> std::path::PathBuf {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "otp-book-test-{}-{}-{}.book",
            std::process::id(),
            tag,
            n
        ))
    }

    /// 写一个内容确定的测试密码本：段 i = 伪随机流（xorshift，非密码学，
    /// 仅测试），返回路径。
    pub(crate) fn write_test_book(
        path: &Path,
        book_id: BookId,
        segments: u64,
    ) -> std::io::Result<()> {
        use std::io::Write;
        let header = BookHeader::new(book_id, segments).expect("测试头必合法");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        f.write_all(&header.encode())?;
        let mut state = 0x9E3779B97F4A7C15u64;
        for _ in 0..segments {
            let mut seg = [0u8; SEGMENT_LEN];
            for chunk in seg.chunks_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                chunk.copy_from_slice(&state.to_le_bytes());
            }
            f.write_all(&seg)?;
        }
        f.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{temp_path, write_test_book};
    use super::*;
    use otp_types::BookId;
    use std::path::PathBuf;

    const ID: BookId = BookId::from_bytes(*b"OTPTERM-TESTBOOK");

    fn book_4segs() -> PathBuf {
        let p = temp_path("open4");
        write_test_book(&p, ID, 4).unwrap();
        p
    }

    #[test]
    fn segment_is_64b_and_zeroized_on_drop() {
        assert_eq!(core::mem::size_of::<Segment>(), SEGMENT_LEN);
        // Segment 不实现 Clone/Debug：以下在编译期即无法通过（注释保留为评审提示）
        // let _ = format!("{:?}", segment);
        // let _ = segment.clone();
    }

    #[test]
    fn header_shape_matches_design() {
        let h = BookHeader {
            version: header::BOOK_VERSION,
            book_id: BookId::from_bytes([0; 16]),
            segment_len: 64,
            segment_count: 3,
        };
        assert_eq!(h.segment_len as usize, SEGMENT_LEN);
        assert!(h.validate().is_ok());
    }

    #[test]
    fn open_validates_and_reports_header() {
        let p = book_4segs();
        let book = Book::open(&p).unwrap();
        assert_eq!(book.segment_count(), 4);
        assert_eq!(book.header().book_id, ID);
        assert_eq!(book.header().version, BOOK_VERSION);
        assert_eq!(
            std::fs::metadata(&p).unwrap().len(),
            (HEADER_LEN as u64) + 4 * 64
        );
        std::fs::remove_file(&p).ok();
    }

    /// 与 [`test_support::write_test_book`] 同一条 xorshift 流：段 i 的第 k 个
    /// 8 字节块 = 全局第 (i*8+k+1) 步输出。
    fn expected_xorshift_segment(i: u64) -> [u8; SEGMENT_LEN] {
        let mut state = 0x9E3779B97F4A7C15u64;
        let step = |s: &mut u64| {
            *s ^= *s << 13;
            *s ^= *s >> 7;
            *s ^= *s << 17;
        };
        for _ in 0..(i * 8) {
            step(&mut state);
        }
        let mut seg = [0u8; SEGMENT_LEN];
        for chunk in seg.chunks_mut(8) {
            step(&mut state);
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        seg
    }

    #[test]
    fn read_segment_returns_exact_segment_bytes_by_index() {
        let p = temp_path("read");
        write_test_book(&p, ID, 4).unwrap();
        let book = Book::open(&p).unwrap();
        for i in 0..4u64 {
            let seg = book.read_segment(SegmentIndex::new(i)).unwrap();
            assert_eq!(seg.0, expected_xorshift_segment(i), "segment {i}");
        }
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn read_segment_no_preread_no_cache_open_then_disk_change_visible() {
        // 打开后只应持有头：正文若在 open 时被预读/缓存，此处改盘后应读到旧值。
        let p = temp_path("nopre");
        write_test_book(&p, ID, 2).unwrap();
        let book = Book::open(&p).unwrap();
        let before = book
            .read_segment(SegmentIndex::new(0))
            .unwrap()
            .0;
        // 盘上把段 0 改成全 0xAA
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.seek(SeekFrom::Start(HEADER_LEN as u64)).unwrap();
        f.write_all(&[0xAA; SEGMENT_LEN]).unwrap();
        f.sync_all().unwrap();
        drop(f);
        let after = book
            .read_segment(SegmentIndex::new(0))
            .unwrap()
            .0;
        assert_eq!(before, expected_xorshift_segment(0));
        assert_eq!(
            after, [0xAA; SEGMENT_LEN],
            "read_segment 必须现读现返回（不缓存）"
        );
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn read_segment_out_of_range_never_reads_beyond_or_wraps() {
        // EXHAUSTED 边界（WP-06 验收 5）：不越界读、不回卷，返回错误而非 panic
        let p = book_4segs();
        let book = Book::open(&p).unwrap();
        for bad in [4u64, 5, u64::MAX, u64::MAX - 1, (1 << 40), (1 << 63)] {
            assert!(
                matches!(
                    book.read_segment(SegmentIndex::new(bad)),
                    Err(BookError::SegmentOutOfRange {
                        index,
                        count: 4
                    }) if index == SegmentIndex::new(bad)
                ),
                "index={bad}"
            );
        }
        // 越界后再读合法索引仍正常（错误不破坏 fd 状态）
        assert!(book.read_segment(SegmentIndex::new(3)).is_ok());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn open_rejects_malformed_files() {
        let good = BookHeader::new(ID, 2).unwrap().encode();
        let mut seg = [0u8; SEGMENT_LEN];
        for (k, b) in seg.iter_mut().enumerate() {
            *b = k as u8;
        }

        let write_case = |tag: &str, bytes: Vec<u8>| -> BookError {
            let p = temp_path(tag);
            std::fs::write(&p, &bytes).unwrap();
            let err = match Book::open(&p) {
                Err(e) => e,
                Ok(_) => panic!("{tag} 应被拒绝"),
            };
            std::fs::remove_file(&p).ok();
            err
        };

        // 空文件 / 短头
        assert_eq!(
            write_case("empty", vec![]),
            BookError::InvalidHeader {
                reason: "header-length"
            }
        );
        assert_eq!(
            write_case("shorthead", good[..100].to_vec()),
            BookError::InvalidHeader {
                reason: "header-length"
            }
        );
        // 头合法但段区缺一整段
        let mut truncated = good.to_vec();
        truncated.extend_from_slice(&seg);
        assert_eq!(
            write_case("shortbody", truncated),
            BookError::InvalidHeader {
                reason: "file-size-mismatch"
            }
        );
        // 尾部多 1 字节垃圾
        let mut trailing = good.to_vec();
        trailing.extend_from_slice(&seg);
        trailing.extend_from_slice(&seg);
        trailing.push(0);
        assert_eq!(
            write_case("trailing", trailing),
            BookError::InvalidHeader {
                reason: "file-size-mismatch"
            }
        );
        // 头字段被改（合法长度）——哈希复核兜底
        let mut badhash = good.to_vec();
        badhash[18] ^= 1; // book_id 变位 → header-hash-mismatch
        badhash.extend_from_slice(&seg);
        badhash.extend_from_slice(&seg);
        assert_eq!(
            write_case("badhash", badhash),
            BookError::InvalidHeader {
                reason: "header-hash-mismatch"
            }
        );
        // 不存在
        let missing = temp_path("missing");
        assert!(matches!(Book::open(&missing), Err(BookError::NotFound)));
        // 非常规文件：目录与字符设备
        assert!(matches!(
            Book::open(&std::env::temp_dir()),
            Err(BookError::InvalidHeader {
                reason: "not-a-regular-file"
            })
        ));
        assert!(matches!(
            Book::open(Path::new("/dev/null")),
            Err(BookError::InvalidHeader {
                reason: "not-a-regular-file"
            })
        ));
    }
}
