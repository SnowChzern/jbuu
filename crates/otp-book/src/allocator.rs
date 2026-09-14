//! Fail-to-waste OTP segment allocator.
//!
//! The transaction order is fixed: INTENT A write/sync, INTENT B write/sync,
//! segment pread, COMMIT A write/sync, COMMIT B write/sync. The allocator keeps
//! its OFD lock for its complete lifetime, including startup reconciliation.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::{Book, BookError};
use otp_anchor_spec::{
    AnchorCopy, AnchorPayload, AnchorRecord, RecoveryDecision, SegmentHash, decide,
    decode_and_verify, encode_record,
};
use otp_platform::{FileLockGuard, PlatformError, acquire_ofd_lock, fsync_file};
use otp_types::{BookId, Generation, SEGMENT_LEN, SegmentIndex};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(ZeroizeOnDrop)]
pub struct CommittedSegment {
    inner: [u8; SEGMENT_LEN],
}

impl CommittedSegment {
    pub fn as_bytes(&self) -> &[u8; SEGMENT_LEN] {
        &self.inner
    }
}

struct ReservedSegment {
    index: SegmentIndex,
    generation: Generation,
}

pub trait SegmentIssuer {
    fn issue(&mut self) -> Result<CommittedSegment, IssueError>;
}

/// 范围签发口（full-OTP bundle 预留；设计书 fullotp-design §2.2：
/// `reserve_range(n_segments)` 的耐久顺序等价 `issue()`，任何不确定均浪费
/// 整个范围，绝不部分回收）。
pub trait RangeIssuer {
    /// 原子预留从当前 `next` 起的 `n_segments` 个连续段（n >= 1）。
    ///
    /// 耐久顺序（等价 `issue()`，WP-02 §1.1）：持锁 → 双锚 INTENT
    /// （`next += n`，reserved = 范围末段）各自 fsync → 读范围全部段 →
    /// COMMIT（next = base+n，previous_segment_hash = 范围末段哈希）双
    /// fsync → 返回。任一写/fsync 不确定 ⇒ 整范围保守浪费（恢复取高，
    /// 单次故障最大浪费 n 段）；读段失败同样浪费整范围（INTENT 已持久）。
    fn reserve_range(&mut self, n_segments: u64) -> Result<ReservedRange, IssueError>;
}

/// 已提交预留范围：`n` 个连续段正文（范围事务 COMMIT 后的唯一产出）。
///
/// 与 [`CommittedSegment`] 同类型义务：不 Clone/Debug/序列化，Drop 清零。
/// full-OTP 数据面把它切为双向 bundle（C2S 前半/S2C 后半，
/// otp-fullotp::split_bundle）。`base` 为公开元数据（非秘密），不参与清零。
pub struct ReservedRange {
    base: SegmentIndex,
    bytes: Vec<u8>,
}

impl Drop for ReservedRange {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl ReservedRange {
    /// 范围首段号（= 预留前 next）。
    #[must_use]
    pub fn base(&self) -> SegmentIndex {
        self.base
    }

    /// 范围内段数。
    #[must_use]
    pub fn segment_count(&self) -> u64 {
        (self.bytes.len() / SEGMENT_LEN) as u64
    }

    /// 全部段正文的平面视图（`n*64` 字节，按段序拼接）。
    #[must_use]
    pub fn flat_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub struct AllocatorConfig {
    pub book: PathBuf,
    pub anchor_a: PathBuf,
    pub anchor_b: PathBuf,
    pub expected_book_id: BookId,
}

pub struct Allocator {
    core: TransactionCore<FileMedia, BookReader>,
    _pointer_lock: FileLockGuard,
}

impl Allocator {
    pub fn open(cfg: AllocatorConfig) -> Result<Self, IssueError> {
        let book = Book::open(&cfg.book).map_err(map_book_open)?;
        if book.header().book_id != cfg.expected_book_id {
            return Err(IssueError::BookMismatch);
        }
        // Open media first: a second open file description can conflict with
        // this process's own OFD lock. The guard then covers reconciliation and issue.
        let media = FileMedia::open(&cfg.anchor_a, &cfg.anchor_b)?;
        let pointer_lock = acquire_ofd_lock(&cfg.anchor_a, true).map_err(map_platform)?;
        let reader = BookReader { book };
        let core = TransactionCore::open(media, reader, cfg.expected_book_id)?;
        Ok(Self {
            core,
            _pointer_lock: pointer_lock,
        })
    }

    pub fn state(&self) -> (SegmentIndex, Generation) {
        (self.core.current.next, self.core.current.generation)
    }
}

impl SegmentIssuer for Allocator {
    fn issue(&mut self) -> Result<CommittedSegment, IssueError> {
        self.core.issue()
    }
}

impl RangeIssuer for Allocator {
    fn reserve_range(&mut self, n_segments: u64) -> Result<ReservedRange, IssueError> {
        self.core.reserve_range(n_segments)
    }
}

impl Allocator {
    /// 原子预留范围（等价 [`RangeIssuer::reserve_range`]；便捷固有方法）。
    pub fn reserve_range(&mut self, n_segments: u64) -> Result<ReservedRange, IssueError> {
        self.core.reserve_range(n_segments)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IssueError {
    Exhausted {
        next: SegmentIndex,
    },
    LockUnavailable,
    PersistenceUncertain,
    AnchorCorrupt,
    BookMismatch,
    Io,
    /// 非法范围参数（n=0 或溢出；本地误用，不触发任何持久化）。
    InvalidRange,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MediaError {
    Io,
    Persistence,
    NoSpace,
    ShortWrite,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Boundary {
    IntentAWriteStart,
    IntentAWriteComplete,
    IntentAFsyncStart,
    IntentAFsyncReturn,
    IntentBWriteStart,
    IntentBWriteComplete,
    IntentBFsyncStart,
    IntentBFsyncReturn,
    SegmentPread,
    FinalAWriteStart,
    FinalAWriteComplete,
    FinalAFsyncStart,
    FinalAFsyncReturn,
    FinalBWriteStart,
    FinalBWriteComplete,
    FinalBFsyncStart,
    FinalBFsyncReturn,
}

trait AnchorMedia {
    fn read(&mut self, copy: AnchorCopy) -> Result<Vec<u8>, MediaError>;
    fn write(&mut self, copy: AnchorCopy, bytes: &[u8]) -> Result<(), MediaError>;
    fn sync(&mut self, copy: AnchorCopy) -> Result<(), MediaError>;
    fn boundary(&mut self, point: Boundary) -> Result<(), MediaError>;
}

trait SegmentReader {
    fn segment_count(&self) -> u64;
    fn read(&mut self, index: SegmentIndex) -> Result<[u8; SEGMENT_LEN], MediaError>;
}

struct TransactionCore<M, R> {
    media: M,
    reader: R,
    book_id: BookId,
    current: AnchorRecord,
    halted: bool,
}

impl<M: AnchorMedia, R: SegmentReader> TransactionCore<M, R> {
    fn open(mut media: M, mut reader: R, book_id: BookId) -> Result<Self, IssueError> {
        let a = read_record(&mut media, AnchorCopy::A)?;
        let b = read_record(&mut media, AnchorCopy::B)?;
        if a.book_id != book_id || b.book_id != book_id {
            return Err(IssueError::BookMismatch);
        }
        let (current, stale) = match decide(Ok(a), Ok(b)) {
            RecoveryDecision::Consistent(record) => (record, None),
            RecoveryDecision::AdoptHigher { adopted, stale } => (adopted, Some(stale)),
            _ => return Err(IssueError::AnchorCorrupt),
        };
        if current.next.get() > reader.segment_count() {
            return Err(IssueError::AnchorCorrupt);
        }
        if let AnchorPayload::Commit {
            previous_segment_hash,
        } = current.payload
        {
            let prior = current
                .next
                .get()
                .checked_sub(1)
                .ok_or(IssueError::AnchorCorrupt)?;
            let body = reader
                .read(SegmentIndex::new(prior))
                .map_err(|_| IssueError::AnchorCorrupt)?;
            if Sha256::digest(body).as_slice() != previous_segment_hash.0 {
                return Err(IssueError::AnchorCorrupt);
            }
        }
        if let Some(copy) = stale {
            persist_one(&mut media, copy, &current)
                .map_err(|_| IssueError::PersistenceUncertain)?;
            let repaired = read_record(&mut media, copy)?;
            if repaired != current {
                return Err(IssueError::PersistenceUncertain);
            }
        }
        Ok(Self {
            media,
            reader,
            book_id,
            current,
            halted: false,
        })
    }

    fn issue(&mut self) -> Result<CommittedSegment, IssueError> {
        if self.halted {
            return Err(IssueError::PersistenceUncertain);
        }
        let index = self.current.next;
        if index.get() >= self.reader.segment_count() {
            return Err(IssueError::Exhausted { next: index });
        }
        let generation = Generation::new(self.current.generation.get().checked_add(1).ok_or_else(
            || {
                self.halted = true;
                IssueError::PersistenceUncertain
            },
        )?);
        let reserved = ReservedSegment { index, generation };
        let intent = AnchorRecord::intent(self.book_id, reserved.generation, reserved.index);
        // Advance memory before the first uncertain operation. It never moves back.
        self.current = intent;
        if self.persist_pair(&intent, true).is_err() {
            self.halted = true;
            return Err(IssueError::PersistenceUncertain);
        }

        if self.media.boundary(Boundary::SegmentPread).is_err() {
            return Err(IssueError::Io);
        }
        let body = self
            .reader
            .read(reserved.index)
            .map_err(|_| IssueError::Io)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&Sha256::digest(body));
        let commit = AnchorRecord::commit(
            self.book_id,
            reserved.generation,
            reserved.index.next(),
            SegmentHash(hash),
        );
        if self.persist_pair(&commit, false).is_err() {
            self.halted = true;
            return Err(IssueError::PersistenceUncertain);
        }
        self.current = commit;
        Ok(CommittedSegment { inner: body })
    }

    /// 原子预留 `n` 个连续段（fullotp-design §2.2 `reserve_range`；
    /// 耐久顺序等价 [`Self::issue`]，任何不确定均浪费整个范围，
    /// 绝不部分回收）。
    ///
    /// INTENT 复用既有线格式：`reserved = base+n-1`（范围末段），
    /// `next = base+n`（既有 `reserved+1 == next` 约束天然成立）。因此
    /// INTENT 任一副本落盘后，恢复 adopt-higher 直接从 `base+n` 继续——
    /// 范围内全部段保守浪费；COMMIT 同样携带范围末段哈希，与启动校验
    /// （验证 `next-1` 段哈希）一致。
    fn reserve_range(&mut self, n: u64) -> Result<ReservedRange, IssueError> {
        if self.halted {
            return Err(IssueError::PersistenceUncertain);
        }
        if n == 0 {
            return Err(IssueError::InvalidRange);
        }
        let base = self.current.next;
        let new_next = base.get().checked_add(n).ok_or(IssueError::InvalidRange)?;
        if new_next > self.reader.segment_count() {
            return Err(IssueError::Exhausted { next: base });
        }
        let n_usize = usize::try_from(n).map_err(|_| IssueError::InvalidRange)?;
        let generation = Generation::new(self.current.generation.get().checked_add(1).ok_or_else(
            || {
                self.halted = true;
                IssueError::PersistenceUncertain
            },
        )?);
        let last = SegmentIndex::new(new_next - 1);
        let intent = AnchorRecord::intent(self.book_id, generation, last);
        // 先推进内存（任何不确定后不回退；范围 [base, base+n) 全部标花费）
        self.current = intent;
        if self.persist_pair(&intent, true).is_err() {
            self.halted = true;
            return Err(IssueError::PersistenceUncertain);
        }

        if self.media.boundary(Boundary::SegmentPread).is_err() {
            return Err(IssueError::Io);
        }
        let mut bytes = Vec::with_capacity(n_usize * SEGMENT_LEN);
        for i in 0..n {
            let body = self
                .reader
                .read(SegmentIndex::new(base.get() + i))
                .map_err(|_| IssueError::Io)?;
            bytes.extend_from_slice(&body);
        }
        let mut hash = [0u8; 32];
        let last_off = bytes.len() - SEGMENT_LEN;
        hash.copy_from_slice(&Sha256::digest(&bytes[last_off..]));
        let commit = AnchorRecord::commit(
            self.book_id,
            generation,
            SegmentIndex::new(new_next),
            SegmentHash(hash),
        );
        if self.persist_pair(&commit, false).is_err() {
            self.halted = true;
            return Err(IssueError::PersistenceUncertain);
        }
        self.current = commit;
        Ok(ReservedRange { base, bytes })
    }

    fn persist_pair(&mut self, record: &AnchorRecord, intent: bool) -> Result<(), MediaError> {
        let points = if intent {
            [
                (
                    Boundary::IntentAWriteStart,
                    Boundary::IntentAWriteComplete,
                    Boundary::IntentAFsyncStart,
                    Boundary::IntentAFsyncReturn,
                ),
                (
                    Boundary::IntentBWriteStart,
                    Boundary::IntentBWriteComplete,
                    Boundary::IntentBFsyncStart,
                    Boundary::IntentBFsyncReturn,
                ),
            ]
        } else {
            [
                (
                    Boundary::FinalAWriteStart,
                    Boundary::FinalAWriteComplete,
                    Boundary::FinalAFsyncStart,
                    Boundary::FinalAFsyncReturn,
                ),
                (
                    Boundary::FinalBWriteStart,
                    Boundary::FinalBWriteComplete,
                    Boundary::FinalBFsyncStart,
                    Boundary::FinalBFsyncReturn,
                ),
            ]
        };
        for (copy, (ws, wc, ss, sr)) in [AnchorCopy::A, AnchorCopy::B].into_iter().zip(points) {
            self.media.boundary(ws)?;
            let mut bytes = Vec::with_capacity(otp_anchor_spec::ANCHOR_RECORD_LEN);
            encode_record(record, &mut bytes);
            self.media.write(copy, &bytes)?;
            self.media.boundary(wc)?;
            self.media.boundary(ss)?;
            self.media.sync(copy)?;
            self.media.boundary(sr)?;
        }
        Ok(())
    }
}

fn read_record<M: AnchorMedia>(
    media: &mut M,
    copy: AnchorCopy,
) -> Result<AnchorRecord, IssueError> {
    let bytes = media.read(copy).map_err(|_| IssueError::AnchorCorrupt)?;
    decode_and_verify(&bytes).map_err(|_| IssueError::AnchorCorrupt)
}

fn persist_one<M: AnchorMedia>(
    media: &mut M,
    copy: AnchorCopy,
    record: &AnchorRecord,
) -> Result<(), MediaError> {
    let mut bytes = Vec::with_capacity(otp_anchor_spec::ANCHOR_RECORD_LEN);
    encode_record(record, &mut bytes);
    media.write(copy, &bytes)?;
    media.sync(copy)
}

struct FileMedia {
    a: File,
    b: File,
}

impl FileMedia {
    fn open(a: &Path, b: &Path) -> Result<Self, IssueError> {
        fn one(path: &Path) -> Result<File, IssueError> {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(|_| IssueError::AnchorCorrupt)
        }
        Ok(Self {
            a: one(a)?,
            b: one(b)?,
        })
    }

    fn file(&mut self, copy: AnchorCopy) -> &mut File {
        match copy {
            AnchorCopy::A => &mut self.a,
            AnchorCopy::B => &mut self.b,
        }
    }
}

impl AnchorMedia for FileMedia {
    fn read(&mut self, copy: AnchorCopy) -> Result<Vec<u8>, MediaError> {
        let file = self.file(copy);
        file.seek(SeekFrom::Start(0)).map_err(|_| MediaError::Io)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|_| MediaError::Io)?;
        Ok(bytes)
    }

    fn write(&mut self, copy: AnchorCopy, bytes: &[u8]) -> Result<(), MediaError> {
        let file = self.file(copy);
        file.seek(SeekFrom::Start(0))
            .map_err(classify_persistence)?;
        let mut remaining = bytes;
        while !remaining.is_empty() {
            match file.write(remaining) {
                Ok(0) => return Err(MediaError::ShortWrite),
                Ok(n) => remaining = &remaining[n..],
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(classify_persistence(e)),
            }
        }
        file.set_len(bytes.len() as u64)
            .map_err(classify_persistence)
    }

    fn sync(&mut self, copy: AnchorCopy) -> Result<(), MediaError> {
        fsync_file(self.file(copy)).map_err(|_| MediaError::Persistence)
    }

    fn boundary(&mut self, _point: Boundary) -> Result<(), MediaError> {
        Ok(())
    }
}

struct BookReader {
    book: Book,
}

impl SegmentReader for BookReader {
    fn segment_count(&self) -> u64 {
        self.book.segment_count()
    }

    fn read(&mut self, index: SegmentIndex) -> Result<[u8; SEGMENT_LEN], MediaError> {
        let segment = self.book.read_segment(index).map_err(|_| MediaError::Io)?;
        Ok(segment.0)
    }
}

fn classify_persistence(error: std::io::Error) -> MediaError {
    if error.raw_os_error() == Some(28) {
        MediaError::NoSpace
    } else {
        MediaError::Persistence
    }
}

fn map_book_open(error: BookError) -> IssueError {
    match error {
        BookError::InvalidHeader { .. } => IssueError::BookMismatch,
        _ => IssueError::Io,
    }
}

fn map_platform(error: PlatformError) -> IssueError {
    match error {
        PlatformError::LockHeld | PlatformError::LockUnsupported => IssueError::LockUnavailable,
        _ => IssueError::PersistenceUncertain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::unix::fs::FileExt;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;
    use std::thread;
    use std::time::{Duration, Instant};

    const ID: BookId = BookId::from_bytes(*b"OTPTERM-TESTBOOK");

    const ALL_BOUNDARIES: [Boundary; 17] = [
        Boundary::IntentAWriteStart,
        Boundary::IntentAWriteComplete,
        Boundary::IntentAFsyncStart,
        Boundary::IntentAFsyncReturn,
        Boundary::IntentBWriteStart,
        Boundary::IntentBWriteComplete,
        Boundary::IntentBFsyncStart,
        Boundary::IntentBFsyncReturn,
        Boundary::SegmentPread,
        Boundary::FinalAWriteStart,
        Boundary::FinalAWriteComplete,
        Boundary::FinalAFsyncStart,
        Boundary::FinalAFsyncReturn,
        Boundary::FinalBWriteStart,
        Boundary::FinalBWriteComplete,
        Boundary::FinalBFsyncStart,
        Boundary::FinalBFsyncReturn,
    ];

    #[derive(Clone)]
    struct MemoryMedia {
        volatile: [Vec<u8>; 2],
        durable: [Vec<u8>; 2],
        fail: Option<(Boundary, MediaError)>,
        trace: Vec<Boundary>,
    }

    impl MemoryMedia {
        fn initialized(count: u64) -> (Self, MemoryReader) {
            let mut bytes = Vec::new();
            encode_record(&AnchorRecord::init(ID), &mut bytes);
            (
                Self {
                    volatile: [bytes.clone(), bytes.clone()],
                    durable: [bytes.clone(), bytes],
                    fail: None,
                    trace: Vec::new(),
                },
                MemoryReader {
                    segments: (0..count).map(|i| [i as u8; SEGMENT_LEN]).collect(),
                    reads: 0,
                    fail: false,
                },
            )
        }

        fn slot(copy: AnchorCopy) -> usize {
            usize::from(copy == AnchorCopy::B)
        }
    }

    impl AnchorMedia for MemoryMedia {
        fn read(&mut self, copy: AnchorCopy) -> Result<Vec<u8>, MediaError> {
            Ok(self.durable[Self::slot(copy)].clone())
        }

        fn write(&mut self, copy: AnchorCopy, bytes: &[u8]) -> Result<(), MediaError> {
            self.volatile[Self::slot(copy)] = bytes.to_vec();
            Ok(())
        }

        fn sync(&mut self, copy: AnchorCopy) -> Result<(), MediaError> {
            self.durable[Self::slot(copy)] = self.volatile[Self::slot(copy)].clone();
            Ok(())
        }

        fn boundary(&mut self, point: Boundary) -> Result<(), MediaError> {
            self.trace.push(point);
            if self.fail.map(|v| v.0) == Some(point) {
                Err(self.fail.unwrap().1)
            } else {
                Ok(())
            }
        }
    }

    #[derive(Clone)]
    struct MemoryReader {
        segments: Vec<[u8; SEGMENT_LEN]>,
        reads: usize,
        fail: bool,
    }

    impl SegmentReader for MemoryReader {
        fn segment_count(&self) -> u64 {
            self.segments.len() as u64
        }

        fn read(&mut self, index: SegmentIndex) -> Result<[u8; SEGMENT_LEN], MediaError> {
            self.reads += 1;
            if self.fail {
                Err(MediaError::Io)
            } else {
                self.segments
                    .get(index.get() as usize)
                    .copied()
                    .ok_or(MediaError::Io)
            }
        }
    }

    fn restart(
        media: MemoryMedia,
        reader: MemoryReader,
    ) -> TransactionCore<MemoryMedia, MemoryReader> {
        TransactionCore::open(media, reader, ID).unwrap()
    }

    struct KillMedia {
        inner: FileMedia,
        kill_at: Boundary,
        marker: PathBuf,
    }

    impl AnchorMedia for KillMedia {
        fn read(&mut self, copy: AnchorCopy) -> Result<Vec<u8>, MediaError> {
            self.inner.read(copy)
        }

        fn write(&mut self, copy: AnchorCopy, bytes: &[u8]) -> Result<(), MediaError> {
            self.inner.write(copy, bytes)
        }

        fn sync(&mut self, copy: AnchorCopy) -> Result<(), MediaError> {
            self.inner.sync(copy)
        }

        fn boundary(&mut self, point: Boundary) -> Result<(), MediaError> {
            if point == self.kill_at {
                let mut marker = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.marker)
                    .map_err(|_| MediaError::Io)?;
                writeln!(marker, "{point:?}").map_err(|_| MediaError::Io)?;
                marker.sync_all().map_err(|_| MediaError::Persistence)?;
                loop {
                    thread::sleep(Duration::from_secs(1));
                }
            }
            Ok(())
        }
    }

    struct FileSegmentReader {
        file: File,
        count: u64,
    }

    impl SegmentReader for FileSegmentReader {
        fn segment_count(&self) -> u64 {
            self.count
        }

        fn read(&mut self, index: SegmentIndex) -> Result<[u8; SEGMENT_LEN], MediaError> {
            let mut body = [0; SEGMENT_LEN];
            self.file
                .read_exact_at(&mut body, 128 + index.get() * SEGMENT_LEN as u64)
                .map_err(|_| MediaError::Io)?;
            Ok(body)
        }
    }

    fn file_reader(path: &Path, count: u64) -> FileSegmentReader {
        FileSegmentReader {
            file: File::open(path).unwrap(),
            count,
        }
    }

    fn write_initial_files(dir: &Path) {
        write_initial_files_with_count(dir, 3);
    }

    /// 指定段数的初始文件夹具（reserve_range 测试需要更大的本）。
    fn write_initial_files_with_count(dir: &Path, count: u64) {
        std::fs::create_dir_all(dir).unwrap();
        let mut anchor = Vec::new();
        encode_record(&AnchorRecord::init(ID), &mut anchor);
        for name in ["a.anchor", "b.anchor"] {
            let file = File::create(dir.join(name)).unwrap();
            (&file).write_all(&anchor).unwrap();
            file.sync_all().unwrap();
        }
        let file = File::create(dir.join("segments.bin")).unwrap();
        let header = crate::header::BookHeader::new(ID, count).unwrap().encode();
        (&file).write_all(&header).unwrap();
        for value in 0..count {
            let mut seg = [0u8; SEGMENT_LEN];
            // 段 i 内容确定性可验：seg[i][j] = (i ^ j) & 0xFF
            // （byte0 == i 保持既有 issue 崩溃测试断言；位置相关支持范围校验）
            for (j, b) in seg.iter_mut().enumerate() {
                *b = (value as u8) ^ (j as u8);
            }
            (&file).write_all(&seg).unwrap();
        }
        file.sync_all().unwrap();
    }

    fn boundary_from_name(name: &str) -> Boundary {
        ALL_BOUNDARIES
            .into_iter()
            .find(|point| format!("{point:?}") == name)
            .unwrap()
    }

    #[test]
    fn exact_transaction_trace_and_committed_only_output() {
        let (media, reader) = MemoryMedia::initialized(2);
        let mut core = restart(media, reader);
        let segment = core.issue().unwrap();
        assert_eq!(segment.as_bytes(), &[0; SEGMENT_LEN]);
        assert_eq!(core.state(), (SegmentIndex::new(1), Generation::new(1)));
        assert_eq!(
            core.media.trace,
            vec![
                Boundary::IntentAWriteStart,
                Boundary::IntentAWriteComplete,
                Boundary::IntentAFsyncStart,
                Boundary::IntentAFsyncReturn,
                Boundary::IntentBWriteStart,
                Boundary::IntentBWriteComplete,
                Boundary::IntentBFsyncStart,
                Boundary::IntentBFsyncReturn,
                Boundary::SegmentPread,
                Boundary::FinalAWriteStart,
                Boundary::FinalAWriteComplete,
                Boundary::FinalAFsyncStart,
                Boundary::FinalAFsyncReturn,
                Boundary::FinalBWriteStart,
                Boundary::FinalBWriteComplete,
                Boundary::FinalBFsyncStart,
                Boundary::FinalBFsyncReturn,
            ]
        );
    }

    #[test]
    fn every_boundary_failure_is_fail_closed_and_reserved_segment_is_not_reused() {
        for point in ALL_BOUNDARIES {
            let (media, reader) = MemoryMedia::initialized(3);
            let mut core = restart(media, reader);
            core.media.fail = Some((point, MediaError::Io));
            let _ = core.issue();
            let durable = core.media.durable.clone();
            let mut reboot_media = core.media.clone();
            reboot_media.volatile = durable.clone();
            reboot_media.durable = durable;
            reboot_media.fail = None;
            reboot_media.trace.clear();
            let mut rebooted = restart(reboot_media, core.reader.clone());
            let recovered_next = rebooted.current.next.get();
            if matches!(
                point,
                Boundary::IntentAWriteStart
                    | Boundary::IntentAWriteComplete
                    | Boundary::IntentAFsyncStart
            ) {
                assert_eq!(recovered_next, 0, "{point:?}");
            } else {
                assert!(recovered_next >= 1, "{point:?}");
                let _ = rebooted.issue().unwrap();
                assert_eq!(rebooted.current.next.get(), 2, "{point:?}");
            }
        }
    }

    #[test]
    fn kill_boundary_child() {
        let Ok(dir) = std::env::var("OTP_ALLOCATOR_KILL_DIR") else {
            return;
        };
        let point = boundary_from_name(&std::env::var("OTP_ALLOCATOR_KILL_POINT").unwrap());
        let dir = PathBuf::from(dir);
        let media = KillMedia {
            inner: FileMedia::open(&dir.join("a.anchor"), &dir.join("b.anchor")).unwrap(),
            kill_at: point,
            marker: dir.join("reached"),
        };
        let reader = file_reader(&dir.join("segments.bin"), 3);
        let mut core = TransactionCore::open(media, reader, ID).unwrap();
        let _ = core.issue();
        panic!("kill boundary was not reached: {point:?}");
    }

    #[test]
    fn sigkill_at_every_boundary_recovers_without_reusing_observable_reservation() {
        let root =
            std::env::temp_dir().join(format!("otp-allocator-kill-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        for point in ALL_BOUNDARIES {
            let dir = root.join(format!("{point:?}"));
            write_initial_files(&dir);
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "allocator::tests::kill_boundary_child",
                    "--nocapture",
                ])
                .env("OTP_ALLOCATOR_KILL_DIR", &dir)
                .env("OTP_ALLOCATOR_KILL_POINT", format!("{point:?}"))
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while !dir.join("reached").exists() {
                assert!(Instant::now() < deadline, "child did not reach {point:?}");
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "child exited at {point:?}"
                );
                thread::sleep(Duration::from_millis(10));
            }
            assert!(
                Command::new("kill")
                    .args(["-9", &child.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
            assert_eq!(child.wait().unwrap().signal(), Some(9), "{point:?}");

            let media = FileMedia::open(&dir.join("a.anchor"), &dir.join("b.anchor")).unwrap();
            let reader = file_reader(&dir.join("segments.bin"), 3);
            let mut recovered = TransactionCore::open(media, reader, ID).unwrap();
            let recovered_next = recovered.current.next.get();
            if point == Boundary::IntentAWriteStart {
                assert_eq!(recovered_next, 0, "pre-write kill must be a no-op");
            } else {
                assert!(
                    recovered_next >= 1,
                    "observable reservation reused at {point:?}"
                );
            }
            let issued = recovered.issue().unwrap();
            assert_eq!(issued.as_bytes()[0], recovered_next as u8, "{point:?}");
            assert_eq!(
                recovered.current.next.get(),
                recovered_next + 1,
                "{point:?}"
            );
            println!(
                "KILL_TRACE point={point:?} signal=9 recovered_next={recovered_next} next_after_issue={}",
                recovered.current.next.get()
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn persistence_errors_halt_but_pread_error_wastes_and_continues() {
        for error in [
            MediaError::Persistence,
            MediaError::NoSpace,
            MediaError::ShortWrite,
        ] {
            let (media, reader) = MemoryMedia::initialized(3);
            let mut core = restart(media, reader);
            core.media.fail = Some((Boundary::FinalBFsyncReturn, error));
            assert_eq!(core.issue().err(), Some(IssueError::PersistenceUncertain));
            assert_eq!(core.issue().err(), Some(IssueError::PersistenceUncertain));
        }

        let (media, mut reader) = MemoryMedia::initialized(3);
        reader.fail = true;
        let mut core = restart(media, reader);
        assert_eq!(core.issue().err(), Some(IssueError::Io));
        core.reader.fail = false;
        assert!(core.issue().is_ok());
        assert_eq!(core.current.next, SegmentIndex::new(2));
    }

    #[test]
    fn exhausted_is_noop_and_never_preads() {
        let (media, reader) = MemoryMedia::initialized(1);
        let mut core = restart(media, reader);
        core.issue().unwrap();
        let reads = core.reader.reads;
        let state = core.current;
        assert_eq!(
            core.issue().err(),
            Some(IssueError::Exhausted {
                next: SegmentIndex::new(1)
            })
        );
        assert_eq!(core.reader.reads, reads);
        assert_eq!(core.current, state);
    }

    // ── reserve_range（fullotp-design §2.2）：范围事务、故障矩阵、崩溃注入 ──

    fn reboot(
        media: MemoryMedia,
        reader: MemoryReader,
    ) -> TransactionCore<MemoryMedia, MemoryReader> {
        TransactionCore::open(media, reader, ID).unwrap()
    }

    #[test]
    fn reserve_range_exact_transaction_trace_and_content() {
        let (media, reader) = MemoryMedia::initialized(256);
        let mut core = reboot(media, reader);
        let range = core.reserve_range(128).unwrap();
        assert_eq!(range.base(), SegmentIndex::new(0));
        assert_eq!(range.segment_count(), 128);
        assert_eq!(range.flat_bytes().len(), 128 * SEGMENT_LEN);
        // 内容按段序逐字对应 MemoryReader 夹具（seg i = [i;64]）
        for i in 0..128u64 {
            let seg = &range.flat_bytes()[(i as usize) * SEGMENT_LEN..][..SEGMENT_LEN];
            assert!(seg.iter().all(|&b| b == i as u8), "段 {i} 内容错位");
        }
        assert_eq!(core.state(), (SegmentIndex::new(128), Generation::new(1)));
        assert_eq!(
            core.media.trace,
            vec![
                Boundary::IntentAWriteStart,
                Boundary::IntentAWriteComplete,
                Boundary::IntentAFsyncStart,
                Boundary::IntentAFsyncReturn,
                Boundary::IntentBWriteStart,
                Boundary::IntentBWriteComplete,
                Boundary::IntentBFsyncStart,
                Boundary::IntentBFsyncReturn,
                Boundary::SegmentPread,
                Boundary::FinalAWriteStart,
                Boundary::FinalAWriteComplete,
                Boundary::FinalAFsyncStart,
                Boundary::FinalAFsyncReturn,
                Boundary::FinalBWriteStart,
                Boundary::FinalBWriteComplete,
                Boundary::FinalBFsyncStart,
                Boundary::FinalBFsyncReturn,
            ]
        );
    }

    #[test]
    fn reserve_range_every_boundary_failure_never_partially_reuses() {
        // §2.2：任何不确定均浪费整个范围，绝不部分回收——恢复后
        // next ∈ {0, 128}（0 仅限 INTENT 未落盘的三个边界），永不为 1..=127
        for point in ALL_BOUNDARIES {
            let (media, reader) = MemoryMedia::initialized(256);
            let mut core = reboot(media, reader);
            core.media.fail = Some((point, MediaError::Io));
            let _ = core.reserve_range(128);
            let durable = core.media.durable.clone();
            let mut reboot_media = core.media.clone();
            reboot_media.volatile = durable.clone();
            reboot_media.durable = durable;
            reboot_media.fail = None;
            reboot_media.trace.clear();
            let mut rebooted = reboot(reboot_media, core.reader.clone());
            let recovered = rebooted.current.next.get();
            let intent_not_durable = matches!(
                point,
                Boundary::IntentAWriteStart
                    | Boundary::IntentAWriteComplete
                    | Boundary::IntentAFsyncStart
            );
            if intent_not_durable {
                assert_eq!(recovered, 0, "{point:?}");
            } else {
                assert_eq!(recovered, 128, "{point:?}: INTENT 已落盘 ⇒ 整范围浪费");
            }
            // 恢复后可继续预留新范围（从浪费后的 next 起，绝不重叠旧范围）
            let again = rebooted.reserve_range(128).unwrap();
            assert_eq!(again.base().get(), recovered);
            assert_eq!(rebooted.current.next.get(), recovered + 128);
        }
    }

    #[test]
    fn reserve_range_invalid_and_exhausted_are_noop() {
        let (media, reader) = MemoryMedia::initialized(3);
        let mut core = reboot(media, reader);
        assert_eq!(core.reserve_range(0).err(), Some(IssueError::InvalidRange));
        assert_eq!(
            core.reserve_range(128).err(),
            Some(IssueError::Exhausted {
                next: SegmentIndex::ZERO
            })
        );
        assert_eq!(core.media.trace, Vec::<Boundary>::new(), "无任何持久化动作");
        assert_eq!(core.reader.reads, 0);
        assert_eq!(core.current.next, SegmentIndex::ZERO);
        // 溢出：先预留 128（本 300 段），再 u64::MAX ⇒ checked_add 溢出
        let (media, reader) = MemoryMedia::initialized(300);
        let mut core2 = reboot(media, reader);
        core2.reserve_range(128).unwrap();
        assert_eq!(
            core2.reserve_range(u64::MAX).err(),
            Some(IssueError::InvalidRange)
        );
        assert_eq!(core2.current.next.get(), 128, "溢出拒绝不推进指针");
    }

    #[test]
    fn reserve_range_pread_failure_wastes_whole_range_and_continues() {
        let (media, mut reader) = MemoryMedia::initialized(256);
        reader.fail = true;
        let mut core = reboot(media, reader);
        assert_eq!(core.reserve_range(128).err(), Some(IssueError::Io));
        // INTENT 已落盘 ⇒ 范围 [0,128) 保守浪费；不 halt，可继续
        core.reader.fail = false;
        let durable = core.media.durable.clone();
        let mut reboot_media = core.media.clone();
        reboot_media.volatile = durable.clone();
        reboot_media.durable = durable;
        reboot_media.fail = None;
        reboot_media.trace.clear();
        let mut rebooted = reboot(reboot_media, core.reader.clone());
        assert_eq!(rebooted.current.next.get(), 128);
        let again = rebooted.reserve_range(128).unwrap();
        assert_eq!(again.base().get(), 128);
    }

    #[test]
    fn issue_and_reserve_interleave_across_reboots() {
        // 握手段（issue）与 bundle（reserve）交替：generation 单调，锚一致
        let (media, reader) = MemoryMedia::initialized(300);
        let mut core = reboot(media, reader);
        core.issue().unwrap(); // 首个握手段：段 0（不属于 bundle）
        let range = core.reserve_range(128).unwrap(); // bundle 0：[1, 129)
        assert_eq!(range.base().get(), 1);
        core.issue().unwrap(); // 后续会话握手段：段 129
        assert_eq!(core.state(), (SegmentIndex::new(130), Generation::new(3)));
        // 重启后状态一致（COMMIT 哈希 = 范围末段/签发段哈希）
        let durable = core.media.durable.clone();
        let mut reboot_media = core.media.clone();
        reboot_media.volatile = durable.clone();
        reboot_media.durable = durable;
        reboot_media.trace.clear();
        let mut rebooted = reboot(reboot_media, core.reader.clone());
        assert_eq!(
            rebooted.state(),
            (SegmentIndex::new(130), Generation::new(3))
        );
        let next_bundle = rebooted.reserve_range(128).unwrap();
        assert_eq!(next_bundle.base().get(), 130);
    }

    #[test]
    fn reserve_kill_boundary_child() {
        let Ok(dir) = std::env::var("OTP_ALLOCATOR_KILL_DIR") else {
            return;
        };
        let point = boundary_from_name(&std::env::var("OTP_ALLOCATOR_KILL_POINT").unwrap());
        let dir = PathBuf::from(dir);
        let media = KillMedia {
            inner: FileMedia::open(&dir.join("a.anchor"), &dir.join("b.anchor")).unwrap(),
            kill_at: point,
            marker: dir.join("reached"),
        };
        let reader = file_reader(&dir.join("segments.bin"), 512);
        let mut core = TransactionCore::open(media, reader, ID).unwrap();
        let _ = core.reserve_range(128);
        panic!("kill boundary was not reached: {point:?}");
    }

    #[test]
    fn sigkill_at_every_boundary_of_range_reservation_wastes_whole_range() {
        // 崩溃注入（任务 #75 验收）：reserve 中途 kill = 整范围浪费。
        // 恢复后 next ∈ {0, 128}，永不为 1..=127（部分回收即段复用风险）。
        let root =
            std::env::temp_dir().join(format!("otp-allocator-reserve-kill-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        for point in ALL_BOUNDARIES {
            let dir = root.join(format!("{point:?}"));
            write_initial_files_with_count(&dir, 512);
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "allocator::tests::reserve_kill_boundary_child",
                    "--nocapture",
                ])
                .env("OTP_ALLOCATOR_KILL_DIR", &dir)
                .env("OTP_ALLOCATOR_KILL_POINT", format!("{point:?}"))
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while !dir.join("reached").exists() {
                assert!(Instant::now() < deadline, "child did not reach {point:?}");
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "child exited at {point:?}"
                );
                thread::sleep(Duration::from_millis(10));
            }
            assert!(
                Command::new("kill")
                    .args(["-9", &child.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
            assert_eq!(child.wait().unwrap().signal(), Some(9), "{point:?}");

            let media = FileMedia::open(&dir.join("a.anchor"), &dir.join("b.anchor")).unwrap();
            let reader = file_reader(&dir.join("segments.bin"), 512);
            let mut recovered = TransactionCore::open(media, reader, ID).unwrap();
            let recovered_next = recovered.current.next.get();
            // 物理口径与既有 issue() 崩溃测试一致：SIGKILL 后页缓存写入仍对
            // 重启可见，故仅首个写前的边界为 0；其余一律整范围浪费（128）。
            // 核心断言：**永不为 1..=127**（部分回收 = 段复用风险）。
            let intent_not_durable = matches!(point, Boundary::IntentAWriteStart);
            if intent_not_durable {
                assert_eq!(recovered_next, 0, "pre-write kill must be a no-op");
            } else {
                assert_eq!(
                    recovered_next, 128,
                    "{point:?}: kill 后必须整范围浪费，禁止部分回收/复用"
                );
            }
            // 恢复后继续预留：从 waste 后指针起，绝不重叠旧范围
            let again = recovered.reserve_range(128).unwrap();
            assert_eq!(again.base().get(), recovered_next);
            assert_eq!(again.segment_count(), 128);
            assert_eq!(recovered.current.next.get(), recovered_next + 128);
            println!(
                "RESERVE_KILL_TRACE point={point:?} signal=9 recovered_next={recovered_next} \
                 next_after_reserve={}",
                recovered.current.next.get()
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    impl<M: AnchorMedia, R: SegmentReader> TransactionCore<M, R> {
        fn state(&self) -> (SegmentIndex, Generation) {
            (self.current.next, self.current.generation)
        }
    }
}
