//! Fail-to-waste OTP segment allocator.
//!
//! The transaction order is fixed: INTENT A write/sync, INTENT B write/sync,
//! segment pread, COMMIT A write/sync, COMMIT B write/sync. The allocator keeps
//! its OFD lock for its complete lifetime, including startup reconciliation.

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use otp_anchor_spec::{
    AnchorCopy, AnchorPayload, AnchorRecord, RecoveryDecision, SegmentHash, decide,
    decode_and_verify, encode_record,
};
use otp_book::{Book, BookError};
use otp_platform::{FileLockGuard, PlatformError, acquire_ofd_lock, fsync_file};
use otp_types::{BookId, Generation, SEGMENT_LEN, SegmentIndex};
use sha2::{Digest, Sha256};
use zeroize::ZeroizeOnDrop;

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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IssueError {
    Exhausted { next: SegmentIndex },
    LockUnavailable,
    PersistenceUncertain,
    AnchorCorrupt,
    BookMismatch,
    Io,
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
        let segment = self
            .book
            .__allocator_read_segment(index)
            .map_err(|_| MediaError::Io)?;
        Ok(*segment.expose_for_allocator())
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
        std::fs::create_dir_all(dir).unwrap();
        let mut anchor = Vec::new();
        encode_record(&AnchorRecord::init(ID), &mut anchor);
        for name in ["a.anchor", "b.anchor"] {
            let file = File::create(dir.join(name)).unwrap();
            (&file).write_all(&anchor).unwrap();
            file.sync_all().unwrap();
        }
        let file = File::create(dir.join("segments.bin")).unwrap();
        let header = otp_book::header::BookHeader::new(ID, 3).unwrap().encode();
        (&file).write_all(&header).unwrap();
        for value in 0..3u8 {
            (&file).write_all(&[value; SEGMENT_LEN]).unwrap();
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
                .args(["--exact", "tests::kill_boundary_child", "--nocapture"])
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

    impl<M: AnchorMedia, R: SegmentReader> TransactionCore<M, R> {
        fn state(&self) -> (SegmentIndex, Generation) {
            (self.current.next, self.current.generation)
        }
    }
}
