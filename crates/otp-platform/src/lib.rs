//! Linux platform persistence primitives for OTP anchors.
//!
//! The APIs in this crate deliberately combine operations which must not be
//! separated by callers: complete writes, file sync, and (for newly-created
//! files) parent-directory sync.  All errors are fail-closed.
#![deny(unsafe_code)]

pub mod audit;
pub mod doctor;

pub use audit::{JsonlAuditSink, audit_entry_to_json, category_str, outcome_str};
pub use doctor::{
    DoctorCategory, DoctorFinding, DoctorPaths, DoctorReport, NO_BACKUP_MARKER,
    collect_backup_facts, collect_core_facts, collect_perm_facts, collect_swap_facts, eval_backup,
    eval_core, eval_perm, eval_swap, harden_process, parse_proc_swaps, run_doctor,
};

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use otp_types::{BookId, ErrorCategory, Generation, SegmentIndex};

/// A supported-filesystem, open-file-description lock.  Closing the owned
/// file description releases the lock, including on process death.
pub struct FileLockGuard {
    file: File,
    path: PathBuf,
}

impl FileLockGuard {
    /// File protected by this guard.
    pub fn file(&self) -> &File {
        &self.file
    }
    /// Lock-file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Lease guard with a persistent monotonic fencing token.
pub struct LeaseGuard {
    lock: FileLockGuard,
    /// Token persisted while holding the same exclusive OFD lock.
    pub fencing_token: u64,
}

impl LeaseGuard {
    /// Underlying lock (kept alive for the lease lifetime).
    pub fn lock(&self) -> &FileLockGuard {
        &self.lock
    }
}

/// Require a local filesystem whose lock and fsync semantics are accepted.
pub fn require_supported_filesystem(path: &Path) -> Result<(), PlatformError> {
    let probe = if path.exists() {
        path
    } else {
        path.parent().unwrap_or(Path::new("."))
    };
    let magic = statfs_magic(probe)?;
    // ext2/3/4, XFS and btrfs. Network, userspace, overlay and volatile
    // filesystems are fail-closed until separately qualified.
    match magic {
        0xEF53 | 0x5846_5342 | 0x9123_683E => Ok(()),
        0x6969 => Err(PlatformError::UnsupportedFilesystem { fs_name: "nfs" }),
        0x6573_5546 => Err(PlatformError::UnsupportedFilesystem { fs_name: "fuse" }),
        0x794C_7630 => Err(PlatformError::UnsupportedFilesystem { fs_name: "overlay" }),
        0x0102_1994 => Err(PlatformError::UnsupportedFilesystem { fs_name: "tmpfs" }),
        _ => Err(PlatformError::UnsupportedFilesystem { fs_name: "unknown" }),
    }
}

/// Acquire a non-blocking Linux OFD lock. Unsupported filesystems and kernels
/// are rejected rather than silently falling back to process-associated locks.
pub fn acquire_ofd_lock(path: &Path, exclusive: bool) -> Result<FileLockGuard, PlatformError> {
    require_supported_filesystem(path)?;
    acquire_ofd_lock_unchecked(path, exclusive)
}

fn acquire_ofd_lock_unchecked(
    path: &Path,
    exclusive: bool,
) -> Result<FileLockGuard, PlatformError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(PlatformError::from_io)?;
    let mut lock = libc::flock {
        l_type: if exclusive {
            libc::F_WRLCK as i16
        } else {
            libc::F_RDLCK as i16
        },
        l_whence: libc::SEEK_SET as i16,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    // SAFETY: fd is live; `lock` points to an initialized libc::flock for the
    // duration of fcntl. F_OFD_SETLK neither retains the pointer nor changes its type.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &mut lock) };
    if rc == -1 {
        let errno = io::Error::last_os_error().raw_os_error();
        return Err(match errno {
            Some(code) if code == libc::EAGAIN || code == libc::EACCES => PlatformError::LockHeld,
            Some(code) if code == libc::EINVAL || code == libc::ENOSYS || code == libc::ENOTSUP => {
                PlatformError::LockUnsupported
            }
            _ => PlatformError::Io,
        });
    }
    Ok(FileLockGuard {
        file,
        path: path.to_owned(),
    })
}

/// Allocate and persist a fencing token while holding the lease lock.
pub fn acquire_lease(path: &Path) -> Result<LeaseGuard, PlatformError> {
    let lock = acquire_ofd_lock(path, true)?;
    let mut f = lock.file.try_clone().map_err(PlatformError::from_io)?;
    f.seek(SeekFrom::Start(0)).map_err(PlatformError::from_io)?;
    let mut bytes = [0u8; 8];
    let n = f.read(&mut bytes).map_err(PlatformError::from_io)?;
    let old = if n == 0 {
        0
    } else if n == 8 {
        u64::from_le_bytes(bytes)
    } else {
        return Err(PlatformError::InvalidData);
    };
    let token = old.checked_add(1).ok_or(PlatformError::InvalidData)?;
    f.seek(SeekFrom::Start(0)).map_err(PlatformError::from_io)?;
    f.set_len(0).map_err(PlatformError::from_io)?;
    write_full(&mut f, &token.to_le_bytes())?;
    fsync_file(&f)?;
    Ok(LeaseGuard {
        lock,
        fencing_token: token,
    })
}

/// Writer abstraction used to exercise short writes and failures.
pub trait FullWrite {
    /// Write some bytes, with normal `Write::write` semantics.
    fn write_some(&mut self, data: &[u8]) -> io::Result<usize>;
}
impl<T: Write> FullWrite for T {
    fn write_some(&mut self, data: &[u8]) -> io::Result<usize> {
        self.write(data)
    }
}

/// Write every byte, retrying Interrupted and looping over short writes.
pub fn write_full<W: FullWrite + ?Sized>(
    writer: &mut W,
    mut data: &[u8],
) -> Result<(), PlatformError> {
    while !data.is_empty() {
        match writer.write_some(data) {
            Ok(0) => return Err(PlatformError::WriteZero),
            Ok(n) if n <= data.len() => data = &data[n..],
            Ok(_) => return Err(PlatformError::Io),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(PlatformError::from_io(e)),
        }
    }
    Ok(())
}

/// Sync file data and metadata; any error is an uncertain persistence result.
pub fn fsync_file(file: &File) -> Result<(), PlatformError> {
    file.sync_all().map_err(|_| PlatformError::FsyncUncertain)
}

/// Open and fsync a directory to persist directory-entry changes.
pub fn fsync_dir(dir: &Path) -> Result<(), PlatformError> {
    let file = File::open(dir).map_err(PlatformError::from_io)?;
    fsync_file(&file)
}

/// Sync the parent iff the target was created by the current operation.
pub fn sync_parent_if_created(path: &Path, created: bool) -> Result<(), PlatformError> {
    if created {
        fsync_dir(path.parent().ok_or(PlatformError::InvalidData)?)
    } else {
        Ok(())
    }
}

/// Minimal anchor backend boundary. Verification belongs to the anchor-format
/// crate and is supplied as a closure, keeping unverified bytes out of callers.
pub trait AnchorBackend {
    /// Read bytes and return only verifier-approved data.
    fn read_verified<T, V>(&mut self, verify: V) -> Result<T, PlatformError>
    where
        V: FnOnce(&[u8]) -> Result<T, PlatformError>;
    /// Replace contents, loop over short writes, and fsync the file.
    fn write_full_and_sync(&mut self, data: &[u8]) -> Result<(), PlatformError>;
    /// If this backend created its file, fsync its parent exactly once.
    fn sync_parent_if_created(&mut self) -> Result<(), PlatformError>;
}

/// Production file anchor backend.
pub struct FileAnchorBackend {
    file: File,
    path: PathBuf,
    created: bool,
}
impl FileAnchorBackend {
    /// Open/create an anchor after filesystem capability probing.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PlatformError> {
        let path = path.as_ref();
        require_supported_filesystem(path)?;
        let created = !path.exists();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(PlatformError::from_io)?;
        Ok(Self {
            file,
            path: path.to_owned(),
            created,
        })
    }
}
impl AnchorBackend for FileAnchorBackend {
    fn read_verified<T, V>(&mut self, verify: V) -> Result<T, PlatformError>
    where
        V: FnOnce(&[u8]) -> Result<T, PlatformError>,
    {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(PlatformError::from_io)?;
        let mut bytes = Vec::new();
        self.file
            .read_to_end(&mut bytes)
            .map_err(PlatformError::from_io)?;
        verify(&bytes)
    }
    fn write_full_and_sync(&mut self, data: &[u8]) -> Result<(), PlatformError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(PlatformError::from_io)?;
        self.file.set_len(0).map_err(PlatformError::from_io)?;
        write_full(&mut self.file, data)?;
        fsync_file(&self.file)
    }
    fn sync_parent_if_created(&mut self) -> Result<(), PlatformError> {
        sync_parent_if_created(&self.path, self.created)?;
        self.created = false;
        Ok(())
    }
}

/// Named injection points consumed by WP-13.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPoint {
    Read,
    Write(usize),
    Fsync,
    ParentFsync,
    Crash,
}

/// Injectable in-memory anchor backend: short-write cap and errno/failure point.
pub struct FaultyAnchorBackend {
    data: Vec<u8>,
    pub short_write: Option<usize>,
    pub fail_at: Option<FaultPoint>,
    writes: usize,
    created: bool,
}
impl FaultyAnchorBackend {
    /// Empty newly-created backend.
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            short_write: None,
            fail_at: None,
            writes: 0,
            created: true,
        }
    }
    /// Current durable-model bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }
    fn fail(&self, point: FaultPoint) -> Result<(), PlatformError> {
        if self.fail_at == Some(point) {
            Err(if point == FaultPoint::Crash {
                PlatformError::CrashInjected
            } else {
                PlatformError::InjectedIo
            })
        } else {
            Ok(())
        }
    }
}
impl Default for FaultyAnchorBackend {
    fn default() -> Self {
        Self::new()
    }
}
impl AnchorBackend for FaultyAnchorBackend {
    fn read_verified<T, V>(&mut self, verify: V) -> Result<T, PlatformError>
    where
        V: FnOnce(&[u8]) -> Result<T, PlatformError>,
    {
        self.fail(FaultPoint::Read)?;
        verify(&self.data)
    }
    fn write_full_and_sync(&mut self, data: &[u8]) -> Result<(), PlatformError> {
        self.data.clear();
        self.writes = 0;
        while self.data.len() < data.len() {
            self.fail(FaultPoint::Write(self.writes))?;
            let cap = self.short_write.unwrap_or(data.len()).max(1);
            let end = (self.data.len() + cap).min(data.len());
            self.data.extend_from_slice(&data[self.data.len()..end]);
            self.writes += 1;
        }
        self.fail(FaultPoint::Fsync)?;
        self.fail(FaultPoint::Crash)
    }
    fn sync_parent_if_created(&mut self) -> Result<(), PlatformError> {
        if self.created {
            self.fail(FaultPoint::ParentFsync)?;
            self.created = false;
        }
        Ok(())
    }
}

/// Best-effort mlock. Failure is reported for doctor/policy but callers may warn.
pub fn mlock_best_effort(data: &mut [u8]) -> Result<(), PlatformError> {
    // SAFETY: the slice guarantees a valid address and length for this call;
    // mlock does not retain a userspace pointer beyond the mapped region.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::mlock(data.as_ptr().cast(), data.len()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(PlatformError::MlockFailed)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CheckStatus {
    Ok,
    Warn { detail: &'static str },
    Block { detail: &'static str },
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EnvironmentReport {
    pub core_dump: CheckStatus,
    pub swap: CheckStatus,
    pub filesystem: CheckStatus,
    pub permissions: CheckStatus,
}

/// Doctor skeleton with real core/swap/filesystem checks. Permission policy is
/// completed by WP-15 once book/anchor paths and ownership policy are wired.
pub fn probe_environment_for(anchor: &Path) -> EnvironmentReport {
    let core_dump = if core_limit() == Some(0) {
        CheckStatus::Ok
    } else {
        CheckStatus::Block {
            detail: "RLIMIT_CORE is not zero",
        }
    };
    let swap = match std::fs::read_to_string("/proc/swaps") {
        Ok(s) if s.lines().count() <= 1 => CheckStatus::Ok,
        Ok(_) => CheckStatus::Warn {
            detail: "swap enabled; require encrypted swap or mlock policy",
        },
        Err(_) => CheckStatus::Warn {
            detail: "cannot inspect /proc/swaps",
        },
    };
    let filesystem = match require_supported_filesystem(anchor) {
        Ok(()) => CheckStatus::Ok,
        Err(_) => CheckStatus::Block {
            detail: "anchor filesystem is unsupported or unknown",
        },
    };
    EnvironmentReport {
        core_dump,
        swap,
        filesystem,
        permissions: CheckStatus::Warn {
            detail: "permission policy pending WP-15 path configuration",
        },
    }
}
/// Backwards-compatible doctor entry point, probing the current directory.
pub fn probe_environment() -> EnvironmentReport {
    probe_environment_for(Path::new("."))
}

fn core_limit() -> Option<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid writable rlimit pointer; getrlimit initializes it synchronously.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) };
    (rc == 0).then_some(lim.rlim_cur)
}
fn statfs_magic(path: &Path) -> Result<i64, PlatformError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let p = CString::new(path.as_os_str().as_bytes()).map_err(|_| PlatformError::InvalidData)?;
    let mut out = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: CString is NUL-terminated and out points to writable statfs storage.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::statfs(p.as_ptr(), out.as_mut_ptr()) };
    if rc != 0 {
        return Err(PlatformError::Io);
    }
    // SAFETY: successful statfs initialized `out`.
    #[allow(unsafe_code)]
    Ok(unsafe { out.assume_init() }.f_type)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AuditEntry {
    pub book_id: BookId,
    pub segment: SegmentIndex,
    pub generation: Generation,
    pub outcome: Outcome,
    pub error_category: Option<ErrorCategory>,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    Issued,
    Wasted,
    Rejected,
    Recovered,
    Quarantined,
}
pub trait AuditLogSink {
    fn emit(&mut self, entry: &AuditEntry) -> Result<(), PlatformError>;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PlatformError {
    LockUnsupported,
    LockHeld,
    FsyncUncertain,
    UnsupportedFilesystem { fs_name: &'static str },
    Io,
    NoSpace,
    WriteZero,
    InvalidData,
    InjectedIo,
    CrashInjected,
    MlockFailed,
}
impl PlatformError {
    fn from_io(e: io::Error) -> Self {
        match e.raw_os_error() {
            Some(libc::ENOSPC) => Self::NoSpace,
            _ => Self::Io,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn short_writes_are_completed_and_faults_surface() {
        let mut b = FaultyAnchorBackend::new();
        b.short_write = Some(2);
        b.write_full_and_sync(b"abcdef").unwrap();
        assert_eq!(b.bytes(), b"abcdef");
        b.fail_at = Some(FaultPoint::Fsync);
        assert_eq!(b.write_full_and_sync(b"x"), Err(PlatformError::InjectedIo));
    }

    #[test]
    fn parent_sync_only_when_created() {
        let mut b = FaultyAnchorBackend::new();
        b.sync_parent_if_created().unwrap();
        b.fail_at = Some(FaultPoint::ParentFsync);
        assert!(b.sync_parent_if_created().is_ok());
    }

    #[test]
    fn unsupported_overlay_is_rejected_when_present() {
        if statfs_magic(Path::new(".")).unwrap() == 0x794C_7630 {
            assert!(matches!(
                require_supported_filesystem(Path::new(".")),
                Err(PlatformError::UnsupportedFilesystem { fs_name: "overlay" })
            ));
        }
    }

    // The parent test starts 32 independent copies of this test binary. Each
    // worker performs 1000 lock/read/increment/write/fsync operations.
    #[test]
    fn process_worker() {
        let Ok(path) = std::env::var("OTP_PLATFORM_WORKER") else {
            return;
        };
        let output = std::env::var("OTP_PLATFORM_OUTPUT").unwrap();
        let mut issued = Vec::with_capacity(1000);
        for _ in 0..1000 {
            loop {
                match acquire_ofd_lock_unchecked(Path::new(&path), true) {
                    Ok(g) => {
                        let mut f = g.file().try_clone().unwrap();
                        f.seek(SeekFrom::Start(0)).unwrap();
                        let mut buf = [0u8; 8];
                        let n = f.read(&mut buf).unwrap();
                        let v = if n == 0 { 0 } else { u64::from_le_bytes(buf) };
                        issued.push(v);
                        let next = v + 1;
                        f.seek(SeekFrom::Start(0)).unwrap();
                        f.set_len(0).unwrap();
                        write_full(&mut f, &next.to_le_bytes()).unwrap();
                        fsync_file(&f).unwrap();
                        break;
                    }
                    Err(PlatformError::LockHeld) => std::thread::yield_now(),
                    Err(e) => panic!("lock failed: {e:?}"),
                }
            }
        }
        let mut bytes = Vec::with_capacity(issued.len() * 8);
        for value in issued {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        std::fs::write(output, bytes).unwrap();
    }

    #[test]
    fn thirty_two_processes_allocate_unique_indices() {
        let base = std::env::temp_dir();
        // Production API rejects tmpfs/overlay. This test deliberately bypasses
        // only that deployment policy so CI can verify the OFD syscall itself.
        let path = base.join(format!(
            "otp-platform-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        File::create(&path).unwrap();
        let exe = std::env::current_exe().unwrap();
        let mut children = Vec::new();
        let mut outputs = Vec::new();
        for worker in 0..32 {
            let output = path.with_extension(format!("worker-{worker}"));
            children.push(
                Command::new(&exe)
                    .arg("--exact")
                    .arg("tests::process_worker")
                    .arg("--nocapture")
                    .env("OTP_PLATFORM_WORKER", &path)
                    .env("OTP_PLATFORM_OUTPUT", &output)
                    .spawn()
                    .unwrap(),
            );
            outputs.push(output);
        }
        for mut child in children {
            assert!(child.wait().unwrap().success());
        }
        let mut observed = Vec::with_capacity(32_000);
        for output in outputs {
            let bytes = std::fs::read(&output).unwrap();
            assert_eq!(bytes.len(), 8_000);
            observed.extend(
                bytes
                    .chunks_exact(8)
                    .map(|v| u64::from_le_bytes(v.try_into().unwrap())),
            );
            std::fs::remove_file(output).unwrap();
        }
        observed.sort_unstable();
        observed.dedup();
        assert_eq!(observed.len(), 32_000);
        assert_eq!(observed.first(), Some(&0));
        assert_eq!(observed.last(), Some(&31_999));
        let mut buf = [0u8; 8];
        File::open(&path).unwrap().read_exact(&mut buf).unwrap();
        assert_eq!(u64::from_le_bytes(buf), 32_000);
        std::fs::remove_file(path).unwrap();
    }
}
