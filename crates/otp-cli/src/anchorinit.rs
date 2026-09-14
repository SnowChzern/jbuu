//! # anchor init —— 首启初始化写路径（wp02 §2.5，任务 #66）
//!
//! v0.1 灰测首跑死锁的修复：新端点锚文件不存在时 doctor BLOCK 拒启
//! （fail-closed 正确），但此前 Init 锚只有 testkit 内存构造路径，CLI
//! 无落盘命令。本模块补上受控运维入口：
//!
//! - 记录 = [`AnchorRecord::init`] + [`encode_record`]（wp02 §2.6 golden#1，
//!   仅公开元数据，不含段材料）；
//! - 两处介质锚文件**均须不存在**：写前显式检查 + `O_CREAT|O_EXCL`
//!   原子兜底（存在即拒绝，防覆盖/防回滚）；
//! - 文件以 `O_EXCL`、mode 0600 创建，写满（短写循环）后 `fsync` 文件
//!   与父目录（目录项落盘，规划 §1.2）；
//! - 文件系统白名单（wp02 §2.7）：NFS/FUSE/overlay/tmpfs/未知一律拒绝
//!   初始化——与其让 serve 在 OFD 锁处拒启，不如在建锚时即 fail closed；
//! - 第二锚写失败/读回校验失败：尽力清理**本次新写**的半成品并返回
//!   错误（现场恢复到命令前状态；清理失败单独报错，绝不静默）。
//!
//! 红线（规划 §2）：错误输出只含公开元数据（路径/book_id/类别），锚
//! 记录本身即公开元数据，无秘密可泄；段材料在本模块不可达。

use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};

use otp_anchor_spec::{ANCHOR_RECORD_LEN, AnchorRecord, decode_and_verify, encode_record};
use otp_platform::{fsync_dir, fsync_file, require_supported_filesystem, write_full};
use otp_types::BookId;
use rustix::fs::{Mode, OFlags, open, unlink};

/// 初始化成功结果（公开元数据）。
#[derive(Clone, Debug)]
pub struct AnchorInitSummary {
    /// 写入两份的同一 Init 记录。
    pub record: AnchorRecord,
    /// 锚副本 A 路径。
    pub path_a: PathBuf,
    /// 锚副本 B 路径。
    pub path_b: PathBuf,
}

/// 初始化错误（fail-closed；不含任何秘密材料）。
#[derive(Debug)]
pub enum AnchorInitError {
    /// 锚路径已存在（O_EXCL 拒绝覆盖）。`existing` 为现存锚可读出的
    /// book_id（不可读/损坏为 None）；`mismatch` 表示其与目标密码本不符。
    AnchorExists {
        path: PathBuf,
        existing: Option<BookId>,
        mismatch: bool,
    },
    /// 两个位置参数指向同一路径（双锚必须位于独立介质，wp02 §2.7）。
    SamePath(PathBuf),
    /// 锚路径所在文件系统不在白名单。
    UnsupportedFilesystem(PathBuf),
    /// I/O 错误（创建/写/fsync 失败）。
    Io(PathBuf),
    /// 写后读回校验失败（所写字节与本应写入的 Init 记录不符）。
    VerifyFailed(PathBuf),
    /// 失败清理半成品未成功（现场残留，需人工处理）。
    CleanupFailed(PathBuf),
}

impl fmt::Display for AnchorInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnchorExists {
                path,
                existing,
                mismatch,
            } => match (existing, mismatch) {
                (Some(id), true) => write!(
                    f,
                    "锚 {} 已存在且 book_id={} 与目标密码本不匹配——O_EXCL 拒绝覆盖（防误毁/防回滚，请人工核对介质）",
                    path.display(),
                    hex(id.as_bytes())
                ),
                (Some(id), false) => write!(
                    f,
                    "锚 {} 已存在（book_id={}，疑似重复 init）——O_EXCL 拒绝覆盖",
                    path.display(),
                    hex(id.as_bytes())
                ),
                (None, _) => write!(
                    f,
                    "锚 {} 已存在且不可读/损坏——O_EXCL 拒绝覆盖（请人工检查现场）",
                    path.display()
                ),
            },
            Self::SamePath(p) => write!(
                f,
                "两个锚路径相同：{}（双锚须位于独立介质，wp02 §2.7）",
                p.display()
            ),
            Self::UnsupportedFilesystem(p) => write!(
                f,
                "锚路径 {} 所在文件系统不在白名单（仅 ext2/3/4、XFS、btrfs；NFS/FUSE/overlay/tmpfs 拒绝初始化）",
                p.display()
            ),
            Self::Io(p) => write!(f, "锚 {} 创建/写入/fsync 失败（I/O 错误）", p.display()),
            Self::VerifyFailed(p) => write!(
                f,
                "锚 {} 写后读回校验失败（与所写 Init 记录不符，fail closed）",
                p.display()
            ),
            Self::CleanupFailed(p) => write!(
                f,
                "失败清理未成功，半成品残留于 {}（O_EXCL 会拒绝下次 init，需人工处理）",
                p.display()
            ),
        }
    }
}

/// 首启初始化：向两处介质写同一 Init 锚（wp02 §2.5）。
///
/// 步骤：文件系统白名单探测 → 存在性前置检查（两锚均须不存在）→
/// `O_EXCL`/0600 创建并写满 104 字节 Init 记录 → fsync 文件 + 父目录 →
/// 读回校验。任一步失败：清理本次新写的半成品并返回错误。
pub fn init_anchor_pair(
    book_id: BookId,
    path_a: &Path,
    path_b: &Path,
) -> Result<AnchorInitSummary, AnchorInitError> {
    if path_a == path_b {
        return Err(AnchorInitError::SamePath(path_a.to_owned()));
    }

    // ① 文件系统白名单（锚不存在时探测父目录，与平台层同口径）。
    for path in [path_a, path_b] {
        require_supported_filesystem(path)
            .map_err(|_| AnchorInitError::UnsupportedFilesystem(path.to_owned()))?;
    }

    // ② 存在性前置检查：写任何字节之前确认两处均无锚（§2.5：存在即
    //    拒绝——避免写完 A 才发现 B 已存在的半初始化窗口；竞态兜底
    //    由 ③ 的 O_EXCL 原子保证）。
    for path in [path_a, path_b] {
        if path.exists() || path.is_symlink() {
            return Err(exists_err(path, book_id));
        }
    }

    // ③ 写两份同一 Init 记录（golden#1；encode_record 内含 SHA-256 校验）。
    let record = AnchorRecord::init(book_id);
    let mut bytes = Vec::with_capacity(ANCHOR_RECORD_LEN);
    encode_record(&record, &mut bytes);

    write_one(path_a, &bytes, book_id)?;
    if let Err(e) = write_one(path_b, &bytes, book_id) {
        cleanup_partial(path_a)?;
        return Err(e);
    }

    // ④ 读回校验：盘上字节必须解码回同一 Init 记录（双份）。
    for path in [path_a, path_b] {
        if std::fs::read(path)
            .ok()
            .and_then(|b| decode_and_verify(&b).ok())
            != Some(record)
        {
            let verify = AnchorInitError::VerifyFailed(path.to_owned());
            cleanup_partial(path_a)?;
            cleanup_partial(path_b)?;
            return Err(verify);
        }
    }

    Ok(AnchorInitSummary {
        record,
        path_a: path_a.to_owned(),
        path_b: path_b.to_owned(),
    })
}

/// 写单个锚：`O_CREAT|O_EXCL`（拒覆盖）+ 0600 + 写满 + fsync 文件与父目录。
fn write_one(path: &Path, bytes: &[u8], expected: BookId) -> Result<(), AnchorInitError> {
    let fd = open(
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR, // 0600：锚为持久状态文件，仅属主可读写
    )
    .map_err(|e| {
        let io: std::io::Error = e.into();
        if io.kind() == std::io::ErrorKind::AlreadyExists {
            exists_err(path, expected)
        } else {
            AnchorInitError::Io(path.to_owned())
        }
    })?;

    let mut file = File::from(fd);
    write_full(&mut file, bytes).map_err(|_| AnchorInitError::Io(path.to_owned()))?;
    fsync_file(&file).map_err(|_| AnchorInitError::Io(path.to_owned()))?;
    drop(file);
    fsync_dir(parent_dir(path)).map_err(|_| AnchorInitError::Io(path.to_owned()))?;
    Ok(())
}

/// 构造"锚已存在"错误：尽力读出现存锚的 book_id 供诊断（公开元数据）。
fn exists_err(path: &Path, expected: BookId) -> AnchorInitError {
    let existing = std::fs::read(path)
        .ok()
        .and_then(|b| decode_and_verify(&b).ok())
        .map(|r| r.book_id);
    AnchorInitError::AnchorExists {
        path: path.to_owned(),
        mismatch: existing.is_some_and(|id| id != expected),
        existing,
    }
}

/// 清理本次新写的半成品（unlink + 父目录 fsync，尽力而为）。
fn cleanup_partial(path: &Path) -> Result<(), AnchorInitError> {
    match unlink(path) {
        Ok(()) => {}
        Err(_) if !path.exists() => {}
        Err(_) => return Err(AnchorInitError::CleanupFailed(path.to_owned())),
    }
    // 目录项落盘（清理失败不影响"文件已不在"的事实，尽力即可）。
    let _ = fsync_dir(parent_dir(path));
    Ok(())
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use otp_anchor_spec::AnchorPayload;

    /// 锚初始化有文件系统白名单（拒绝 tmpfs 等），测试不能落
    /// `std::env::temp_dir()`（常见 tmpfs）——用构建树 target/ 下的
    /// 临时目录（构建盘为白名单文件系统；gitignore 已覆盖）。
    fn workdir(tag: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap_or(Path::new("."))
            .join("target")
            .join(format!("otp-cli-anchorinit-{}-{}", std::process::id(), tag));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const ID: BookId = BookId::from_bytes(*b"OTPTERM-TESTBOOK");

    #[test]
    fn init_writes_identical_init_records_0600() {
        let dir = workdir("pair");
        let (a, b) = (dir.join("a.anchor"), dir.join("c.anchor"));
        std::fs::remove_file(&a).ok();
        std::fs::remove_file(&b).ok();

        let summary = init_anchor_pair(ID, &a, &b).expect("双锚初始化应成功");
        assert_eq!(summary.record, AnchorRecord::init(ID));

        let mut expected = Vec::new();
        encode_record(&AnchorRecord::init(ID), &mut expected);
        for p in [&a, &b] {
            assert_eq!(
                std::fs::read(p).unwrap(),
                expected,
                "{p:?} 须为 golden#1 字节"
            );
            assert_eq!(
                std::fs::metadata(p).unwrap().len(),
                ANCHOR_RECORD_LEN as u64
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "锚文件必须 0600");
            }
            assert!(matches!(
                decode_and_verify(&std::fs::read(p).unwrap())
                    .unwrap()
                    .payload,
                AnchorPayload::Init
            ));
        }
        std::fs::remove_file(&a).ok();
        std::fs::remove_file(&b).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn init_refuses_when_either_anchor_exists() {
        let dir = workdir("exists");
        let (a, b) = (dir.join("a.anchor"), dir.join("c.anchor"));
        std::fs::remove_file(&a).ok();
        std::fs::remove_file(&b).ok();

        // B 预先存在（内容为另一 book_id 的 Init 锚）。
        let other = BookId::from_bytes(*b"OTPTERM-OTHERBK1");
        let mut bytes = Vec::new();
        encode_record(&AnchorRecord::init(other), &mut bytes);
        std::fs::write(&b, &bytes).unwrap();

        // 前置检查在任何写入之前生效：A 不得被创建（无半初始化窗口）。
        let err = init_anchor_pair(ID, &a, &b).expect_err("B 已存在必须拒绝");
        match &err {
            AnchorInitError::AnchorExists {
                existing: Some(id),
                mismatch: true,
                ..
            } => assert_eq!(*id, other),
            other_kind => panic!("期待 book_id 不匹配的 AnchorExists，得到 {other_kind:?}"),
        }
        assert!(!a.exists(), "拒绝时不得写入任何新锚");
        // A 存在而 B 不存在同样拒绝。
        std::fs::write(&a, &bytes).unwrap();
        std::fs::remove_file(&b).unwrap();
        assert!(matches!(
            init_anchor_pair(ID, &a, &b),
            Err(AnchorInitError::AnchorExists { .. })
        ));
        std::fs::remove_file(&a).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn init_refuses_same_path_and_reports_repeat_as_exists() {
        let dir = workdir("same");
        let a = dir.join("a.anchor");
        std::fs::remove_file(&a).ok();

        assert!(matches!(
            init_anchor_pair(ID, &a, &a),
            Err(AnchorInitError::SamePath(_))
        ));

        // 重复 init：同一 book_id 再跑 → AnchorExists（mismatch=false）。
        init_anchor_pair(ID, &a, &dir.join("c.anchor")).unwrap();
        let err = init_anchor_pair(ID, &a, &dir.join("c.anchor")).expect_err("重复 init 必须拒绝");
        match &err {
            AnchorInitError::AnchorExists {
                existing: Some(id),
                mismatch: false,
                ..
            } => assert_eq!(*id, ID),
            other_kind => panic!("期待同 id 的 AnchorExists，得到 {other_kind:?}"),
        }
        std::fs::remove_file(&a).ok();
        std::fs::remove_file(dir.join("c.anchor")).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
