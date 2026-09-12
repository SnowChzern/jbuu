//! 测试密码本生成（设计书 §3：CSPRNG 离线生成；规划 §5 测试 1）。
//!
//! - 随机源为 OS CSPRNG（`getrandom`）；失败即终止（fail-closed），绝不降级
//!   为弱源或口令扩展；
//! - 输出文件以 `O_CREAT|O_EXCL`、mode 0600 创建：**拒绝覆盖已存在文件**
//!   （防误毁真实密码本，也防“生成一半的旧文件被当新本”）；
//! - 逐块生成（64 KiB/块）零填充后即时清零，峰值内存 ≤ 64 KiB；
//! - 写满后 `fsync` 文件与父目录（目录项落盘，规划 §1.2）；
//! - 任一步失败：尽力 `unlink` 半成品并返回错误（半成品残留在下次
//!   `O_EXCL` 重试时也会因已存在被拒绝，但清理是卫生要求）。

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::Path;

use super::header::{BookHeader, MAX_SEGMENT_COUNT};
use otp_types::BookId;
use rustix::fs::{Mode, OFlags, open, unlink};
use zeroize::Zeroizing;

/// 每块段数（64 KiB 段正文）。
const SEGMENTS_PER_CHUNK: u64 = 1024;

/// 生成错误（fail-closed；不含任何秘密材料）。
#[derive(Debug)]
pub enum GenerateError {
    /// 输出路径已存在（O_EXCL 拒绝覆盖）。
    PathExists,
    /// 段数非法（须 1..=MAX_SEGMENT_COUNT）。
    BadSegmentCount(u64),
    /// OS CSPRNG 失败：立即终止，绝不降级弱源。
    Csprng,
    /// I/O 错误。
    Io(std::io::Error),
}

impl std::fmt::Display for GenerateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathExists => write!(f, "输出路径已存在，拒绝覆盖（防误毁密码本）"),
            Self::BadSegmentCount(n) => write!(f, "段数非法：{n}（须 1..={MAX_SEGMENT_COUNT}）"),
            Self::Csprng => write!(f, "OS CSPRNG 失败，生成终止（不降级弱源）"),
            Self::Io(e) => write!(f, "生成 I/O 错误：{e}"),
        }
    }
}

impl std::error::Error for GenerateError {}

/// CSPRNG 生成一个随机 `BookId`（16 B，公开标识，非秘密）。
pub fn random_book_id() -> Result<BookId, GenerateError> {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).map_err(|_| GenerateError::Csprng)?;
    Ok(BookId::from_bytes(buf))
}

/// 生成测试密码本：`O_EXCL` 创建（拒绝覆盖）、CSPRNG 逐块填充、fsync 文件
/// 与父目录。成功返回已写出的文件头。
///
/// 仅限离线测试或受控工具环境调用（规划 §2 otp-cli 条目约束）。
pub fn generate_book(
    path: &Path,
    segment_count: u64,
    book_id: BookId,
) -> Result<BookHeader, GenerateError> {
    if segment_count == 0 || segment_count > MAX_SEGMENT_COUNT {
        return Err(GenerateError::BadSegmentCount(segment_count));
    }
    let header = BookHeader::new(book_id, segment_count)
        .map_err(|_| GenerateError::BadSegmentCount(segment_count))?;

    let fd = open(
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR, // 0600：密码本是秘密材料
    )
    .map_err(|e| {
        let e: std::io::Error = e.into();
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            GenerateError::PathExists
        } else {
            GenerateError::Io(e)
        }
    })?;

    let result = write_book_body(&fd, &header);
    let outcome = match result {
        Ok(()) => match rustix::fs::fsync(&fd) {
            Ok(()) => Ok(header),
            Err(e) => Err(GenerateError::Io(e.into())),
        },
        Err(e) => Err(e),
    };
    drop(fd);
    if outcome.is_ok() {
        if let Err(e) = fsync_parent_dir(path) {
            cleanup_partial(path);
            return Err(GenerateError::Io(e));
        }
        Ok(header)
    } else {
        cleanup_partial(path);
        outcome
    }
}

/// 写头 + 逐块 CSPRNG 段正文。缓冲 `Zeroizing`，用完即清。
fn write_book_body(fd: &rustix::fd::OwnedFd, header: &BookHeader) -> Result<(), GenerateError> {
    let mut file = std::fs::File::from(fd.try_clone().map_err(GenerateError::Io)?);
    file.write_all(&header.encode())
        .map_err(GenerateError::Io)?;

    let mut chunk = Zeroizing::new(vec![0u8; (SEGMENTS_PER_CHUNK as usize) * 64]);
    let mut remaining = header.segment_count;
    while remaining > 0 {
        let segs = remaining.min(SEGMENTS_PER_CHUNK);
        let len = segs as usize * 64;
        getrandom::fill(&mut chunk[..len]).map_err(|_| GenerateError::Csprng)?;
        file.write_all(&chunk[..len]).map_err(GenerateError::Io)?;
        remaining -= segs;
    }
    Ok(())
}

/// 父目录 fsync（目录项持久化；规划 §1.2）。
fn fsync_parent_dir(path: &Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let dir = open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    rustix::fs::fsync(&dir)?;
    Ok(())
}

fn cleanup_partial(path: &Path) {
    let _ = unlink(path);
}

#[cfg(test)]
mod tests {
    use super::super::Book;
    use super::*;
    use crate::test_support::temp_path;

    #[test]
    fn generate_then_open_roundtrip_small() {
        let p = temp_path("gen3");
        let id = random_book_id().unwrap();
        let header = generate_book(&p, 3, id).unwrap();
        assert_eq!(header.book_id, id);
        assert_eq!(header.segment_count, 3);

        let book = Book::open(&p).unwrap();
        assert_eq!(*book.header(), header);
        assert_eq!(book.segment_count(), 3);
        // 权限 0600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "密码本文件必须 0600");
        }
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn generate_refuses_to_overwrite() {
        let p = temp_path("gen-exists");
        let id = random_book_id().unwrap();
        generate_book(&p, 1, id).unwrap();
        assert!(matches!(
            generate_book(&p, 1, id),
            Err(GenerateError::PathExists)
        ));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn generate_rejects_bad_segment_counts() {
        let p = temp_path("gen-bad");
        let id = random_book_id().unwrap();
        assert!(matches!(
            generate_book(&p, 0, id),
            Err(GenerateError::BadSegmentCount(0))
        ));
        assert!(matches!(
            generate_book(&p, MAX_SEGMENT_COUNT + 1, id),
            Err(GenerateError::BadSegmentCount(_))
        ));
        assert!(!p.exists(), "失败不得留下半成品");
    }

    #[test]
    fn generated_segments_are_csprng_not_degenerate() {
        // 小规模健康检查：段间两两不同、无全零段（生成器不退化为常数填充）。
        // 统计仅健康告警，不宣称随机性证明（规划 §5 测试 1）。
        let p = temp_path("gen-sanity");
        let id = random_book_id().unwrap();
        generate_book(&p, 256, id).unwrap();
        let book = Book::open(&p).unwrap();
        let mut seen = std::collections::HashSet::new();
        for i in 0..256u64 {
            let seg = book.read_segment(otp_types::SegmentIndex::new(i)).unwrap();
            let bytes = *seg.expose_for_allocator();
            assert_ne!(bytes, [0u8; 64], "段 {i} 不得为全零");
            assert!(seen.insert(bytes), "段 {i} 与此前段重复");
        }
        std::fs::remove_file(&p).ok();
    }
}
