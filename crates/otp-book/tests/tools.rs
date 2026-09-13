//! 工具链集成测试（公开 API 面）：生成 → 打开/头校验 → inspect 统计/去重，
//! 以及注入重复段/全零段必检出的端到端验证（设计书 §9 测试项 1 缩影；
//! 1,000,000 段全量跑见 evidence/task-35 的 CLI 实测）。

#![forbid(unsafe_code)]

use std::io::{Read as _, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::Instant;

use otp_book::generate::{GenerateError, generate_book, random_book_id};
use otp_book::header::HEADER_LEN;
use otp_book::inspect::{DuplicatePair, inspect_book};
use otp_book::{Book, BookError};

fn temp_path(tag: &str) -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "otp-book-it-{}-{}-{n}.book",
        std::process::id(),
        tag
    ))
}

fn mkbook(tag: &str, segments: u64) -> PathBuf {
    let p = temp_path(tag);
    generate_book(&p, segments, random_book_id().unwrap()).unwrap();
    p
}

#[test]
fn generate_open_roundtrip_various_sizes() {
    for n in [1u64, 2, 63, 64, 65, 1025] {
        let p = mkbook("rt", n);
        let book = Book::open(&p).unwrap();
        assert_eq!(book.segment_count(), n);
        assert_eq!(
            std::fs::metadata(&p).unwrap().len(),
            HEADER_LEN as u64 + n * 64,
            "段数 {n}"
        );
        std::fs::remove_file(&p).ok();
    }
}

#[test]
fn generate_refuses_overwrite_and_bad_counts() {
    let p = mkbook("excl", 1);
    assert!(matches!(
        generate_book(&p, 1, random_book_id().unwrap()),
        Err(GenerateError::PathExists)
    ));
    std::fs::remove_file(&p).ok();

    let q = temp_path("badcount");
    assert!(matches!(
        generate_book(&q, 0, random_book_id().unwrap()),
        Err(GenerateError::BadSegmentCount(0))
    ));
}

#[test]
fn inspect_clean_generated_book_ok_with_sane_stats() {
    // 8192 段 = 512 KiB 正文：bit 比例应显著落在告警带内
    let p = mkbook("clean", 8192);
    let rep = inspect_book(&p).unwrap();
    assert!(rep.ok, "统计摘要：\n{}", rep.summary());
    assert_eq!(rep.duplicate_count, 0);
    assert_eq!(rep.zero_segment_count, 0);
    assert!(
        (0.48..=0.52).contains(&rep.ones_ratio),
        "{}",
        rep.ones_ratio
    );
    assert!(rep.warnings.is_empty(), "{:?}", rep.warnings);
    let json = rep.to_json();
    assert!(json.contains("\"duplicate_count\": 0"));
    assert!(json.contains("\"ok\": true"));
    std::fs::remove_file(&p).ok();
}

#[test]
fn injected_duplicate_always_detected() {
    // 设计书 §9 测试项 1：人工复制一个 64B 段后检测必失败
    let p = mkbook("dup", 4096);
    // 读取段 0 原文（检查工具路径本身允许读；用 std 直读 offset 128）
    let mut seg0 = [0u8; 64];
    {
        let mut f = std::fs::File::open(&p).unwrap();
        f.seek(SeekFrom::Start(HEADER_LEN as u64)).unwrap();
        f.read_exact(&mut seg0).unwrap();
    }
    // 注入：把段 0 覆盖到段 2048
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.seek(SeekFrom::Start(HEADER_LEN as u64 + 2048 * 64))
            .unwrap();
        f.write_all(&seg0).unwrap();
        f.sync_all().unwrap();
    }
    let rep = inspect_book(&p).unwrap();
    assert!(!rep.ok, "注入重复段必须被检出");
    assert_eq!(rep.duplicate_count, 1);
    assert_eq!(
        rep.duplicates.first(),
        Some(&DuplicatePair {
            first: 0,
            other: 2048
        })
    );
    std::fs::remove_file(&p).ok();
}

#[test]
fn injected_zero_segment_always_detected() {
    let p = mkbook("zero", 128);
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.seek(SeekFrom::Start(HEADER_LEN as u64 + 127 * 64))
            .unwrap();
        f.write_all(&[0u8; 64]).unwrap();
        f.sync_all().unwrap();
    }
    let rep = inspect_book(&p).unwrap();
    assert!(!rep.ok);
    assert_eq!(rep.zero_segment_count, 1);
    assert_eq!(rep.zero_segments, vec![127]);
    std::fs::remove_file(&p).ok();
}

#[test]
fn truncated_book_rejected_by_open_and_inspect() {
    let p = mkbook("trunc", 4);
    // 截掉最后一个段
    let len = std::fs::metadata(&p).unwrap().len();
    let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
    f.set_len(len - 64).unwrap();
    drop(f);
    assert!(matches!(
        Book::open(&p),
        Err(BookError::InvalidHeader { .. })
    ));
    assert!(matches!(
        inspect_book(&p),
        Err(BookError::InvalidHeader { .. })
    ));
    std::fs::remove_file(&p).ok();
}

/// 1,000,000 段实测（默认忽略；`cargo test -- --ignored` 或见
/// evidence/task-35）：生成/头校验/按索引读段不得退化为全本扫描。
#[test]
#[ignore = "大本实测（约 3-6s）：cargo test -p otp-book --test tools -- --ignored"]
fn million_segment_book_generate_open_read_without_full_scan() {
    let p = temp_path("million");
    let t = Instant::now();
    generate_book(&p, 1_000_000, random_book_id().unwrap()).unwrap();
    let gen_dt = t.elapsed();
    assert_eq!(
        std::fs::metadata(&p).unwrap().len(),
        HEADER_LEN as u64 + 1_000_000 * 64
    );

    let t = Instant::now();
    let book = Book::open(&p).unwrap();
    let open = t.elapsed();
    assert_eq!(book.segment_count(), 1_000_000);

    // open 只验证固定长度文件头；正文读取行为由 crate 内单元测试覆盖。
    assert!(open.as_millis() < 200, "open 耗时 {open:?}：疑似预读全本");
    eprintln!("1M 段实测：生成 {gen_dt:?} / open {open:?}，无全本扫描");
    std::fs::remove_file(&p).ok();
}
