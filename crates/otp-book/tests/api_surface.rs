//! 架构测试（规划 §2.2 / WP-06 验收 2）：`read_segment` 必须 crate-private，
//! 公开面不得出现任何“预留前读段”入口；过渡入口必须 `#[doc(hidden)]`。
//!
//! Rust 无法在稳定版做跨 crate 负向编译断言（无 trybuild 依赖），故按本仓
//! `scripts/check-unsafe.sh` 同款源扫描模式落地（源文件自检 + 集成测试
//! 固化公开面形状）。

#![forbid(unsafe_code)]

/// 公开面形状断言：这些是 otp-book 唯一允许公开的读相关入口。
///
/// 若有人把 `read_segment` 改成 `pub`，本测试文件的下一行无需改动即可
/// 通过编译——因此关键防线在下面的源码扫描；两者共同构成机械可查的双保险。
#[test]
fn public_surface_has_no_direct_segment_read() {
    let src = include_str!("../src/lib.rs");

    // 1) read_segment 必须是 crate-private
    assert!(
        src.contains("pub(crate) fn read_segment"),
        "read_segment 必须保持 pub(crate)（规划 §2.2）"
    );
    // 2) 不得出现公开的 read_segment
    assert!(
        !src.contains("pub fn read_segment"),
        "read_segment 不得 pub（仅 allocator 可经封印入口调用）"
    );
    // 3) 过渡入口必须 doc(hidden) 且仅委托 crate-private 实现
    assert!(
        src.contains("#[doc(hidden)]\n    pub fn __allocator_read_segment"),
        "过渡入口 __allocator_read_segment 必须保持 #[doc(hidden)]"
    );
    // 4) Book 不实现 Clone（fd 复制扩大泄露面）：源内不得出现 derive(Clone)
    //    覆盖到 Book/Segment 的迹象——直接检查类型定义附近无 derive。
    for banned in [
        "#[derive(Clone)]\npub struct Book",
        "#[derive(Clone, ZeroizeOnDrop)]\npub struct Segment",
        "#[derive(ZeroizeOnDrop, Clone)]\npub struct Segment",
    ] {
        assert!(!src.contains(banned), "敏感类型不得 Clone：{banned}");
    }
}

/// 头模块：解码严格性常量必须存在且值冻结（防误改后静默放行）。
#[test]
fn header_constants_frozen() {
    assert_eq!(otp_book::BOOK_MAGIC, *b"OTPB");
    assert_eq!(otp_book::BOOK_VERSION, 1);
    assert_eq!(otp_book::header::HEADER_LEN, 128);
    assert_eq!(otp_book::MAX_SEGMENT_COUNT, (1u64 << 40) - 1);
    assert_eq!(otp_book::header::SEGMENT_AREA_OFFSET, 128);
}
