//! 架构边界证明（任务 #47 验收 ④）：握手层零直读密码本段。
//!
//! 四层证据：
//! 1. **依赖面**：`[dependencies]` 段不含 otp-book / otp-anchor-spec——
//!    握手层生产编译单元在名称解析上无法触达密码本与锚；
//! 2. **源码面**：src/ 无 `read_segment` / `otp_book` token；
//! 3. **入口面**：段正文唯一 ingress 是 `dyn SegmentIssuer` 的 `issue()`；
//! 4. **类型面**：compile-fail 夹具（trybuild，同任务 #45 方式）——即使
//!    测试环境拿到 otp-book（dev-dependency），`Book::read_segment` 仍是
//!    crate-private（E0624），不存在任何绕过 SegmentIssuer 的读段路径。

#![forbid(unsafe_code)]

#[test]
fn production_dependencies_exclude_book_and_anchor_crates() {
    let manifest = include_str!("../Cargo.toml");
    let prod = manifest
        .split("[dev-dependencies]")
        .next()
        .expect("Cargo.toml 必须有 [dev-dependencies] 段");
    assert!(!prod.contains("otp-book"), "生产依赖不得包含 otp-book");
    assert!(
        !prod.contains("otp-anchor-spec"),
        "生产依赖不得包含 otp-anchor-spec"
    );
    assert!(prod.contains("otp-allocator"), "取段经 SegmentIssuer");
    assert!(prod.contains("otp-session"));
}

#[test]
fn source_never_mentions_direct_segment_reads() {
    let src = include_str!("../src/lib.rs");
    assert!(!src.contains("read_segment"), "禁止直读密码本段");
    assert!(!src.contains("otp_book"), "禁止引用 otp_book");
    assert!(!src.contains("otp_anchor_spec"), "禁止直接操作锚");
    assert!(!src.contains("Book::open"));
}

#[test]
fn segment_ingress_is_exclusively_segment_issuer() {
    let src = include_str!("../src/lib.rs");
    assert!(
        src.contains("dyn SegmentIssuer"),
        "签发接口只能是 SegmentIssuer trait 对象"
    );
    assert!(
        src.matches("issuer.issue()").count() >= 2,
        "客户端（含间隙废弃）与服务端均经 issue() 取段"
    );
}

#[test]
fn unsafe_is_forbidden_in_source() {
    let src = include_str!("../src/lib.rs");
    assert!(src.contains("#![forbid(unsafe_code)]"));
    assert!(
        !src.replace("#![forbid(unsafe_code)]", "")
            .contains("unsafe")
    );
}

#[test]
fn handshake_cannot_call_book_read_segment_even_with_dev_access() {
    // 类型系统证明：read_segment 为 crate-private（E0624）。
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/raw_segment_access.rs");
}
