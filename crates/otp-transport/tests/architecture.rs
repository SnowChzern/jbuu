//! 架构边界证明（任务 #50 验收 ④）。
//!
//! 四层证据：
//! 1. **依赖面**：`[dependencies]` 段只有 otp-types/otp-codec——传输层
//!    生产编译单元在名称解析上不可达密码本/锚/会话/握手；
//! 2. **源码面**：src/ 无会话/握手/分配器/密码本/锚 token，无消息语义
//!    解码调用（decode/Message 等）——线格式判定归 codec；
//! 3. **上限面**：帧长上限编译期钉死在 codec 注册表常量（不设第二套）；
//! 4. **unsafe 面**：`#![forbid(unsafe_code)]` 且源码零 unsafe token。
//!
//! 会话/握手/分配器仅在 `[dev-dependencies]`（M1 加密回显验收），不进
//! 生产编译单元。

#![forbid(unsafe_code)]

#[test]
fn production_dependencies_are_types_and_codec_only() {
    let manifest = include_str!("../Cargo.toml");
    let prod = manifest
        .split("[dev-dependencies]")
        .next()
        .expect("Cargo.toml 必须有 [dev-dependencies] 段");
    assert!(prod.contains("otp-types"), "错误类别经 otp-types");
    assert!(
        prod.contains("otp-codec"),
        "帧常量/错误码注册表经 otp-codec"
    );
    for banned in [
        "otp-session",
        "otp-handshake",
        "otp-allocator",
        "otp-book",
        "otp-anchor-spec",
        "otp-recovery",
        "otp-terminal",
        "otp-platform",
    ] {
        assert!(
            !prod.contains(banned),
            "传输层生产依赖不得包含 {banned}（零段材料/零语义解析边界）"
        );
    }
}

#[test]
fn source_mentions_no_protocol_semantics_or_segment_material() {
    for src in [
        include_str!("../src/lib.rs"),
        include_str!("../src/frame.rs"),
        include_str!("../src/loopback.rs"),
        include_str!("../src/tcp.rs"),
    ] {
        for banned in [
            "otp_session",
            "otp_handshake",
            "otp_allocator",
            "otp_book",
            "otp_anchor",
            "CommittedSegment",
            "read_segment",
            "decode(",
            "Message::",
            "MsgType",
            "seal(",
            "open(",
        ] {
            assert!(
                !src.contains(banned),
                "传输层源码不得出现 {banned}（零协议语义解析/零段材料接触）"
            );
        }
    }
}

#[test]
fn frame_bound_is_pinned_to_codec_registry() {
    let lib = include_str!("../src/lib.rs");
    assert!(
        lib.contains("pub const MAX_WIRE_FRAME: usize = otp_codec::MAX_FRAME;"),
        "帧长上限必须直接钉在 codec 常量上"
    );
    let frame = include_str!("../src/frame.rs");
    assert!(
        frame.contains("MAX_FRAME_PAYLOAD"),
        "接收侧上限校验必须联动 codec 注册表常量"
    );
}

#[test]
fn unsafe_is_forbidden_in_all_sources() {
    // crate 级 forbid 声明覆盖全部模块（lib.rs）
    let lib = include_str!("../src/lib.rs");
    assert!(lib.contains("#![forbid(unsafe_code)]"));
    for src in [
        lib,
        include_str!("../src/frame.rs"),
        include_str!("../src/loopback.rs"),
        include_str!("../src/tcp.rs"),
    ] {
        assert!(
            !src.replace("#![forbid(unsafe_code)]", "")
                .contains("unsafe"),
            "源码不得出现 unsafe 用法"
        );
    }
}

#[test]
fn error_model_is_wp01_registry_no_parallel_system() {
    let lib = include_str!("../src/lib.rs");
    assert!(
        lib.contains("pub const fn code(self) -> ErrorCode"),
        "TransportError 必须映射 wp01 注册表（不新造平行错误体系）"
    );
    for code in ["IO_ERROR", "FRAME_TRUNCATED", "BAD_LENGTH"] {
        assert!(lib.contains(code), "注册表映射必须覆盖 {code}");
    }
}
