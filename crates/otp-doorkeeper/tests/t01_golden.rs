//! §8 测试 1：警告行 golden + W1–W5 不变式 + 三个负例
#![allow(dead_code)]
mod support;

use otp_doorkeeper::warn::{self, DEFAULT_WARN_LINE_HEX, DEFAULT_WARN_LINE_LEN, LineError};

/// §3.1 冻结 golden：默认行 101 字节、hex 逐字节一致、md5 独立复算
#[test]
fn t01_golden_default_warn_line() {
    let line = warn::default_warn_line();

    // 长度
    assert_eq!(
        line.len(),
        DEFAULT_WARN_LINE_LEN,
        "默认警告行必须为 101 字节"
    );
    assert_eq!(line.len(), 101);

    // hex golden 逐字节一致（§3.2 表下 golden 向量）
    assert_eq!(warn::hex_encode(&line), DEFAULT_WARN_LINE_HEX);
    assert_eq!(
        DEFAULT_WARN_LINE_HEX,
        "4e4f544943453a2053534820656e64706f696e7420646570726563617465642c\
         206d6967726174696e6720746f206a6275752028e994a6e4b9a6292e20e69cac\
         e9809ae98193e4bb85e8bf87e6b8a1efbc8ce8afb7e8bf81e7a7bb206a627575\
         e380820d0a"
            .replace(' ', "")
    );

    // md5 独立复算（测试工装内置 md5 实现，不依赖生产代码）
    assert_eq!(
        support::md5_hex(&line),
        "aecf98908984d17e97343cafb25dfa59",
        "md5 必须与设计书 §3.1 冻结值一致"
    );

    // W1：CRLF 结尾
    assert_eq!(&line[line.len() - 2..], b"\r\n");
    // W2：行首非 "SSH-"
    assert!(!line.starts_with(b"SSH-"));
    // W4：≤200
    assert!(line.len() <= 200);
    // W5：UTF-8 有效（由构造保证，这里显式复核）
    let _ = std::str::from_utf8(&line[..line.len() - 2]).expect("W5 UTF-8");
}

/// md5 工装自校验（RFC 1321 向量）：golden 断言的 md5 不是自说自话
#[test]
fn t01_md5_implementation_selfcheck() {
    assert_eq!(support::md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(support::md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(
        support::md5_hex(b"The quick brown fox jumps over the lazy dog"),
        "9e107d9d372bb6826bd81d3542a419d6"
    );
}

/// §3.4 失败提示行：字节精确 + W1–W5
#[test]
fn t01_failure_line_shape() {
    let line = warn::failure_line();
    assert_eq!(
        line,
        b"NOTICE: upstream sshd unreachable via doorkeeper, try later\r\n".to_vec()
    );
    assert_eq!(&line[line.len() - 2..], b"\r\n"); // W1
    assert!(!line.starts_with(b"SSH-")); // W2
    assert!(line[..line.len() - 2].iter().all(|&b| b >= 0x20)); // W3（不含终止符）
    assert!(line.len() <= 200); // W4
}

/// §3.2 W3 负例全集：CR / LF / NUL / 其它 C0 控制符 → 拒绝
#[test]
fn t01_negative_control_chars() {
    for bad in ["a\rb", "a\nb", "a\0b", "a\x1bb", "\ta"] {
        assert_eq!(
            warn::validate_line(bad),
            Err(LineError::ControlChar {
                byte: bad.bytes().find(|&b| b < 0x20).unwrap(),
                pos: bad.bytes().position(|b| b < 0x20).unwrap()
            }),
            "含控制符的行必须被 W3 拒绝：{bad:?}"
        );
    }
}

/// §3.2 负例三件套（§8 测试 1 点名）：SSH- 前缀 / 含 CR / >200B → 拒绝启动（W2/W3/W4）
#[test]
fn t01_negative_ssh_prefix() {
    assert_eq!(
        warn::validate_line("SSH-2.0-OpenSSH_10.0"),
        Err(LineError::SshPrefix)
    );
    assert_eq!(warn::validate_line("SSH-"), Err(LineError::SshPrefix));
}

#[test]
fn t01_negative_embedded_cr() {
    assert!(matches!(
        warn::validate_line("hello\rworld"),
        Err(LineError::ControlChar {
            byte: b'\r',
            pos: 5
        })
    ));
}

#[test]
fn t01_negative_too_long() {
    let long = "x".repeat(199); // +CRLF = 201 > 200
    assert_eq!(
        warn::validate_line(&long),
        Err(LineError::TooLong { len: 201 })
    );
    // 边界内放行：198 + CRLF = 200
    let ok = "x".repeat(198);
    let line = warn::validate_line(&ok).expect("200 字节整应通过 W4");
    assert_eq!(line.len(), 200);
}

/// 合法自定义行：正确追加 CRLF
#[test]
fn t01_custom_line_gets_crlf() {
    let line = warn::validate_line("migrating soon").unwrap();
    assert_eq!(line, b"migrating soon\r\n".to_vec());
}
