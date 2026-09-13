//! 警告行字节级规格（设计书 §3 全部不变式）。
//!
//! - [`DEFAULT_WARN_LINE`]：§3.1 冻结 golden（101 字节含 CRLF，
//!   md5 `aecf98908984d17e97343cafb25dfa59`，golden hex 见 [`DEFAULT_WARN_LINE_HEX`]）。
//! - [`validate_line`]：§3.2 W1–W5 强制校验（W6：启动期校验，任一不满足即拒绝启动）。

#![forbid(unsafe_code)]

use std::fmt;

/// §3.1 默认警告行内容（不含终止符；doorkeeper 自行追加 CRLF）
pub const DEFAULT_WARN_LINE: &str =
    "NOTICE: SSH endpoint deprecated, migrating to jbuu (锦书). 本通道仅过渡，请迁移 jbuu。";

/// §3.2 默认行完整 hex golden（101 字节，含 CRLF；由设计书 verify_wp14.py 程序化生成）
pub const DEFAULT_WARN_LINE_HEX: &str = concat!(
    "4e4f544943453a2053534820656e64706f696e7420646570726563617465642c",
    "206d6967726174696e6720746f206a6275752028e994a6e4b9a6292e20e69cac",
    "e9809ae98193e4bb85e8bf87e6b8a1efbc8ce8afb7e8bf81e7a7bb206a627575",
    "e380820d0a"
);

/// §3.1 默认行字节数（含 CRLF）
pub const DEFAULT_WARN_LINE_LEN: usize = 101;

/// §3.4 上游不可达提示行（不含终止符）
pub const FAILURE_LINE: &str = "NOTICE: upstream sshd unreachable via doorkeeper, try later";

/// §3.2 W4：总长（含 CRLF）上限
pub const MAX_LINE_LEN: usize = 200;

/// §3.2 不变式违规（错误信息含不变式编号，供启动拒绝与测试断言）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineError {
    /// W2：行首 4 字节不得为 "SSH-"（RFC 4253 §4.2 MUST NOT）
    SshPrefix,
    /// W3：行内不得含 CR/LF/NUL 及 C0 控制符
    ControlChar { byte: u8, pos: usize },
    /// W4：总长（含 CRLF）不得超过 200 字节（实际 {len}）
    TooLong { len: usize },
}

impl fmt::Display for LineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LineError::SshPrefix => {
                write!(
                    f,
                    "W2 违规：行首 4 字节为 \"SSH-\"（RFC 4253 §4.2 MUST NOT begin with \"SSH-\"）"
                )
            }
            LineError::ControlChar { byte, pos } => {
                write!(
                    f,
                    "W3 违规：第 {pos} 字节为控制符 0x{byte:02x}（行内不得含 CR/LF/NUL 及 C0 控制符）"
                )
            }
            LineError::TooLong { len } => {
                write!(
                    f,
                    "W4 违规：含 CRLF 总长 {len} 字节 > {MAX_LINE_LEN}（Go x/crypto/ssh 读入预算 255B）"
                )
            }
        }
    }
}

impl std::error::Error for LineError {}

/// §3.2 校验并构造完整行字节：`content` 为**不含终止符**的行内容，
/// 校验通过后追加 `\r\n` 返回。
///
/// 逐条强制（W6：启动期即拒，不进运行时）：
/// - W2 行首 ≠ `"SSH-"`
/// - W3 行内无 CR/LF/NUL 及 C0 控制符（0x00–0x1F）
/// - W4 总长（含追加的 CRLF）≤ 200
/// - W1 由本函数保证（自行追加 `\r\n`）
/// - W5 由入参 `&str` 类型保证 UTF-8 有效性
pub fn validate_line(content: &str) -> Result<Vec<u8>, LineError> {
    for (pos, &byte) in content.as_bytes().iter().enumerate() {
        if byte < 0x20 {
            return Err(LineError::ControlChar { byte, pos });
        }
    }
    if content.as_bytes().starts_with(b"SSH-") {
        return Err(LineError::SshPrefix);
    }
    let mut line = Vec::with_capacity(content.len() + 2);
    line.extend_from_slice(content.as_bytes());
    line.extend_from_slice(b"\r\n"); // W1
    if line.len() > MAX_LINE_LEN {
        return Err(LineError::TooLong { len: line.len() });
    }
    Ok(line)
}

/// 默认警告行完整字节（golden；构造失败即 bug，panic 于开发期断言）
pub fn default_warn_line() -> Vec<u8> {
    let line = validate_line(DEFAULT_WARN_LINE).expect("默认警告行必须满足 W1–W5");
    debug_assert_eq!(line.len(), DEFAULT_WARN_LINE_LEN);
    debug_assert_eq!(hex_encode(&line), DEFAULT_WARN_LINE_HEX);
    line
}

/// §3.4 失败提示行完整字节
pub fn failure_line() -> Vec<u8> {
    validate_line(FAILURE_LINE).expect("失败提示行必须满足 W1–W5")
}

/// 小写 hex 编码（测试与 golden 断言共用）
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_line_matches_frozen_golden() {
        let line = default_warn_line();
        assert_eq!(line.len(), DEFAULT_WARN_LINE_LEN);
        assert_eq!(hex_encode(&line), DEFAULT_WARN_LINE_HEX);
        assert_eq!(&line[line.len() - 2..], b"\r\n"); // W1
        assert!(!line.starts_with(b"SSH-")); // W2
    }

    #[test]
    fn failure_line_shape() {
        let line = failure_line();
        let mut expect = FAILURE_LINE.as_bytes().to_vec();
        expect.extend_from_slice(b"\r\n");
        assert_eq!(line, expect);
        assert_eq!(&line[line.len() - 2..], b"\r\n");
    }
}
