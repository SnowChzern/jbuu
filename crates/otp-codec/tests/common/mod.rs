//! 集成测试共用夹具：hex 解析与 §6.1 测试夹具常量（仅测试用，禁止入生产）。

/// 小写连续 hex 串 → 字节串。非法输入 panic（测试代码，向量本身已由
/// 独立脚本逐字节核对）。
pub fn h(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length: {s}");
    let b = s.as_bytes();
    (0..b.len())
        .step_by(2)
        .map(|i| {
            let hi = (b[i] as char)
                .to_digit(16)
                .unwrap_or_else(|| panic!("bad hex {s}"));
            let lo = (b[i + 1] as char)
                .to_digit(16)
                .unwrap_or_else(|| panic!("bad hex {s}"));
            ((hi << 4) | lo) as u8
        })
        .collect()
}

// ---- WP-01 §6.1 测试夹具 ----

/// BOOK_ID 夹具。
pub const BOOK_ID: &str = "00112233445566778899aabbccddeeff";
/// CLIENT_NONCE 夹具。
pub const CLIENT_NONCE: &str = "101112131415161718191a1b1c1d1e1f";
/// SERVER_NONCE 夹具。
pub const SERVER_NONCE: &str = "202122232425262728292a2b2c2d2e2f";
/// SESSION_NONCE 夹具（= C⊕S，D3）。
pub const SESSION_NONCE: &str = "30303030303030303030303030303030";
