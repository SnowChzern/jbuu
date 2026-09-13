//! 客户端版本串旁路观察器（设计书 §3.5——门卫唯一“看”数据面的地方）。
//!
//! 观察不是解析：在 c2s 方向 pipe 循环内对数据块做无状态行扫描——取首个以 `\n`
//! 结尾且以 `SSH-` 开头的行记录原文（截断至 128B）；累计扫描窗 8 KiB，超窗或
//! 未见即放弃（记 `version: null`）。**绝不缓存、绝不等待、绝不改写**：扫描在
//! 转发同一循环内进行，转发零延迟零滞留。
#![forbid(unsafe_code)]

use std::sync::Mutex;

/// §3.5 累计扫描窗
pub const SCAN_WINDOW: usize = 8 * 1024;
/// §3.5 版本串记录截断上限
pub const VERSION_MAX_BYTES: usize = 128;

/// 无状态扫描窗（由 c2s pipe 线程独占使用；Mutex 仅为让句柄跨线程移动而设）
pub struct VersionObserver {
    /// 待扫描的未消费字节（绝对起点 = consumed）
    buf: Vec<u8>,
    /// 已观察到的累计字节数（窗口计量）
    scanned: usize,
    /// buf[0] 在字节流中的绝对位置
    base: usize,
    done: bool,
    version: Option<String>,
    truncated: bool,
}

impl Default for VersionObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl VersionObserver {
    pub fn new() -> Self {
        VersionObserver {
            buf: Vec::new(),
            scanned: 0,
            base: 0,
            done: false,
            version: None,
            truncated: false,
        }
    }

    /// 观察一个 c2s 数据块（不改写、不滞留、O(n) 单遍）
    pub fn observe(&mut self, chunk: &[u8]) {
        if self.done {
            return;
        }
        self.scanned += chunk.len();
        self.buf.extend_from_slice(chunk);
        // 逐行扫描：完整行（\n 结尾）且行结束位置落在扫描窗内才参与判定
        while let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
            let line_end_abs = self.base + i; // \n 的绝对位置
            if line_end_abs >= SCAN_WINDOW {
                // 行尾已在窗外：放弃（§3.5 超窗即放弃）
                self.finish_none();
                return;
            }
            let mut line = self.buf.drain(..=i).collect::<Vec<u8>>();
            self.base += i + 1;
            line.pop(); // 去 \n
            if line.last() == Some(&b'\r') {
                line.pop(); // 去 CRLF 的 \r
            }
            if line.starts_with(b"SSH-") {
                self.truncated = line.len() > VERSION_MAX_BYTES;
                line.truncate(VERSION_MAX_BYTES);
                self.version = Some(String::from_utf8_lossy(&line).into_owned());
                self.done = true;
                self.buf = Vec::new();
                return;
            }
            // 非 SSH- 行（随机前置行/诱饵行）：丢弃继续看后续行
        }
        if self.scanned >= SCAN_WINDOW {
            // 已观察满窗口且未见到完整 SSH- 行：放弃（§3.5 超窗即放弃）
            self.finish_none();
        }
    }

    fn finish_none(&mut self) {
        self.done = true;
        self.version = None;
        self.buf = Vec::new();
    }

    /// 是否已得出结论（找到或放弃；此后 observe 为空操作）
    pub fn done(&self) -> bool {
        self.done
    }

    /// 取出观察结果：(version, truncated)。未见/放弃时 version 为 None。
    pub fn take_result(&mut self) -> (Option<String>, bool) {
        if !self.done {
            self.finish_none(); // 流结束仍未定论 → 放弃
        }
        (self.version.take(), self.truncated)
    }
}

/// 跨线程句柄（c2s pipe 线程写、连接收尾线程读）
pub type SharedObserver = Mutex<VersionObserver>;

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(chunks: &[&[u8]]) -> (Option<String>, bool) {
        let mut obs = VersionObserver::new();
        for c in chunks {
            obs.observe(c);
        }
        obs.take_result()
    }

    #[test]
    fn first_ssh_line_wins() {
        let (v, t) = feed(&[
            b"NOTICE: random pre-line\r\n",
            b"garbage no newline yet",
            b"\r\nSSH-2.0-OpenSSH_10.0p2 Debian-7-13u2\r\n",
            b"SSH-2.0-later-should-be-ignored\r\n",
        ]);
        assert_eq!(v.as_deref(), Some("SSH-2.0-OpenSSH_10.0p2 Debian-7-13u2"));
        assert!(!t);
    }

    #[test]
    fn truncates_over_128_bytes() {
        let mut line = String::from("SSH-2.0-");
        for _ in 0..200 {
            line.push('x');
        }
        line.push_str("\r\n");
        let (v, t) = feed(&[line.as_bytes()]);
        assert_eq!(v.as_deref().map(|s| s.len()), Some(128));
        assert!(t);
    }

    #[test]
    fn gives_up_beyond_window() {
        let big = vec![b'a'; SCAN_WINDOW + 100]; // 无换行巨型单行
        let (v, t) = feed(&[&big]);
        assert_eq!(v, None);
        assert!(!t);
    }

    #[test]
    fn no_version_when_stream_ends() {
        let (v, _) = feed(&[b"hello\r\n", b"world"]);
        assert_eq!(v, None);
    }

    #[test]
    fn line_ending_outside_window_is_ignored() {
        // SSH- 行的 \n 落在窗外（8192 位置）→ 放弃
        let mut buf = vec![b'x'; SCAN_WINDOW - 8];
        buf.extend_from_slice(b"SSH-2.0-x\n");
        let (v, _) = feed(&[&buf]);
        assert_eq!(v, None);
    }
}
