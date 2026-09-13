//! JSONL 连接日志（设计书 §5.5）：单 write 原子追加 + SIGHUP reopen，无进程内聚合。
//!
//! 原子性（E6 实证教训）：一条日志事件**一次 `write()` 系统调用**写完（O_APPEND；
//! 单行 ≤ PIPE_BUF 量级时 append 原子性由内核保证）。跨线程共享一个 fd，
//! 写路径不持锁（`RwLock` 仅保护 reopen 时的 fd 句柄交换，不序列化写）。
#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// JSONL 事件字段值
pub enum Field<'a> {
    Str(&'a str),
    U64(u64),
    Bool(bool),
    Null,
}

/// JSONL 追加写日志（跨线程共享：`Arc<JsonlLog>`）
pub struct JsonlLog {
    file: RwLock<Arc<File>>,
    path: PathBuf,
    verbose: bool,
}

impl JsonlLog {
    /// 打开（append+create）日志文件；父目录缺失时尝试创建一次
    pub fn open(path: &Path, verbose: bool) -> io::Result<JsonlLog> {
        let file = open_append(path)?;
        Ok(JsonlLog {
            file: RwLock::new(Arc::new(file)),
            path: path.to_path_buf(),
            verbose,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// SIGHUP 轮转（D9）：按原路径重新打开并交换 fd，随后在新文件记 `log_reopened`。
    /// 失败时保留旧 fd 继续写（返回 Err 由调用方记 stderr）。
    pub fn reopen(&self) -> io::Result<()> {
        let new_file = open_append(&self.path)?;
        {
            let mut guard = self.file.write().unwrap();
            *guard = Arc::new(new_file);
        }
        self.event(
            "info",
            "log_reopened",
            &[("path", Field::Str(&self.path.display().to_string()))],
        );
        Ok(())
    }

    /// 写一条事件：拼成单行 JSON 后**一次 write 落盘**。
    pub fn event(&self, level: &str, kind: &str, fields: &[(&str, Field<'_>)]) {
        let mut line = String::with_capacity(192);
        line.push_str("{\"ts\":\"");
        line.push_str(&now_rfc3339_millis());
        line.push_str("\",\"level\":\"");
        escape_into(level, &mut line);
        line.push_str("\",\"event\":\"");
        escape_into(kind, &mut line);
        line.push('"');
        for (key, value) in fields {
            line.push(',');
            line.push('"');
            escape_into(key, &mut line);
            line.push_str("\":");
            match value {
                Field::Str(s) => {
                    line.push('"');
                    escape_into(s, &mut line);
                    line.push('"');
                }
                Field::U64(n) => line.push_str(&n.to_string()),
                Field::Bool(b) => line.push_str(if *b { "true" } else { "false" }),
                Field::Null => line.push_str("null"),
            }
        }
        line.push_str("}\n");

        let file = self.file.read().unwrap().clone();
        let bytes = line.as_bytes();
        // 单 write 原子性；短写（常规小行几乎不可能）时补齐并告警，不留半行
        match (&*file).write(bytes) {
            Ok(n) if n == bytes.len() => {}
            Ok(n) => {
                eprintln!(
                    "jbuu-doorkeeper: 日志短写（{n}/{} 字节），补写剩余部分",
                    bytes.len()
                );
                let _ = (&*file).write_all(&bytes[n..]);
            }
            Err(e) => {
                eprintln!("jbuu-doorkeeper: 日志写入失败：{e}");
            }
        }
        if self.verbose {
            let _ = io::stderr().write_all(bytes);
        }
    }

    // ---- §5.5 事件集专用封装 ----

    /// listen_start：{listen, upstream, warn_mode, max_conns, pid, version}
    pub fn listen_start(&self, listen: &str, upstream: &str, warn_mode: &str, max_conns: usize) {
        self.event(
            "info",
            "listen_start",
            &[
                ("listen", Field::Str(listen)),
                ("upstream", Field::Str(upstream)),
                ("warn_mode", Field::Str(warn_mode)),
                ("max_conns", Field::U64(max_conns as u64)),
                ("pid", Field::U64(std::process::id() as u64)),
                ("version", Field::Str(crate::VERSION)),
            ],
        );
    }

    /// conn_accept：{conn_id, src_ip, src_port, family}
    pub fn conn_accept(&self, conn_id: u64, src_ip: &str, src_port: u16, family: &str) {
        self.event(
            "info",
            "conn_accept",
            &[
                ("conn_id", Field::U64(conn_id)),
                ("src_ip", Field::Str(src_ip)),
                ("src_port", Field::U64(src_port as u64)),
                ("family", Field::Str(family)),
            ],
        );
    }

    /// warn_sent：{conn_id, bytes}
    pub fn warn_sent(&self, conn_id: u64, bytes: usize) {
        self.event(
            "info",
            "warn_sent",
            &[
                ("conn_id", Field::U64(conn_id)),
                ("bytes", Field::U64(bytes as u64)),
            ],
        );
    }

    /// upstream_connect：{conn_id, ok, elapsed_ms, err?}
    pub fn upstream_connect(&self, conn_id: u64, ok: bool, elapsed_ms: u64, err: Option<&str>) {
        let mut fields = vec![
            ("conn_id", Field::U64(conn_id)),
            ("ok", Field::Bool(ok)),
            ("elapsed_ms", Field::U64(elapsed_ms)),
        ];
        if let Some(e) = err {
            fields.push(("err", Field::Str(e)));
        }
        self.event("info", "upstream_connect", &fields);
    }

    /// client_version：{conn_id, version, truncated}
    pub fn client_version(&self, conn_id: u64, version: Option<&str>, truncated: bool) {
        self.event(
            "info",
            "client_version",
            &[
                ("conn_id", Field::U64(conn_id)),
                (
                    "version",
                    match version {
                        Some(v) => Field::Str(v),
                        None => Field::Null,
                    },
                ),
                ("truncated", Field::Bool(truncated)),
            ],
        );
    }

    /// conn_close：{conn_id, reason, bytes_c2s, bytes_s2c, duration_ms}
    pub fn conn_close(
        &self,
        conn_id: u64,
        reason: &str,
        bytes_c2s: u64,
        bytes_s2c: u64,
        duration_ms: u64,
    ) {
        self.event(
            "info",
            "conn_close",
            &[
                ("conn_id", Field::U64(conn_id)),
                ("reason", Field::Str(reason)),
                ("bytes_c2s", Field::U64(bytes_c2s)),
                ("bytes_s2c", Field::U64(bytes_s2c)),
                ("duration_ms", Field::U64(duration_ms)),
            ],
        );
    }

    /// conn_refused_over_limit：{src_ip, src_port, cur_conns}
    pub fn conn_refused_over_limit(&self, src_ip: &str, src_port: u16, cur_conns: usize) {
        self.event(
            "warn",
            "conn_refused_over_limit",
            &[
                ("src_ip", Field::Str(src_ip)),
                ("src_port", Field::U64(src_port as u64)),
                ("cur_conns", Field::U64(cur_conns as u64)),
            ],
        );
    }
}

fn open_append(path: &Path) -> io::Result<File> {
    match OpenOptions::new().append(true).create(true).open(path) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            OpenOptions::new().append(true).create(true).open(path)
        }
        Err(e) => Err(e),
    }
}

/// RFC 3339 UTC 毫秒（无外部时间 crate；civil 历法换算为 Howard Hinnant 算法）
pub(crate) fn now_rfc3339_millis() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let secs = d.as_secs() as i64;
    let millis = d.subsec_millis();
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, dd) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y,
        m,
        dd,
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60,
        millis
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let dd = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, dd)
}

/// 最小 JSON 字符串转义（控制符转 \u00XX）
fn escape_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let code = c as u32;
                out.push_str(&format!("\\u{code:04x}"));
            }
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_shape() {
        let ts = now_rfc3339_millis();
        // 2026-01-02T03:04:05.678Z
        assert_eq!(ts.len(), 24, "{ts}");
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[19..20], ".");
        assert!(ts.ends_with('Z'));
    }

    #[test]
    fn escape_control_chars() {
        let mut out = String::new();
        escape_into("a\"b\\c\nd\u{1}", &mut out);
        assert_eq!(out, "a\\\"b\\\\c\\nd\\u0001");
    }
}
