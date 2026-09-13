//! # 安全审计日志 sink（规划 §94 / §2.2 白名单）
//!
//! 审计日志采用**结构化白名单字段**：`book_id`、段号、generation、结果、
//! 错误类别——仅此五项，字段顺序与取值域均在本模块冻结：
//!
//! - [`AuditEntry`] 的全部字段都是枚举/定长整数类型，**类型系统上不存在**
//!   自由格式字符串或附带敏感对象的路径（[`audit_entry_to_json`] 逐字段
//!   序列化，无任何调用方可注入内容的通道）；
//! - 输出为 JSON Lines（每行一条），写入侧 [`JsonlAuditSink`] 以 0600
//!   追加打开，逐条 `fsync`；
//! - 时间戳等附加字段**有意不加**：白名单是封闭集合，扩字段须走设计
//!   变更（规划 §7.2），不得在实现里"顺手"放宽。

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use super::{AuditEntry, AuditLogSink, Outcome, PlatformError, fsync_dir, fsync_file, write_full};
use otp_types::ErrorCategory;

/// 一行审计记录的 JSON 编码（无换行；键序固定为白名单顺序）。
///
/// 纯函数：字段全部来自 [`AuditEntry`] 的封闭类型，无自由格式输入点。
#[must_use]
pub fn audit_entry_to_json(entry: &AuditEntry) -> String {
    let mut s = String::with_capacity(96);
    s.push_str("{\"book_id\":\"");
    for b in entry.book_id.as_bytes() {
        s.push_str(&format!("{b:02x}"));
    }
    s.push_str("\",\"segment\":");
    s.push_str(&entry.segment.get().to_string());
    s.push_str(",\"generation\":");
    s.push_str(&entry.generation.get().to_string());
    s.push_str(",\"outcome\":\"");
    s.push_str(outcome_str(entry.outcome));
    s.push_str("\",\"error_category\":");
    if let Some(cat) = entry.error_category {
        s.push('"');
        s.push_str(category_str(cat));
        s.push('"');
    } else {
        s.push_str("null");
    }
    s.push('}');
    s
}

/// [`Outcome`] 的封闭字符串域（白名单"结果"字段）。
#[must_use]
pub const fn outcome_str(o: Outcome) -> &'static str {
    match o {
        Outcome::Issued => "issued",
        Outcome::Wasted => "wasted",
        Outcome::Rejected => "rejected",
        Outcome::Recovered => "recovered",
        Outcome::Quarantined => "quarantined",
    }
}

/// [`ErrorCategory`] 的封闭字符串域（白名单"错误类别"字段）。
#[must_use]
pub const fn category_str(c: ErrorCategory) -> &'static str {
    match c {
        ErrorCategory::Book => "book",
        ErrorCategory::Codec => "codec",
        ErrorCategory::Anchor => "anchor",
        ErrorCategory::Allocation => "allocation",
        ErrorCategory::Recovery => "recovery",
        ErrorCategory::Handshake => "handshake",
        ErrorCategory::Session => "session",
        ErrorCategory::Transport => "transport",
        ErrorCategory::Terminal => "terminal",
        ErrorCategory::Platform => "platform",
        ErrorCategory::Internal => "internal",
    }
}

/// JSON Lines 审计 sink：0600 追加写 + 逐条 fsync。
///
/// 新建文件时同步父目录（目录项可见性尽力持久，失败即报错，不静默）。
pub struct JsonlAuditSink {
    file: File,
}

impl JsonlAuditSink {
    /// 打开（或创建）审计日志文件。已存在则追加；新建时 mode 0600 并
    /// fsync 父目录。
    pub fn open(path: &Path) -> Result<Self, PlatformError> {
        let existed = path.exists();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(PlatformError::from_io)?;
        if !existed {
            if let Some(parent) = path.parent() {
                fsync_dir(parent)?;
            }
        }
        Ok(Self { file })
    }

    /// 写入一条审计记录（JSON 行 + `\n`）并 fsync。完整写（短写循环），
    /// 不允许半行。
    pub fn write_entry(&mut self, entry: &AuditEntry) -> Result<(), PlatformError> {
        let mut line = audit_entry_to_json(entry);
        line.push('\n');
        write_full(&mut self.file, line.as_bytes())?;
        fsync_file(&self.file)?;
        Ok(())
    }
}

impl AuditLogSink for JsonlAuditSink {
    fn emit(&mut self, entry: &AuditEntry) -> Result<(), PlatformError> {
        self.write_entry(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use otp_types::{BookId, Generation, SegmentIndex};

    fn entry(outcome: Outcome, cat: Option<ErrorCategory>) -> AuditEntry {
        AuditEntry {
            book_id: BookId::from_bytes(*b"OTPTERM-TESTBOOK"),
            segment: SegmentIndex::new(7),
            generation: Generation::new(8),
            outcome,
            error_category: cat,
        }
    }

    #[test]
    fn json_carries_exactly_the_whitelist_fields_in_frozen_order() {
        let line = audit_entry_to_json(&entry(Outcome::Issued, Some(ErrorCategory::Handshake)));
        // 键序与键集合逐一冻结：恰五个键、顺序固定、无任何其他内容。
        assert_eq!(
            line,
            "{\"book_id\":\"4f54505445524d2d54455354424f4f4b\",\"segment\":7,\"generation\":8,\
             \"outcome\":\"issued\",\"error_category\":\"handshake\"}"
        );
    }

    #[test]
    fn outcome_and_category_domains_are_closed() {
        // 结果域五值；错误类别全 11 值 + 成功路径 null。
        for (o, s) in [
            (Outcome::Issued, "issued"),
            (Outcome::Wasted, "wasted"),
            (Outcome::Rejected, "rejected"),
            (Outcome::Recovered, "recovered"),
            (Outcome::Quarantined, "quarantined"),
        ] {
            assert_eq!(outcome_str(o), s);
        }
        let cats = [
            (ErrorCategory::Book, "book"),
            (ErrorCategory::Codec, "codec"),
            (ErrorCategory::Anchor, "anchor"),
            (ErrorCategory::Allocation, "allocation"),
            (ErrorCategory::Recovery, "recovery"),
            (ErrorCategory::Handshake, "handshake"),
            (ErrorCategory::Session, "session"),
            (ErrorCategory::Transport, "transport"),
            (ErrorCategory::Terminal, "terminal"),
            (ErrorCategory::Platform, "platform"),
            (ErrorCategory::Internal, "internal"),
        ];
        for (c, s) in cats {
            assert_eq!(category_str(c), s);
        }
        let null_line = audit_entry_to_json(&entry(Outcome::Issued, None));
        assert!(null_line.ends_with("\"error_category\":null}"));
    }

    #[test]
    fn every_renderable_line_matches_the_whitelist_shape() {
        // 穷举全部 outcome × (None ∪ 全部类别)：每条输出都必须满足冻结
        // 形状——恰 4 对字符串定界引号、五键齐全。自由格式在输出端
        // 结构上不可能出现（字段无 String/Vec<u8> 通道）。
        let mut cats = vec![None];
        cats.extend(
            [
                ErrorCategory::Book,
                ErrorCategory::Codec,
                ErrorCategory::Anchor,
                ErrorCategory::Allocation,
                ErrorCategory::Recovery,
                ErrorCategory::Handshake,
                ErrorCategory::Session,
                ErrorCategory::Transport,
                ErrorCategory::Terminal,
                ErrorCategory::Platform,
                ErrorCategory::Internal,
            ]
            .iter()
            .copied()
            .map(Some),
        );
        for o in [
            Outcome::Issued,
            Outcome::Wasted,
            Outcome::Rejected,
            Outcome::Recovered,
            Outcome::Quarantined,
        ] {
            for c in &cats {
                let line = audit_entry_to_json(&entry(o, *c));
                assert!(line.starts_with("{\"book_id\":\""));
                assert!(line.contains("\",\"segment\":"));
                assert!(line.contains(",\"generation\":"));
                assert!(line.contains(",\"outcome\":\""));
                assert!(line.ends_with("\"}") || line.ends_with("null}"));
                let quotes = line.matches('"').count();
                // 引号数冻结：五个键名各 2、字符串值（book_id/outcome/
                // 类别）再各 2：null 时 14，有类别时 16。
                let expect_quotes = if c.is_some() { 16 } else { 14 };
                assert_eq!(quotes, expect_quotes, "引号数冻结，got: {line}");
            }
        }
    }

    #[test]
    fn sink_appends_jsonl_lines_and_creates_0600() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/tmp")
            .join(format!("otp-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);

        let mut sink = JsonlAuditSink::open(&path).unwrap();
        sink.write_entry(&entry(Outcome::Issued, None)).unwrap();
        sink.write_entry(&entry(Outcome::Rejected, Some(ErrorCategory::Session)))
            .unwrap();
        drop(sink);

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"outcome\":\"issued\""));
        assert!(lines[1].contains("\"outcome\":\"rejected\""));
        assert!(lines[1].contains("\"error_category\":\"session\""));

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "审计日志必须 0600");

        // 追加而非截断：再开一次，前两行仍在。
        let mut sink2 = JsonlAuditSink::open(&path).unwrap();
        sink2.write_entry(&entry(Outcome::Recovered, None)).unwrap();
        drop(sink2);
        let text2 = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text2.lines().count(), 3);
        assert!(text2.starts_with(lines[0]));

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
