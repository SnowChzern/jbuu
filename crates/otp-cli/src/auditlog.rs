//! # 审计日志胶水（规划 §94 白名单）
//!
//! 只暴露"填白名单字段"的构造函数：book_id、段号、generation、结果、
//! 错误类别——五个字段之外无任何输入点（无格式串、无任意对象），自由
//! 格式与敏感对象在类型层即不可表达。落盘经 [`JsonlAuditSink`]（0600、
//! 逐条 fsync）。

use otp_platform::{AuditEntry, JsonlAuditSink, Outcome};
use otp_types::{BookId, ErrorCategory, Generation, SegmentIndex};

/// 可选审计 sink（无 `--audit-log` 时为 None，事件被丢弃；serve/connect
/// 在显式给出路径时才记录）。
pub struct Audit {
    sink: Option<JsonlAuditSink>,
}

impl Audit {
    /// 不落盘（测试/交互用途）。
    #[must_use]
    pub const fn disabled() -> Self {
        Self { sink: None }
    }

    /// 打开 JSONL sink（0600 追加）。
    pub fn open(path: &std::path::Path) -> Result<Self, String> {
        JsonlAuditSink::open(path)
            .map(|sink| Self { sink: Some(sink) })
            .map_err(|_| "审计日志打开失败".to_string())
    }

    /// 记录一条会话事件（成功路径：结果=issued/recovered，无错误类别）。
    pub fn emit_ok(
        &mut self,
        book_id: BookId,
        segment: SegmentIndex,
        generation: Generation,
        outcome: Outcome,
    ) -> Result<(), String> {
        self.emit(AuditEntry {
            book_id,
            segment,
            generation,
            outcome,
            error_category: None,
        })
    }

    /// 记录一条失败事件（结果=rejected/quarantined，带错误类别）。
    pub fn emit_err(
        &mut self,
        book_id: BookId,
        segment: SegmentIndex,
        generation: Generation,
        outcome: Outcome,
        category: ErrorCategory,
    ) -> Result<(), String> {
        self.emit(AuditEntry {
            book_id,
            segment,
            generation,
            outcome,
            error_category: Some(category),
        })
    }

    fn emit(&mut self, entry: AuditEntry) -> Result<(), String> {
        match &mut self.sink {
            Some(sink) => sink
                .write_entry(&entry)
                .map_err(|_| "审计日志写入失败（fail closed）".to_string()),
            None => Ok(()),
        }
    }
}
