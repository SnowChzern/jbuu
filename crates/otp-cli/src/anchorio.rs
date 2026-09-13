//! # 锚 inspect（规划 §65 otp-cli 行：只读、仅公开元数据）
//!
//! 读取锚文件并 `decode_and_verify`，输出：book_id、next、generation、
//! payload 类别（Init / Intent{reserved} / Commit{previous_segment_hash}）。
//! 双锚时另给出 `decide` 关系（一致 / 取高修复 / 隔离）。
//!
//! §65 红线：**默认不打印秘密**——锚记录中唯一与段材料相关的是
//! `previous_segment_hash`（段正文的 SHA-256 摘要，非段材料本身，且本就
//! 明文存于锚文件中供校验）；段正文/密钥在本模块不可达（不打开密码本）。

use std::path::Path;

use otp_anchor_spec::{AnchorRecord, RecoveryDecision, decide, decode_and_verify};

/// 单个锚的检查结果。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AnchorStatus {
    /// 读取/校验后的记录（None = 不可读或校验失败）。
    pub record: Option<AnchorRecord>,
    /// 失败时的白名单原因（不含文件内容）。
    pub failure: Option<&'static str>,
}

/// 双锚检查报告（公开元数据）。
pub struct AnchorInspectReport {
    pub a: AnchorStatus,
    pub b: AnchorStatus,
}

/// 检查单个锚文件。
#[must_use]
pub fn inspect_anchor(path: &Path) -> AnchorStatus {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => {
            return AnchorStatus {
                record: None,
                failure: Some("unreadable"),
            };
        }
    };
    match decode_and_verify(&bytes) {
        Ok(rec) => AnchorStatus {
            record: Some(rec),
            failure: None,
        },
        Err(_) => AnchorStatus {
            record: None,
            failure: Some("corrupt"),
        },
    }
}

/// 双锚关系（wp02 决策表的公开投影；None = 存在不可读/损坏副本）。
#[must_use]
pub fn relation(a: &AnchorStatus, b: &AnchorStatus) -> Option<&'static str> {
    let (Some(ra), Some(rb)) = (&a.record, &b.record) else {
        return None;
    };
    match decide(Ok(*ra), Ok(*rb)) {
        RecoveryDecision::Consistent(_) => Some("consistent"),
        RecoveryDecision::AdoptHigher { .. } => Some("adopt-higher (stale copy repairable)"),
        RecoveryDecision::QuarantineCorrupt { .. } => Some("quarantine"),
        RecoveryDecision::BothUnreadable => Some("both-unreadable"),
        RecoveryDecision::CannotProveSafe { .. } => Some("cannot-prove-safe"),
    }
}

fn record_line(label: &str, rec: &AnchorRecord) -> String {
    let mut s = format!("{label}: book_id={}", hex(rec.book_id.as_bytes()));
    s.push_str(&format!(
        " next={} generation={} payload={}",
        rec.next.get(),
        rec.generation.get(),
        payload_name(rec)
    ));
    s
}

fn payload_name(rec: &AnchorRecord) -> String {
    match rec.payload {
        otp_anchor_spec::AnchorPayload::Init => "init".to_string(),
        otp_anchor_spec::AnchorPayload::Intent { reserved } => {
            format!("intent(reserved={})", reserved.get())
        }
        otp_anchor_spec::AnchorPayload::Commit {
            previous_segment_hash,
        } => {
            format!("commit(prev_hash={})", hex(&previous_segment_hash.0))
        }
    }
}

/// 人类可读摘要（每锚一行 + 关系行；仅公开元数据）。
#[must_use]
pub fn summary(path_a: &Path, path_b: Option<&Path>, r: &AnchorInspectReport) -> String {
    let mut s = String::new();
    match &r.a.record {
        Some(rec) => s.push_str(&record_line(&path_a.display().to_string(), rec)),
        None => s.push_str(&format!(
            "{}: FAILED({})",
            path_a.display(),
            r.a.failure.unwrap_or("unknown")
        )),
    }
    s.push('\n');
    if let Some(pb) = path_b {
        match &r.b.record {
            Some(rec) => s.push_str(&record_line(&pb.display().to_string(), rec)),
            None => s.push_str(&format!(
                "{}: FAILED({})",
                pb.display(),
                r.b.failure.unwrap_or("unknown")
            )),
        }
        s.push('\n');
    }
    if path_b.is_some() {
        match relation(&r.a, &r.b) {
            Some(rel) => s.push_str(&format!("relation: {rel}\n")),
            None => s.push_str("relation: unreadable/corrupt copy present\n"),
        }
    }
    s
}

impl AnchorInspectReport {
    /// 是否两锚均可校验（单锚模式只看 a）。
    #[must_use]
    pub fn ok(&self) -> bool {
        self.a.record.is_some() && self.b.record.is_some()
    }

    /// 机器可读 JSON（公开元数据；可入 evidence/）。
    #[must_use]
    pub fn to_json(&self, path_a: &Path, path_b: Option<&Path>) -> String {
        let mut s = String::from("{");
        s.push_str(&anchor_json("a", path_a, &self.a));
        if let Some(pb) = path_b {
            s.push(',');
            s.push_str(&anchor_json("b", pb, &self.b));
            s.push_str(&format!(
                ",\"relation\":\"{}\"",
                relation(&self.a, &self.b).unwrap_or("unreadable-or-corrupt")
            ));
        }
        s.push('}');
        s
    }
}

fn anchor_json(key: &str, path: &Path, st: &AnchorStatus) -> String {
    match &st.record {
        Some(rec) => format!(
            "\"{key}\":{{\"path\":\"{}\",\"book_id\":\"{}\",\"next\":{},\"generation\":{},\"payload\":\"{}\"}}",
            path.display(),
            hex(rec.book_id.as_bytes()),
            rec.next.get(),
            rec.generation.get(),
            payload_name(rec)
        ),
        None => format!(
            "\"{key}\":{{\"path\":\"{}\",\"error\":\"{}\"}}",
            path.display(),
            st.failure.unwrap_or("unknown")
        ),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
