//! # otp-recovery —— 崩溃恢复【高危】
//!
//! 实现规划 §2 职责：启动读取/验证双锚，采用较高 generation/next；一新一旧
//! 修复；损坏隔离；双回滚能力边界告警。
//!
//! 禁止事项（规划 §2）：不自动降低状态；无法证明安全时不得启动服务。
//!
//! 决策依据：设计书 §6 五类崩溃窗口 + §7 回滚锚；逐条决策表由 WP-02 冻结
//! （otp-anchor-spec::decide），本 crate 负责真实后端上的编排：
//! 读取 → 决策 → 修复回写 → 双 fsync → 报告/拒绝启动。
//!
//! 实现归属：栋梁 WP-08（CODEOWNERS 双批准路径，榫卯不得单独修改）。

#![forbid(unsafe_code)]

use otp_anchor_spec::{AnchorCopy, AnchorRecord, AnchorStore};

/// 恢复结果报告（仅公开元数据；可进入审计日志白名单字段）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecoveryReport {
    /// 最终采用的状态（两副本已修复一致并各自 fsync）。
    pub adopted: AnchorRecord,
    /// 被修复的旧副本（一新一旧场景）。
    pub repaired: Option<AnchorCopy>,
    /// 被隔离的损坏副本（等待人工恢复）。
    pub quarantined: Vec<AnchorCopy>,
    /// 能力边界/风险告警。
    pub warnings: Vec<RecoveryWarning>,
}

/// 恢告警告。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecoveryWarning {
    /// 一新一旧：旧副本已被修复并 fsync（日志记 rollback/stale-copy）。
    StaleCopyRepaired {
        /// 被修复副本。
        copy: AnchorCopy,
    },
    /// 校验失败副本已隔离，等待人工恢复。
    CorruptCopyQuarantined {
        /// 被隔离副本。
        copy: AnchorCopy,
    },
    /// 双副本同时回滚且无外部单调源（TPM/NVRAM counter/远端审计水位）：
    /// 软件无法检测 —— 显式能力边界告警，不得宣称安全，也不得自动猜测前进
    /// （设计书 §7 / 规划 §5.2）。
    DualRollbackUndetectable,
}

/// 恢复失败：服务不得启动（fail-closed）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecoveryError {
    /// 双副本均不可读取。
    BothUnreadable,
    /// 无法证明安全，拒绝启动服务（绝不自动降低状态/猜测前进）。
    CannotProveSafe {
        /// 原因说明。
        reason: &'static str,
    },
    /// 存储读写失败。
    Store,
}

/// 启动恢复：读取/验证双锚 → 按 WP-02 决策表取高修复 → 回写并双 fsync。
/// 任何不确定都返回 Err（调用方必须拒绝提供服务）。
pub fn recover<A: AnchorStore, B: AnchorStore>(
    _a: &mut A,
    _b: &mut B,
) -> Result<RecoveryReport, RecoveryError> {
    todo!("WP-08")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_only_carries_public_metadata() {
        let r = RecoveryReport {
            adopted: AnchorRecord {
                book_id: otp_types::BookId::from_bytes([0; 16]),
                next: otp_types::SegmentIndex::new(1),
                generation: otp_types::Generation::new(1),
                previous_segment_hash: otp_anchor_spec::SegmentHash([0; 32]),
            },
            repaired: Some(AnchorCopy::B),
            quarantined: vec![],
            warnings: vec![RecoveryWarning::StaleCopyRepaired {
                copy: AnchorCopy::B,
            }],
        };
        assert!(matches!(
            r.warnings.as_slice(),
            [RecoveryWarning::StaleCopyRepaired {
                copy: AnchorCopy::B
            }]
        ));
    }
}
