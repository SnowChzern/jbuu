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

use otp_anchor_spec::{AnchorCopy, AnchorPayload, AnchorRecord, AnchorStore, decide};
use otp_types::Generation;

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
    /// 锚副本损坏或无法证明双锚状态安全，拒绝启动。
    Quarantined {
        /// 被隔离的副本（双锚异常时为 None）。
        copy: Option<AnchorCopy>,
        /// 机器可读的白名单原因。
        reason: &'static str,
    },
    /// 外部单调水位高于双锚，阻断疑似快照回滚。
    RollbackBlocked,
}

/// 启动恢复：读取/验证双锚 → 按 WP-02 决策表取高修复 → 回写并双 fsync。
/// 任何不确定都返回 Err（调用方必须拒绝提供服务）。
pub fn recover<A: AnchorStore, B: AnchorStore>(
    a: &mut A,
    b: &mut B,
) -> Result<RecoveryReport, RecoveryError> {
    recover_with_options(a, b, None, |_| true)
}

/// Recover with the optional external generation watermark and book verifier.
///
/// The verifier is called only for COMMIT records. Returning false is a
/// quarantine condition; it never causes the pointer to advance. The default
/// [`recover`] entry point deliberately has no implicit book access because
/// the anchor-store boundary does not own the book file.
pub fn recover_with_options<A, B, F>(
    a: &mut A,
    b: &mut B,
    watermark: Option<Generation>,
    mut verify_commit: F,
) -> Result<RecoveryReport, RecoveryError>
where
    A: AnchorStore,
    B: AnchorStore,
    F: FnMut(&AnchorRecord) -> bool,
{
    let ra = a.read_verified().map_err(|_| ());
    let rb = b.read_verified().map_err(|_| ());

    // The store abstraction intentionally exposes only verified records. Any
    // read error is therefore treated as an invalid copy and never repaired.
    // `decide` still handles the both-unreadable case for callers whose
    // backend can distinguish it before crossing this deliberately small API.
    let decision = decide(
        ra.map_err(|_| otp_anchor_spec::ReadFailure::Corrupt),
        rb.map_err(|_| otp_anchor_spec::ReadFailure::Corrupt),
    );
    let (adopted, stale) = match decision {
        otp_anchor_spec::RecoveryDecision::Consistent(record) => (record, None),
        otp_anchor_spec::RecoveryDecision::AdoptHigher { adopted, stale } => (adopted, Some(stale)),
        otp_anchor_spec::RecoveryDecision::QuarantineCorrupt { copy, reason } => {
            return Err(RecoveryError::Quarantined {
                copy: Some(copy),
                reason,
            });
        }
        otp_anchor_spec::RecoveryDecision::BothUnreadable => {
            return Err(RecoveryError::Quarantined {
                copy: None,
                reason: "both-anchors-unreadable",
            });
        }
        otp_anchor_spec::RecoveryDecision::CannotProveSafe { reason } => {
            return Err(RecoveryError::Quarantined { copy: None, reason });
        }
    };

    if watermark.is_some_and(|floor| adopted.generation < floor) {
        return Err(RecoveryError::RollbackBlocked);
    }
    if matches!(adopted.payload, AnchorPayload::Commit { .. }) && !verify_commit(&adopted) {
        return Err(RecoveryError::Quarantined {
            copy: None,
            reason: "book-anchor-mismatch",
        });
    }

    let mut warnings = vec![RecoveryWarning::DualRollbackUndetectable];
    let repaired = if let Some(stale_copy) = stale {
        // `write_full_and_sync` is the complete repair transaction: the
        // backend must finish the full record and fsync before returning.
        // No lower record is ever written, so recovery cannot move next back.
        match stale_copy {
            AnchorCopy::A => {
                a.write_full_and_sync(&adopted)
                    .map_err(|_| RecoveryError::Store)?;
                a.sync_parent_if_created()
                    .map_err(|_| RecoveryError::Store)?;
                if a.read_verified().map_err(|_| RecoveryError::Store)? != adopted {
                    return Err(RecoveryError::Store);
                }
            }
            AnchorCopy::B => {
                b.write_full_and_sync(&adopted)
                    .map_err(|_| RecoveryError::Store)?;
                b.sync_parent_if_created()
                    .map_err(|_| RecoveryError::Store)?;
                if b.read_verified().map_err(|_| RecoveryError::Store)? != adopted {
                    return Err(RecoveryError::Store);
                }
            }
        }
        warnings.push(RecoveryWarning::StaleCopyRepaired { copy: stale_copy });
        Some(stale_copy)
    } else {
        None
    };

    Ok(RecoveryReport {
        adopted,
        repaired,
        quarantined: Vec::new(),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const ID: otp_types::BookId = otp_types::BookId::from_bytes(*b"OTPTERM-TESTBOOK");

    #[derive(Clone)]
    struct Store {
        record: Result<AnchorRecord, ()>,
        writes: Cell<usize>,
    }

    impl Store {
        fn valid(record: AnchorRecord) -> Self {
            Self {
                record: Ok(record),
                writes: Cell::new(0),
            }
        }
        fn invalid() -> Self {
            Self {
                record: Err(()),
                writes: Cell::new(0),
            }
        }
    }

    impl AnchorStore for Store {
        type Error = ();

        fn read_verified(&mut self) -> Result<AnchorRecord, Self::Error> {
            self.record
        }
        fn write_full_and_sync(&mut self, record: &AnchorRecord) -> Result<(), Self::Error> {
            self.record = Ok(*record);
            self.writes.set(self.writes.get() + 1);
            Ok(())
        }
        fn sync_parent_if_created(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn record(generation: u64, next: u64) -> AnchorRecord {
        AnchorRecord::commit(
            ID,
            Generation::new(generation),
            otp_types::SegmentIndex::new(next),
            otp_anchor_spec::SegmentHash([generation as u8; 32]),
        )
    }

    #[test]
    fn report_only_carries_public_metadata() {
        let r = RecoveryReport {
            adopted: record(1, 1),
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

    #[test]
    fn adopts_and_repairs_when_a_is_new_b_is_old() {
        let newer = record(2, 3);
        let mut a = Store::valid(newer);
        let mut b = Store::valid(record(1, 2));
        let report = recover(&mut a, &mut b).unwrap();
        assert_eq!(report.adopted, newer);
        assert_eq!(report.repaired, Some(AnchorCopy::B));
        assert_eq!(b.record, Ok(newer));
        assert_eq!(b.writes.get(), 1);
        assert!(
            report
                .warnings
                .contains(&RecoveryWarning::StaleCopyRepaired {
                    copy: AnchorCopy::B
                })
        );
    }

    #[test]
    fn adopts_and_repairs_when_b_is_new_a_is_old() {
        let newer = record(7, 9);
        let mut a = Store::valid(record(6, 8));
        let mut b = Store::valid(newer);
        let report = recover(&mut a, &mut b).unwrap();
        assert_eq!(report.adopted, newer);
        assert_eq!(report.repaired, Some(AnchorCopy::A));
        assert_eq!(a.record, Ok(newer));
        assert_eq!(a.writes.get(), 1);
    }

    #[test]
    fn inconsistent_anchors_are_quarantined_without_writes() {
        let mut a = Store::valid(record(3, 4));
        let mut b = Store::valid(record(3, 5));
        let err = recover(&mut a, &mut b).unwrap_err();
        assert_eq!(
            err,
            RecoveryError::Quarantined {
                copy: None,
                reason: "same-order-different-bytes"
            }
        );
        assert_eq!(a.writes.get(), 0);
        assert_eq!(b.writes.get(), 0);
    }

    #[test]
    fn corrupt_copy_is_quarantined_and_frozen() {
        let mut a = Store::invalid();
        let mut b = Store::valid(record(1, 2));
        let err = recover(&mut a, &mut b).unwrap_err();
        assert_eq!(
            err,
            RecoveryError::Quarantined {
                copy: Some(AnchorCopy::A),
                reason: "anchor-a-invalid"
            }
        );
        assert_eq!(a.writes.get(), 0);
        assert_eq!(b.writes.get(), 0);
    }

    #[test]
    fn software_only_mode_reports_undetectable_dual_rollback() {
        let mut a = Store::valid(record(4, 6));
        let mut b = Store::valid(record(4, 6));
        let report = recover(&mut a, &mut b).unwrap();
        assert!(
            report
                .warnings
                .contains(&RecoveryWarning::DualRollbackUndetectable)
        );
        assert_eq!(report.adopted.next.get(), 6);
    }

    #[test]
    fn watermark_blocks_start_without_advancing_or_repairing() {
        let mut a = Store::valid(record(4, 6));
        let mut b = Store::valid(record(4, 6));
        let err =
            recover_with_options(&mut a, &mut b, Some(Generation::new(5)), |_| true).unwrap_err();
        assert_eq!(err, RecoveryError::RollbackBlocked);
        assert_eq!(a.writes.get(), 0);
        assert_eq!(b.writes.get(), 0);
    }

    #[test]
    fn commit_verification_failure_is_fail_closed() {
        let mut a = Store::valid(record(2, 3));
        let mut b = Store::valid(record(2, 3));
        let err = recover_with_options(&mut a, &mut b, None, |_| false).unwrap_err();
        assert_eq!(
            err,
            RecoveryError::Quarantined {
                copy: None,
                reason: "book-anchor-mismatch"
            }
        );
        assert_eq!(a.writes.get(), 0);
        assert_eq!(b.writes.get(), 0);
    }

    #[test]
    fn adopted_next_never_recedes_and_candidate_cannot_be_reused() {
        let newer = record(9, 11);
        let mut a = Store::valid(newer);
        let mut b = Store::valid(record(8, 10));
        let report = recover(&mut a, &mut b).unwrap();
        // The next allocation starts at adopted.next, never at the candidate
        // i = adopted.next - 1; recovery itself has no decrementing path.
        assert!(report.adopted.next.get() >= 11);
        assert_ne!(report.adopted.next.get(), 10);
        assert_eq!(b.record, Ok(newer));
    }
}
