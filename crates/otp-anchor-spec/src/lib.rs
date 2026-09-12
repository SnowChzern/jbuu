//! # otp-anchor-spec —— 锚记录格式与恢复决策表
//!
//! 实现规划 §2 职责：斗拱输出的锚记录格式、CRC/MAC/完整性接口、generation
//! 比较、状态转移与恢复决策表。线格式、校验算法与 5 类崩溃窗口的决策表由
//! WP-02 冻结；本骨架（WP-04）固定接口形状。
//!
//! 禁止事项（规划 §2）：不实现实际落盘事务（真实后端在 otp-platform，
//! 事务顺序在 otp-allocator，恢复编排在此之上的 otp-recovery）。

#![forbid(unsafe_code)]

use core::cmp::Ordering;
use otp_types::{BookId, Generation, SegmentIndex};

/// `previous_segment_hash`：SHA-256。仅作状态回滚检测的工程完整性锚，
/// 不参与段到密钥的任何转换（设计书 §6：安全性依赖抗碰撞/抗篡改存储，
/// 不得据此宣称签发层依赖哈希或获得信息论认证）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SegmentHash(pub [u8; 32]);

/// 锚记录（两处独立介质各存一份；字段见设计书 §7）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AnchorRecord {
    /// 密码本 ID。
    pub book_id: BookId,
    /// 下一个可用段（已预留/提交的段不再可用）。
    pub next: SegmentIndex,
    /// 单调 generation（两副本取高比较）。
    pub generation: Generation,
    /// 上一已签发段的 SHA-256（回滚检测锚）。
    pub previous_segment_hash: SegmentHash,
}

impl AnchorRecord {
    /// 按（generation, next）比较状态新旧，供“采用较高状态”判定。
    pub fn state_cmp(&self, other: &Self) -> Ordering {
        (self.generation, self.next).cmp(&(other.generation, other.next))
    }
}

/// 锚副本标识（两处独立介质；不得只是同一文件的两个副本，设计书 §7）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnchorCopy {
    /// 副本 A。
    A,
    /// 副本 B。
    B,
}

/// 锚后端抽象（规划 §2.2）：只暴露这三个操作；测试后端（otp-testkit）
/// 可逐步注入短写、I/O 错误和 crash。
pub trait AnchorStore {
    /// 后端错误类型。
    type Error;
    /// 读取并做完整性校验（CRC/MAC 算法由 WP-02 冻结）；校验失败返回 Err。
    fn read_verified(&mut self) -> Result<AnchorRecord, Self::Error>;
    /// 全量覆盖写入并 fsync（短写必须循环补齐或显式报错，不得静默截断）。
    fn write_full_and_sync(&mut self, record: &AnchorRecord) -> Result<(), Self::Error>;
    /// 当次会话创建过文件时，对其父目录 fsync。
    fn sync_parent_if_created(&mut self) -> Result<(), Self::Error>;
}

/// 锚记录读取失败分类。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReadFailure {
    /// 记录存在但完整性校验失败（→ 隔离）。
    Corrupt,
    /// 介质不可读/不存在。
    Unreadable,
}

/// 锚格式/校验错误。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnchorSpecError {
    /// 记录线格式解码失败。
    DecodeFailed {
        /// 原因。
        reason: &'static str,
    },
    /// CRC/MAC 完整性校验失败。
    IntegrityCheckFailed,
}

/// 恢复决策（覆盖设计书 §6 崩溃分析 5 类窗口 + §7 回滚检测）。
/// 决策表逐条冻结于 WP-02；本枚举固定可能的结果空间。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecoveryDecision {
    /// 两副本状态一致：直接采用。
    Consistent(AnchorRecord),
    /// 一新一旧：采用较高 generation/next，候选段作废（浪费），
    /// 修复并回写旧副本后各自 fsync（设计书 §6 窗口 2）。
    AdoptHigher {
        /// 采用的记录。
        adopted: AnchorRecord,
        /// 落后的副本（将被修复）。
        stale: AnchorCopy,
    },
    /// 某副本校验失败：隔离该副本等待人工恢复，不得自动降级继续服务
    /// （设计书 §7）。
    QuarantineCorrupt {
        /// 被隔离副本。
        copy: AnchorCopy,
        /// 原因说明。
        reason: &'static str,
    },
    /// 双副本状态无法证明安全（如同时回滚且无外部单调源）：拒绝启动
    /// （fail-closed；能力边界告警见 otp-recovery::RecoveryWarning）。
    CannotProveSafe {
        /// 原因说明。
        reason: &'static str,
    },
    /// 双副本均不可读取。
    BothUnreadable,
}

/// 编码一条锚记录（线格式 + CRC/MAC 由 WP-02 冻结）。
pub fn encode_record(_record: &AnchorRecord, _out: &mut Vec<u8>) {
    todo!("WP-02")
}

/// 解码并校验一条锚记录。
pub fn decode_and_verify(_buf: &[u8]) -> Result<AnchorRecord, AnchorSpecError> {
    todo!("WP-02")
}

/// 恢复决策表入口：输入两副本的读取结果，输出唯一决策。
/// 实现由 WP-02 冻结的决策表；恢复编排（读→决策→修复→回写→fsync）在
/// otp-recovery。
pub fn decide(
    _a: Result<AnchorRecord, ReadFailure>,
    _b: Result<AnchorRecord, ReadFailure>,
) -> RecoveryDecision {
    todo!("WP-02")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(g: u64, next: u64) -> AnchorRecord {
        AnchorRecord {
            book_id: BookId::from_bytes([1; 16]),
            next: SegmentIndex::new(next),
            generation: Generation::new(g),
            previous_segment_hash: SegmentHash([2; 32]),
        }
    }

    #[test]
    fn state_cmp_prefers_higher_generation_then_next() {
        let old = sample(3, 10);
        let newer = sample(4, 11);
        let same_gen_higher_next = sample(3, 11);
        assert_eq!(old.state_cmp(&newer), Ordering::Less);
        assert_eq!(old.state_cmp(&same_gen_higher_next), Ordering::Less);
        assert_eq!(old.state_cmp(&old), Ordering::Equal);
    }
}
