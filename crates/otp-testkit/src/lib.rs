//! # otp-testkit —— 测试基础设施
//!
//! 实现规划 §2 职责：确定性测试本、虚拟/故障注入持久化后端、代理网络、
//! 进程崩溃控制、模型 oracle。
//!
//! 禁止事项（规划 §2）：不链接进生产二进制（otp-cli 不得依赖本 crate）。
//!
//! 实现归属：榫卯 WP-13（故障注入框架）+ 各里程碑复用。

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use otp_anchor_spec::{AnchorRecord, AnchorStore};
use otp_types::SegmentIndex;

/// 已生成的测试密码本（内容独立均匀随机；仅测试用）。
pub struct TestBook {
    /// 密码本文件路径。
    pub path: PathBuf,
    /// 总段数。
    pub segment_count: u64,
}

/// 生成确定性/随机测试密码本（OS CSPRNG；secret 只留在临时目录，不入 git）。
pub fn generate_test_book(_dir: &Path, _segment_count: u64) -> Result<TestBook, TestkitError> {
    todo!("WP-13")
}

/// 故障注入点：锚后端每个 write/fsync/pread 边界均可命名注入
/// （规划 §5.1 进程层验证）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Failpoint {
    /// 指定副本短写。
    WriteShort {
        /// 目标副本。
        copy: otp_anchor_spec::AnchorCopy,
    },
    /// 指定操作返回 I/O 错误（EIO/ENOSPC 语义）。
    IoError {
        /// 目标操作。
        op: AnchorOp,
    },
    /// 命中点子进程立即被 SIGKILL（由 CrashController 编排）。
    Crash {
        /// 目标操作。
        op: AnchorOp,
    },
}

/// 锚后端可注入的操作边界（枚举覆盖设计书 §6 事务全顺序）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnchorOp {
    /// intent write 开始。
    IntentWriteA,
    /// intent fsync A 返回。
    IntentFsyncA,
    /// intent write B 开始。
    IntentWriteB,
    /// intent fsync B 返回。
    IntentFsyncB,
    /// 段正文 pread。
    SegmentPread,
    /// 最终锚 write A。
    FinalWriteA,
    /// 最终锚 fsync A。
    FinalFsyncA,
    /// 最终锚 write B。
    FinalWriteB,
    /// 最终锚 fsync B。
    FinalFsyncB,
}

/// 故障注入锚后端（模型层：内存 FaultyAnchorStore，穷举状态转移）。
pub struct FaultyAnchorStore {
    /// 内部状态随 WP-13 落地。
    _wp13: (),
}

impl AnchorStore for FaultyAnchorStore {
    type Error = TestkitError;

    fn read_verified(&mut self) -> Result<AnchorRecord, Self::Error> {
        todo!("WP-13")
    }
    fn write_full_and_sync(&mut self, _record: &AnchorRecord) -> Result<(), Self::Error> {
        todo!("WP-13")
    }
    fn sync_parent_if_created(&mut self) -> Result<(), Self::Error> {
        todo!("WP-13")
    }
}

/// 进程内回环传输对（M1 loopback 用）。
pub struct LoopbackPair {
    /// 客户端端点。
    pub client: otp_transport::LoopbackTransport,
    /// 服务端端点。
    pub server: otp_transport::LoopbackTransport,
}

/// 创建一对互通的回环传输（WP-12 落地：委托传输层默认容量构造；
/// 需要旁路字节记录/有界容量背压时直接用
/// `otp_transport::LoopbackTransport::new_pair_tapped/_bounded`）。
pub fn loopback_pair() -> LoopbackPair {
    let (client, server) = otp_transport::LoopbackTransport::new_pair();
    LoopbackPair { client, server }
}

/// 进程崩溃控制器：子进程在命名 failpoint 向父进程发“已到达”事件，
/// 父进程立即 SIGKILL，随后重启恢复并核对（规划 §5.1 第 2 层）。
pub struct CrashController {
    /// 内部状态随 WP-13 落地。
    _wp13: (),
}

impl CrashController {
    /// 派生一个执行 issue() 的子进程并在 `_failpoint` 处 kill。
    pub fn spawn_issue_child(&self, _failpoint: Failpoint) -> Result<CrashOutcome, TestkitError> {
        todo!("WP-13")
    }
}

/// 一次崩溃注入的结果（机器可读，写入 evidence/<run-id>/）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CrashOutcome {
    /// 命中的注入点。
    pub failpoint: Failpoint,
    /// 重启恢复后的 next 指针。
    pub recovered_next: SegmentIndex,
}

/// 模型 oracle：断言 next 不下降、已返回索引全局唯一（M2 验收 6）。
pub struct IssueOracle {
    next: SegmentIndex,
    issued: BTreeSet<u64>,
}

impl IssueOracle {
    /// 以初始指针构造。
    pub fn new(start: SegmentIndex) -> Self {
        Self {
            next: start,
            issued: BTreeSet::new(),
        }
    }

    /// 记录一次签发结果。返回 false 当且仅当违反不变量：
    /// 索引重复（复用死刑）或指针回退。跳号（浪费）合法。
    pub fn observe(&mut self, index: SegmentIndex) -> bool {
        if index.get() < self.next.get() {
            return false; // 回退
        }
        if !self.issued.insert(index.get()) {
            return false; // 重复签发
        }
        if index >= self.next {
            self.next = index.next();
        }
        true
    }

    /// 当前期望的最低 next。
    pub fn next(&self) -> SegmentIndex {
        self.next
    }

    /// 已观察的签发总数。
    pub fn issued_count(&self) -> usize {
        self.issued.len()
    }
}

/// 测试工具错误。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TestkitError {
    /// 测试本生成失败。
    BookGeneration,
    /// 注入后端错误（模拟 EIO/ENOSPC 等）。
    InjectedFailure,
    /// 子进程/管道错误。
    CrashController,
    /// I/O 错误。
    Io,
}

/// proptest 策略（供各 crate 性质测试复用；WP-05/10/11 使用）。
pub mod strategies {
    use super::*;
    use otp_types::BookId;
    use proptest::prelude::*;

    /// 任意段索引（0..=max）。
    pub fn any_segment_index(max: u64) -> BoxedStrategy<SegmentIndex> {
        (0..=max).prop_map(SegmentIndex::new).boxed()
    }

    /// 任意 book_id。
    pub fn any_book_id() -> BoxedStrategy<BookId> {
        proptest::array::uniform16(any::<u8>())
            .prop_map(BookId::from_bytes)
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_rejects_replay_and_regression_allows_holes() {
        let mut o = IssueOracle::new(SegmentIndex::new(0));
        assert!(o.observe(SegmentIndex::new(0)));
        assert!(o.observe(SegmentIndex::new(1)));
        assert!(!o.observe(SegmentIndex::new(1)), "重复签发必须被拒绝");
        assert!(!o.observe(SegmentIndex::new(0)), "回退必须被拒绝");
        assert!(o.observe(SegmentIndex::new(5)), "跳号=浪费，合法");
        assert_eq!(o.next(), SegmentIndex::new(6));
        assert_eq!(o.issued_count(), 3);
    }

    #[test]
    fn failpoints_cover_full_issue_sequence() {
        // 覆盖设计书 §6 事务全顺序的命名注入点（崩溃窗口 1-5 均可命名复现）
        let ops = [
            AnchorOp::IntentWriteA,
            AnchorOp::IntentFsyncA,
            AnchorOp::IntentWriteB,
            AnchorOp::IntentFsyncB,
            AnchorOp::SegmentPread,
            AnchorOp::FinalWriteA,
            AnchorOp::FinalFsyncA,
            AnchorOp::FinalWriteB,
            AnchorOp::FinalFsyncB,
        ];
        assert_eq!(ops.len(), 9);
    }
}
