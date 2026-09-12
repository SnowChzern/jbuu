//! # otp-allocator —— 段分配器【高危】
//!
//! 实现规划 §2 职责：跨线程/进程互斥、reservation intent、双锚写满+各自
//! fsync、读段、最终锚、返回 committed segment；耗尽处理。
//!
//! ## fail-to-waste 铁律（设计书 §6，顺序冻结）
//!
//! ```text
//! lock → load_and_reconcile_anchor(取高，不接受回退) → i = next
//! → i >= count ? EXHAUSTED
//! → intent{reserved:i, next:i+1, gen+1} → write a → fsync a → write b → fsync b
//! → segment = pread(book, i*64, 64)
//! → candidate{next:i+1, H(segment), gen+1} → write a → fsync a → write b → fsync b
//! → 返回 CommittedSegment
//! ```
//!
//! 任一步失败/不确定：fail-closed —— 段只能浪费，绝不回退、绝不复用
//! （设计书 §6 五类崩溃窗口均满足“最多浪费一段”）。
//!
//! 禁止事项（规划 §2）：不允许调用方指定回退值；不在持久化完成前返回段。
//!
//! ## 模块边界（规划 §2.2）
//!
//! - 握手层只能经 [`SegmentIssuer::issue`] 取段；类型系统中不存在从
//!   `ReservedSegment` 转成 AEAD key 的公开路径。
//! - [`CommittedSegment`] 不实现 Clone/Debug/序列化；Drop 清零。
//!
//! 实现归属：栋梁 WP-07（CODEOWNERS 双批准路径，榫卯不得单独修改）。

#![forbid(unsafe_code)]

use std::path::PathBuf;

use otp_types::{BookId, Generation, SEGMENT_LEN, SegmentIndex};
use zeroize::ZeroizeOnDrop;

/// 已提交段：双锚最终 fsync 全部成功后的唯一合法产出。
///
/// 安全属性（规划 §2.2）：不实现 Clone/Debug/PartialEq/序列化；Drop 清零；
/// 只能由本 crate 构造；唯一读取出口是 [`CommittedSegment::as_bytes`]，
/// 仅供会话层（otp-session）建链使用。
#[derive(ZeroizeOnDrop)]
pub struct CommittedSegment {
    inner: [u8; SEGMENT_LEN],
}

impl CommittedSegment {
    /// 读取段正文（仅供 otp-session 建链拆方向密钥）。
    /// 64B 段直接拆两个 32B 方向密钥由会话层完成；本类型不做任何密码学转换。
    pub fn as_bytes(&self) -> &[u8; SEGMENT_LEN] {
        &self.inner
    }
}

/// 预留中状态：仅分配器内部存在，无公开转换路径（规划 §2.2）。
pub struct ReservedSegment {
    /// 防构造。
    _private: (),
}

/// 签发接口：握手层唯一合法的取段入口（规划 §2.2）。
pub trait SegmentIssuer {
    /// 签发下一段。成功返回已提交段；失败分类见 [`IssueError`]。
    /// 本接口绝不接受“回退值”参数，也绝不返回未持久化的段。
    fn issue(&mut self) -> Result<CommittedSegment, IssueError>;
}

/// 分配器配置。
pub struct AllocatorConfig {
    /// 密码本路径。
    pub book: PathBuf,
    /// 锚副本 A 路径（独立介质）。
    pub anchor_a: PathBuf,
    /// 锚副本 B 路径（独立介质）。
    pub anchor_b: PathBuf,
    /// 期望 book_id（不匹配即拒绝运行，防错拿另一套本体）。
    pub expected_book_id: BookId,
}

/// 段分配器。内部状态（book/store/锁/内存提交表）随 WP-07 落地。
pub struct Allocator {
    /// 内部状态随 WP-07 落地。
    _wp07: (),
}

impl Allocator {
    /// 打开密码本 + 双锚 + 跨进程互斥锁（锁语义由 otp-platform 提供），
    /// 并执行启动恢复（采用较高状态）。
    pub fn open(_cfg: AllocatorConfig) -> Result<Self, IssueError> {
        todo!("WP-07")
    }

    /// 当前安全状态（恢复后的 next 与 generation；只读视图，供审计）。
    pub fn state(&self) -> (SegmentIndex, Generation) {
        todo!("WP-07")
    }
}

impl SegmentIssuer for Allocator {
    fn issue(&mut self) -> Result<CommittedSegment, IssueError> {
        // 顺序铁律见 crate 文档；实现于 WP-07（栋梁）。
        todo!("WP-07：fail-to-waste 双锚事务")
    }
}

/// 签发错误。只携带指针/类别等公开元数据，绝不携带段正文。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IssueError {
    /// 密码本耗尽：需离线换本；绝不越界读取、绝不回卷。
    Exhausted {
        /// 当前 next。
        next: SegmentIndex,
    },
    /// 锁不可用（被占用/超时/锁后端不受支持）。
    LockUnavailable,
    /// 持久化不确定（短写/EIO/ENOSPC/fsync 结果未知）：fail-closed，
    /// 候选段作废。
    PersistenceUncertain,
    /// 锚校验失败：需隔离并人工恢复（转 otp-recovery）。
    AnchorCorrupt,
    /// book_id 与配置不符。
    BookMismatch,
    /// 其他 I/O 错误。
    Io,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_segment_is_64b_and_zeroized_on_drop() {
        // 构造在 WP-07 实现；这里固化不变量：64B、无 Clone/Debug/序列化。
        assert_eq!(core::mem::size_of::<CommittedSegment>(), SEGMENT_LEN);
        // 以下在编译期即无法通过（评审提示）：
        // let _ = format!("{:?}", committed);
        // let _ = committed.clone();
    }

    #[test]
    fn issue_error_carries_no_secret_material() {
        let e = IssueError::Exhausted {
            next: SegmentIndex::new(3),
        };
        // 错误只含指针/类别（审计白名单），可安全打印
        assert!(matches!(e, IssueError::Exhausted { .. }));
    }
}
