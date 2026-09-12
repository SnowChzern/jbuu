//! # otp-book —— 密码本读取器
//!
//! 实现规划 §2 职责：验证文件头、book_id、段长/总段数；在已提交预留后按索引
//! `pread_exact(64)`；测试本生成/校验工具的底层支撑（工具入口在 otp-cli /
//! otp-testkit）。
//!
//! 禁止事项（规划 §2）：不拥有/推进指针（指针归锚/分配器）；不得预读全本；
//! 不得在预留前读段。
//!
//! ## 段读取的模块边界（规划 §2.2）
//!
//! `read_segment` 为 crate-private；生产路径只有 otp-allocator 能在双锚
//! reservation fsync 成功之后调用。跨 crate 的封印机制（`#[doc(hidden)]`
//! 受控入口 / 独立 internal shim / 宏导出）由 WP-06（本 crate）与 WP-07
//! （allocator）联合定稿；在此之前仅提供 `__allocator_read_segment`
//! 过渡入口，且本目录已列入 CODEOWNERS 双批准清单，任何收紧/放松都需
//! 栋梁 + 安全审计复核。

#![forbid(unsafe_code)]

use std::path::Path;

use otp_types::{BookId, SEGMENT_LEN, SegmentIndex};
use zeroize::ZeroizeOnDrop;

/// 已打开并通过头校验的密码本（真实 fd/句柄随 WP-06 落地）。
pub struct Book {
    /// 内部状态（fd、头缓存等）随 WP-06 落地。
    _wp06: (),
}

/// 密码本文件头（设计书 §3：版本、密码本 ID、段长 64、总段数、校验元数据）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BookHeader {
    /// 文件格式版本。
    pub version: u16,
    /// 密码本 ID（绑定两端配置，防错拿另一套本体）。
    pub book_id: BookId,
    /// 段长（必须为 64）。
    pub segment_len: u32,
    /// 总段数。
    pub segment_count: u64,
}

/// 单个 64B 段正文。敏感数据：Drop 清零；不实现 Clone/Debug/PartialEq/序列化。
#[derive(ZeroizeOnDrop)]
pub struct Segment([u8; SEGMENT_LEN]);

impl Segment {
    /// 过渡入口：仅供 otp-allocator 在双 reservation fsync 后读取
    /// （见本 crate 文档“段读取的模块边界”）。
    #[doc(hidden)]
    pub fn expose_for_allocator(&self) -> &[u8; SEGMENT_LEN] {
        &self.0
    }
}

/// 密码本错误。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BookError {
    /// 文件不存在/不可读。
    NotFound,
    /// 文件头非法（版本/段长/总段数与文件长度不一致等）。
    InvalidHeader {
        /// 原因。
        reason: &'static str,
    },
    /// 索引越界（绝不越界读，规划 M2 验收）。
    SegmentOutOfRange {
        /// 请求的索引。
        index: SegmentIndex,
        /// 总段数。
        count: u64,
    },
    /// I/O 错误（pread 短读等，fail-closed）。
    Io,
}

impl Book {
    /// 打开并验证文件头：版本、book_id、段长必须为 64、总段数与文件长度一致。
    pub fn open(_path: &Path) -> Result<Self, BookError> {
        todo!("WP-06")
    }

    /// 已验证的文件头。
    pub fn header(&self) -> &BookHeader {
        todo!("WP-06")
    }

    /// 总段数（耗尽判定：next >= segment_count 即 EXHAUSTED）。
    pub fn segment_count(&self) -> u64 {
        todo!("WP-06")
    }

    /// 按索引 `pread_exact(64)` 读取段正文。crate-private（规划 §2.2）：
    /// 不预读、不缓存、指针语义归 otp-allocator；只能在预留提交后调用。
    pub(crate) fn read_segment(&self, _index: SegmentIndex) -> Result<Segment, BookError> {
        todo!("WP-06")
    }

    /// 过渡受控入口（见 crate 文档）；WP-06/07 定稿封印机制后移除或收紧。
    #[doc(hidden)]
    pub fn __allocator_read_segment(&self, index: SegmentIndex) -> Result<Segment, BookError> {
        self.read_segment(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_is_64b_and_zeroized_on_drop() {
        // 构造路径在 WP-06 实现；这里只固化不变量：段长 64、类型无 Debug/Clone。
        assert_eq!(core::mem::size_of::<Segment>(), SEGMENT_LEN);
        // Segment 不实现 Clone/Debug：以下在编译期即无法通过（注释保留为评审提示）
        // let _ = format!("{:?}", segment);
        // let _ = segment.clone();
    }

    #[test]
    fn header_shape_matches_design() {
        let h = BookHeader {
            version: 1,
            book_id: BookId::from_bytes([0; 16]),
            segment_len: 64,
            segment_count: 3,
        };
        assert_eq!(h.segment_len as usize, SEGMENT_LEN);
    }
}
