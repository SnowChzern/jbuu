//! # otp-platform —— 平台持久化与安全基线
//!
//! 实现规划 §2 职责：锁/租约、目录 fsync、mlock（尽力）、core/swap/文件系统
//! 检查、权限与审计日志 sink。WP-09（栋梁主责，榫卯协作）落点。
//!
//! 禁止事项（规划 §2）：不宣称软件可消除 SSD wear-leveling 残留（设计书 §7：
//! 用户态清零不能保证历史物理副本消失）。
//!
//! ## unsafe 政策（规划 §1.2：核心 crate 禁止 unsafe）
//!
//! 本 crate 是 workspace 内唯一允许出现 `unsafe` 的位置：仅限 rustix 未覆盖
//! 的 syscall 包装，且每次引入必须经单独审计卡批准（显式
//! `#[allow(unsafe_code)]` 并注释说明理由）。其余 crate 一律
//! `#![forbid(unsafe_code)]`，由 scripts/check-unsafe.sh 在质量门强制。

// deny 而非 forbid：为将来经审计批准的 syscall 包装留显式豁免点
#![deny(unsafe_code)]

use std::fs::File;
use std::path::Path;

use otp_types::{BookId, ErrorCategory, Generation, SegmentIndex};

/// 跨进程文件锁守卫（RAII：drop 释放；优先 Linux OFD lock）。
pub struct FileLockGuard {
    /// 内部状态随 WP-09 落地。
    _wp09: (),
}

/// 租约守卫：携带单调递增 fencing token，陈旧持有者不得继续写 PTY/锚
/// （规划 M4 验收 10）。
#[non_exhaustive]
pub struct LeaseGuard {
    /// fencing token（单调递增）。
    pub fencing_token: u64,
}

/// 获取文件锁（exclusive=true 为写锁）。锁后端不受支持（NFS/FUSE/overlay 等
/// 未验证 FS）必须返回 Err（拒绝运行，规划 M2 验收）。
pub fn acquire_ofd_lock(_path: &Path, _exclusive: bool) -> Result<FileLockGuard, PlatformError> {
    todo!("WP-09")
}

/// 获取租约（含 fencing token 分配）。
pub fn acquire_lease(_path: &Path) -> Result<LeaseGuard, PlatformError> {
    todo!("WP-09")
}

/// 对已打开文件 fsync：必须真正穿透文件系统与设备缓存；结果不确定即报错
/// （fail-closed，设计书 §6）。
pub fn fsync_file(_file: &File) -> Result<(), PlatformError> {
    todo!("WP-09")
}

/// 对目录 fsync（当次会话创建过文件时必需，保证目录项持久化）。
pub fn fsync_dir(_dir: &Path) -> Result<(), PlatformError> {
    todo!("WP-09")
}

/// mlock 尽力而为：失败只告警不虚报；swap/core 策略由 doctor 检查，
/// 本函数不宣称能消除 SSD/swap 残留。
pub fn mlock_best_effort(_data: &mut [u8]) -> Result<(), PlatformError> {
    todo!("WP-09")
}

/// 环境检查项状态。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CheckStatus {
    /// 通过。
    Ok,
    /// 告警（可运行但需人工确认）。
    Warn {
        /// 说明。
        detail: &'static str,
    },
    /// 阻断（按策略拒绝启动）。
    Block {
        /// 说明。
        detail: &'static str,
    },
}

/// 环境体检报告（doctor 数据源）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EnvironmentReport {
    /// core dump 配置（RLIMIT_CORE/dumpable）。
    pub core_dump: CheckStatus,
    /// swap 配置（禁用或加密）。
    pub swap: CheckStatus,
    /// 锚存储文件系统持久化语义支持情况。
    pub filesystem: CheckStatus,
    /// 密码本/锚文件权限。
    pub permissions: CheckStatus,
}

/// 探测运行环境：core dump/swap/文件系统/权限。高风险条件按策略 Block。
pub fn probe_environment() -> EnvironmentReport {
    todo!("WP-09/WP-15")
}

/// 审计日志条目：结构化白名单字段（规划 §2.2）——book_id、段号、generation、
/// 结果、错误类别。禁止自由格式字段，禁止附带敏感对象（段正文/方向密钥/
/// 业务明文/确认明文，设计书 §9）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AuditEntry {
    /// 密码本 ID。
    pub book_id: BookId,
    /// 段号。
    pub segment: SegmentIndex,
    /// generation。
    pub generation: Generation,
    /// 操作结果。
    pub outcome: Outcome,
    /// 错误分类（若有）。
    pub error_category: Option<ErrorCategory>,
}

/// 审计结果分类。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// 段已签发。
    Issued,
    /// 段已浪费（崩溃窗口/不确定）。
    Wasted,
    /// 请求被拒绝。
    Rejected,
    /// 状态已恢复。
    Recovered,
    /// 副本已隔离。
    Quarantined,
}

/// 审计日志 sink：实现方必须保证不落任何敏感材料。
pub trait AuditLogSink {
    /// 追加一条审计记录。
    fn emit(&mut self, entry: &AuditEntry) -> Result<(), PlatformError>;
}

/// 平台错误。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PlatformError {
    /// 锁后端不受支持（NFS/FUSE/overlay 等未验证 FS）。
    LockUnsupported,
    /// 锁被其他进程持有。
    LockHeld,
    /// fsync 结果不确定（fail-closed）。
    FsyncUncertain,
    /// 文件系统不受支持。
    UnsupportedFilesystem {
        /// 文件系统名。
        fs_name: &'static str,
    },
    /// I/O 错误。
    Io,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_entry_has_whitelist_fields_only() {
        let e = AuditEntry {
            book_id: BookId::from_bytes([1; 16]),
            segment: SegmentIndex::new(7),
            generation: Generation::new(9),
            outcome: Outcome::Issued,
            error_category: None,
        };
        // 白名单五字段之外无任何自由格式载体（编译期形状，评审核对）
        let _ = format!("{e:?}");
        assert!(matches!(e.outcome, Outcome::Issued));
    }
}
