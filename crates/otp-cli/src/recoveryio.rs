//! # 恢复编排适配（WP-15 ②前置）
//!
//! [`otp_recovery::recover`] 面向 [`otp_anchor_spec::AnchorStore`] 抽象；
//! 本模块把平台层 [`otp_platform::FileAnchorBackend`]（闭包式 read_verified）
//! 适配为 AnchorStore，并做存在性前置检查（锚缺失 → 拒绝启动，**绝不**
//! 因 open 语义顺手创建空锚文件毁掉现场）。
//!
//! 语义边界：本模块不改变 otp-recovery/otp-platform 的任何生产语义，
//! 只是组合；真正的取高修复决策仍在 WP-08 的 recover 内。

use std::path::Path;

use otp_anchor_spec::{AnchorRecord, AnchorStore, encode_record};
use otp_platform::{AnchorBackend, FileAnchorBackend, PlatformError};
use otp_recovery::{RecoveryError, RecoveryReport, recover};

/// 真实文件锚的 AnchorStore 适配。
pub struct FileAnchorStore {
    backend: FileAnchorBackend,
}

impl FileAnchorStore {
    /// 打开既有锚文件（不存在 → Err；不创建）。
    pub fn open_existing(path: &Path) -> Result<Self, PlatformError> {
        if !path.exists() {
            return Err(PlatformError::InvalidData);
        }
        FileAnchorBackend::open(path).map(|backend| Self { backend })
    }
}

impl AnchorStore for FileAnchorStore {
    type Error = PlatformError;

    fn read_verified(&mut self) -> Result<AnchorRecord, Self::Error> {
        self.backend
            .read_verified(|bytes| decode_record(bytes).ok_or(PlatformError::InvalidData))
    }

    fn write_full_and_sync(&mut self, record: &AnchorRecord) -> Result<(), Self::Error> {
        let mut buf = Vec::with_capacity(128);
        encode_record(record, &mut buf);
        self.backend.write_full_and_sync(&buf)
    }

    fn sync_parent_if_created(&mut self) -> Result<(), Self::Error> {
        self.backend.sync_parent_if_created()
    }
}

fn decode_record(bytes: &[u8]) -> Option<AnchorRecord> {
    otp_anchor_spec::decode_and_verify(bytes).ok()
}

/// serve/connect 启动恢复：双锚必须存在；恢复失败 → Err（调用方拒绝服务）。
///
/// 注：`verify_commit` 传 `|_| true`——密码本段哈希的严格校验在随后
/// `Allocator::open` 内完成（其 BookReader 拥有唯一的段读取路径），
/// 此处不复制段读取逻辑（§2.2 接口隔离）。
pub fn startup_recover(anchor_a: &Path, anchor_b: &Path) -> Result<RecoveryReport, RecoveryError> {
    let mut a = FileAnchorStore::open_existing(anchor_a).map_err(|_| RecoveryError::Store)?;
    let mut b = FileAnchorStore::open_existing(anchor_b).map_err(|_| RecoveryError::Store)?;
    recover_with_default(&mut a, &mut b)
}

fn recover_with_default(
    a: &mut FileAnchorStore,
    b: &mut FileAnchorStore,
) -> Result<RecoveryReport, RecoveryError> {
    recover(a, b)
}
