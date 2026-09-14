//! # doctor 的 CLI 面（规划 §151）
//!
//! 平台层 [`otp_platform::run_doctor`] 给出严格策略；本模块补两件事：
//!
//! 1. **swap 覆盖**：`--allow-unencrypted-swap`（显式运维动作）把 swap 的
//!    Block 降级为 Warn 并在输出中留痕。平台策略本体不放宽——覆盖只存在
//!    于操作员显式声明后的报告副本；
//! 2. **渲染**：人类可读行 + JSON（公开元数据，可入 evidence/）。

use std::path::{Path, PathBuf};

use otp_platform::{
    CheckStatus, DoctorCategory, DoctorFinding, DoctorPaths, DoctorReport, NO_BACKUP_MARKER,
    run_doctor,
};

/// CLI doctor 结果 = 报告 + 是否拒绝启动。
pub struct DoctorOutcome {
    pub report: DoctorReport,
}

impl DoctorOutcome {
    /// 是否存在（覆盖后仍为）Block 的项 → 拒绝启动。
    #[must_use]
    pub fn refuse_startup(&self) -> bool {
        self.report.refuse_startup()
    }

    /// 人类可读输出（含覆盖留痕行）。
    #[must_use]
    pub fn summary(&self, swap_overridden: bool) -> String {
        let mut s = self.report.summary();
        if swap_overridden {
            s.push_str(
                "覆盖：--allow-unencrypted-swap 已把 swap 的 BLOCK 降级为 warn（操作员显式声明，仅限受控环境）\n",
            );
        }
        s
    }

    /// JSON（公开元数据）。
    #[must_use]
    pub fn to_json(&self) -> String {
        self.report.to_json()
    }
}

/// 运行体检（含可选 swap 覆盖）。`paths=None` 时只做进程/系统级检查
/// （core/swap），不检查文件（单机自检入口）。
pub fn run(paths: Option<&DoctorPaths>, allow_unencrypted_swap: bool) -> DoctorOutcome {
    let euid = current_euid();
    let mut report = match paths {
        Some(p) => run_doctor(p, euid),
        None => DoctorReport {
            findings: vec![
                DoctorFinding {
                    category: DoctorCategory::CoreDump,
                    target: "process",
                    status: otp_platform::eval_core(&otp_platform::collect_core_facts()),
                },
                DoctorFinding {
                    category: DoctorCategory::Swap,
                    target: "system",
                    status: otp_platform::eval_swap(&otp_platform::collect_swap_facts()),
                },
            ],
        },
    };
    if allow_unencrypted_swap {
        for f in &mut report.findings {
            if f.category == DoctorCategory::Swap && matches!(f.status, CheckStatus::Block { .. }) {
                f.status = CheckStatus::Warn {
                    detail: "swap BLOCK downgraded by --allow-unencrypted-swap (operator opt-in)",
                };
            }
        }
    }
    DoctorOutcome { report }
}

fn current_euid() -> u32 {
    // euid 只用于权限比对展示；doctor 不持密钥材料。经 /proc/self/status
    // 读取（Uid: 行），避免在本 crate 引入 unsafe（geteuid 属平台层职责）。
    match std::fs::read_to_string("/proc/self/status") {
        Ok(text) => text
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(u32::MAX),
        Err(_) => u32::MAX,
    }
}

/// 为密码本目录生成备份排除标记（doctor 报告 warn 时的一键补救；
/// 幂等：已存在即成功）。
pub fn write_no_backup_marker(book: &Path) -> Result<PathBuf, String> {
    let Some(dir) = book.parent() else {
        return Err("密码本路径无父目录".to_string());
    };
    let marker = dir.join(NO_BACKUP_MARKER);
    if marker.exists() {
        return Ok(marker);
    }
    std::fs::write(
        &marker,
        b"jbuu: book/anchors excluded from backups (ops marker)\n",
    )
    .map_err(|_| "排除标记写入失败".to_string())?;
    Ok(marker)
}
