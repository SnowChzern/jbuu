//! # doctor —— 运行环境体检（规划 §151 / §5 测试 11、13）
//!
//! 五类检查：**core dump、swap、锚/密码本权限、文件系统支持、备份风险
//! 配置**。每类检查拆成"事实采集"（读 /proc、stat、prctl）与"策略评估"
//! （纯函数）两层，正反用例在纯函数层穷举，采集层另以真实环境断言形状。
//!
//! 高风险（`Block`）条件按策略**拒绝启动**：`DoctorReport::refuse_startup`
//! 汇总；CLI（`otp-term serve/connect`）在加载任何段材料前调用并以此
//! 判定。
//!
//! `harden_process`：serve/connect 启动自加固——`RLIMIT_CORE=0` +
//! `PR_SET_DUMPABLE(0)`，随后用同一套 doctor 采集/评估验证（§5 测试 11
//! "正常生产配置再验证 RLIMIT_CORE=0、dumpable"）。这是把策略从
//! "检查环境"变成"建立环境再验证"，对不可加固项（如 swap）仍依赖
//! 拒绝启动。

use std::path::{Path, PathBuf};

use super::{CheckStatus, PlatformError, require_supported_filesystem};

/// doctor 检查的五类（规划 §151）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DoctorCategory {
    /// core dump（RLIMIT_CORE / dumpable）。
    CoreDump,
    /// swap（/proc/swaps；未禁用且未证明加密 → Block）。
    Swap,
    /// 锚/密码本文件权限（0600、属主、常规文件）。
    Permissions,
    /// 文件系统支持（锚/密码本所在 FS；复用 [`require_supported_filesystem`]）。
    Filesystem,
    /// 备份风险配置（同步盘目录 / 排除标记）。
    BackupRisk,
}

impl DoctorCategory {
    /// 类别名（doctor 报告/JSON 用；公开元数据）。
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CoreDump => "core-dump",
            Self::Swap => "swap",
            Self::Permissions => "permissions",
            Self::Filesystem => "filesystem",
            Self::BackupRisk => "backup-risk",
        }
    }
}

/// 单条检查结论（目标标签 + 状态；detail 为冻结的 &'static str，无自由
/// 格式通道）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DoctorFinding {
    pub category: DoctorCategory,
    pub target: &'static str,
    pub status: CheckStatus,
}

impl DoctorFinding {
    /// 人类可读行（公开元数据）。
    #[must_use]
    pub fn line(&self) -> String {
        let (tag, detail) = match self.status {
            CheckStatus::Ok => ("ok", ""),
            CheckStatus::Warn { detail } => ("warn", detail),
            CheckStatus::Block { detail } => ("BLOCK", detail),
        };
        if detail.is_empty() {
            format!("[{tag}] {}: {}", self.category.name(), self.target)
        } else {
            format!(
                "[{tag}] {}: {} — {detail}",
                self.category.name(),
                self.target
            )
        }
    }
}

/// 体检对象路径集（密码本 + 双锚）。
pub struct DoctorPaths {
    pub book: PathBuf,
    pub anchor_a: PathBuf,
    pub anchor_b: PathBuf,
}

/// 体检报告（公开元数据；可进 evidence/）。
#[derive(Clone, Debug, Default)]
pub struct DoctorReport {
    pub findings: Vec<DoctorFinding>,
}

impl DoctorReport {
    /// 是否存在任一 Block（高风险 → 拒绝启动）。
    #[must_use]
    pub fn refuse_startup(&self) -> bool {
        self.findings
            .iter()
            .any(|f| matches!(f.status, CheckStatus::Block { .. }))
    }

    /// 人类可读摘要（每检查一行 + 拒绝启动判定）。
    #[must_use]
    pub fn summary(&self) -> String {
        let mut s = String::new();
        for f in &self.findings {
            s.push_str(&f.line());
            s.push('\n');
        }
        if self.refuse_startup() {
            s.push_str("结论：存在高风险（BLOCK）项，按策略拒绝启动\n");
        } else {
            s.push_str("结论：无 BLOCK 项（warn 项见上）\n");
        }
        s
    }

    /// 机器可读 JSON（公开元数据；可入 evidence/）。
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut s = String::from("{\"findings\":[");
        for (i, f) in self.findings.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let (status, detail) = match f.status {
                CheckStatus::Ok => ("ok", ""),
                CheckStatus::Warn { detail } => ("warn", detail),
                CheckStatus::Block { detail } => ("block", detail),
            };
            s.push_str(&format!(
                "{{\"category\":\"{}\",\"target\":\"{}\",\"status\":\"{}\",\"detail\":\"{}\"}}",
                f.category.name(),
                f.target,
                status,
                detail
            ));
        }
        s.push_str(&format!("],\"refuse_startup\":{}}}", self.refuse_startup()));
        s
    }
}

// ───────────────────────── core dump（§5 测试 11） ─────────────────────────

/// core dump 相关事实。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CoreFacts {
    /// RLIMIT_CORE 软限（None = 读取失败）。
    pub core_limit: Option<u64>,
    /// PR_GET_DUMPABLE（None = 读取失败；0 = 不可转储）。
    pub dumpable: Option<u32>,
}

/// 采集 core 事实（getrlimit + prctl）。
pub fn collect_core_facts() -> CoreFacts {
    CoreFacts {
        core_limit: core_limit(),
        dumpable: dumpable_flag(),
    }
}

/// 策略：`RLIMIT_CORE == 0` **且** `dumpable == 0` 才通过；任一不满足或
/// 读取失败 → Block（fail closed）。
#[must_use]
pub const fn eval_core(f: &CoreFacts) -> CheckStatus {
    match (f.core_limit, f.dumpable) {
        (Some(0), Some(0)) => CheckStatus::Ok,
        (Some(_), Some(_)) => CheckStatus::Block {
            detail: "RLIMIT_CORE/dumpable 未同时归零（core 泄露面）",
        },
        _ => CheckStatus::Block {
            detail: "无法读取 RLIMIT_CORE 或 dumpable 状态",
        },
    }
}

fn core_limit() -> Option<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid writable rlimit pointer; getrlimit initializes it synchronously.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) };
    (rc == 0).then_some(lim.rlim_cur)
}

fn dumpable_flag() -> Option<u32> {
    // SAFETY: PR_GET_DUMPABLE takes no pointer arguments and returns the flag.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
    (rc >= 0).then_some(rc as u32)
}

/// 启动自加固：`RLIMIT_CORE` 软限归零 + `PR_SET_DUMPABLE(0)`，随后用
/// 同一套采集/评估验证。任一步失败 → Err（调用方必须拒绝启动）。
pub fn harden_process() -> Result<(), &'static str> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid writable rlimit pointer for the synchronous getrlimit call.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) };
    if rc != 0 {
        return Err("getrlimit(RLIMIT_CORE) 失败");
    }
    let zeroed = libc::rlimit {
        rlim_cur: 0,
        rlim_max: lim.rlim_max,
    };
    // SAFETY: zeroed points to an initialized rlimit for the duration of setrlimit.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zeroed) };
    if rc != 0 {
        return Err("setrlimit(RLIMIT_CORE, 0) 失败");
    }
    // SAFETY: PR_SET_DUMPABLE takes a plain integer argument, no pointers.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong) };
    if rc != 0 {
        return Err("prctl(PR_SET_DUMPABLE, 0) 失败");
    }
    // 验证路径：加固后同一套采集/评估必须 Ok。
    match eval_core(&collect_core_facts()) {
        CheckStatus::Ok => Ok(()),
        _ => Err("加固后 core dump 检查仍未通过"),
    }
}

// ───────────────────────── swap（§5 测试 11） ─────────────────────────

/// /proc/swaps 单行（设备名与类型）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SwapLine {
    pub name: String,
    pub kind: String,
}

/// swap 事实（`readable=false` 表示 /proc/swaps 不可读）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SwapFacts {
    pub readable: bool,
    pub lines: Vec<SwapLine>,
}

/// 解析 /proc/swaps 文本（首行为表头；空设备名行忽略）。
#[must_use]
pub fn parse_proc_swaps(text: &str) -> SwapFacts {
    let mut lines = Vec::new();
    for row in text.lines().skip(1) {
        let mut it = row.split_whitespace();
        if let (Some(name), Some(kind)) = (it.next(), it.next()) {
            lines.push(SwapLine {
                name: name.to_string(),
                kind: kind.to_string(),
            });
        }
    }
    SwapFacts {
        readable: true,
        lines,
    }
}

/// 采集 swap 事实。
pub fn collect_swap_facts() -> SwapFacts {
    match std::fs::read_to_string("/proc/swaps") {
        Ok(text) => parse_proc_swaps(&text),
        Err(_) => SwapFacts {
            readable: false,
            lines: Vec::new(),
        },
    }
}

/// 策略：
/// - /proc/swaps 不可读 → Warn（无法证明安全，交由运维裁决）；
/// - 无活动 swap → Ok；
/// - 活动 swap 全部位于 `/dev/mapper/*` 或 `/dev/dm-*`（设备映射器加密
///   的常规形态）→ Warn（依赖设备映射器配置正确，无法在本机证明）；
/// - 其余（裸分区/文件 swap，未证明加密）→ Block（§5 测试 11：
///   "swap 未禁用/加密 → doctor 阻断/高危告警"）。
#[must_use]
pub fn eval_swap(f: &SwapFacts) -> CheckStatus {
    if !f.readable {
        return CheckStatus::Warn {
            detail: "cannot inspect /proc/swaps",
        };
    }
    if f.lines.is_empty() {
        return CheckStatus::Ok;
    }
    let unencrypted = f
        .lines
        .iter()
        .any(|l| !(l.name.starts_with("/dev/mapper/") || l.name.starts_with("/dev/dm-")));
    if unencrypted {
        CheckStatus::Block {
            detail: "swap enabled without verified encryption (plain partition/file swap)",
        }
    } else {
        CheckStatus::Warn {
            detail: "swap active under /dev/mapper (assumed encrypted; verify device config)",
        }
    }
}

// ───────────────────────── 权限（§5 测试 13 前置） ─────────────────────────

/// 单个锚/密码本文件的权限事实。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PermFacts {
    pub exists: bool,
    pub is_regular: bool,
    /// st_mode 低 12 位（权限位 + 类型位由 is_regular 表达）。
    pub mode: u32,
    pub uid: u32,
}

/// 采集路径权限事实（stat 失败 → exists=false）。
pub fn collect_perm_facts(path: &Path) -> PermFacts {
    match std::fs::metadata(path) {
        Ok(m) => {
            use std::os::unix::fs::MetadataExt;
            PermFacts {
                exists: true,
                is_regular: m.is_file(),
                mode: m.mode(),
                uid: m.uid(),
            }
        }
        Err(_) => PermFacts {
            exists: false,
            is_regular: false,
            mode: 0,
            uid: 0,
        },
    }
}

/// 策略：常规文件；无任何 group/world 位（含读）；属主可读（锚还需可
/// 写）；属主为当前 euid。任一不满足 → Block。
#[must_use]
pub const fn eval_perm(f: &PermFacts, euid: u32, need_write: bool) -> CheckStatus {
    if !f.exists {
        return CheckStatus::Block {
            detail: "file is missing",
        };
    }
    if !f.is_regular {
        return CheckStatus::Block {
            detail: "not a regular file",
        };
    }
    if f.mode & 0o077 != 0 {
        return CheckStatus::Block {
            detail: "group/world permission bits set on secret material",
        };
    }
    if f.mode & 0o400 == 0 {
        return CheckStatus::Block {
            detail: "owner read bit missing",
        };
    }
    if need_write && f.mode & 0o200 == 0 {
        return CheckStatus::Block {
            detail: "owner write bit missing (mutually required)",
        };
    }
    if f.uid != euid {
        return CheckStatus::Block {
            detail: "file owner is not the current effective user",
        };
    }
    CheckStatus::Ok
}

// ───────────────────────── 备份风险（§5 测试 13） ─────────────────────────

/// 备份排除标记文件名（放置于密码本所在目录；运维按 §5 测试 13 的
/// canary/exclusion 流程创建）。
pub const NO_BACKUP_MARKER: &str = ".otp-term-nobackup";

/// 已知同步/备份工具目录名（组件级匹配，大小写不敏感）。
const SYNC_DIR_COMPONENTS: &[&str] = &[
    "dropbox",
    "nextcloud",
    "seafile",
    "syncthing",
    "mega",
    "onedrive",
    "googledrive",
    "backup",
    "backups",
    ".git",
];

/// 备份风险事实。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BackupFacts {
    /// 命中的同步/备份目录组件（None = 未命中）。
    pub sync_dir_hit: Option<String>,
    /// 排除标记是否存在。
    pub marker_present: bool,
}

/// 采集备份风险事实（`root` = 密码本所在目录）。
pub fn collect_backup_facts(book: &Path) -> BackupFacts {
    let hit = book
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .find(|c| SYNC_DIR_COMPONENTS.contains(&c.to_ascii_lowercase().as_str()))
        .map(|c| c.to_string());
    let marker_present = book
        .parent()
        .map(|dir| dir.join(NO_BACKUP_MARKER).exists())
        .unwrap_or(false);
    BackupFacts {
        sync_dir_hit: hit,
        marker_present,
    }
}

/// 策略：命中同步/备份目录 → Block（密码本不得进入常规备份面）；未命中
/// 但无排除标记 → Warn（按 §5 测试 13 流程补 canary/排除规则）；两者都
/// 满足 → Ok。
#[must_use]
pub fn eval_backup(f: &BackupFacts) -> CheckStatus {
    if f.sync_dir_hit.is_some() {
        return CheckStatus::Block {
            detail: "book/anchor path is inside a sync/backup directory",
        };
    }
    if !f.marker_present {
        return CheckStatus::Warn {
            detail: "no backup-exclusion marker next to the book (ops: create it)",
        };
    }
    CheckStatus::Ok
}

// ───────────────────────── 汇总 ─────────────────────────

/// 汇总五类检查（真实采集 + 评估）。euid 由调用方传入（便于测试与将来
/// 权降升场景一致）。
pub fn run_doctor(paths: &DoctorPaths, euid: u32) -> DoctorReport {
    let mut findings = Vec::new();

    findings.push(DoctorFinding {
        category: DoctorCategory::CoreDump,
        target: "process",
        status: eval_core(&collect_core_facts()),
    });
    findings.push(DoctorFinding {
        category: DoctorCategory::Swap,
        target: "system",
        status: eval_swap(&collect_swap_facts()),
    });

    for (target, path, need_write) in [
        ("book", &paths.book, false),
        ("anchor-a", &paths.anchor_a, true),
        ("anchor-b", &paths.anchor_b, true),
    ] {
        findings.push(DoctorFinding {
            category: DoctorCategory::Permissions,
            target,
            status: eval_perm(&collect_perm_facts(path), euid, need_write),
        });
    }

    for (target, path) in [
        ("book", &paths.book),
        ("anchor-a", &paths.anchor_a),
        ("anchor-b", &paths.anchor_b),
    ] {
        let status = match require_supported_filesystem(path) {
            Ok(()) => CheckStatus::Ok,
            Err(PlatformError::UnsupportedFilesystem { .. }) => CheckStatus::Block {
                detail: "book/anchor filesystem is unsupported or unknown",
            },
            Err(_) => CheckStatus::Block {
                detail: "filesystem probe failed",
            },
        };
        findings.push(DoctorFinding {
            category: DoctorCategory::Filesystem,
            target,
            status,
        });
    }

    let backup = collect_backup_facts(&paths.book);
    findings.push(DoctorFinding {
        category: DoctorCategory::BackupRisk,
        target: "book-dir",
        status: eval_backup(&backup),
    });

    DoctorReport { findings }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // ── core：正反用例（纯函数层） ──

    #[test]
    fn core_policy_positive_and_negative() {
        // 正向：双零。
        assert_eq!(
            eval_core(&CoreFacts {
                core_limit: Some(0),
                dumpable: Some(0)
            }),
            CheckStatus::Ok
        );
        // 反向：RLIMIT_CORE 非零（即使 dumpable=0）。
        assert_eq!(
            eval_core(&CoreFacts {
                core_limit: Some(1024),
                dumpable: Some(0)
            }),
            CheckStatus::Block {
                detail: "RLIMIT_CORE/dumpable 未同时归零（core 泄露面）"
            }
        );
        // 反向：仍可转储（即使 RLIMIT_CORE=0）。
        assert_eq!(
            eval_core(&CoreFacts {
                core_limit: Some(0),
                dumpable: Some(1)
            }),
            CheckStatus::Block {
                detail: "RLIMIT_CORE/dumpable 未同时归零（core 泄露面）"
            }
        );
        // 反向：读取失败（fail closed）。
        assert_eq!(
            eval_core(&CoreFacts {
                core_limit: None,
                dumpable: None
            }),
            CheckStatus::Block {
                detail: "无法读取 RLIMIT_CORE 或 dumpable 状态"
            }
        );
    }

    #[test]
    fn harden_then_verify_is_ok_on_this_process() {
        // 真实路径：加固 + 复验（§5 测试 11 的 RLIMIT_CORE=0/dumpable 验证）。
        harden_process().expect("普通进程应可自加固");
        assert_eq!(eval_core(&collect_core_facts()), CheckStatus::Ok);
    }

    // ── swap：解析 + 策略正反用例 ──

    #[test]
    fn proc_swaps_fixture_is_parsed() {
        let f = parse_proc_swaps(
            "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n\
             /dev/sda3                               partition\t16677884\t7999684\t-2\n\
             /dev/mapper/crypt-swap                  partition\t8388604\t0\t-3\n",
        );
        assert_eq!(
            f,
            SwapFacts {
                readable: true,
                lines: vec![
                    SwapLine {
                        name: "/dev/sda3".into(),
                        kind: "partition".into()
                    },
                    SwapLine {
                        name: "/dev/mapper/crypt-swap".into(),
                        kind: "partition".into()
                    },
                ]
            }
        );
        // 空表头/空文本 → 无活动 swap。
        let empty = parse_proc_swaps("Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n");
        assert!(empty.lines.is_empty());
    }

    #[test]
    fn swap_policy_positive_and_negative() {
        // 正向：无活动 swap。
        assert_eq!(
            eval_swap(&SwapFacts {
                readable: true,
                lines: vec![]
            }),
            CheckStatus::Ok
        );
        // 正向（降级 warn）：设备映射器下的加密 swap。
        assert_eq!(
            eval_swap(&SwapFacts {
                readable: true,
                lines: vec![SwapLine {
                    name: "/dev/mapper/crypt-swap".into(),
                    kind: "partition".into()
                }]
            }),
            CheckStatus::Warn {
                detail: "swap active under /dev/mapper (assumed encrypted; verify device config)"
            }
        );
        // 反向：裸分区 swap。
        assert_eq!(
            eval_swap(&SwapFacts {
                readable: true,
                lines: vec![SwapLine {
                    name: "/dev/sda3".into(),
                    kind: "partition".into()
                }]
            }),
            CheckStatus::Block {
                detail: "swap enabled without verified encryption (plain partition/file swap)"
            }
        );
        // 反向：swap 文件。
        assert_eq!(
            eval_swap(&SwapFacts {
                readable: true,
                lines: vec![SwapLine {
                    name: "/swapfile".into(),
                    kind: "file".into()
                }]
            }),
            CheckStatus::Block {
                detail: "swap enabled without verified encryption (plain partition/file swap)"
            }
        );
        // 不可读 → warn（无法证明）。
        assert_eq!(
            eval_swap(&SwapFacts {
                readable: false,
                lines: vec![]
            }),
            CheckStatus::Warn {
                detail: "cannot inspect /proc/swaps"
            }
        );
        // 真实采集形状：本机 /proc/swaps 应可解析出 SwapLine 列表。
        let real = collect_swap_facts();
        if real.readable {
            for l in &real.lines {
                assert!(!l.name.is_empty() && !l.kind.is_empty());
            }
        }
    }

    // ── 权限：正反用例 ──

    fn perm(mode: u32, uid: u32, regular: bool) -> PermFacts {
        PermFacts {
            exists: true,
            is_regular: regular,
            mode,
            uid,
        }
    }

    #[test]
    fn permission_policy_positive_and_negative() {
        let me = safe_euid();
        // 正向：0600 属主本人（书与锚皆过）。
        assert_eq!(eval_perm(&perm(0o600, me, true), me, true), CheckStatus::Ok);
        assert_eq!(
            eval_perm(&perm(0o400, me, true), me, false),
            CheckStatus::Ok
        );
        // 反向：group/world 任意位（0644 常见错误）。
        assert_eq!(
            eval_perm(&perm(0o644, me, true), me, true),
            CheckStatus::Block {
                detail: "group/world permission bits set on secret material"
            }
        );
        // 反向：world 可写。
        assert_eq!(
            eval_perm(&perm(0o602, me, true), me, true),
            CheckStatus::Block {
                detail: "group/world permission bits set on secret material"
            }
        );
        // 反向：锚缺属主写位。
        assert_eq!(
            eval_perm(&perm(0o400, me, true), me, true),
            CheckStatus::Block {
                detail: "owner write bit missing (mutually required)"
            }
        );
        // 反向：缺属主读位。
        assert_eq!(
            eval_perm(&perm(0o200, me, true), me, true),
            CheckStatus::Block {
                detail: "owner read bit missing"
            }
        );
        // 反向：属主非当前 euid。
        assert_eq!(
            eval_perm(&perm(0o600, me.wrapping_add(1), true), me, true),
            CheckStatus::Block {
                detail: "file owner is not the current effective user"
            }
        );
        // 反向：非常规文件（目录/设备）。
        assert_eq!(
            eval_perm(&perm(0o600, me, false), me, true),
            CheckStatus::Block {
                detail: "not a regular file"
            }
        );
        // 反向：文件不存在。
        assert_eq!(
            eval_perm(
                &PermFacts {
                    exists: false,
                    is_regular: false,
                    mode: 0,
                    uid: 0
                },
                me,
                true
            ),
            CheckStatus::Block {
                detail: "file is missing"
            }
        );
    }

    fn safe_euid() -> u32 {
        // SAFETY: geteuid takes no arguments and cannot fail.
        #[allow(unsafe_code)]
        let uid = unsafe { libc::geteuid() };
        uid
    }

    #[test]
    fn collect_perm_facts_reads_real_file_mode() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/tmp")
            .join(format!("otp-doc-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f");
        std::fs::write(&p, b"x").unwrap();
        let facts = collect_perm_facts(&p);
        assert!(facts.exists && facts.is_regular);
        // umask 因环境而异（如 022→0644、002→0664），只断言含属主读写位。
        assert_eq!(facts.mode & 0o600, 0o600);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(collect_perm_facts(&p).mode & 0o777, 0o600);
        // stat 失败 → exists=false。
        assert!(!collect_perm_facts(&dir.join("nope")).exists);
        std::fs::remove_file(&p).ok();
        std::fs::remove_dir(&dir).ok();
    }

    // ── 备份风险：正反用例 ──

    #[test]
    fn backup_policy_positive_and_negative() {
        // 正向：无同步目录命中 + 有排除标记。
        assert_eq!(
            eval_backup(&BackupFacts {
                sync_dir_hit: None,
                marker_present: true
            }),
            CheckStatus::Ok
        );
        // 反向：位于同步/备份目录（大小写不敏感、组件级）。
        for hit in ["Dropbox", "nextcloud", ".git", "Backups"] {
            assert_eq!(
                eval_backup(&BackupFacts {
                    sync_dir_hit: Some(hit.to_string()),
                    marker_present: true
                }),
                CheckStatus::Block {
                    detail: "book/anchor path is inside a sync/backup directory"
                }
            );
        }
        // 无标记 → warn（提示补 canary/排除规则）。
        assert_eq!(
            eval_backup(&BackupFacts {
                sync_dir_hit: None,
                marker_present: false
            }),
            CheckStatus::Warn {
                detail: "no backup-exclusion marker next to the book (ops: create it)"
            }
        );
    }

    #[test]
    fn backup_facts_are_collected_from_real_paths() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/tmp")
            .join(format!("otp-doc-bk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let book = dir.join("book.bin");
        std::fs::write(&book, b"x").unwrap();
        // 无标记。
        let f = collect_backup_facts(&book);
        assert!(f.sync_dir_hit.is_none());
        assert!(!f.marker_present);
        // 建标记后。
        std::fs::write(dir.join(NO_BACKUP_MARKER), b"").unwrap();
        assert!(collect_backup_facts(&book).marker_present);
        // 同步目录命中（组件级）。
        let sync = dir.join("Dropbox");
        std::fs::create_dir_all(&sync).unwrap();
        let hit = collect_backup_facts(&sync.join("b.bin"));
        assert_eq!(hit.sync_dir_hit.as_deref(), Some("Dropbox"));
        std::fs::remove_file(dir.join(NO_BACKUP_MARKER)).ok();
        std::fs::remove_file(&book).ok();
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── 汇总：形状 + JSON/summary 可渲染 ──

    #[test]
    fn report_shape_and_renderers() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/tmp")
            .join(format!("otp-doc-run-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let book = dir.join("b.book");
        let a = dir.join("a.anchor");
        let b = dir.join("c.anchor");
        for p in [&book, &a, &b] {
            std::fs::write(p, b"x").unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(dir.join(NO_BACKUP_MARKER), b"").unwrap();

        harden_process().unwrap();
        let report = run_doctor(
            &DoctorPaths {
                book: book.clone(),
                anchor_a: a.clone(),
                anchor_b: b.clone(),
            },
            safe_euid(),
        );
        // 五类齐全：1 core + 1 swap + 3 perm + 3 fs + 1 backup = 9 条。
        assert_eq!(report.findings.len(), 9);
        for cat in [
            DoctorCategory::CoreDump,
            DoctorCategory::Swap,
            DoctorCategory::Permissions,
            DoctorCategory::Filesystem,
            DoctorCategory::BackupRisk,
        ] {
            assert!(
                report.findings.iter().any(|f| f.category == cat),
                "缺 {cat:?} 检查项"
            );
        }
        // 本机 swap 可能为裸分区（Block）——剔除 swap 后其余项应全 Ok，
        // 以证明 perm/fs/backup/core 的正向路径真实成立。
        let non_swap: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.category != DoctorCategory::Swap)
            .collect();
        for f in &non_swap {
            assert_eq!(f.status, CheckStatus::Ok, "意外非 Ok：{}", f.line());
        }
        let json = report.to_json();
        assert!(json.starts_with("{\"findings\":["));
        assert!(json.contains("\"category\":\"core-dump\""));
        assert!(json.ends_with(&format!("\"refuse_startup\":{}}}", report.refuse_startup())));
        assert!(report.summary().contains("结论"));

        // 负向：把书改成 0644 → permissions Block → refuse_startup。
        std::fs::set_permissions(&book, std::fs::Permissions::from_mode(0o644)).unwrap();
        let bad = run_doctor(
            &DoctorPaths {
                book,
                anchor_a: a,
                anchor_b: b,
            },
            safe_euid(),
        );
        assert!(bad.refuse_startup());
        assert!(
            bad.findings
                .iter()
                .any(|f| f.category == DoctorCategory::Permissions
                    && matches!(f.status, CheckStatus::Block { .. }))
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
