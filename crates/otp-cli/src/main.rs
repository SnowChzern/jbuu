//! # otp-term CLI —— 运维入口（骨架）
//!
//! 实现规划 §2 职责：server/client、book inspect/generate（仅离线测试或受控
//! 工具）、anchor inspect、doctor、drain/rotate。
//!
//! 禁止事项（规划 §2）：默认不打印秘密（book/anchor inspect 只输出公开
//! 元数据）；危险操作要求显式确认/双人流程接口。
//!
//! 本骨架（WP-04）只固定命令面与参数形状；业务实现见 WP-15。

#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "otp-term",
    version,
    about = "OTP 密码本池终端协议 CLI（骨架；业务在 WP-15 落地）"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// 启动服务端：加载密码本+双锚，执行恢复，接受连接并签发段。
    Serve {
        /// 密码本路径。
        #[arg(long)]
        book: PathBuf,
        /// 锚副本 A 路径（独立介质）。
        #[arg(long)]
        anchor_a: PathBuf,
        /// 锚副本 B 路径（独立介质）。
        #[arg(long)]
        anchor_b: PathBuf,
        /// 监听地址（host:port）。
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: String,
    },
    /// 以客户端身份连接服务端并建立加密终端。
    Connect {
        /// 密码本路径。
        #[arg(long)]
        book: PathBuf,
        /// 服务端地址（host:port）。
        #[arg(long)]
        target: String,
    },
    /// 密码本工具（仅离线测试或受控环境使用）。
    Book {
        #[command(subcommand)]
        cmd: BookCmd,
    },
    /// 锚检查（只读；仅打印公开元数据，不含任何段材料）。
    Anchor {
        #[command(subcommand)]
        cmd: AnchorCmd,
    },
    /// 环境体检：core dump/swap/文件系统/权限/备份风险；高风险按策略拒绝启动。
    Doctor,
    /// 排空：停止接受新会话，进入换本流程。
    Drain,
    /// 换本轮换：需 book_id/version 明确核对与双人授权。
    Rotate,
}

#[derive(Debug, Subcommand)]
enum BookCmd {
    /// 检查密码本（头/统计/重复段检测，规划 §5 测试 1）。
    Inspect {
        /// 密码本路径。
        path: PathBuf,
    },
    /// 生成测试密码本（仅测试；受控环境）。
    Generate {
        /// 输出路径。
        path: PathBuf,
        /// 段数。
        #[arg(long)]
        segments: u64,
    },
}

#[derive(Debug, Subcommand)]
enum AnchorCmd {
    /// 检查锚状态（generation/next/一致性）。
    Inspect {
        /// 锚文件路径。
        path: PathBuf,
    },
}

/// CLI 错误。永不包含秘密材料。
#[derive(Debug)]
enum CliError {
    /// 子命令尚未实现（对应工作包）。
    NotImplemented(&'static str),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotImplemented(wp) => {
                write!(f, "该子命令尚未实现（将于 {wp} 落地）")
            }
        }
    }
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli.command) {
        eprintln!("otp-term: {e}");
        std::process::exit(1);
    }
}

fn run(cmd: Cmd) -> Result<(), CliError> {
    // 骨架：固定命令面；业务实现于 WP-15（client/server/doctor 等）。
    let _ = cmd;
    Err(CliError::NotImplemented("WP-15"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_surface_parses() {
        let cli = Cli::try_parse_from(["otp-term", "doctor"]).expect("doctor 可解析");
        assert!(matches!(cli.command, Cmd::Doctor));

        let cli = Cli::try_parse_from([
            "otp-term",
            "serve",
            "--book",
            "b.book",
            "--anchor-a",
            "a.anchor",
            "--anchor-b",
            "c.anchor",
        ])
        .expect("serve 可解析");
        assert!(matches!(cli.command, Cmd::Serve { .. }));

        let cli = Cli::try_parse_from([
            "otp-term",
            "book",
            "generate",
            "out.book",
            "--segments",
            "3",
        ])
        .expect("book generate 可解析");
        assert!(matches!(
            cli.command,
            Cmd::Book {
                cmd: BookCmd::Generate { .. }
            }
        ));
    }

    #[test]
    fn skeleton_reports_not_implemented() {
        assert!(matches!(
            run(Cmd::Doctor),
            Err(CliError::NotImplemented("WP-15"))
        ));
    }
}
