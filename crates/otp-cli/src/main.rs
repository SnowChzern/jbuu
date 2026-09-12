//! # otp-term CLI —— 运维入口（骨架）
//!
//! 实现规划 §2 职责：server/client、book inspect/generate（仅离线测试或受控
//! 工具）、anchor inspect、doctor、drain/rotate。
//!
//! 禁止事项（规划 §2）：默认不打印秘密（book/anchor inspect 只输出公开
//! 元数据）；危险操作要求显式确认/双人流程接口。
//!
//! 已落地（WP-06）：`book generate`（CSPRNG 测试本生成，规划 §5 测试 1）
//! 与 `book inspect`（头校验/统计/重复段/全零段检测）。其余子命令业务
//! 实现见 WP-15。

#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use otp_book::generate::{generate_book, random_book_id};
use otp_types::BookId;

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
        /// 输出机器可读 JSON（公开元数据，无段材料；可入 evidence/）。
        #[arg(long)]
        json: bool,
    },
    /// 生成测试密码本（仅测试；受控环境；OS CSPRNG，拒绝覆盖已有文件）。
    Generate {
        /// 输出路径（O_EXCL：已存在即拒绝）。
        path: PathBuf,
        /// 段数（1..=2^40-1）。
        #[arg(long)]
        segments: u64,
        /// 指定 book_id（32 位十六进制；缺省由 CSPRNG 随机生成）。
        #[arg(long)]
        book_id: Option<String>,
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
    /// 密码本检查未通过（重复段/全零段等；退出码 1，供 CI/脚本判定）。
    BookCheckFailed,
    /// 参数非法（如 book_id 不是 32 位十六进制）。
    BadArg(String),
    /// 业务执行错误（底层错误已格式化为不含秘密的消息）。
    Failed(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotImplemented(wp) => {
                write!(f, "该子命令尚未实现（将于 {wp} 落地）")
            }
            Self::BookCheckFailed => {
                write!(f, "密码本检查未通过（重复段/全零段等，见上方报告）")
            }
            Self::BadArg(why) => write!(f, "参数非法：{why}"),
            Self::Failed(what) => write!(f, "{what}"),
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
    match cmd {
        Cmd::Book { cmd } => run_book(cmd),
        // 其余子命令业务实现于 WP-15（client/server/doctor 等）。
        Cmd::Serve { .. }
        | Cmd::Connect { .. }
        | Cmd::Anchor { .. }
        | Cmd::Doctor
        | Cmd::Drain
        | Cmd::Rotate => Err(CliError::NotImplemented("WP-15")),
    }
}

fn run_book(cmd: BookCmd) -> Result<(), CliError> {
    match cmd {
        BookCmd::Generate {
            path,
            segments,
            book_id,
        } => {
            let id = match book_id {
                Some(hex) => parse_book_id(&hex)?,
                None => random_book_id().map_err(|e| CliError::Failed(e.to_string()))?,
            };
            let header =
                generate_book(&path, segments, id).map_err(|e| CliError::Failed(e.to_string()))?;
            println!("已生成测试密码本（OS CSPRNG，已 fsync 文件与父目录）：");
            println!("  path          : {}", path.display());
            println!("  book_id       : {}", hex(header.book_id.as_bytes()));
            println!("  version       : {}", header.version);
            println!("  segment_len   : {}", header.segment_len);
            println!("  segment_count : {}", header.segment_count);
            println!(
                "  file_size     : {}",
                std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0)
            );
            Ok(())
        }
        BookCmd::Inspect { path, json } => {
            let report = otp_book::inspect::inspect_book(&path)
                .map_err(|e| CliError::Failed(e.to_string()))?;
            if json {
                println!("{}", report.to_json());
            } else {
                println!("{}", report.summary());
            }
            if report.ok {
                Ok(())
            } else {
                Err(CliError::BookCheckFailed)
            }
        }
    }
}

fn parse_book_id(hex: &str) -> Result<BookId, CliError> {
    let bytes = hex_parse(hex)
        .ok_or_else(|| CliError::BadArg(format!("--book-id 须为 32 位十六进制，得到 {hex:?}")))?;
    Ok(BookId::from_bytes(bytes))
}

fn hex_parse(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

        let cli = Cli::try_parse_from([
            "otp-term",
            "book",
            "generate",
            "out.book",
            "--segments",
            "3",
            "--book-id",
            "00112233445566778899aabbccddeeff",
        ])
        .expect("book generate --book-id 可解析");
        assert!(matches!(
            cli.command,
            Cmd::Book {
                cmd: BookCmd::Generate {
                    book_id: Some(_),
                    ..
                }
            }
        ));

        let cli = Cli::try_parse_from(["otp-term", "book", "inspect", "b.book", "--json"])
            .expect("book inspect --json 可解析");
        assert!(matches!(
            cli.command,
            Cmd::Book {
                cmd: BookCmd::Inspect { json: true, .. }
            }
        ));
    }

    #[test]
    fn book_generate_and_inspect_end_to_end() {
        let dir = std::env::temp_dir().join(format!("otp-cli-it-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let book = dir.join("e2e.book");
        let _ = std::fs::remove_file(&book);

        run(Cmd::Book {
            cmd: BookCmd::Generate {
                path: book.clone(),
                segments: 256,
                book_id: Some("00112233445566778899aabbccddeeff".to_string()),
            },
        })
        .expect("生成 256 段测试本");

        run(Cmd::Book {
            cmd: BookCmd::Inspect {
                path: book.clone(),
                json: false,
            },
        })
        .expect("干净本 inspect 应 ok");

        // 注入重复段：把段 0 复制到段 100 → inspect 必须失败（退出码 1 语义）
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&book)
            .unwrap();
        let mut seg0 = [0u8; 64];
        f.seek(SeekFrom::Start(128)).unwrap();
        f.read_exact(&mut seg0).unwrap();
        f.seek(SeekFrom::Start(128 + 100 * 64)).unwrap();
        f.write_all(&seg0).unwrap();
        drop(f);

        let err = run(Cmd::Book {
            cmd: BookCmd::Inspect {
                path: book.clone(),
                json: true,
            },
        })
        .expect_err("注入重复段后 inspect 必须失败");
        assert!(matches!(err, CliError::BookCheckFailed));

        std::fs::remove_file(&book).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn skeleton_reports_not_implemented() {
        assert!(matches!(
            run(Cmd::Doctor),
            Err(CliError::NotImplemented("WP-15"))
        ));
    }
}
