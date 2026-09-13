//! # otp-term CLI —— 运维入口（WP-15，任务 #52）
//!
//! 实现规划 §2 职责：server/client、book inspect/generate（仅离线测试或
//! 受控工具）、anchor inspect、doctor、drain/rotate 骨架。
//!
//! 子命令状态：
//! - `serve` / `connect`：WP-15 ① —— 基于 otp-transport + otp-handshake +
//!   otp-session 的端到端加密会话（数据面 = WP-12 M1 回显口径；PTY 终端
//!   形态归 WP-16）；
//! - `doctor`：WP-15 ② —— core dump / swap / 权限 / FS / 备份风险五类，
//!   高风险按策略拒绝启动（serve/connect 内嵌同一策略）；
//! - `book generate|inspect`、`anchor inspect`：§65 —— 只输出公开元数据；
//! - `drain` / `rotate`：§145 **骨架形态**——参数面完整、拒绡任何状态
//!   变更，完整语义（drain 后不接新会话、双人授权、book_id/version
//!   原子切换）归 WP-17。
//!
//! 红线（规划 §2）：默认不打印秘密；所有状态/错误输出只含公开元数据
//! （错误码/类别/指针/字节数），数据面明文只经过 stdio。

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use otp_book::generate::{generate_book, random_book_id};

use otp_term_cli::auditlog::Audit;
use otp_term_cli::doctor as cli_doctor;
use otp_term_cli::proto::{self, Endpoint, SessionFailure, SessionInfo};
use otp_term_cli::recoveryio;
use otp_transport::FramedStream as _;
use otp_types::{BookId, Generation, SegmentIndex};

/// 骨架子命令（drain/rotate）的退出码（区别于 1=运行失败、2=策略拒绝）。
const EXIT_WP17_SKELETON: i32 = 3;
/// 策略拒绝启动（doctor BLOCK / 恢复失败 / 分配器拒绝）。
const EXIT_POLICY_REFUSED: i32 = 2;
/// 默认会话超时（握手 + 数据面整体）。
const DEFAULT_DEADLINE_SECS: u64 = 120;

#[derive(Debug, Parser)]
#[command(
    name = "otp-term",
    version,
    about = "OTP 密码本池终端协议 CLI（serve/connect/doctor/inspect；drain/rotate 为 WP-17 骨架）"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// 启动服务端：体检→恢复→加载密码本+双锚，接受连接并签发段（数据面：
    /// 加密回显，PTY 归 WP-16）。
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
        /// 监听地址（host:port；端口 0 = 随机）。
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: String,
        /// 审计日志路径（JSONL 白名单字段；缺省不落盘）。
        #[arg(long)]
        audit_log: Option<PathBuf>,
        /// 服务多少个连接后退出（默认一直服务；受控测试/轮换演练用）。
        #[arg(long, default_value_t = u64::MAX)]
        sessions: u64,
        /// 会话超时（秒）。
        #[arg(long, default_value_t = DEFAULT_DEADLINE_SECS)]
        deadline_secs: u64,
        /// 显式接受未证明加密的 swap（把 BLOCK 降级为 warn；仅限受控环境）。
        #[arg(long)]
        allow_unencrypted_swap: bool,
    },
    /// 以客户端身份连接服务端并建立加密会话（stdin→加密→回显解密→stdout）。
    Connect {
        /// 密码本路径（与服务端同本同 book_id）。
        #[arg(long)]
        book: PathBuf,
        /// 客户端锚副本 A 路径（客户端拥有自己的双锚）。
        #[arg(long)]
        anchor_a: PathBuf,
        /// 客户端锚副本 B 路径。
        #[arg(long)]
        anchor_b: PathBuf,
        /// 服务端地址（host:port）。
        #[arg(long)]
        target: String,
        /// 审计日志路径（JSONL 白名单字段；缺省不落盘）。
        #[arg(long)]
        audit_log: Option<PathBuf>,
        /// 会话超时（秒）。
        #[arg(long, default_value_t = DEFAULT_DEADLINE_SECS)]
        deadline_secs: u64,
        /// 显式接受未证明加密的 swap（把 BLOCK 降级为 warn；仅限受控环境）。
        #[arg(long)]
        allow_unencrypted_swap: bool,
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
    /// 环境体检：core dump/swap/权限/文件系统/备份风险；高风险按策略拒绝启动。
    Doctor {
        /// 密码本路径（给出时启用权限/FS/备份检查）。
        #[arg(long)]
        book: Option<PathBuf>,
        /// 锚副本 A 路径。
        #[arg(long)]
        anchor_a: Option<PathBuf>,
        /// 锚副本 B 路径。
        #[arg(long)]
        anchor_b: Option<PathBuf>,
        /// 输出机器可读 JSON（公开元数据，可入 evidence/）。
        #[arg(long)]
        json: bool,
        /// 显式接受未证明加密的 swap（把 BLOCK 降级为 warn；仅限受控环境）。
        #[arg(long)]
        allow_unencrypted_swap: bool,
    },
    /// 排空：停止接受新会话（骨架：状态变更归 WP-17，本命令不改动任何状态）。
    Drain,
    /// 换本轮换（骨架：book_id/version 核对与双人授权归 WP-17，本命令不改动任何状态）。
    Rotate {
        /// 新密码本 book_id（32 位十六进制；核对用，WP-17 生效）。
        #[arg(long)]
        book_id: Option<String>,
        /// 新密码本 version（核对用，WP-17 生效）。
        #[arg(long)]
        version: Option<u16>,
        /// 授权人 A（双人流程接口，WP-17 生效）。
        #[arg(long)]
        authorizer_a: Option<String>,
        /// 授权人 B（双人流程接口，WP-17 生效）。
        #[arg(long)]
        authorizer_b: Option<String>,
    },
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
    /// 检查锚状态（generation/next/一致性；仅公开元数据）。
    Inspect {
        /// 锚文件路径。
        path: PathBuf,
        /// 第二锚路径（给出时附双锚关系判定）。
        path_b: Option<PathBuf>,
        /// 输出机器可读 JSON。
        #[arg(long)]
        json: bool,
    },
}

/// CLI 错误。永不包含秘密材料。
#[derive(Debug)]
enum CliError {
    /// 退出码 + 一行原因（公开元数据）。
    Exit(i32, String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exit(code, what) => write!(f, "{what}（exit={code}）"),
        }
    }
}

fn main() {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("otp-term: {e}");
            std::process::exit(match &e {
                CliError::Exit(code, _) => *code,
            });
        }
    }
}

fn status(line: &str) {
    // 状态面统一走 stderr；stdout 只留给数据面（connect 回显明文）。
    eprintln!("{line}");
}

fn run(cmd: Cmd) -> Result<(), CliError> {
    match cmd {
        Cmd::Serve {
            book,
            anchor_a,
            anchor_b,
            listen,
            audit_log,
            sessions,
            deadline_secs,
            allow_unencrypted_swap,
        } => run_serve(ServeArgs {
            book,
            anchor_a,
            anchor_b,
            listen,
            audit_log,
            sessions,
            deadline: Duration::from_secs(deadline_secs.max(1)),
            allow_unencrypted_swap,
        }),
        Cmd::Connect {
            book,
            anchor_a,
            anchor_b,
            target,
            audit_log,
            deadline_secs,
            allow_unencrypted_swap,
        } => run_connect(ConnectArgs {
            book,
            anchor_a,
            anchor_b,
            target,
            audit_log,
            deadline: Duration::from_secs(deadline_secs.max(1)),
            allow_unencrypted_swap,
        }),
        Cmd::Book { cmd } => run_book(cmd),
        Cmd::Anchor { cmd } => run_anchor(cmd),
        Cmd::Doctor {
            book,
            anchor_a,
            anchor_b,
            json,
            allow_unencrypted_swap,
        } => {
            let paths = match (book, anchor_a, anchor_b) {
                (Some(b), Some(a), Some(c)) => Some(otp_platform::DoctorPaths {
                    book: b,
                    anchor_a: a,
                    anchor_b: c,
                }),
                (None, None, None) => None,
                _ => {
                    return Err(CliError::Exit(
                        2,
                        "doctor：--book/--anchor-a/--anchor-b 需同时给出（或全部省略）".into(),
                    ));
                }
            };
            let outcome = {
                // 与 serve/connect 同口径：先自加固再体检（报告的是 otp-term
                // 进程加固后的真实达阵状态）。
                otp_platform::harden_process().map_err(|why| {
                    CliError::Exit(EXIT_POLICY_REFUSED, format!("自加固失败：{why}"))
                })?;
                cli_doctor::run(paths.as_ref(), allow_unencrypted_swap)
            };
            if json {
                println!("{}", outcome.to_json());
            } else {
                print!("{}", outcome.summary(allow_unencrypted_swap));
            }
            if outcome.refuse_startup() {
                return Err(CliError::Exit(
                    EXIT_POLICY_REFUSED,
                    "doctor：存在高风险（BLOCK）项".into(),
                ));
            }
            Ok(())
        }
        // §145：骨架形态——参数面已冻结，状态变更与双人授权语义归 WP-17。
        Cmd::Drain => {
            status("drain：骨架（WP-15）——排空标记/阻止新会话语义在 WP-17 落地；");
            status("本命令未执行任何状态变更（serve 目前以 --sessions 控制接受量）。");
            Err(CliError::Exit(
                EXIT_WP17_SKELETON,
                "drain 骨架：完整语义在 WP-17 落地".into(),
            ))
        }
        Cmd::Rotate {
            book_id,
            version,
            authorizer_a,
            authorizer_b,
        } => {
            status("rotate：骨架（WP-15）——需 book_id/version 明确核对与双人授权（WP-17 落地）；");
            status(&format!(
                "参数面：book_id={} version={} authorizer_a={} authorizer_b={}",
                book_id.as_deref().unwrap_or("<未提供>"),
                version
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "<未提供>".into()),
                authorizer_a.as_deref().unwrap_or("<未提供>"),
                authorizer_b.as_deref().unwrap_or("<未提供>"),
            ));
            status("本命令未执行任何状态变更（旧本不会被重新打开）。");
            Err(CliError::Exit(
                EXIT_WP17_SKELETON,
                "rotate 骨架：完整语义在 WP-17 落地".into(),
            ))
        }
    }
}

// ───────────────────────── serve ─────────────────────────

struct ServeArgs {
    book: PathBuf,
    anchor_a: PathBuf,
    anchor_b: PathBuf,
    listen: String,
    audit_log: Option<PathBuf>,
    sessions: u64,
    deadline: Duration,
    allow_unencrypted_swap: bool,
}

fn run_serve(args: ServeArgs) -> Result<(), CliError> {
    use otp_platform::{Outcome, harden_process};

    // ① 自加固 + 验证（§5 测试 11：RLIMIT_CORE=0 / dumpable=0）。
    harden_process()
        .map_err(|why| CliError::Exit(EXIT_POLICY_REFUSED, format!("自加固失败：{why}")))?;

    // ② 密码本头（book_id/段数；公开元数据）。
    let header = otp_book::Book::open(&args.book)
        .map_err(|e| CliError::Exit(1, format!("密码本打开失败：{e:?}")))?;
    let book_id = header.header().book_id;
    let segment_count = header.header().segment_count;
    let ep = Endpoint {
        book_id,
        segment_count,
    };

    // ③ doctor：高风险按策略拒绝启动（§151）。
    let paths = otp_platform::DoctorPaths {
        book: args.book.clone(),
        anchor_a: args.anchor_a.clone(),
        anchor_b: args.anchor_b.clone(),
    };
    let outcome = cli_doctor::run(Some(&paths), args.allow_unencrypted_swap);
    status(&outcome.summary(args.allow_unencrypted_swap));
    if outcome.refuse_startup() {
        return Err(CliError::Exit(
            EXIT_POLICY_REFUSED,
            "serve：环境体检存在 BLOCK 项，拒绝启动".into(),
        ));
    }

    // ④ 审计 sink（白名单字段；打开失败 = 拒绝启动，不静默丢弃审计）。
    let mut audit = match &args.audit_log {
        Some(p) => Audit::open(p).map_err(|why| CliError::Exit(EXIT_POLICY_REFUSED, why))?,
        None => Audit::disabled(),
    };

    // ⑤ 启动恢复（WP-08）：双锚取高修复；失败 → 拒绝服务（审计记
    // quarantined；此时锚内容不可信，段号/generation 只能填 0）。
    let report = recoveryio::startup_recover(&args.anchor_a, &args.anchor_b).map_err(|e| {
        let _ = audit.emit_err(
            book_id,
            SegmentIndex::ZERO,
            Generation::new(0),
            Outcome::Quarantined,
            otp_types::ErrorCategory::Recovery,
        );
        CliError::Exit(
            EXIT_POLICY_REFUSED,
            format!("启动恢复失败（拒绝服务）：{e:?}"),
        )
    })?;
    let _ = audit.emit_ok(
        book_id,
        report.adopted.next,
        report.adopted.generation,
        Outcome::Recovered,
    );
    for w in &report.warnings {
        status(&format!("recovery-warning: {w:?}"));
    }
    if let Some(copy) = report.repaired {
        status(&format!("recovery: stale copy {copy:?} repaired+fsynced"));
    }

    // ⑥ 分配器（内部再次做严格双锚对账 + 密码本哈希校验；OFD 锁独占）。
    let mut alloc = otp_allocator::Allocator::open(otp_allocator::AllocatorConfig {
        book: args.book.clone(),
        anchor_a: args.anchor_a.clone(),
        anchor_b: args.anchor_b.clone(),
        expected_book_id: book_id,
    })
    .map_err(|e| {
        CliError::Exit(
            EXIT_POLICY_REFUSED,
            format!("分配器打开失败（拒绝服务）：{e:?}"),
        )
    })?;
    let (next0, gen0) = alloc.state();
    status(&format!(
        "READY next={} generation={}",
        next0.get(),
        gen0.get()
    ));

    // ⑦ 监听 + 会话循环（每连接：握手→回显；fail-closed per connection）。
    let listener = otp_transport::TcpListener::bind(&args.listen)
        .map_err(|_| CliError::Exit(1, format!("监听失败：{}", args.listen)))?;
    let addr = listener
        .local_addr()
        .map_err(|_| CliError::Exit(1, "无法获取监听地址".into()))?;
    status(&format!("LISTEN={addr}"));

    let mut served: u64 = 0;
    while served < args.sessions {
        let mut io = match listener.accept() {
            Ok(io) => io,
            Err(e) => {
                status(&format!("accept 失败：{e:?}（继续/退出由循环边界决定）"));
                break;
            }
        };
        served += 1;
        match serve_one(&mut io, &mut alloc, ep, args.deadline, &mut audit, book_id) {
            Ok((info, bytes)) => {
                status(&format!(
                    "SESSION segment={} generation={} echoed_bytes={}",
                    info.segment.get(),
                    info.generation.get(),
                    bytes
                ));
            }
            Err(f) => {
                let (next, generation) = alloc.state();
                let _ = audit.emit_err(book_id, next, generation, Outcome::Rejected, f.category);
                status(&format!(
                    "SESSION-FAILED {} (next={})",
                    f.line(),
                    next.get()
                ));
            }
        }
        let _ = io.close();
    }
    let (next, generation) = alloc.state();
    status(&format!(
        "EXIT next={} generation={} sessions={}",
        next.get(),
        generation.get(),
        served
    ));
    Ok(())
}

fn serve_one(
    io: &mut dyn otp_transport::FramedStream,
    alloc: &mut otp_allocator::Allocator,
    ep: Endpoint,
    deadline: Duration,
    audit: &mut Audit,
    book_id: BookId,
) -> Result<(SessionInfo, u64), SessionFailure> {
    let (mut session, info) = proto::server_handshake(io, alloc, ep, deadline)?;
    // 审计先于数据面：签发事实落盘（失败即 fail closed 整个 serve 会话）。
    audit
        .emit_ok(
            book_id,
            info.segment,
            info.generation,
            otp_platform::Outcome::Issued,
        )
        .map_err(|_| {
            SessionFailure::new(
                otp_codec::ErrorCode::IO_ERROR,
                otp_types::ErrorCategory::Platform,
            )
        })?;
    let bytes = proto::server_echo_loop(io, &mut session)?;
    Ok((info, bytes))
}

// ───────────────────────── connect ─────────────────────────

struct ConnectArgs {
    book: PathBuf,
    anchor_a: PathBuf,
    anchor_b: PathBuf,
    target: String,
    audit_log: Option<PathBuf>,
    deadline: Duration,
    allow_unencrypted_swap: bool,
}

fn run_connect(args: ConnectArgs) -> Result<(), CliError> {
    use otp_platform::{Outcome, harden_process};

    // ① 自加固（客户端同样持有段材料）。
    harden_process()
        .map_err(|why| CliError::Exit(EXIT_POLICY_REFUSED, format!("自加固失败：{why}")))?;

    // ② 密码本头。
    let header = otp_book::Book::open(&args.book)
        .map_err(|e| CliError::Exit(1, format!("密码本打开失败：{e:?}")))?;
    let book_id = header.header().book_id;
    let ep = Endpoint {
        book_id,
        segment_count: header.header().segment_count,
    };

    // ③ doctor（与 serve 同策略）。
    let paths = otp_platform::DoctorPaths {
        book: args.book.clone(),
        anchor_a: args.anchor_a.clone(),
        anchor_b: args.anchor_b.clone(),
    };
    let outcome = cli_doctor::run(Some(&paths), args.allow_unencrypted_swap);
    status(&outcome.summary(args.allow_unencrypted_swap));
    if outcome.refuse_startup() {
        return Err(CliError::Exit(
            EXIT_POLICY_REFUSED,
            "connect：环境体检存在 BLOCK 项，拒绝启动".into(),
        ));
    }

    let mut audit = match &args.audit_log {
        Some(p) => Audit::open(p).map_err(|why| CliError::Exit(EXIT_POLICY_REFUSED, why))?,
        None => Audit::disabled(),
    };

    // ④ 客户端自己的双锚：恢复 + 分配器。
    let report = recoveryio::startup_recover(&args.anchor_a, &args.anchor_b).map_err(|e| {
        CliError::Exit(
            EXIT_POLICY_REFUSED,
            format!("启动恢复失败（拒绝服务）：{e:?}"),
        )
    })?;
    let _ = audit.emit_ok(
        book_id,
        report.adopted.next,
        report.adopted.generation,
        Outcome::Recovered,
    );
    for w in &report.warnings {
        status(&format!("recovery-warning: {w:?}"));
    }
    let mut alloc = otp_allocator::Allocator::open(otp_allocator::AllocatorConfig {
        book: args.book.clone(),
        anchor_a: args.anchor_a.clone(),
        anchor_b: args.anchor_b.clone(),
        expected_book_id: book_id,
    })
    .map_err(|e| {
        CliError::Exit(
            EXIT_POLICY_REFUSED,
            format!("分配器打开失败（拒绝服务）：{e:?}"),
        )
    })?;

    // ⑤ TCP 连接 + 握手 + stdio 数据面。
    let mut io = otp_transport::TcpTransport::connect(&args.target)
        .map_err(|_| CliError::Exit(1, format!("连接失败：{}", args.target)))?;
    let result = (|| -> Result<(SessionInfo, u64), SessionFailure> {
        let (mut session, info) = proto::client_handshake(&mut io, &mut alloc, ep, args.deadline)?;
        audit
            .emit_ok(book_id, info.segment, info.generation, Outcome::Issued)
            .map_err(|_| {
                SessionFailure::new(
                    otp_codec::ErrorCode::IO_ERROR,
                    otp_types::ErrorCategory::Platform,
                )
            })?;
        let stdin = std::io::stdin();
        let mut lock = stdin.lock();
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let bytes = proto::client_stdio_pump(&mut io, &mut session, &mut lock, &mut out)?;
        Ok((info, bytes))
    })();
    match result {
        Ok((info, bytes)) => {
            let _ = io.close();
            status(&format!(
                "DONE segment={} generation={} sent_bytes={} next={}",
                info.segment.get(),
                info.generation.get(),
                bytes,
                alloc.state().0.get()
            ));
            Ok(())
        }
        Err(f) => {
            let (next, generation) = alloc.state();
            let _ = audit.emit_err(book_id, next, generation, Outcome::Rejected, f.category);
            let _ = io.close();
            Err(CliError::Exit(1, format!("会话失败：{}", f.line())))
        }
    }
}

// ───────────────────────── book / anchor ─────────────────────────

fn run_book(cmd: BookCmd) -> Result<(), CliError> {
    match cmd {
        BookCmd::Generate {
            path,
            segments,
            book_id,
        } => {
            let id = match book_id {
                Some(hex) => parse_book_id(&hex)?,
                None => random_book_id().map_err(|e| CliError::Exit(1, e.to_string()))?,
            };
            let header =
                generate_book(&path, segments, id).map_err(|e| CliError::Exit(1, e.to_string()))?;
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
                .map_err(|e| CliError::Exit(1, e.to_string()))?;
            if json {
                println!("{}", report.to_json());
            } else {
                println!("{}", report.summary());
            }
            if report.ok {
                Ok(())
            } else {
                Err(CliError::Exit(
                    1,
                    "密码本检查未通过（重复段/全零段等，见上方报告）".into(),
                ))
            }
        }
    }
}

fn run_anchor(cmd: AnchorCmd) -> Result<(), CliError> {
    let AnchorCmd::Inspect { path, path_b, json } = cmd;
    let a = otp_term_cli::anchorio::inspect_anchor(&path);
    let b = path_b
        .as_ref()
        .map(|p| otp_term_cli::anchorio::inspect_anchor(p));
    let report = otp_term_cli::anchorio::AnchorInspectReport {
        a,
        b: b.unwrap_or(otp_term_cli::anchorio::AnchorStatus {
            record: None,
            failure: None,
        }),
    };
    if json {
        println!("{}", report.to_json(&path, path_b.as_deref()));
    } else {
        print!(
            "{}",
            otp_term_cli::anchorio::summary(&path, path_b.as_deref(), &report)
        );
    }
    if path_b.is_some() && !report.ok() {
        return Err(CliError::Exit(
            1,
            "锚检查未通过（存在不可读/损坏副本）".into(),
        ));
    }
    if path_b.is_none() && report.a.record.is_none() {
        return Err(CliError::Exit(1, "锚检查未通过（不可读/损坏）".into()));
    }
    Ok(())
}

fn parse_book_id(hex: &str) -> Result<BookId, CliError> {
    let bytes = hex_parse(hex).ok_or_else(|| {
        CliError::Exit(
            2,
            format!("参数非法：--book-id 须为 32 位十六进制，得到 {hex:?}"),
        )
    })?;
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
        assert!(matches!(cli.command, Cmd::Doctor { .. }));

        let cli = Cli::try_parse_from([
            "otp-term",
            "serve",
            "--book",
            "b.book",
            "--anchor-a",
            "a.anchor",
            "--anchor-b",
            "c.anchor",
            "--sessions",
            "1",
        ])
        .expect("serve 可解析");
        assert!(matches!(cli.command, Cmd::Serve { .. }));

        let cli = Cli::try_parse_from([
            "otp-term",
            "connect",
            "--book",
            "b.book",
            "--anchor-a",
            "a.anchor",
            "--anchor-b",
            "c.anchor",
            "--target",
            "127.0.0.1:1",
        ])
        .expect("connect 可解析（含客户端双锚）");
        assert!(matches!(cli.command, Cmd::Connect { .. }));

        let cli = Cli::try_parse_from([
            "otp-term",
            "doctor",
            "--book",
            "b.book",
            "--anchor-a",
            "a.anchor",
            "--anchor-b",
            "c.anchor",
            "--json",
        ])
        .expect("doctor 带路径可解析");
        assert!(matches!(cli.command, Cmd::Doctor { json: true, .. }));

        let cli = Cli::try_parse_from(["otp-term", "drain"]).expect("drain 可解析");
        assert!(matches!(cli.command, Cmd::Drain));

        let cli = Cli::try_parse_from([
            "otp-term",
            "rotate",
            "--book-id",
            "00112233445566778899aabbccddeeff",
            "--version",
            "1",
            "--authorizer-a",
            "alice",
            "--authorizer-b",
            "bob",
        ])
        .expect("rotate 骨架参数面可解析");
        assert!(matches!(cli.command, Cmd::Rotate { .. }));

        let cli = Cli::try_parse_from(["otp-term", "anchor", "inspect", "a.anchor"])
            .expect("anchor inspect 单锚可解析");
        assert!(matches!(
            cli.command,
            Cmd::Anchor {
                cmd: AnchorCmd::Inspect { .. }
            }
        ));

        let cli = Cli::try_parse_from([
            "otp-term", "anchor", "inspect", "a.anchor", "b.anchor", "--json",
        ])
        .expect("anchor inspect 双锚可解析");
        assert!(matches!(
            cli.command,
            Cmd::Anchor {
                cmd: AnchorCmd::Inspect { json: true, .. }
            }
        ));

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
    fn drain_and_rotate_are_wp17_skeletons() {
        // 骨架形态：明确拒绝执行状态变更，退出码 3（§145 范围内不冒进）。
        let err = run(Cmd::Drain).expect_err("drain 骨架必须显式退出而非空转");
        assert!(matches!(err, CliError::Exit(3, _)));

        let err = run(Cmd::Rotate {
            book_id: Some("00112233445566778899aabbccddeeff".into()),
            version: Some(1),
            authorizer_a: Some("alice".into()),
            authorizer_b: Some("bob".into()),
        })
        .expect_err("rotate 骨架必须显式退出而非空转");
        assert!(matches!(err, CliError::Exit(3, _)));
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
        assert!(matches!(err, CliError::Exit(1, _)));

        std::fs::remove_file(&book).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
