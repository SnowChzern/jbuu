//! jbuu-doorkeeper —— SSH 过渡兼容垫（SSH transition shim）。
//! 唯一规格：docs/specs/wp14-doorkeeper-design.md（任务 #49 评审冻结 v1.0）。
//!
//! 安全边界声明：门卫不增强 SSH 会话安全。门卫模式下，SSH 会话的安全上限 =
//! SSH 自身（host key + 用户密钥 + SSH 加密）。门卫的全部价值 = 暴露面收缩 +
//! 迁移期兼容 + 可观测性。门卫不做任何 SSH 协议解析与判定（唯一例外：客户端
//! 版本串旁路观察，只看不改不拦）；不是长期组件：出生即带日落条件，过期退役。
#![forbid(unsafe_code)]

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use clap::Parser;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use otp_doorkeeper::log::JsonlLog;
use otp_doorkeeper::proxy;
use otp_doorkeeper::{Cli, Config};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let cfg = match Config::from_cli(&cli) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("jbuu-doorkeeper: 配置校验失败，拒绝启动：{err}");
            return ExitCode::FAILURE;
        }
    };
    let log = match JsonlLog::open(&cfg.log_path, cfg.verbose) {
        Ok(log) => Arc::new(log),
        Err(err) => {
            eprintln!(
                "jbuu-doorkeeper: 无法打开日志文件 {}：{err}",
                cfg.log_path.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    if let Err(err) = install_signal_handlers(log.clone(), stop.clone(), cfg.listen) {
        eprintln!("jbuu-doorkeeper: 信号处理初始化失败：{err}");
        return ExitCode::FAILURE;
    }

    match proxy::run(cfg, log, stop) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!(
                "jbuu-doorkeeper: 退出：{err}（提示：若为 IPv6 禁用环境，改用 --listen 0.0.0.0:22）"
            );
            ExitCode::FAILURE
        }
    }
}

/// §5.5/§6.2：SIGHUP → 日志 reopen（logrotate 外置轮转）；SIGTERM/SIGINT → 优雅退出
/// （置 stop 位并做一次哑连接唤醒阻塞在 accept 上的循环）。
fn install_signal_handlers(
    log: Arc<JsonlLog>,
    stop: Arc<AtomicBool>,
    listen: SocketAddr,
) -> io::Result<()> {
    let mut signals = Signals::new([SIGHUP, SIGTERM, SIGINT])?;
    thread::Builder::new()
        .name("dk-signal".to_string())
        .stack_size(64 * 1024)
        .spawn(move || {
            for sig in signals.forever() {
                match sig {
                    SIGHUP => {
                        if let Err(err) = log.reopen() {
                            eprintln!("jbuu-doorkeeper: SIGHUP reopen 失败，保留旧 fd：{err}");
                        }
                    }
                    SIGTERM | SIGINT => {
                        stop.store(true, Ordering::Release);
                        let _ = TcpStream::connect_timeout(&listen, Duration::from_millis(500));
                    }
                    _ => unreachable!("仅注册了 SIGHUP/SIGTERM/SIGINT"),
                }
            }
        })?;
    Ok(())
}
