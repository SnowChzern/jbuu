//! jbuu doorkeeper 库面：SSH 过渡兼容垫。
//! 唯一规格：docs/specs/wp14-doorkeeper-design.md（任务 #49 评审冻结 v1.0，决策 D1–D11）。
//!
//! # 安全边界声明（设计书「安全边界声明」节原文复述，任务卡已定决策 5）
//!
//! 门卫不增强 SSH 会话安全。门卫模式下，SSH 会话的安全上限 = SSH 自身
//! （host key + 用户密钥 + SSH 加密）。
//!
//! 门卫的全部价值 = 三件事：暴露面收缩（公网只能到达门卫，sshd 仅回环可达）+
//! 迁移期兼容（存量 SSH 链路不断）+ 可观测性（连接日志 = 迁移仪表盘数据源）。
//!
//! 门卫不得做任何 SSH 协议解析与判定（唯一例外：[`obs::VersionObserver`] 客户端
//! 版本串旁路观察，只看不改不拦）；门卫不是长期组件：出生即带日落条件，过期退役。
#![forbid(unsafe_code)]

pub mod log;
pub mod obs;
pub mod proxy;
pub mod warn;

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use clap::Parser;

/// 二进制版本（写入 listen_start 日志事件）
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// `--warn-mode` / `--failure-line` 的 on/off 取值
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnOff {
    On,
    Off,
}

impl FromStr for OnOff {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "on" => Ok(OnOff::On),
            "off" => Ok(OnOff::Off),
            _ => Err(format!("无效取值 {s:?}：仅接受 on 或 off")),
        }
    }
}

impl fmt::Display for OnOff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OnOff::On => "on",
            OnOff::Off => "off",
        })
    }
}

/// 命令行参数（设计书 §6.2：配置面全走 CLI flags，无配置文件；默认值即全部裁决值）
#[derive(Debug, Parser)]
#[command(
    name = "jbuu-doorkeeper",
    version = VERSION,
    about = "SSH 过渡兼容垫：listen → 发前置警告行（RFC 4253 §4.2）→ 原样 pipe 到上游 sshd",
    long_about = "安全边界声明：门卫不增强 SSH 会话安全。门卫模式下，SSH 会话的安全上限 = SSH 自身 \
（host key + 用户密钥 + SSH 加密）。门卫的全部价值 = 暴露面收缩（公网只能到达门卫，sshd 仅回环可达）+ \
迁移期兼容（存量 SSH 链路不断）+ 可观测性（连接日志 = 迁移仪表盘数据源）。门卫不做任何 SSH 协议解析与 \
判定（唯一例外：客户端版本串旁路观察，只看不改不拦），也不是长期组件：出生即带日落条件，过期退役。\n\
\n行为（设计书 §1.3 一句话规格）：accept → 向客户端写一行警告（可选关闭）→ 连接上游（5s 超时）→ \
双向原样 pipe（每方向独立线程、16 KiB 缓冲、半关闭传播）。全程不改写、不缓存判定、不注入任何字节 \
（警告行除外）。"
)]
pub struct Cli {
    /// 监听地址（默认 [::]:22，双栈单套接字，代码内显式 IPV6_V6ONLY=0；IPv6 禁用环境退回 0.0.0.0:22）
    #[arg(long, default_value = "[::]:22")]
    pub listen: SocketAddr,

    /// 上游 sshd 地址（回环地址自动顺序尝试对侧回环：127.0.0.1 ↔ [::1]）
    #[arg(long, default_value = "127.0.0.1:2222")]
    pub upstream: SocketAddr,

    /// 前置警告行开关（D6：默认 on；off = 纯透传 TCP 中继）
    #[arg(long, default_value = "on")]
    pub warn_mode: OnOff,

    /// 自定义警告行内容，不含终止符（启动时强制校验 §3.2 W1–W5，任一不满足拒绝启动）
    #[arg(long, default_value = warn::DEFAULT_WARN_LINE)]
    pub warn_line: String,

    /// 上游不可达提示行开关（D11：默认 on）
    #[arg(long, default_value = "on")]
    pub failure_line: OnOff,

    /// 同时活跃连接上限（D8；达到上限 accept 后立即关闭并记 conn_refused_over_limit）
    #[arg(long, default_value_t = 128)]
    pub max_conns: usize,

    /// JSONL 连接日志路径（SIGHUP 触发 reopen，配合 logrotate）
    #[arg(long, default_value = "/var/log/jbuu/doorkeeper.log")]
    pub log_file: PathBuf,

    /// 日志同时镜像到 stderr
    #[arg(long)]
    pub verbose: bool,
}

/// 校验通过后的运行配置（警告/失败行均已含 CRLF 终止符）
#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub upstream: SocketAddr,
    pub warn_mode: OnOff,
    pub warn_line: Vec<u8>,
    pub failure_line: OnOff,
    pub max_conns: usize,
    pub log_path: PathBuf,
    pub verbose: bool,
}

impl Config {
    /// 从 CLI 构造：执行 W1–W5 校验与基础合法性检查，任一失败返回带不变式编号的错误
    /// （设计书 §3.2 W6：把误配挡在部署前，而非运行中）。
    pub fn from_cli(cli: &Cli) -> Result<Config, String> {
        if cli.max_conns == 0 {
            return Err("--max-conns 必须大于 0".to_string());
        }
        if cli.upstream.ip().is_unspecified() {
            return Err(format!(
                "--upstream 不得使用未指定地址（{}）：那会指回门卫自身",
                cli.upstream
            ));
        }
        let warn_line = warn::validate_line(&cli.warn_line).map_err(|e| {
            format!(
                "--warn-line 违反 §3.2 不变式，拒绝启动：{e}（传入内容不含终止符，doorkeeper 自行追加 CRLF）"
            )
        })?;
        Ok(Config {
            listen: cli.listen,
            upstream: cli.upstream,
            warn_mode: cli.warn_mode,
            warn_line,
            failure_line: cli.failure_line,
            max_conns: cli.max_conns,
            log_path: cli.log_file.clone(),
            verbose: cli.verbose,
        })
    }

    /// 测试直配构造（警告/失败行用默认冻结文案）
    pub fn new_for_test(listen: SocketAddr, upstream: SocketAddr, log_path: PathBuf) -> Config {
        Config {
            listen,
            upstream,
            warn_mode: OnOff::On,
            warn_line: warn::default_warn_line(),
            failure_line: OnOff::On,
            max_conns: 128,
            log_path,
            verbose: false,
        }
    }
}

/// §5.5 conn_accept 的 family 字段取值：v4 / v4mapped / v6
pub(crate) fn family_of(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "v4",
        IpAddr::V6(v6) => {
            let s = v6.segments();
            if s[..5].iter().all(|&x| x == 0) && s[5] == 0xffff {
                "v4mapped"
            } else {
                "v6"
            }
        }
    }
}
