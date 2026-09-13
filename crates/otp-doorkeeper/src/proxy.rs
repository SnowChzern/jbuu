//! accept 循环、连接计数、每连接双向 pipe + 半关闭（设计书 §1.3 / §5）。
//!
//! 形态（D1）：thread-per-conn + std::net，零异步依赖。每连接 = 1 个处理线程 +
//! 2 个 pipe 线程（`try_clone` 句柄，每方向一个），阻塞式 copy 循环承载 TCP 背压。
#![forbid(unsafe_code)]

use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustix::net::{
    AddressFamily, SocketAddr as RustixSocketAddr, SocketFlags, SocketType, sockopt,
};

use crate::Config;
use crate::log::JsonlLog;
use crate::obs::{SharedObserver, VersionObserver};

/// §5.3 每方向用户态缓冲
pub const PIPE_BUF_SIZE: usize = 16 * 1024;
/// §5.2 上游 connect 超时
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// §5.2 警告行/失败行 write 超时（SO_SNDTIMEO）
pub const WARN_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// §5.2 TCP keepalive：KEEPIDLE=600s / KEEPINTVL=60s / KEEPCNT=5（两端套接字）
pub const KEEPALIVE_IDLE: Duration = Duration::from_secs(600);
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);
pub const KEEPALIVE_COUNT: u32 = 5;
/// §5.1 listen backlog
pub const LISTEN_BACKLOG: i32 = 256;
/// §2.2 pipe/处理线程栈
const THREAD_STACK: usize = 256 * 1024;

/// 数据面字节流向（c2s = client→sshd）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Client,
    Upstream,
}

/// 进程内共享状态
struct Shared {
    cfg: Config,
    log: Arc<JsonlLog>,
    /// 当前活跃连接数（上限 D8）
    conns: Arc<AtomicUsize>,
    /// 单调连接号（§5.5 join key）
    next_conn_id: AtomicU64,
}

/// 连接计数守卫：线程退出（含 panic 展开）时严格减一（§5.4 资源归还红线）
struct ConnGuard(Arc<AtomicUsize>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// 监听生命周期入口：绑定 → listen_start → accept 循环。
/// `stop` 置位后由外部唤醒（一次哑连接）使 accept 返回并退出循环。
pub fn run(cfg: Config, log: Arc<JsonlLog>, stop: Arc<AtomicBool>) -> io::Result<()> {
    let listener = bind_listener(cfg.listen)?;
    serve(listener, cfg, log, stop)
}

/// accept 循环（接受预绑定 listener；测试工装用）
pub fn serve(
    listener: TcpListener,
    cfg: Config,
    log: Arc<JsonlLog>,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    log.listen_start(
        &cfg.listen.to_string(),
        &cfg.upstream.to_string(),
        &cfg.warn_mode.to_string(),
        cfg.max_conns,
    );
    let shared = Arc::new(Shared {
        cfg,
        log,
        conns: Arc::new(AtomicUsize::new(0)),
        next_conn_id: AtomicU64::new(1),
    });

    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        let (stream, peer) = match listener.accept() {
            Ok(x) => x,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if stop.load(Ordering::Acquire) {
            break; // 唤醒用哑连接：直接丢弃退出
        }
        if !try_inc(&shared.conns, shared.cfg.max_conns) {
            // §5.1：达到上限 accept 后立即关闭（不写警告行——上限保护优先于告知）
            shared.log.conn_refused_over_limit(
                &peer.ip().to_string(),
                peer.port(),
                shared.cfg.max_conns,
            );
            let conn_id = shared.next_conn_id.fetch_add(1, Ordering::Relaxed);
            shared.log.conn_close(conn_id, "over_limit", 0, 0, 0);
            drop(stream);
            continue;
        }
        let sh = shared.clone();
        let spawned = thread::Builder::new()
            .stack_size(THREAD_STACK)
            .name("dk-conn".to_string())
            .spawn(move || sh.handle_conn(stream, peer));
        if spawned.is_err() {
            // 线程资源耗尽：归还计数；stream 已随闭包 drop 而关闭
            shared.conns.fetch_sub(1, Ordering::AcqRel);
            shared.log.event(
                "error",
                "conn_spawn_failed",
                &[("src_ip", crate::log::Field::Str(&peer.ip().to_string()))],
            );
        }
    }
    Ok(())
}

/// 绑定监听套接字（D10：v6 监听显式 IPV6_V6ONLY=0，单套接字双栈）
pub fn bind_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    match addr {
        SocketAddr::V6(v6) => {
            let fd = rustix::net::socket_with(
                AddressFamily::INET6,
                SocketType::STREAM,
                SocketFlags::empty(),
                None,
            )?;
            // 不依赖 sysctl net.ipv6.bindv6only（§1.2）
            sockopt::set_ipv6_v6only(&fd, false)?;
            let sa = RustixSocketAddr::V6(v6);
            rustix::net::bind(&fd, &sa)?;
            rustix::net::listen(&fd, LISTEN_BACKLOG)?;
            Ok(TcpListener::from(fd))
        }
        v4 => {
            let listener = TcpListener::bind(v4)?;
            listener.set_nonblocking(false)?;
            Ok(listener)
        }
    }
}

fn try_inc(counter: &AtomicUsize, max: usize) -> bool {
    let mut cur = counter.load(Ordering::Acquire);
    loop {
        if cur >= max {
            return false;
        }
        match counter.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(actual) => cur = actual,
        }
    }
}

impl Shared {
    fn handle_conn(self: Arc<Self>, client: TcpStream, peer: SocketAddr) {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let t0 = Instant::now();
        self.log.conn_accept(
            conn_id,
            &peer.ip().to_string(),
            peer.port(),
            crate::family_of(&peer.ip()),
        );
        let _guard = ConnGuard(self.conns.clone());

        // 套接字策略：keepalive（§5.2 死端检测）+ 发送超时（仅警告行 write 阶段）
        if let Err(e) = sock::apply_client_policy(&client) {
            self.log
                .conn_close(conn_id, "client_reset", 0, 0, elapsed_ms(t0));
            eprintln!("jbuu-doorkeeper: conn {conn_id} 套接字选项设置失败：{e}");
            return;
        }

        // §3.3（D3）：accept 后立即写警告行，此前不读客户端任何字节
        if self.cfg.warn_mode == crate::OnOff::On {
            match write_all_via(&client, &self.cfg.warn_line) {
                Ok(()) => {
                    self.log.warn_sent(conn_id, self.cfg.warn_line.len());
                }
                Err(e) => {
                    let reason = match e.kind() {
                        ErrorKind::ConnectionReset
                        | ErrorKind::BrokenPipe
                        | ErrorKind::ConnectionAborted => "client_reset",
                        _ => "warn_write_timeout", // §5.2：SO_SNDTIMEO 超时（EAGAIN/WouldBlock）归此
                    };
                    self.log.conn_close(conn_id, reason, 0, 0, elapsed_ms(t0));
                    return;
                }
            }
        }

        // 上游连接（§5.2：5s 超时；§1.2：回环顺序尝试对侧）
        let t_up = Instant::now();
        match connect_upstream(&self.cfg.upstream) {
            Ok(upstream) => {
                self.log
                    .upstream_connect(conn_id, true, elapsed_ms(t_up), None);
                self.pipe(conn_id, client, upstream, t0);
            }
            Err(e) => {
                self.log
                    .upstream_connect(conn_id, false, elapsed_ms(t_up), Some(&e.to_string()));
                // §3.4（D11）：关闭前补发诊断行（可关）
                if self.cfg.failure_line == crate::OnOff::On {
                    let _ = write_all_via(&client, &crate::warn::failure_line());
                }
                self.log
                    .conn_close(conn_id, "upstream_unavailable", 0, 0, elapsed_ms(t0));
            }
        }
    }

    /// 双向原样 pipe：各方向独立线程、16 KiB 缓冲、半关闭传播（§5.3/§5.4）
    fn pipe(self: &Arc<Self>, conn_id: u64, client: TcpStream, upstream: TcpStream, t0: Instant) {
        // §5.2（D7）：pipe 阶段显式无应用层超时——清掉警告行阶段的发送超时
        sock::clear_app_timeouts(&client);
        sock::clear_app_timeouts(&upstream);

        let clones = || -> io::Result<(TcpStream, TcpStream, TcpStream, TcpStream)> {
            Ok((
                client.try_clone()?,
                upstream.try_clone()?,
                upstream.try_clone()?,
                client.try_clone()?,
            ))
        };
        let (c_read, u_write, u_read, c_write) = match clones() {
            Ok(x) => x,
            Err(e) => {
                eprintln!("jbuu-doorkeeper: conn {conn_id} 句柄克隆失败：{e}");
                self.log
                    .conn_close(conn_id, "client_reset", 0, 0, elapsed_ms(t0));
                return;
            }
        };

        let bytes_c2s = Arc::new(AtomicU64::new(0));
        let bytes_s2c = Arc::new(AtomicU64::new(0));
        let first_err: Arc<Mutex<Option<Side>>> = Arc::new(Mutex::new(None));
        let observer: Arc<SharedObserver> = Arc::new(Mutex::new(VersionObserver::new()));

        let t_c2s = spawn_pipe_thread(
            c_read,
            u_write,
            Side::Client,
            bytes_c2s.clone(),
            Some(observer.clone()),
            first_err.clone(),
        );
        let t_s2c = spawn_pipe_thread(
            u_read,
            c_write,
            Side::Upstream,
            bytes_s2c.clone(),
            None,
            first_err.clone(),
        );

        let _ = t_c2s.join();
        let _ = t_s2c.join();

        // §3.5：观察结果落日志（未见即 version: null）
        let (version, truncated) = observer.lock().unwrap().take_result();
        self.log
            .client_version(conn_id, version.as_deref(), truncated);

        let reason = match *first_err.lock().unwrap() {
            Some(Side::Client) => "client_reset",
            Some(Side::Upstream) => "upstream_reset",
            None => "normal",
        };
        self.log.conn_close(
            conn_id,
            reason,
            bytes_c2s.load(Ordering::Relaxed),
            bytes_s2c.load(Ordering::Relaxed),
            elapsed_ms(t0),
        );
        // 此处 drop client/upstream 原始句柄 → 双向全关
    }
}

fn elapsed_ms(t0: Instant) -> u64 {
    t0.elapsed().as_millis() as u64
}

fn spawn_pipe_thread(
    read: TcpStream,
    write: TcpStream,
    read_side: Side,
    counter: Arc<AtomicU64>,
    observer: Option<Arc<SharedObserver>>,
    first_err: Arc<Mutex<Option<Side>>>,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .stack_size(THREAD_STACK)
        .name("dk-pipe".to_string())
        .spawn(move || {
            pipe_one(
                read,
                write,
                read_side,
                &counter,
                observer.as_deref(),
                &first_err,
            )
        })
        .expect("pipe 线程创建失败（资源耗尽应在 accept 侧已暴露；此处快速失败）")
}

/// 单方向 copy 循环。EOF → 对端 `shutdown(Write)` 传播半关闭；
/// 硬错误 → 双向关闭（另一方向线程因 fd 关闭自然退出）。§5.4。
fn pipe_one(
    mut read: TcpStream,
    mut write: TcpStream,
    read_side: Side,
    counter: &AtomicU64,
    observer: Option<&SharedObserver>,
    first_err: &Mutex<Option<Side>>,
) {
    let mut buf = [0u8; PIPE_BUF_SIZE];
    loop {
        match read.read(&mut buf) {
            Ok(0) => {
                // 半关闭传播：本方向对端 FIN → 另一端也应收不到更多数据
                let _ = write.shutdown(std::net::Shutdown::Write);
                return;
            }
            Ok(n) => {
                // §3.5：c2s 方向在转发同一循环内旁路观察（零延迟零滞留）
                if let Some(obs) = observer {
                    obs.lock().unwrap().observe(&buf[..n]);
                }
                if let Err(e) = write.write_all(&buf[..n]) {
                    record_err(first_err, write_side(read_side), e.kind());
                    hard_close(&read, &write);
                    return;
                }
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                record_err(first_err, read_side, e.kind());
                hard_close(&read, &write);
                return;
            }
        }
    }
}

fn write_side(read_side: Side) -> Side {
    match read_side {
        Side::Client => Side::Upstream,
        Side::Upstream => Side::Client,
    }
}

fn record_err(first_err: &Mutex<Option<Side>>, side: Side, _kind: ErrorKind) {
    let mut slot = first_err.lock().unwrap();
    if slot.is_none() {
        *slot = Some(side);
    }
}

fn hard_close(a: &TcpStream, b: &TcpStream) {
    let _ = a.shutdown(std::net::Shutdown::Both);
    let _ = b.shutdown(std::net::Shutdown::Both);
}

/// 带 SO_SNDTIMEO 的整行写入（§5.2：警告行/失败行 write 10s 超时）
fn write_all_via(stream: &TcpStream, line: &[u8]) -> io::Result<()> {
    let mut w = stream;
    w.write_all(line)
}

/// §1.2：上游连接。回环地址顺序尝试对侧回环（127.0.0.1 ↔ [::1]），每候选 5s 超时。
fn connect_upstream(addr: &SocketAddr) -> io::Result<TcpStream> {
    let mut last_err = None;
    for cand in upstream_candidates(addr) {
        match TcpStream::connect_timeout(&cand, CONNECT_TIMEOUT) {
            Ok(stream) => {
                if let Err(e) = sock::apply_upstream_policy(&stream) {
                    eprintln!("jbuu-doorkeeper: 上游套接字选项设置失败：{e}");
                }
                return Ok(stream);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(ErrorKind::InvalidInput, "无上游候选地址")))
}

fn upstream_candidates(addr: &SocketAddr) -> Vec<SocketAddr> {
    match addr.ip() {
        IpAddr::V4(v4) if v4.is_loopback() => vec![
            *addr,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port()),
        ],
        IpAddr::V6(v6) if v6.is_loopback() => vec![
            *addr,
            SocketAddr::new(
                IpAddr::V4(
                    v6.to_ipv4_mapped()
                        .map_or(std::net::Ipv4Addr::LOCALHOST, |v4| {
                            if v4.is_loopback() {
                                v4
                            } else {
                                std::net::Ipv4Addr::LOCALHOST
                            }
                        }),
                ),
                addr.port(),
            ),
        ],
        _ => vec![*addr],
    }
}

/// socket 选项策略（§5.2 D7 / §1.2 D10）：全部经 rustix 安全封装，无 unsafe。
pub mod sock {
    use std::net::TcpStream;

    use rustix::net::sockopt;

    use super::{KEEPALIVE_COUNT, KEEPALIVE_IDLE, KEEPALIVE_INTERVAL, WARN_WRITE_TIMEOUT};

    /// 客户端侧套接字（accept 后立即）：keepalive 三参 + 发送超时（警告行 write 阶段）
    pub fn apply_client_policy(stream: &TcpStream) -> std::io::Result<()> {
        apply_keepalive(stream)?;
        sockopt::set_socket_timeout(stream, sockopt::Timeout::Send, Some(WARN_WRITE_TIMEOUT))?;
        Ok(())
    }

    /// 上游侧套接字：keepalive 三参（无发送超时需求）
    pub fn apply_upstream_policy(stream: &TcpStream) -> std::io::Result<()> {
        apply_keepalive(stream)
    }

    /// §5.2 死端检测：SO_KEEPALIVE + TCP_KEEPIDLE=600s / TCP_KEEPINTVL=60s / TCP_KEEPCNT=5。
    /// 只杀真死对端（网卡消失/断电），对健康空闲会话透明。
    pub fn apply_keepalive(stream: &TcpStream) -> std::io::Result<()> {
        sockopt::set_socket_keepalive(stream, true)?;
        sockopt::set_tcp_keepidle(stream, KEEPALIVE_IDLE)?;
        sockopt::set_tcp_keepintvl(stream, KEEPALIVE_INTERVAL)?;
        sockopt::set_tcp_keepcnt(stream, KEEPALIVE_COUNT)?;
        Ok(())
    }

    /// §5.2（D7）：pipe 阶段显式无应用层超时——清除收/发超时
    pub fn clear_app_timeouts(stream: &TcpStream) {
        let _ = sockopt::set_socket_timeout(stream, sockopt::Timeout::Send, None);
        let _ = sockopt::set_socket_timeout(stream, sockopt::Timeout::Recv, None);
    }
}
