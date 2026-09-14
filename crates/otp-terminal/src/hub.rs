//! PTY 终端枢纽（WP-16）：PTY 实例 + 单主写租约 + 恢复句柄注册表。
//!
//! 生命周期模型（wp02 §5.3"断线恢复终端上下文"）：
//! - **创建**：首个 `Open` 帧到达时 spawn shell 于新 PTY，登记句柄
//!   （`u64` 计数器——恢复 token 只能是索引/句柄，非段材料）；
//! - **持有**：每连接经 [`TerminalRegistry::acquire_for`] 取得写租约
//!   （单主 + fencing token，见 [`crate::lease`]）；
//! - **恢复**：断线后新连接 `Attach{handle}` → **完整重新握手 + 新签发
//!   段**（由调用方每连接驱动 WP-11 握手实现——恢复绝不重用旧段），
//!   随后重新仲裁租约（接管 token 递增）并附着到**同一 PTY**
//!   （shell 及其会话状态存活）；
//! - **退出**：shell 退出（退出码经 Exit 帧回传）后句柄作废，后续
//!   Attach 一律 `Gone`；hub 从注册表退役。
//!
//! 读写边界：一切写（Input/Resize）都经 fencing 写门（单主执行点）；
//! 读（drain output）无副作用，由当前 holder 连接线程独占执行，
//! 被接管后下一循环即被 token 检查逐出。
//!
//! ## 写入分片与回显排空（任务 #56 F2 返工）
//!
//! ECHO 开启时 master 写入的每个字节都被回显到 master 读队列，而读侧
//! 与写侧是**同一个连接线程**：单次大块写会塞满回显队列 → 写侧阻塞、
//! 读侧永远排不了空（互锁）。因此服务端泵按 [`PTY_WRITE_SLICE`] 分片
//! 写入，并在片间排空 master 输出（见 `server.rs`）；底层 master fd 恒
//! 非阻塞 + 写预算（见 `otp-platform::pty`）保证 fail closed。
//!
//! ## PTY 子进程的收割锚点（任务 #56 F4 返工）
//!
//! PTY 子进程在专用长寿命 spawn 线程上派生（`PR_SET_PDEATHSIG(SIGKILL)`
//! 的投递锚点 = 该线程）：连接线程退出（detach/断线）**不会**误杀
//! shell（恢复语义不变）；serve 进程死亡（含 SIGKILL 硬杀）时 spawn
//! 线程一并消亡，内核向全部 PTY 子进程投递 SIGKILL——不残留 pts
//! 孤儿（交互式 shell 忽略 SIGTERM，故用 SIGKILL；见 otp-platform
//! pty 模块文档）。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use otp_platform::pty::{PtyMaster, PtyRead, PtyWinsize};

use super::lease::{ConnId, FencingToken, LeaseDenied, LeaseGrant, LeaseManager};
use super::{ExitStatus, TerminalError, TerminalHandle, WindowSize};

/// master 写预算（fencing 写门内执行；超时即 fail closed 关闭该连接）。
/// master fd 恒非阻塞（otp-platform pty 阻塞纪律）：预算对每一次内核
/// 进入都生效——写路径**有界**，绝不无限阻塞（任务 #56 F2）。
const MASTER_WRITE_BUDGET: Duration = Duration::from_secs(5);

/// 单次写 master 的分片上限（字节）。ECHO 开启时分片的回显量远小于
/// master 读队列容量，服务端泵在片间排空回显——写读互锁从根上不发生
/// （任务 #56 F2：单线程泵的根治方案，配合 master fd 非阻塞）。
pub const PTY_WRITE_SLICE: usize = 2048;

struct PtySlot {
    master: PtyMaster,
    child: std::process::Child,
    /// 已观测到的子进程退出码（wait 之后填充）。
    exit: Option<i32>,
}

/// 单个 PTY 终端（shell 进程 + master fd + 单主租约）。
pub struct PtyHub {
    handle: TerminalHandle,
    shell: Vec<String>,
    lease: Arc<LeaseManager>,
    pty: Mutex<PtySlot>,
}

impl PtyHub {
    /// spawn shell 于新 PTY（在调用方线程上直接派生）。
    ///
    /// 生产路径应优先 [`TerminalRegistry::open`]（经专用 spawn 线程派生
    /// ——PDEATHSIG 锚点是长寿命线程，detach/断线不误杀 shell）；本构
    /// 造器供测试与无 registry 场景使用。
    pub fn spawn(
        handle: TerminalHandle,
        shell: Vec<String>,
        window: WindowSize,
        lease_timeout: Duration,
    ) -> Result<Self, TerminalError> {
        let (master, child) = spawn_pty_pair(&shell, window)?;
        Ok(Self::from_parts(
            handle,
            shell,
            master,
            child,
            lease_timeout,
        ))
    }

    /// 以既有 master/子进程构造（spawn 线程派生后的装配点）。
    fn from_parts(
        handle: TerminalHandle,
        shell: Vec<String>,
        master: PtyMaster,
        child: std::process::Child,
        lease_timeout: Duration,
    ) -> Self {
        Self {
            handle,
            shell,
            lease: Arc::new(LeaseManager::new(lease_timeout)),
            pty: Mutex::new(PtySlot {
                master,
                child,
                exit: None,
            }),
        }
    }

    /// 本终端恢复句柄（索引/句柄，非段材料）。
    #[must_use]
    pub const fn handle(&self) -> TerminalHandle {
        self.handle
    }

    /// 声明该终端的 shell 命令行（诊断/审计元数据）。
    #[must_use]
    pub fn shell(&self) -> &[String] {
        &self.shell
    }

    /// 申请写租约（单主；活跃 holder 在位即拒绝）。
    pub fn acquire(self: &Arc<Self>, conn: ConnId) -> Result<LeaseGrant, LeaseDenied> {
        self.lease.acquire(conn)
    }

    /// 心跳续期（token 必须当前）。
    pub fn heartbeat(&self, token: FencingToken) -> Result<(), TerminalError> {
        self.lease.heartbeat(token)
    }

    /// token 是否仍为活跃当前授予。
    #[must_use]
    pub fn lease_is_current(&self, token: FencingToken) -> bool {
        self.lease.is_current(token)
    }

    /// 租约快照（测试/审计观测）。
    #[must_use]
    pub fn lease_snapshot(&self) -> super::lease::LeaseSnapshot {
        self.lease.snapshot()
    }

    /// 终端输入：**fencing 写门内**写 master（单主执行点；陈旧 writer
    /// 一律拒绝，绝不与新 holder 的写交错）。写路径有界（master fd 非
    /// 阻塞 + 预算，任务 #56 F2）：持锁时间上限即预算。
    ///
    /// 调用方（服务端泵）应按 [`PTY_WRITE_SLICE`] 分片调用并在片间排空
    /// master 输出（ECHO 回显不能由本线程写完再读——见模块文档）。
    pub fn write_input(&self, token: FencingToken, data: &[u8]) -> Result<(), TerminalError> {
        self.lease.with_write_gate(token, || {
            let slot = self.pty.lock().unwrap_or_else(|p| p.into_inner());
            if slot.exit.is_some() {
                return Err(TerminalError::Closed);
            }
            slot.master
                .write_all_bounded(data, MASTER_WRITE_BUDGET)
                .map_err(|_| TerminalError::Io)
        })
    }

    /// 窗口协商（fencing 门内执行 TIOCSWINSZ）。
    pub fn resize(&self, token: FencingToken, window: WindowSize) -> Result<(), TerminalError> {
        self.lease.with_write_gate(token, || {
            let slot = self.pty.lock().unwrap_or_else(|p| p.into_inner());
            if slot.exit.is_some() {
                return Err(TerminalError::Closed);
            }
            slot.master
                .set_winsize(PtyWinsize {
                    rows: window.rows,
                    cols: window.cols,
                })
                .map_err(|_| TerminalError::Io)
        })
    }

    /// 非阻塞排空 master 输出（仅当前 holder 连接线程调用）。
    pub fn drain_output(&self, buf: &mut [u8]) -> Result<PtyRead, TerminalError> {
        let slot = self.pty.lock().unwrap_or_else(|p| p.into_inner());
        slot.master
            .read_timeout(buf, Duration::ZERO)
            .map_err(|_| TerminalError::Io)
    }

    /// 探测子进程退出（非阻塞 try_wait；观测到即缓存退出码）。
    pub fn poll_exit(&self) -> Option<ExitStatus> {
        let mut slot = self.pty.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(code) = slot.exit {
            return Some(ExitStatus { code });
        }
        match slot.child.try_wait() {
            Ok(Some(status)) => {
                let code = status.code().unwrap_or(128 + signal_of(&status));
                slot.exit = Some(code);
                Some(ExitStatus { code })
            }
            _ => None,
        }
    }

    /// 子进程是否已退出。
    #[must_use]
    pub fn has_exited(&self) -> bool {
        let slot = self.pty.lock().unwrap_or_else(|p| p.into_inner());
        slot.exit.is_some()
    }
}

impl Drop for PtyHub {
    fn drop(&mut self) {
        // 退役：确保 shell 不残留（kill + 收尸；已退出则仅 reap）。
        let mut slot = self.pty.lock().unwrap_or_else(|p| p.into_inner());
        let _ = slot.child.kill();
        let _ = slot.child.wait();
    }
}

fn signal_of(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt as _;
    status.signal().unwrap_or(0)
}

/// 终端注册表：句柄 → PTY 枢纽；新终端/恢复句柄的唯一事实源。
///
/// PTY 子进程经内部**专用长寿命 spawn 线程**派生（F4：PDEATHSIG 锚点
/// = spawn 线程——连接线程退出不误杀 shell，进程死亡则全部收割）。
pub struct TerminalRegistry {
    shell: Vec<String>,
    lease_timeout: Duration,
    conn_counter: AtomicU64,
    inner: Mutex<RegInner>,
}

struct RegInner {
    next_handle: u64,
    hubs: HashMap<u64, Arc<PtyHub>>,
    /// 专用 spawn 线程的投递端（懒创建；随 registry Drop 关闭 → 线程
    /// 退出 → PDEATHSIG 收割残余 shell）。None = 线程不可用（创建失败
    /// 或已死亡：open 时重试创建，仍失败则 fail closed）。
    spawner: Option<mpsc::Sender<SpawnJob>>,
}

/// spawn 线程作业：在该线程上完成 PTY 派生（PDEATHSIG 锚点）。
struct SpawnJob {
    shell: Vec<String>,
    ws: PtyWinsize,
    reply: mpsc::Sender<Result<(PtyMaster, std::process::Child), TerminalError>>,
}

fn spawn_pty_pair(
    shell: &[String],
    window: WindowSize,
) -> Result<(PtyMaster, std::process::Child), TerminalError> {
    let ws = PtyWinsize {
        rows: window.rows,
        cols: window.cols,
    };
    let master = PtyMaster::open(ws).map_err(|_| TerminalError::Io)?;
    let child =
        otp_platform::pty::spawn_on_pty(&master, shell, ws).map_err(|_| TerminalError::Io)?;
    Ok((master, child))
}

/// 起一个 PTY spawn 线程（返回投递端）。线程存活至投递端全部 Drop。
fn spawn_thread() -> Option<mpsc::Sender<SpawnJob>> {
    let (tx, rx) = mpsc::channel::<SpawnJob>();
    std::thread::Builder::new()
        .name("otp-term-pty-spawn".into())
        .spawn(move || {
            // 串行处理派生作业；无分配、无跨作业状态。
            for job in rx {
                let res = PtyMaster::open(job.ws)
                    .map_err(|_| TerminalError::Io)
                    .and_then(|m| {
                        otp_platform::pty::spawn_on_pty(&m, &job.shell, job.ws)
                            .map(|child| (m, child))
                            .map_err(|_| TerminalError::Io)
                    });
                // 回信端已放弃（registry 撤单）则丢弃结果：master Drop
                // 关闭 → 子进程收 SIGHUP/EIO 退出，不残留。
                let _ = job.reply.send(res);
            }
        })
        .ok()
        .map(|_| tx)
}

impl TerminalRegistry {
    /// 以默认 shell 命令行与 lease 超时构造（spawn 线程懒创建）。
    pub fn new(shell: Vec<String>, lease_timeout: Duration) -> Self {
        Self {
            shell,
            lease_timeout,
            conn_counter: AtomicU64::new(0),
            inner: Mutex::new(RegInner {
                next_handle: 1,
                hubs: HashMap::new(),
                spawner: None,
            }),
        }
    }

    /// 分配下一个连接标识（每连接唯一，供租约/审计观测）。
    pub fn next_conn(&self) -> ConnId {
        self.conn_counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// 经专用 spawn 线程派生 PTY（F4：PDEATHSIG 锚点 = 长寿命线程）。
    /// 线程不可用时重试创建一次，仍不可用则 fail closed（Io）。
    fn spawn_via_worker(
        &self,
        reg: &mut RegInner,
        window: WindowSize,
    ) -> Result<(PtyMaster, std::process::Child), TerminalError> {
        if reg.spawner.is_none() {
            reg.spawner = spawn_thread();
        }
        let Some(tx) = reg.spawner.clone() else {
            return Err(TerminalError::Io);
        };
        let (rtx, rrx) = mpsc::channel();
        if tx
            .send(SpawnJob {
                shell: self.shell.clone(),
                ws: PtyWinsize {
                    rows: window.rows,
                    cols: window.cols,
                },
                reply: rtx,
            })
            .is_err()
        {
            reg.spawner = None;
            return Err(TerminalError::Io);
        }
        match rrx.recv() {
            Ok(res) => res,
            Err(_) => {
                // spawn 线程已死（作业未交付）：标记失效，fail closed。
                reg.spawner = None;
                Err(TerminalError::Io)
            }
        }
    }

    /// 创建新终端（spawn PTY + 登记句柄；初始窗口在派生时点生效）。
    pub fn open(&self, window: WindowSize) -> Result<Arc<PtyHub>, TerminalError> {
        let mut reg = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let handle = reg.next_handle;
        reg.next_handle = reg
            .next_handle
            .checked_add(1)
            .expect("句柄计数器溢出（2^64 终端）");
        let (master, child) = self.spawn_via_worker(&mut reg, window)?;
        let hub = Arc::new(PtyHub::from_parts(
            TerminalHandle(handle),
            self.shell.clone(),
            master,
            child,
            self.lease_timeout,
        ));
        reg.hubs.insert(handle, Arc::clone(&hub));
        Ok(hub)
    }

    /// 按恢复句柄查找终端。
    #[must_use]
    pub fn find(&self, handle: TerminalHandle) -> Option<Arc<PtyHub>> {
        let reg = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        reg.hubs.get(&handle.0).cloned()
    }

    /// 退役已退出的终端（句柄此后 Attach 一律 Gone）。
    pub fn retire(&self, handle: TerminalHandle) {
        let mut reg = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        reg.hubs.remove(&handle.0);
    }

    /// 当前登记的终端句柄数（诊断）。
    #[must_use]
    pub fn live_handles(&self) -> usize {
        let reg = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        reg.hubs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh() -> Vec<String> {
        vec!["/bin/sh".into()]
    }

    #[test]
    fn registry_handles_are_sequential_indexes() {
        // 恢复 token = 索引计数器（1, 2, ...），与段号/段材料无任何路径关联。
        let reg = TerminalRegistry::new(sh(), Duration::from_secs(30));
        let h1 = reg.open(WindowSize { rows: 24, cols: 80 }).unwrap();
        let h2 = reg.open(WindowSize { rows: 24, cols: 80 }).unwrap();
        assert_eq!(h1.handle(), TerminalHandle(1));
        assert_eq!(h2.handle(), TerminalHandle(2));
        assert!(reg.find(TerminalHandle(1)).is_some());
        reg.retire(TerminalHandle(1));
        assert!(reg.find(TerminalHandle(1)).is_none());
        assert_eq!(reg.live_handles(), 1);
    }

    #[test]
    fn hub_exit_code_cached_and_drop_reaps() {
        let reg = TerminalRegistry::new(
            vec!["/bin/sh".into(), "-c".into(), "exit 9".into()],
            Duration::from_secs(30),
        );
        let hub = reg.open(WindowSize { rows: 24, cols: 80 }).unwrap();
        // 等待子进程退出被观测。
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let exit = loop {
            if let Some(e) = hub.poll_exit() {
                break e;
            }
            assert!(std::time::Instant::now() < deadline, "子进程应退出");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(exit, ExitStatus { code: 9 });
        assert!(hub.has_exited());
        drop(hub);
    }
}
