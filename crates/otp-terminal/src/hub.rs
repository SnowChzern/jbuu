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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use otp_platform::pty::{PtyMaster, PtyRead, PtyWinsize};

use super::lease::{ConnId, FencingToken, LeaseDenied, LeaseGrant, LeaseManager};
use super::{ExitStatus, TerminalError, TerminalHandle, WindowSize};

/// master 写预算（fencing 写门内执行；超时即 fail closed 关闭该连接）。
const MASTER_WRITE_BUDGET: Duration = Duration::from_secs(5);

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
    /// spawn shell 于新 PTY。
    pub fn spawn(
        handle: TerminalHandle,
        shell: Vec<String>,
        window: WindowSize,
        lease_timeout: Duration,
    ) -> Result<Self, TerminalError> {
        let ws = PtyWinsize {
            rows: window.rows,
            cols: window.cols,
        };
        let master = PtyMaster::open(ws).map_err(|_| TerminalError::Io)?;
        let child =
            otp_platform::pty::spawn_on_pty(&master, &shell, ws).map_err(|_| TerminalError::Io)?;
        Ok(Self {
            handle,
            shell,
            lease: Arc::new(LeaseManager::new(lease_timeout)),
            pty: Mutex::new(PtySlot {
                master,
                child,
                exit: None,
            }),
        })
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
    /// 一律拒绝，绝不与新 holder 的写交错）。
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
pub struct TerminalRegistry {
    shell: Vec<String>,
    lease_timeout: Duration,
    conn_counter: AtomicU64,
    inner: Mutex<RegInner>,
}

struct RegInner {
    next_handle: u64,
    hubs: HashMap<u64, Arc<PtyHub>>,
}

impl TerminalRegistry {
    /// 以默认 shell 命令行与 lease 超时构造。
    pub fn new(shell: Vec<String>, lease_timeout: Duration) -> Self {
        Self {
            shell,
            lease_timeout,
            conn_counter: AtomicU64::new(0),
            inner: Mutex::new(RegInner {
                next_handle: 1,
                hubs: HashMap::new(),
            }),
        }
    }

    /// 分配下一个连接标识（每连接唯一，供租约/审计观测）。
    pub fn next_conn(&self) -> ConnId {
        self.conn_counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// 创建新终端（spawn PTY + 登记句柄）。
    pub fn open(&self, window: WindowSize) -> Result<Arc<PtyHub>, TerminalError> {
        let mut reg = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let handle = reg.next_handle;
        reg.next_handle = reg
            .next_handle
            .checked_add(1)
            .expect("句柄计数器溢出（2^64 终端）");
        let hub = Arc::new(PtyHub::spawn(
            TerminalHandle(handle),
            self.shell.clone(),
            window,
            self.lease_timeout,
        )?);
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
