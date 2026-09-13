//! PTY 单主写租约与 fencing token（WP-16；规划 §5 测试 10 口径）。
//!
//! 不变量（wp02 §5.3 + 规划 M4 验收）：
//! 1. **单主**：同一时刻至多一个活跃 writer；holder 活跃（未放弃且
//!    lease 未超时）时，一切后续 acquire 一律 [`LeaseDenied::Busy`]——
//!    绝无双主（单主不变量优先于任何性能/可用性优化）；
//! 2. **fencing token 单调**：每次授予/接管 token 恒 +1；陈旧 token
//!    （落后于当前值）的一切写/续期操作一律 [`TerminalError::StaleWriter`]
//!    拒绝（陈旧 writer 不得继续写）；
//! 3. **接管**：holder 放弃（连接关闭，guard Drop）或 lease 超时（无
//!    心跳续期）后，下一 acquire 以更高 token 接管；
//! 4. **写互斥**：[`LeaseManager::with_write_gate`] 在持锁状态下校验
//!    token 并执行 PTY 写——接管与写不可能交错，旧/新连接绝不
//!    同时写同一 PTY。
//!
//! 本模块纯逻辑（无 I/O、无时间注入器以外的依赖），规划 §5 测试 10 的
//! 夹具（barrier 并发竞争、holder kill/超时接管）直接落在
//! `tests/lease_race.rs`。

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use super::TerminalError;

/// 连接标识（服务端每连接分配；审计/测试观测用）。
pub type ConnId = u64;

/// fencing token：每次授予单调 +1（陈旧 token 即被 fence）。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FencingToken(pub u64);

impl FencingToken {
    /// 首个 token 之前的哨兵值（从未授予过）。
    pub const ZERO: Self = Self(0);
}

/// acquire 被拒的原因。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LeaseDenied {
    /// 单主拒绝：租约被活跃连接持有。
    Busy {
        /// 当前 holder 连接。
        holder: ConnId,
        /// 当前 fencing token（拒绝方据此知晓自身是否陈旧）。
        token: FencingToken,
    },
}

struct LeaseInner {
    token: u64,
    holder: Option<ConnId>,
    last_seen: Instant,
    /// holder 已放弃（guard Drop）：可立即接管。
    abandoned: bool,
}

/// 单 PTY 写租约管理器。
pub struct LeaseManager {
    inner: Mutex<LeaseInner>,
    timeout: Duration,
}

/// 租约守卫：持有期间本连接为唯一合法 writer；Drop = 放弃（立即可接管）。
pub struct LeaseGrant {
    mgr: Arc<LeaseManager>,
    token: u64,
}

impl LeaseGrant {
    /// 本次授予的 fencing token。
    #[must_use]
    pub const fn token(&self) -> FencingToken {
        FencingToken(self.token)
    }
}

impl Drop for LeaseGrant {
    fn drop(&mut self) {
        // 仅当自己仍是当前授予时标记放弃：陈旧 grant（已被接管）的
        // Drop 不得污染新 holder 的租约。
        let mut g = self.mgr.lock();
        if g.token == self.token && !g.abandoned {
            g.abandoned = true;
        }
    }
}

/// 租约可观测快照（审计/测试）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LeaseSnapshot {
    /// 当前 fencing token。
    pub token: FencingToken,
    /// 当前 holder（无则 None）。
    pub holder: Option<ConnId>,
    /// holder 是否已放弃。
    pub abandoned: bool,
    /// lease 是否已超时（无心跳）。
    pub expired: bool,
}

impl LeaseManager {
    /// 以给定 lease 超时构造（初始：token=0，无 holder）。
    ///
    /// # Panics
    /// timeout 为零（零超时使一切 holder 立刻可被接管，违反单主不变量）。
    pub fn new(timeout: Duration) -> Self {
        assert!(timeout > Duration::ZERO, "lease timeout 必须为正");
        Self {
            inner: Mutex::new(LeaseInner {
                token: 0,
                holder: None,
                last_seen: Instant::now(),
                abandoned: true,
            }),
            timeout,
        }
    }

    fn lock(&self) -> MutexGuard<'_, LeaseInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// 当前 lease 是否（对观察时刻而言）已超时。
    fn is_expired(inner: &LeaseInner, timeout: Duration) -> bool {
        inner.last_seen.elapsed() > timeout
    }

    /// 申请写租约。
    ///
    /// - 无 holder / holder 已放弃 / holder lease 超时 → **授予**（新
    ///   token = 旧 token + 1；接管语义）；
    /// - holder 活跃 → [`LeaseDenied::Busy`]（单主拒绝，不降级、不排队）。
    pub fn acquire(self: &Arc<Self>, conn: ConnId) -> Result<LeaseGrant, LeaseDenied> {
        let mut g = self.lock();
        if let Some(holder) = g.holder {
            let busy = !g.abandoned && !Self::is_expired(&g, self.timeout);
            if busy {
                return Err(LeaseDenied::Busy {
                    holder,
                    token: FencingToken(g.token),
                });
            }
        }
        g.token = g
            .token
            .checked_add(1)
            .expect("fencing token 溢出（2^64 授予）");
        g.holder = Some(conn);
        g.last_seen = Instant::now();
        g.abandoned = false;
        Ok(LeaseGrant {
            mgr: Arc::clone(self),
            token: g.token,
        })
    }

    /// 续期（心跳）：token 必须为当前授予；陈旧或已超时一律拒绝。
    pub fn heartbeat(&self, token: FencingToken) -> Result<(), TerminalError> {
        let mut g = self.lock();
        if g.token != token.0 || g.abandoned || Self::is_expired(&g, self.timeout) {
            return Err(TerminalError::StaleWriter);
        }
        g.last_seen = Instant::now();
        Ok(())
    }

    /// token 是否仍为活跃当前授予（未放弃、未超时）。
    pub fn is_current(&self, token: FencingToken) -> bool {
        let g = self.lock();
        g.token == token.0 && !g.abandoned && !Self::is_expired(&g, self.timeout)
    }

    /// **写门**：在持有 lease 锁的状态下校验 token 并执行写入动作。
    ///
    /// 这保证"检查 token ⇒ 写 PTY"相对"接管"原子：接管方必须等本写
    /// 完成才能获得新 token，而本 token 在写完成时仍为当前值——
    /// 旧/新 writer 的字节永不交错（单主不变量的执行点）。
    pub fn with_write_gate<T>(
        &self,
        token: FencingToken,
        action: impl FnOnce() -> Result<T, TerminalError>,
    ) -> Result<T, TerminalError> {
        let g = self.lock();
        if g.token != token.0 || g.abandoned || Self::is_expired(&g, self.timeout) {
            return Err(TerminalError::StaleWriter);
        }
        action()
    }

    /// 可观测快照。
    pub fn snapshot(&self) -> LeaseSnapshot {
        let g = self.lock();
        LeaseSnapshot {
            token: FencingToken(g.token),
            holder: g.holder,
            abandoned: g.abandoned,
            expired: Self::is_expired(&g, self.timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_grant_takes_token_one_and_second_is_busy() {
        let mgr = Arc::new(LeaseManager::new(Duration::from_secs(60)));
        let a = mgr.acquire(1).unwrap();
        assert_eq!(a.token(), FencingToken(1));
        assert_eq!(
            mgr.acquire(2).err(),
            Some(LeaseDenied::Busy {
                holder: 1,
                token: FencingToken(1)
            })
        );
    }

    #[test]
    fn drop_grant_allows_immediate_takeover_with_incremented_token() {
        let mgr = Arc::new(LeaseManager::new(Duration::from_secs(60)));
        let a = mgr.acquire(1).unwrap();
        assert_eq!(a.token(), FencingToken(1));
        drop(a); // holder 放弃（连接关闭语义）
        let b = mgr.acquire(2).unwrap();
        assert_eq!(b.token(), FencingToken(2), "接管必须递增 fencing token");
        assert!(matches!(
            mgr.acquire(3).err(),
            Some(LeaseDenied::Busy { .. })
        ));
    }

    #[test]
    fn timeout_allows_takeover_without_drop() {
        let mgr = Arc::new(LeaseManager::new(Duration::from_millis(40)));
        let a = mgr.acquire(1).unwrap();
        assert_eq!(a.token(), FencingToken(1));
        std::thread::sleep(Duration::from_millis(90));
        // 未 Drop（holder 卡死），但 lease 已超时 → 接管。
        let b = mgr.acquire(2).unwrap();
        assert_eq!(b.token(), FencingToken(2));
        // 旧 token 现在是陈旧 writer：一切操作被拒。
        assert_eq!(
            mgr.heartbeat(a.token()).unwrap_err(),
            TerminalError::StaleWriter
        );
        assert!(!mgr.is_current(a.token()));
        // 旧 grant 的 Drop 不得污染新租约。
        drop(a);
        assert!(mgr.is_current(b.token()));
        assert!(matches!(
            mgr.acquire(3).err(),
            Some(LeaseDenied::Busy { .. })
        ));
    }

    #[test]
    fn heartbeat_extends_lease_window() {
        let mgr = Arc::new(LeaseManager::new(Duration::from_millis(120)));
        let a = mgr.acquire(1).unwrap();
        for _ in 0..6 {
            std::thread::sleep(Duration::from_millis(60));
            mgr.heartbeat(a.token()).expect("心跳必须续期");
        }
        assert!(mgr.is_current(a.token()));
        assert!(matches!(
            mgr.acquire(2).err(),
            Some(LeaseDenied::Busy { .. })
        ));
    }

    #[test]
    fn write_gate_rejects_stale_and_runs_action_under_lock() {
        let mgr = Arc::new(LeaseManager::new(Duration::from_secs(60)));
        let a = mgr.acquire(1).unwrap();
        // 门内动作执行期间（同步闭包）snapshot 不可重入锁——这里用动作
        // 结果证明执行；并发不重入见 lease_race 集成测试。
        let n = mgr
            .with_write_gate(a.token(), || Ok(42usize))
            .expect("当前 token 应放行");
        assert_eq!(n, 42);
        // 陈旧 token（从未授予过的更高值）被拒。
        assert_eq!(
            mgr.with_write_gate(FencingToken(99), || Ok(0usize))
                .unwrap_err(),
            TerminalError::StaleWriter
        );
        drop(a);
        let b = mgr.acquire(2).unwrap();
        assert_eq!(b.token(), FencingToken(2));
        // 旧 token 在接管后必被 fence。
        assert_eq!(
            mgr.with_write_gate(FencingToken(1), || Ok(0usize))
                .unwrap_err(),
            TerminalError::StaleWriter
        );
    }
}
