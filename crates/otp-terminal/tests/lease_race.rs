//! 恢复双主竞争夹具（规划 §5 测试 10 口径，lease 层）。
//!
//! 覆盖：
//! - **barrier 并发竞争**：N 线程同屏障放行后同时 acquire——恰一胜者，
//!   其余一律 `Busy`（绝不双主）；
//! - **holder kill**（连接关闭语义 = grant Drop）：立即可接管，token 递增，
//!   旧 token 一切写被 fence；
//! - **holder 超时**：不 Drop、仅停止心跳，lease 到期接管，token 递增，
//!   旧 token 心跳/写一律 `StaleWriter`；
//! - **接管后旧 grant Drop 不污染新租约**；
//! - **写互斥**：fencing 写门下旧/新 writer 字节永不交错（单主不变量）。

#![forbid(unsafe_code)]

use std::sync::{Arc, Barrier};
use std::time::Duration;

use otp_terminal::{FencingToken, LeaseDenied, LeaseManager, TerminalError, lease::LeaseSnapshot};

const RACE_THREADS: usize = 8;

#[test]
fn barrier_race_grants_exactly_one_writer() {
    let mgr = Arc::new(LeaseManager::new(Duration::from_secs(60)));
    let barrier = Arc::new(Barrier::new(RACE_THREADS));
    let mut handles = Vec::new();
    for conn in 1..=RACE_THREADS as u64 {
        let mgr = Arc::clone(&mgr);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            mgr.acquire(conn)
        }));
    }
    let mut winners = Vec::new();
    let mut busy = 0usize;
    for h in handles {
        match h.join().unwrap() {
            Ok(g) => winners.push(g), // 持有 grant（防 Drop 即放弃）
            Err(LeaseDenied::Busy { .. }) => busy += 1,
        }
    }
    assert_eq!(winners.len(), 1, "竞争 lease 后必须恰一个 writer");
    assert_eq!(busy, RACE_THREADS - 1, "其余全部单主拒绝");
    assert_eq!(winners[0].token(), FencingToken(1));
    let snap: LeaseSnapshot = mgr.snapshot();
    assert!(snap.holder.is_some());
    assert!(!snap.abandoned && !snap.expired);
}

#[test]
fn holder_kill_then_takeover_token_increments_and_stale_is_fenced() {
    let mgr = Arc::new(LeaseManager::new(Duration::from_secs(60)));
    let a = mgr.acquire(1).unwrap();
    let t1 = a.token();
    // holder kill：连接关闭语义（guard Drop）。
    drop(a);
    let b = mgr.acquire(2).unwrap();
    let t2 = b.token();
    assert!(t2 > t1, "接管必须使用递增 fencing token（{t1:?} → {t2:?}）");
    // 陈旧 writer：写门/心跳一律拒绝。
    assert_eq!(
        mgr.with_write_gate(t1, || Ok(())).unwrap_err(),
        TerminalError::StaleWriter
    );
    assert_eq!(mgr.heartbeat(t1).unwrap_err(), TerminalError::StaleWriter);
    assert!(!mgr.is_current(t1));
    // 新 holder 正常。
    assert!(mgr.is_current(t2));
    assert!(mgr.with_write_gate(t2, || Ok(())).is_ok());
}

#[test]
fn holder_timeout_takeover_without_drop() {
    let mgr = Arc::new(LeaseManager::new(Duration::from_millis(80)));
    let a = mgr.acquire(1).unwrap();
    let t1 = a.token();
    std::thread::sleep(Duration::from_millis(200)); // holder 卡死（无心跳）
    let b = mgr.acquire(2).unwrap();
    assert_eq!(b.token().0, t1.0 + 1);
    // 旧 holder 苏醒续期 → 已陈旧，被拒。
    assert_eq!(mgr.heartbeat(t1).unwrap_err(), TerminalError::StaleWriter);
    // 陈旧 grant 的 Drop 不得污染新租约（接管后 token 已更高）。
    drop(a);
    assert!(mgr.is_current(b.token()));
    assert!(matches!(
        mgr.acquire(3).err(),
        Some(LeaseDenied::Busy { .. })
    ));
}

#[test]
fn takeover_race_after_expiry_grants_exactly_one_with_single_increment() {
    let mgr = Arc::new(LeaseManager::new(Duration::from_millis(60)));
    let a = mgr.acquire(1).unwrap();
    let t1 = a.token();
    drop(a); // 放弃，立即可竞争
    let barrier = Arc::new(Barrier::new(RACE_THREADS));
    let mut handles = Vec::new();
    for conn in 10..10 + RACE_THREADS as u64 {
        let mgr = Arc::clone(&mgr);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            mgr.acquire(conn)
        }));
    }
    let mut tokens = Vec::new();
    let mut busy = 0usize;
    for h in handles {
        match h.join().unwrap() {
            Ok(g) => tokens.push(g.token()),
            Err(LeaseDenied::Busy { .. }) => busy += 1,
        }
    }
    assert_eq!(tokens.len(), 1);
    assert_eq!(busy, RACE_THREADS - 1);
    assert_eq!(tokens[0].0, t1.0 + 1, "竞争接管仍恰一次递增");
}

#[test]
fn gated_writes_of_old_and_new_holder_never_interleave() {
    // A 持租约连续经写门写 "AAAA" 块；B 在 A 超时后接管写 "BBBB" 块。
    // 写门持锁执行 ⇒ A 的每块在接管前完成；接管后 A 被 fence——流中
    // 不存在 A/B 交错的混合块。
    let mgr = Arc::new(LeaseManager::new(Duration::from_millis(150)));
    let a = mgr.acquire(1).unwrap();
    let t1 = a.token();
    let stream: Arc<std::sync::Mutex<Vec<u8>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer_a = {
        let mgr = Arc::clone(&mgr);
        let stream = Arc::clone(&stream);
        std::thread::spawn(move || {
            for _ in 0..40 {
                let block = b"AAAA".to_vec();
                let s = Arc::clone(&stream);
                match mgr.with_write_gate(t1, move || {
                    let mut g = s.lock().unwrap();
                    g.extend_from_slice(&block);
                    Ok::<(), TerminalError>(())
                }) {
                    Ok(()) => {}
                    Err(TerminalError::StaleWriter) => return, // 被接管：立即停止
                    Err(e) => panic!("写门意外错误：{e:?}"),
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })
    };
    // 保持 A 心跳一会，随后停止 → 超时。
    for _ in 0..5 {
        std::thread::sleep(Duration::from_millis(40));
        let _ = mgr.heartbeat(t1);
    }
    std::thread::sleep(Duration::from_millis(220)); // lease 过期
    let b = mgr.acquire(2).unwrap();
    for _ in 0..10 {
        let block = b"BBBB".to_vec();
        let s = Arc::clone(&stream);
        mgr.with_write_gate(b.token(), move || {
            s.lock().unwrap().extend_from_slice(&block);
            Ok::<(), TerminalError>(())
        })
        .expect("新 holder 写必须放行");
    }
    writer_a.join().unwrap();
    let data = stream.lock().unwrap().clone();
    // 不存在交错的混合块：任意 4 字节窗口要么全 A 要么全 B。
    for w in data.chunks_exact(4) {
        assert!(
            w == b"AAAA" || w == b"BBBB",
            "出现交错块 {w:?}（单主不变量被破坏）"
        );
    }
    assert!(data.windows(4).any(|w| w == b"BBBB"), "新 holder 应已写入");
    // 旧 token 最终必被 fence（接管后不再可能写）。
    assert!(!mgr.is_current(t1));
}
