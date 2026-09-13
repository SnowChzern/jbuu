//! §8 测试 9：循环建立/销毁 10⁴ 连接——fd 数、线程数回到基线（无泄漏）。
//! 单独成测试二进制：/proc/self 计量不与其他测试混跑。
#![allow(dead_code)]
mod support;

use std::io::Write;
use std::time::Duration;

use support::{DkHandle, EchoUpstream, TempDir, dk_config, events};

fn proc_count(entry: &str) -> usize {
    std::fs::read_dir(format!("/proc/self/{entry}"))
        .map(|rd| rd.filter_map(|e| e.ok()).count())
        .unwrap_or(0)
}

#[test]
fn t09_ten_thousand_conns_no_leak() {
    let dir = TempDir::new("t09");
    let echo = EchoUpstream::spawn(true);
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        echo.addr,
        dir.join("dk.log"),
    ));

    // 基线（echo + dk 均已就绪后测量）
    let warmup_rounds = 50;
    for _ in 0..warmup_rounds {
        let mut c = dk.connect();
        let mut warn = [0u8; 101];
        support::read_exact_into(&mut c, &mut warn);
        c.write_all(b"w").unwrap();
        let _ = support::read_exact_timeout(&mut c, 1, Duration::from_secs(5)).unwrap();
    }
    assert!(support::wait_until(Duration::from_secs(10), || {
        events(&dk.log_path, "conn_close").len() >= warmup_rounds
    }));
    let fd_base = proc_count("fd");
    let task_base = proc_count("task");
    eprintln!("t09 基线：fd={fd_base} task={task_base}");

    // 10⁴ 建立销毁
    const N: usize = 10_000;
    let t0 = std::time::Instant::now();
    for i in 0..N {
        let mut c = dk.connect();
        let mut warn = [0u8; 101];
        support::read_exact_into(&mut c, &mut warn);
        c.write_all(b"x").unwrap();
        let _ = support::read_exact_timeout(&mut c, 1, Duration::from_secs(10)).unwrap();
        if i % 2000 == 0 {
            eprintln!("t09 进度 {i}/{N}");
        }
    }
    eprintln!("t09 完成 {N} 连接，耗时 {:?}", t0.elapsed());

    // 等全部收尾 + 资源归还
    assert!(
        support::wait_until(Duration::from_secs(30), || {
            events(&dk.log_path, "conn_close").len() >= warmup_rounds + N
        }),
        "全部连接应记 conn_close（当前 {}）",
        events(&dk.log_path, "conn_close").len()
    );
    let ok = support::wait_until(Duration::from_secs(30), || {
        proc_count("fd") <= fd_base + 4 && proc_count("task") <= task_base + 2
    });
    let fd_now = proc_count("fd");
    let task_now = proc_count("task");
    eprintln!("t09 终态：fd={fd_now}（基线 {fd_base}）task={task_now}（基线 {task_base}）");
    assert!(
        ok,
        "fd/线程未回到基线：fd {fd_base}->{fd_now}, task {task_base}->{task_now}"
    );

    // 门卫仍健康
    let mut c = dk.connect();
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut c, &mut warn);
    c.write_all(b"still-alive").unwrap();
    let got = support::read_exact_timeout(&mut c, 11, Duration::from_secs(5)).unwrap();
    assert_eq!(got, b"still-alive");
    drop(c); // 探针连接收尾后 conn_close 才落盘

    // 每条连接的事件数守恒：accept == close，且无 unknown reason 堆积
    assert!(support::wait_until(Duration::from_secs(10), || {
        events(&dk.log_path, "conn_close").len() > warmup_rounds + N
    }));
    let accepts = events(&dk.log_path, "conn_accept").len();
    let closes = events(&dk.log_path, "conn_close").len();
    assert_eq!(accepts, warmup_rounds + N + 1);
    assert_eq!(closes, warmup_rounds + N + 1);
    let over_limit = events(&dk.log_path, "conn_refused_over_limit").len();
    assert_eq!(over_limit, 0, "未达上限不应有拒连");
}
