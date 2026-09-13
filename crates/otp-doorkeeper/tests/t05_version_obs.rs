//! §8 测试 5：版本串观察——随机前置行 + SSH-2.0-x 精确提取；
//! >8 KiB 无换行 → 放弃（version: null）且吞吐不变。
#![allow(dead_code)]
mod support;

use std::io::Write;
use std::time::Duration;

use support::{DkHandle, EchoUpstream, TempDir, dk_config};

/// 随机前置行 + 真版本行（分段发送模拟真实包切分）→ 提取精确
#[test]
fn t05_version_extracted_after_random_pre_lines() {
    let dir = TempDir::new("t05a");
    let echo = EchoUpstream::spawn(true);
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        echo.addr,
        dir.join("dk.log"),
    ));

    let mut client = dk.connect();
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut client, &mut warn);

    let mut stream_bytes: Vec<u8> = Vec::new();
    stream_bytes.extend_from_slice(b"NOTICE: some random pre-line\r\n");
    stream_bytes.extend_from_slice(b"another line without terminator yet");
    stream_bytes.extend_from_slice(b" -- now terminated\r\n"); // 跨块拼接成行
    stream_bytes.extend_from_slice(b"SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u2\r\n");
    stream_bytes.extend_from_slice(b"post-version kex payload bytes");

    // 分 3 段发送，制造行跨块
    let third = stream_bytes.len() / 3 + 1;
    for chunk in stream_bytes.chunks(third) {
        client.write_all(chunk).unwrap();
    }
    let got = support::read_exact_timeout(&mut client, stream_bytes.len(), Duration::from_secs(10))
        .unwrap();
    assert_eq!(support::md5_hex(&got), support::md5_hex(&stream_bytes));
    drop(client); // client_version/conn_close 在 pipe 收尾时落盘（§5.5 事件序）

    let ver = support::wait_for_event(&dk.log_path, "client_version", |_| true);
    assert_eq!(
        ver["version"].as_str(),
        Some("SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u2"),
        "必须取首个 SSH- 开头完整行"
    );
    assert_eq!(ver["truncated"], serde_json::json!(false));
}

/// >8 KiB 无换行 → 放弃记 version: null，吞吐不变（负载完整送达）
#[test]
fn t05_gives_up_beyond_window_and_throughput_intact() {
    let dir = TempDir::new("t05b");
    let echo = EchoUpstream::spawn(true);
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        echo.addr,
        dir.join("dk.log"),
    ));

    let payload = support::Rng::new(0xABCD).bytes(64 * 1024); // 无任何换行的随机字节（概率上可能含 \n，用滤除保证无换行）
    let payload: Vec<u8> = payload.into_iter().filter(|&b| b != b'\n').collect();
    assert!(payload.len() > 8 * 1024 + 1024);

    let t0 = std::time::Instant::now();
    let mut client = dk.connect();
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut client, &mut warn);
    client.write_all(&payload).unwrap();
    let got =
        support::read_exact_timeout(&mut client, payload.len(), Duration::from_secs(30)).unwrap();
    let elapsed = t0.elapsed();
    assert_eq!(
        support::md5_hex(&got),
        support::md5_hex(&payload),
        "吞吐不受观察器影响"
    );
    // 64KiB 回环 echo 应在秒级完成（远小于超时），观察器放弃不拖慢转发
    assert!(elapsed < Duration::from_secs(20), "{elapsed:?}");
    drop(client);

    let ver = support::wait_for_event(&dk.log_path, "client_version", |_| true);
    assert_eq!(ver["version"], serde_json::json!(null), "超窗必须放弃");
}

/// 超长版本行（>128B）→ 截断 + truncated=true
#[test]
fn t05_long_version_truncated() {
    let dir = TempDir::new("t05c");
    let echo = EchoUpstream::spawn(true);
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        echo.addr,
        dir.join("dk.log"),
    ));
    let mut client = dk.connect();
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut client, &mut warn);
    let mut version_line = String::from("SSH-2.0-");
    for _ in 0..300 {
        version_line.push('q');
    }
    version_line.push_str("\r\n");
    client.write_all(version_line.as_bytes()).unwrap();
    client.write_all(b"tail").unwrap();
    let _ =
        support::read_exact_timeout(&mut client, version_line.len() + 4, Duration::from_secs(10))
            .unwrap();
    drop(client);

    let ver = support::wait_for_event(&dk.log_path, "client_version", |_| true);
    assert_eq!(ver["version"].as_str().map(str::len), Some(128));
    assert_eq!(ver["truncated"], serde_json::json!(true));
}

/// 观察器纯单元复核（同 src 单测口径，在集成层再钉一遍窗口边界）
#[test]
fn t05_observer_window_boundary() {
    use otp_doorkeeper::obs::VersionObserver;
    // SSH- 行恰好结束在窗口内（\n 在第 8191 字节）→ 应命中
    let mut obs = VersionObserver::new();
    // 前置行 8182B + \n（第 8183 字节），SSH- 行 8B，\n 恰在第 8191 字节（窗口内）
    let mut data = vec![b'x'; 8182];
    data.push(b'\n');
    data.extend_from_slice(b"SSH-2.0z\n");
    obs.observe(&data);
    let (v, _) = obs.take_result();
    assert_eq!(v.as_deref(), Some("SSH-2.0z"));
}
