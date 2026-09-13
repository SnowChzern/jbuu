//! §8 测试 4 + 13：透传字节精确性（性质测试）——随机负载双向过 echo 上游，
//! 入口/出口 hash 相等；含空、1B、>64 KiB、二进制垃圾、伪造 SSH- 诱饵行；
//! 随机分段切割（1B 粒度）同覆盖。
#![allow(dead_code)]
mod support;

use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

use proptest::prelude::*;
use sha2::{Digest, Sha256};
use support::{DkHandle, EchoUpstream, Rng, TempDir, dk_config};

fn sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 过门卫做一次 echo 事务：先消费警告行，再按分段发送 payload，收满回显，比对 sha256
fn echo_roundtrip(
    dk: &DkHandle,
    payload: &[u8],
    segments: &[usize],
    inter_segment_delay_us: u64,
) -> String {
    let payload_len = payload.len();
    let mut client = dk.connect();
    let mut warn = [0u8; 101];
    support::read_exact_into(&mut client, &mut warn); // 先消费警告行
    let mut writer = client.try_clone().unwrap();
    let reader = std::thread::spawn(move || {
        let mut c = client;
        support::read_exact_timeout(&mut c, payload_len, Duration::from_secs(30))
            .expect("echo 回读失败")
    });
    let mut pos = 0usize;
    let mut seg_iter = segments.iter().cycle().copied();
    while pos < payload.len() {
        let take = seg_iter.next().unwrap().min(payload.len() - pos).max(1);
        writer
            .write_all(&payload[pos..pos + take])
            .expect("分段写失败");
        pos += take;
        if inter_segment_delay_us > 0 {
            std::thread::sleep(Duration::from_micros(inter_segment_delay_us));
        }
    }
    let got = reader.join().expect("读线程 panic");
    sha256(&got)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// 性质：任意随机负载 + 随机分段 → 逐字节无损
    #[test]
    fn t04_proptest_passthrough_integrity(seed in any::<u64>(), size in 0usize..96 * 1024) {
        let dir = TempDir::new("t04p");
        let echo = EchoUpstream::spawn(true);
        let dk = DkHandle::start(dk_config("127.0.0.1:0".parse().unwrap(), echo.addr, dir.join("dk.log")));
        let mut rng = Rng::new(seed);
        let payload = rng.bytes(size);
        let segments: Vec<usize> = (0..8).map(|_| (rng.next_u64() % 4096 + 1) as usize).collect();
        let delay = if size < 8 * 1024 { rng.next_u64() % 300 } else { 0 };
        let got_hash = echo_roundtrip(&dk, &payload, &segments, delay);
        prop_assert_eq!(got_hash, sha256(&payload));
    }

    /// 性质（测试 13）：1B 粒度分段发送（警告行后的首 kex 包等效）→ 逐字节无损
    #[test]
    fn t13_proptest_one_byte_segmentation(seed in any::<u64>(), size in 1usize..6 * 1024) {
        let dir = TempDir::new("t13p");
        let echo = EchoUpstream::spawn(true);
        let dk = DkHandle::start(dk_config("127.0.0.1:0".parse().unwrap(), echo.addr, dir.join("dk.log")));
        let mut rng = Rng::new(seed);
        let payload = rng.bytes(size);
        let got_hash = echo_roundtrip(&dk, &payload, &[1], if rng.next_u64() % 2 == 0 { 50 } else { 0 });
        prop_assert_eq!(got_hash, sha256(&payload));
    }
}

/// 固定用例全家：空、1B、>64 KiB、全字节值二进制垃圾、SSH- 诱饵行
#[test]
fn t04_fixed_cases_byte_exactness() {
    let dir = TempDir::new("t04f");
    let echo = EchoUpstream::spawn(true);
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        echo.addr,
        dir.join("dk.log"),
    ));

    let mut allbytes = Vec::new();
    for b in 0u16..256 {
        allbytes.push(b as u8);
    }
    let allbytes = allbytes;

    let large: Vec<u8> = (0..150 * 1024u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("one-byte", vec![0x42]),
        ("all-byte-values", allbytes),
        ("binary-garbage-with-controls", {
            let mut v = vec![0u8; 4096];
            let mut rng = Rng::new(0xC0FFEE);
            for b in v.iter_mut() {
                *b = (rng.next_u64() >> 24) as u8;
            }
            v
        }),
        ("large-150KiB", large),
        (
            "ssh-decoy-lines",
            b"SSH-2.0-decoy-not-a-client\r\nrandom pre-line\r\nSSH-2.0-also-decoy\r\nreal payload follows: \x00\x01\x02\r\n".to_vec(),
        ),
    ];

    for (name, payload) in cases {
        let mut client = dk.connect();
        // 先消费警告行（除空用例外：payload 为空时也先读到警告行再 EOF）
        let mut warnbuf = [0u8; 101];
        support::read_exact_into(&mut client, &mut warnbuf);
        assert_eq!(
            &warnbuf[..],
            otp_doorkeeper::warn::default_warn_line(),
            "[{name}] 先收警告行"
        );
        if payload.is_empty() {
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let rest = support::read_to_end_timeout(&mut client, Duration::from_secs(5)).unwrap();
            assert!(rest.is_empty(), "[{name}] 空负载不应有多余字节");
            continue;
        }
        client.write_all(&payload).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let got = support::read_to_end_timeout(&mut client, Duration::from_secs(30)).unwrap();
        assert_eq!(
            sha256(&got),
            sha256(&payload),
            "[{name}] 入口/出口 hash 必须相等（got {}B want {}B）",
            got.len(),
            payload.len()
        );
    }

    // 诱饵行后仍出现真版本行时取首个 SSH- 行（§8 测试 4 点名）
    let ver = support::wait_for_event(&dk.log_path, "client_version", |v| {
        v["conn_id"].as_u64() == Some(6)
    });
    assert_eq!(ver["version"].as_str(), Some("SSH-2.0-decoy-not-a-client"));
}

/// 双向并发（全双工压形态）：两个方向同时灌随机负载
#[test]
fn t04_full_duplex_bidirectional() {
    let dir = TempDir::new("t04d");
    let echo = EchoUpstream::spawn(true);
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        echo.addr,
        dir.join("dk.log"),
    ));

    let n_rounds = 24;
    let mut rng = Rng::new(0xD00D);
    let mut handles = Vec::new();
    for _ in 0..n_rounds {
        let addr = dk.addr;
        let payload_len = 1024 * (rng.next_u64() % 64 + 1) as usize;
        let payload = rng.bytes(payload_len);
        handles.push(
            std::thread::Builder::new()
                .stack_size(128 * 1024)
                .spawn(move || {
                    let mut c = TcpStream::connect(addr).expect("连接失败");
                    let mut warn = [0u8; 101];
                    support::read_exact_into(&mut c, &mut warn);
                    c.write_all(&payload).unwrap();
                    let got =
                        support::read_exact_timeout(&mut c, payload.len(), Duration::from_secs(30))
                            .unwrap();
                    assert_eq!(sha256(&got), sha256(&payload));
                })
                .unwrap(),
        );
    }
    for h in handles {
        h.join().expect("并发线程 panic");
    }
}
