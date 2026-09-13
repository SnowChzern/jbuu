//! 集成测试公共工装（§8 测试清单）
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use otp_doorkeeper::Config;
use otp_doorkeeper::log::JsonlLog;
use otp_doorkeeper::proxy;

// ---------- 临时目录 ----------

static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        let n = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("jbuu-dk-{}-{}-{}", tag, std::process::id(), n));
        std::fs::create_dir_all(&p).expect("创建临时目录失败");
        TempDir(p)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------- 端口与等待 ----------

/// 取一个空闲 TCP 端口（绑 :0 后立即释放；仅供测试，存在微小竞争窗口）
pub fn free_port(bind_v6: bool) -> u16 {
    if bind_v6 {
        let l = TcpListener::bind("[::1]:0").expect("绑定 ::1:0 失败");
        l.local_addr().unwrap().port()
    } else {
        let l = TcpListener::bind("127.0.0.1:0").expect("绑定 127.0.0.1:0 失败");
        l.local_addr().unwrap().port()
    }
}

/// 轮询等待条件成立（超时返回 false）
pub fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if pred() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    pred()
}

// ---------- echo 上游 ----------

/// 回声上游：读到什么原样写回；可选半关闭传播（读到 EOF → shutdown(Write)）
pub struct EchoUpstream {
    pub addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    pub conns_served: Arc<AtomicU64>,
}

impl EchoUpstream {
    pub fn spawn(propagate_halfclose: bool) -> EchoUpstream {
        let listener = TcpListener::bind("127.0.0.1:0").expect("echo 上游绑定失败");
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let conns_served = Arc::new(AtomicU64::new(0));
        let flag = shutdown.clone();
        let counter = conns_served.clone();
        thread::Builder::new()
            .name("echo-accept".to_string())
            .stack_size(128 * 1024)
            .spawn(move || {
                loop {
                    if flag.load(Ordering::Acquire) {
                        break;
                    }
                    match listener.accept() {
                        Ok((stream, _)) => {
                            counter.fetch_add(1, Ordering::Relaxed);
                            let flag = flag.clone();
                            let _ = thread::Builder::new()
                                .name("echo-conn".to_string())
                                .stack_size(64 * 1024)
                                .spawn(move || echo_conn(stream, propagate_halfclose, flag));
                        }
                        Err(_) => break,
                    }
                }
            })
            .expect("echo accept 线程失败");
        EchoUpstream {
            addr,
            shutdown,
            conns_served,
        }
    }

    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Release);
        // 唤醒 accept
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
    }
}

impl Drop for EchoUpstream {
    fn drop(&mut self) {
        self.stop();
    }
}

fn echo_conn(mut stream: TcpStream, propagate_halfclose: bool, _flag: Arc<AtomicBool>) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                if propagate_halfclose {
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                }
                return;
            }
            Ok(n) => {
                if stream.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

// ---------- 门卫进程内实例 ----------

/// 进程内门卫句柄：serve 在后台线程跑，stop() 唤醒并 join
pub struct DkHandle {
    pub addr: SocketAddr,
    pub log_path: PathBuf,
    stop: Arc<AtomicBool>,
    join: Mutex<Option<thread::JoinHandle<()>>>,
}

impl DkHandle {
    /// 起一个门卫实例（listen 端口为 0 时自动分配并回填）
    pub fn start(mut cfg: Config) -> DkHandle {
        let listener = proxy::bind_listener(cfg.listen).expect("门卫监听绑定失败");
        cfg.listen = listener.local_addr().expect("local_addr");
        let log = Arc::new(JsonlLog::open(&cfg.log_path, false).expect("打开日志失败"));
        let stop = Arc::new(AtomicBool::new(false));
        let join = thread::Builder::new()
            .name("dk-serve".to_string())
            .stack_size(256 * 1024)
            .spawn({
                let cfg = cfg.clone();
                let log = log.clone();
                let stop = stop.clone();
                move || {
                    if let Err(e) = proxy::serve(listener, cfg, log, stop) {
                        eprintln!("（测试）门卫 serve 退出：{e}");
                    }
                }
            })
            .expect("serve 线程失败");
        DkHandle {
            addr: cfg.listen,
            log_path: cfg.log_path.clone(),
            stop,
            join: Mutex::new(Some(join)),
        }
    }

    pub fn connect(&self) -> TcpStream {
        TcpStream::connect(self.addr).expect("连接门卫失败")
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(500));
        if let Some(handle) = self.join.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

impl Drop for DkHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 标准测试配置：临时日志 + 指定上游
pub fn dk_config(listen: SocketAddr, upstream: SocketAddr, log_path: PathBuf) -> Config {
    Config::new_for_test(listen, upstream, log_path)
}

// ---------- 读取工装 ----------

/// 带总时限的读取全部（至 EOF）
pub fn read_to_end_timeout(stream: &mut TcpStream, timeout: Duration) -> std::io::Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok();
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        if Instant::now() > deadline {
            return Err(std::io::Error::other("读取超时"));
        }
        match stream.read(&mut buf) {
            Ok(0) => return Ok(out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

/// 读满 n 字节（带总时限；不足即 Err）
pub fn read_exact_timeout(
    stream: &mut TcpStream,
    n: usize,
    timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok();
    let mut out = vec![0u8; n];
    let mut got = 0;
    while got < n {
        if Instant::now() > deadline {
            return Err(std::io::Error::other("读取超时"));
        }
        match stream.read(&mut out[got..]) {
            Ok(0) => return Err(std::io::Error::other("对端提前 EOF")),
            Ok(k) => got += k,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// 读满 buf.len() 字节到 buf（超时 panic）
pub fn read_exact_into(stream: &mut TcpStream, buf: &mut [u8]) {
    let got =
        read_exact_timeout(stream, buf.len(), Duration::from_secs(10)).expect("读满指定字节失败");
    buf.copy_from_slice(&got);
}

// ---------- 日志断言工装 ----------

pub fn parse_log(path: &Path) -> Vec<Value> {
    let text = std::fs::read_to_string(path).expect("读日志失败");
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("日志行必须是合法 JSON"))
        .collect()
}

/// 等待日志中出现指定事件（超时 panic，附提示）
pub fn wait_for_event(path: &Path, event: &str, pred: impl Fn(&Value) -> bool + Copy) -> Value {
    let ok = wait_until(Duration::from_secs(10), || {
        std::fs::read_to_string(path)
            .map(|t| {
                t.lines()
                    .filter(|l| !l.trim().is_empty())
                    .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                    .any(|v| v.get("event").and_then(Value::as_str) == Some(event) && pred(&v))
            })
            .unwrap_or(false)
    });
    assert!(ok, "等待日志事件 {event} 超时（log={}）", path.display());
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|v| v.get("event").and_then(Value::as_str) == Some(event) && pred(v))
        .unwrap()
}

pub fn events(path: &Path, event: &str) -> Vec<Value> {
    parse_log(path)
        .into_iter()
        .filter(|v| v.get("event").and_then(Value::as_str) == Some(event))
        .collect()
}

// ---------- md5（golden 独立复算）----------

pub fn md5_hex(data: &[u8]) -> String {
    let digest = md5(data);
    let mut s = String::with_capacity(32);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn md5(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;
    let mut msg = input.to_vec();
    let bitlen = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_le_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            let sum = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(S[i]));
            a = tmp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

// ---------- 伪随机 ----------

/// xorshift64*（测试负载生成）
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next_u64() >> 32) as u8).collect()
    }
}

// ---------- sshd 测试工装（T2 / §4.1 矩阵实测）----------

pub struct SshdRig {
    pub addr: SocketAddr,
    pub dir: PathBuf,
    pub user: String,
    pub identity: PathBuf,
    child_pid: u32,
}

impl SshdRig {
    /// 起一个测试 sshd：临时目录 + 测试密钥 + 回环高位端口（非 root 可用）。
    /// 二进制缺席时返回 Err（调用方 SKIP 并标注）。
    pub fn start() -> Result<SshdRig, String> {
        let sshd = "/usr/sbin/sshd";
        let keygen = "ssh-keygen";
        if !Path::new(sshd).exists() || which(keygen).is_none() {
            return Err(format!("sshd/keygen 缺席（{sshd}）"));
        }
        let dir = TempDir::new("sshd").leak();
        let hostkey = dir.join("hostkey");
        let userkey = dir.join("userkey");
        let run = |cmd: &mut std::process::Command| -> Result<String, String> {
            let out = cmd
                .output()
                .map_err(|e| format!("执行 {:?} 失败：{e}", cmd.get_program()))?;
            if !out.status.success() {
                return Err(format!(
                    "{:?} 失败：{}",
                    cmd.get_program(),
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        };
        run(std::process::Command::new(keygen)
            .args(["-t", "ed25519", "-f"])
            .arg(&hostkey)
            .args(["-N", "", "-q"]))
        .map_err(|e| format!("生成 hostkey 失败：{e}"))?;
        run(std::process::Command::new(keygen)
            .args(["-t", "ed25519", "-f"])
            .arg(&userkey)
            .args(["-N", "", "-q"]))
        .map_err(|e| format!("生成 userkey 失败：{e}"))?;
        let pubkey =
            std::fs::read_to_string(userkey.with_extension("pub")).map_err(|e| e.to_string())?;
        std::fs::write(dir.join("authorized_keys"), pubkey).map_err(|e| e.to_string())?;
        let port = free_port(false);
        let cfg = dir.join("sshd_config");
        std::fs::write(
            &cfg,
            format!(
                "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\n\
                 PermitRootLogin no\nPasswordAuthentication no\nPubkeyAuthentication yes\n\
                 StrictModes no\nUsePAM no\nLogLevel INFO\nSubsystem sftp internal-sftp\n\
                 PidFile {}\n",
                hostkey.display(),
                dir.join("authorized_keys").display(),
                dir.join("sshd.pid").display()
            ),
        )
        .map_err(|e| e.to_string())?;
        let cfg_test = std::process::Command::new(sshd)
            .arg("-t")
            .arg("-f")
            .arg(&cfg)
            .output()
            .map_err(|e| e.to_string())?;
        if !cfg_test.status.success() {
            return Err(format!(
                "sshd -t 失败：{}",
                String::from_utf8_lossy(&cfg_test.stderr)
            ));
        }
        let child = std::process::Command::new(sshd)
            .arg("-e")
            .arg("-f")
            .arg(&cfg)
            .spawn()
            .map_err(|e| e.to_string())?;
        let rig = SshdRig {
            addr: format!("127.0.0.1:{port}").parse().unwrap(),
            dir,
            user: whoami(),
            identity: userkey,
            child_pid: child.id(),
        };
        // 等 sshd 就绪
        if !wait_until(Duration::from_secs(5), || {
            TcpStream::connect_timeout(&rig.addr, Duration::from_millis(100)).is_ok()
                || std::net::TcpStream::connect(rig.addr).is_ok()
        }) {
            return Err("sshd 未在 5s 内就绪".to_string());
        }
        Ok(rig)
    }

    /// ssh 客户端公共参数（-F /dev/null 绕过宿主机坏权限系统配置）
    pub fn ssh_base_args(&self) -> Vec<String> {
        vec![
            "-F".to_string(),
            "/dev/null".to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=no".to_string(),
            "-o".to_string(),
            "UserKnownHostsFile=/dev/null".to_string(),
            "-o".to_string(),
            "IdentitiesOnly=yes".to_string(),
            "-i".to_string(),
            self.identity.display().to_string(),
        ]
    }
}

impl Drop for SshdRig {
    fn drop(&mut self) {
        let _ = std::process::Command::new("kill")
            .arg(self.child_pid.to_string())
            .output();
    }
}

impl TempDir {
    /// 交出路径并放弃自动清理（sshd 测试需要持久目录）
    pub fn leak(self) -> PathBuf {
        let p = self.0.clone();
        std::mem::forget(self);
        p
    }
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| {
            std::process::Command::new("id")
                .arg("-un")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .unwrap_or_else(|_| "nobody".to_string())
}

pub fn which(prog: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join(prog);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}
