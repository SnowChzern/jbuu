//! 进程内回环传输（内存双端；M1 loopback 用，规划 §3 M1）。
//!
//! 语义与 TCP 适配对齐：每方向一个有界字节管道（容量 = 背压），写满阻塞
//! 直到读方腾挪或超时；读空阻塞直到写方推进、半关闭或超时；半关闭后
//! 读方排空缓冲即见 `ClosedByPeer`，写方向对端已 close 的管道写入得
//! `ClosedByPeer`（EPIPE 语义）。
//!
//! [`WireTap`] 为旁路审计钩（M1 验收"抓取 transport 字节流"）：只追加
//! 记录流经字节、不修改任何搬运内容；字节本身是 codec/session 的产物，
//! 传输层不解读。

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::TransportError;
use crate::frame::{self, ByteIo};

/// 默认每方向管道容量：恰容纳一个最大协议帧（65576B）——单帧往返永不
/// 阻塞，双帧排队即触发背压（与 ping-pong 会话驱动天然匹配）。
pub(crate) const DEFAULT_CAPACITY: usize = crate::MAX_WIRE_FRAME;

/// 进程内回环传输端点（与配对端点互通；不可 Clone——端点身份即连接身份）。
pub struct LoopbackTransport {
    shared: Arc<Shared>,
    /// 本端编号：A 的发送管道 = a2b、接收管道 = b2a；B 对称。
    side: Side,
    /// 收发超时（None = 无限期阻塞）。
    timeout: Option<Duration>,
    /// 本端已 close()。
    closed: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    A,
    B,
}

struct Shared {
    a2b: Pipe,
    b2a: Pipe,
}

struct Pipe {
    state: Mutex<PipeState>,
    readable: Condvar,
    writable: Condvar,
}

struct PipeState {
    buf: VecDeque<u8>,
    capacity: usize,
    /// 写方半关闭/关闭：读方排空后见 EOF。
    write_closed: bool,
    /// 读方已放弃（对端 close）：写方写入立即失败。
    reader_gone: bool,
    /// 旁路审计钩（两方向共享同一实例）。
    tap: Option<Arc<Mutex<Vec<u8>>>>,
}

impl Pipe {
    fn new(capacity: usize, tap: Option<Arc<Mutex<Vec<u8>>>>) -> Self {
        Self {
            state: Mutex::new(PipeState {
                buf: VecDeque::with_capacity(capacity.min(1 << 20)),
                capacity,
                write_closed: false,
                reader_gone: false,
                tap,
            }),
            readable: Condvar::new(),
            writable: Condvar::new(),
        }
    }
}

/// 旁路字节记录器：对两方向流经的全部字节做只增记录（审计/测试断言
/// "明文不出传输层"用）。非密钥材料，也不参与任何收发判定。
pub struct WireTap {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl WireTap {
    /// 当前已旁录字节的快照（拷贝）。
    #[must_use]
    pub fn snapshot(&self) -> Vec<u8> {
        match self.inner.lock() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// 已旁录字节数。
    #[must_use]
    pub fn len(&self) -> usize {
        match self.inner.lock() {
            Ok(g) => g.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// 是否尚无字节。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl core::fmt::Debug for WireTap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 审计安全：只报长度，不 dump 字节内容
        write!(f, "WireTap(len={})", self.len())
    }
}

impl LoopbackTransport {
    /// 创建一对互通的回环传输（client/server 两端；默认容量，见
    /// [`DEFAULT_CAPACITY`]）。
    #[must_use]
    pub fn new_pair() -> (Self, Self) {
        Self::new_pair_bounded(DEFAULT_CAPACITY)
    }

    /// 创建指定每方向容量的配对端点（容量即背压触发点；测试大帧分片/
    /// 短写/背压路径用）。`capacity` 必须非零。
    pub fn new_pair_bounded(capacity: usize) -> (Self, Self) {
        Self::build(capacity, None)
    }

    /// 创建默认容量配对端点 + 共享 [`WireTap`]（旁路记录两方向全部
    /// 流经字节；M1"抓取 transport 字节流"验收口径）。
    #[must_use]
    pub fn new_pair_tapped() -> ((Self, Self), WireTap) {
        let tap = Arc::new(Mutex::new(Vec::new()));
        let (a, b) = Self::build(DEFAULT_CAPACITY, Some(Arc::clone(&tap)));
        ((a, b), WireTap { inner: tap })
    }

    fn build(capacity: usize, tap: Option<Arc<Mutex<Vec<u8>>>>) -> (Self, Self) {
        assert!(capacity > 0, "loopback 管道容量必须非零");
        let shared = Arc::new(Shared {
            a2b: Pipe::new(capacity, tap.clone()),
            b2a: Pipe::new(capacity, tap),
        });
        (
            Self {
                shared: Arc::clone(&shared),
                side: Side::A,
                timeout: None,
                closed: false,
            },
            Self {
                shared,
                side: Side::B,
                timeout: None,
                closed: false,
            },
        )
    }

    /// 本端发送管道（流向对端）。
    fn outgoing(&self) -> &Pipe {
        match self.side {
            Side::A => &self.shared.a2b,
            Side::B => &self.shared.b2a,
        }
    }

    /// 本端接收管道（自对端流入）。
    fn incoming(&self) -> &Pipe {
        match self.side {
            Side::A => &self.shared.b2a,
            Side::B => &self.shared.a2b,
        }
    }

    /// 管道字节快照（cfg(test)：单元测试注入原始字节/检查管道状态用）。
    #[cfg(test)]
    fn incoming_bytes(&self) -> Vec<u8> {
        let guard = lock_or_io(self.incoming()).expect("test 内锁不毒化");
        guard.buf.iter().copied().collect()
    }

    /// 向对端方向注入原始字节，绕过帧校验（cfg(test)：模拟对端发出
    /// 畸形/截断原始流，驱动 FrameMalformed/FrameTooLarge 路径）。
    #[cfg(test)]
    fn inject_raw_outgoing(&self, bytes: &[u8]) {
        let mut guard = lock_or_io(self.outgoing()).expect("test 内锁不毒化");
        guard.buf.extend(bytes.iter().copied());
        self.outgoing().readable.notify_all();
    }
}

fn lock_or_io(pipe: &Pipe) -> Result<MutexGuard<'_, PipeState>, TransportError> {
    pipe.state.lock().map_err(|_| TransportError::Io)
}

/// loopback 端点的字节流视图（携带本端超时设置）。
struct PipeEnd<'a> {
    pipe: &'a Pipe,
    timeout: Option<Duration>,
}

impl ByteIo for PipeEnd<'_> {
    fn read_full(&mut self, buf: &mut [u8]) -> Result<bool, TransportError> {
        let deadline = self.deadline()?;
        let mut guard = lock_or_io(self.pipe)?;
        let mut off = 0;
        loop {
            let buffered = guard.buf.len();
            if buffered > 0 {
                let take = buffered.min(buf.len() - off);
                let drained: Vec<u8> = guard.buf.drain(..take).collect();
                buf[off..off + take].copy_from_slice(&drained);
                off += take;
                // 腾出了空间：唤醒阻塞的写方（背压解除点）
                self.pipe.writable.notify_all();
                if off == buf.len() {
                    return Ok(true);
                }
            }
            if guard.write_closed {
                // 排空后见对端半关闭/关闭：起始 = 干净 EOF，中途 = 0x0308
                return if off == 0 {
                    Ok(false)
                } else {
                    Err(TransportError::FrameMalformed)
                };
            }
            guard = self.wait_readable(guard, deadline)?;
        }
    }

    fn write_partial(&mut self, buf: &[u8]) -> Result<usize, TransportError> {
        let deadline = self.deadline()?;
        let mut guard = lock_or_io(self.pipe)?;
        loop {
            if guard.reader_gone {
                // 对端已整体关闭：EPIPE 语义
                return Err(TransportError::ClosedByPeer);
            }
            let space = guard.capacity - guard.buf.len();
            if space > 0 {
                let n = space.min(buf.len());
                guard.buf.extend(buf[..n].iter().copied());
                if let Some(tap) = &guard.tap {
                    let mut t = match tap.lock() {
                        Ok(t) => t,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    t.extend_from_slice(&buf[..n]);
                }
                self.pipe.readable.notify_all();
                return Ok(n); // 可能 < buf.len()：短写（分片/背压观察点）
            }
            // 管道满：阻塞等待读方腾挪（背压），或超时/对端放弃
            guard = self.wait_writable(guard, deadline)?;
        }
    }
}

impl PipeEnd<'_> {
    fn deadline(&self) -> Result<Option<Instant>, TransportError> {
        match self.timeout {
            None => Ok(None),
            Some(t) if t.is_zero() => Err(TransportError::Io), // 零时长非法（对齐 SO_RCVTIMEO）
            Some(t) => Ok(Instant::now().checked_add(t)),      // 溢出按无限期处理
        }
    }

    fn wait_readable<'a>(
        &self,
        guard: MutexGuard<'a, PipeState>,
        deadline: Option<Instant>,
    ) -> Result<MutexGuard<'a, PipeState>, TransportError> {
        self.wait(&self.pipe.readable, guard, deadline)
    }

    fn wait_writable<'a>(
        &self,
        guard: MutexGuard<'a, PipeState>,
        deadline: Option<Instant>,
    ) -> Result<MutexGuard<'a, PipeState>, TransportError> {
        self.wait(&self.pipe.writable, guard, deadline)
    }

    fn wait<'a>(
        &self,
        cv: &Condvar,
        guard: MutexGuard<'a, PipeState>,
        deadline: Option<Instant>,
    ) -> Result<MutexGuard<'a, PipeState>, TransportError> {
        let Some(deadline) = deadline else {
            return cv.wait(guard).map_err(|_| TransportError::Io);
        };
        let now = Instant::now();
        if now >= deadline {
            return Err(TransportError::Timeout);
        }
        let (guard, _) = cv
            .wait_timeout(guard, deadline - now)
            .map_err(|_| TransportError::Io)?;
        Ok(guard)
    }
}

impl crate::FramedStream for LoopbackTransport {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::ClosedByPeer);
        }
        let mut io = PipeEnd {
            pipe: self.outgoing(),
            timeout: self.timeout,
        };
        frame::send_frame(&mut io, frame)
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        if self.closed {
            return Err(TransportError::ClosedByPeer);
        }
        let mut io = PipeEnd {
            pipe: self.incoming(),
            timeout: self.timeout,
        };
        frame::recv_frame(&mut io)
    }

    fn set_deadline(&mut self, timeout: Duration) -> Result<(), TransportError> {
        if timeout.is_zero() {
            return Err(TransportError::Io);
        }
        self.timeout = Some(timeout);
        Ok(())
    }

    fn shutdown_write(&mut self) -> Result<(), TransportError> {
        let mut guard = lock_or_io(self.outgoing())?;
        guard.write_closed = true;
        drop(guard);
        self.outgoing().readable.notify_all(); // 唤醒排空后等待的读方
        Ok(())
    }

    fn close(&mut self) -> Result<(), TransportError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        // 停发： outgoing 标记写关闭
        {
            let mut guard = lock_or_io(self.outgoing())?;
            guard.write_closed = true;
        }
        self.outgoing().readable.notify_all();
        // 停收：incoming 标记读方放弃 → 对端后续写入得 ClosedByPeer
        {
            let mut guard = lock_or_io(self.incoming())?;
            guard.reader_gone = true;
        }
        self.incoming().writable.notify_all();
        Ok(())
    }
}

impl Drop for LoopbackTransport {
    fn drop(&mut self) {
        // 端点消亡视同 close：绝不留阻塞中的对端（唤醒并给出确定结局）
        let _ = crate::FramedStream::close(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FramedStream;
    use otp_codec::FRAME_HEADER_LEN;

    /// 构造带自洽长度前缀的测试帧（payload 按伪随机模式填充）。
    fn frame(len: usize) -> Vec<u8> {
        let mut f: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let payload = (len - FRAME_HEADER_LEN) as u32;
        f[4..8].copy_from_slice(&payload.to_be_bytes());
        f
    }

    #[test]
    fn small_frame_roundtrip_both_directions() {
        let (mut a, mut b) = LoopbackTransport::new_pair();
        let f = frame(52);
        a.send_frame(&f).unwrap();
        assert_eq!(b.recv_frame().unwrap(), f);
        b.send_frame(&f).unwrap();
        assert_eq!(a.recv_frame().unwrap(), f);
    }

    #[test]
    fn peer_close_unblocks_reader_with_closed_by_peer() {
        let (mut a, mut b) = LoopbackTransport::new_pair();
        a.set_deadline(Duration::from_secs(30)).unwrap();
        b.close().unwrap();
        assert_eq!(a.recv_frame(), Err(TransportError::ClosedByPeer));
        // 关闭后本端读写均失败
        assert_eq!(a.send_frame(&frame(52)), Err(TransportError::ClosedByPeer));
    }

    #[test]
    fn dropping_peer_closes_connection() {
        let (mut a, b) = LoopbackTransport::new_pair();
        drop(b);
        a.set_deadline(Duration::from_secs(30)).unwrap();
        assert_eq!(a.recv_frame(), Err(TransportError::ClosedByPeer));
    }

    #[test]
    fn recv_timeout_when_peer_silent() {
        let (mut a, _b) = LoopbackTransport::new_pair();
        a.set_deadline(Duration::from_millis(80)).unwrap();
        let t0 = Instant::now();
        assert_eq!(a.recv_frame(), Err(TransportError::Timeout));
        assert!(t0.elapsed() >= Duration::from_millis(75));
    }

    #[test]
    fn half_close_preserves_reverse_direction() {
        let (mut a, mut b) = LoopbackTransport::new_pair();
        let f = frame(40);
        a.send_frame(&f).unwrap();
        a.shutdown_write().unwrap();
        // B 排空缓冲后见干净关闭
        assert_eq!(b.recv_frame().unwrap(), f);
        b.set_deadline(Duration::from_secs(30)).unwrap();
        assert_eq!(b.recv_frame(), Err(TransportError::ClosedByPeer));
        // 反向仍通：B → A
        b.send_frame(&f).unwrap();
        a.set_deadline(Duration::from_secs(30)).unwrap();
        assert_eq!(a.recv_frame().unwrap(), f);
        // 双向都半关闭后，A 再收也是干净关闭
        b.shutdown_write().unwrap();
        assert_eq!(a.recv_frame(), Err(TransportError::ClosedByPeer));
    }

    #[test]
    fn write_after_peer_close_is_closed_by_peer() {
        let (mut a, mut b) = LoopbackTransport::new_pair();
        b.close().unwrap();
        a.set_deadline(Duration::from_secs(30)).unwrap();
        assert_eq!(a.send_frame(&frame(16)), Err(TransportError::ClosedByPeer));
    }

    #[test]
    fn raw_mid_frame_eof_maps_to_frame_malformed() {
        let (mut a, mut b) = LoopbackTransport::new_pair();
        // 注入 8B 头（声明 100B payload）+ 仅 30B 正文，随后对端半关闭
        let mut raw = vec![0u8; FRAME_HEADER_LEN];
        raw[4..8].copy_from_slice(&100u32.to_be_bytes());
        raw.extend_from_slice(&[7u8; 30]);
        a.inject_raw_outgoing(&raw);
        crate::FramedStream::shutdown_write(&mut a).unwrap();
        b.set_deadline(Duration::from_secs(30)).unwrap();
        assert_eq!(b.recv_frame(), Err(TransportError::FrameMalformed));
    }

    #[test]
    fn raw_overlong_declaration_maps_to_frame_too_large() {
        let (a, mut b) = LoopbackTransport::new_pair();
        let mut raw = vec![0u8; FRAME_HEADER_LEN];
        raw[4..8].copy_from_slice(&((otp_codec::MAX_FRAME_PAYLOAD + 1) as u32).to_be_bytes());
        a.inject_raw_outgoing(&raw);
        b.set_deadline(Duration::from_secs(30)).unwrap();
        assert_eq!(
            b.recv_frame(),
            Err(TransportError::FrameTooLarge {
                len: otp_codec::MAX_FRAME_PAYLOAD + 1
            })
        );
    }

    #[test]
    fn large_frame_fragmented_through_bounded_pipe() {
        // 容量 4096 ≪ 帧长 65576：必然分片 + 背压推进
        let (mut a, mut b) = LoopbackTransport::new_pair_bounded(4096);
        let sent = frame(crate::MAX_WIRE_FRAME);
        std::thread::scope(|s| {
            let writer = s.spawn(|| a.send_frame(&sent).unwrap());
            let got = b.recv_frame().unwrap();
            writer.join().unwrap();
            assert_eq!(got.len(), sent.len());
            assert_eq!(got, sent);
        });
        assert!(b.incoming_bytes().is_empty(), "帧收完后管道应排空");
    }

    #[test]
    fn backpressure_blocks_writer_until_reader_drains() {
        let (mut a, mut b) = LoopbackTransport::new_pair_bounded(4096);
        let sent = frame(crate::MAX_WIRE_FRAME);
        let done = Arc::new(Mutex::new(false));
        let flag = Arc::clone(&done);
        std::thread::scope(|s| {
            let writer = s.spawn(move || {
                a.set_deadline(Duration::from_secs(30)).unwrap();
                a.send_frame(&sent).unwrap();
                *flag.lock().unwrap() = true;
            });
            std::thread::sleep(Duration::from_millis(100));
            assert!(
                !*done.lock().unwrap(),
                "容量 4096 装不下 65576B 帧：写方必须被背压阻塞"
            );
            b.set_deadline(Duration::from_secs(30)).unwrap();
            let got = b.recv_frame().unwrap();
            writer.join().unwrap();
            assert_eq!(got.len(), crate::MAX_WIRE_FRAME);
        });
        assert!(*done.lock().unwrap());
    }

    #[test]
    fn write_timeout_under_backpressure_without_reader() {
        let (mut a, _b) = LoopbackTransport::new_pair_bounded(4096);
        a.set_deadline(Duration::from_millis(80)).unwrap();
        let f = frame(crate::MAX_WIRE_FRAME);
        let t0 = Instant::now();
        assert_eq!(a.send_frame(&f), Err(TransportError::Timeout));
        assert!(t0.elapsed() >= Duration::from_millis(75));
    }

    #[test]
    fn zero_deadline_is_rejected_like_so_timeout() {
        let (mut a, _b) = LoopbackTransport::new_pair();
        assert_eq!(a.set_deadline(Duration::ZERO), Err(TransportError::Io));
    }

    #[test]
    fn tap_records_both_directions_verbatim() {
        let ((mut a, mut b), tap) = LoopbackTransport::new_pair_tapped();
        let fa = frame(60);
        let fb = frame(120);
        a.send_frame(&fa).unwrap();
        b.send_frame(&fb).unwrap();
        assert_eq!(b.recv_frame().unwrap(), fa);
        assert_eq!(a.recv_frame().unwrap(), fb);
        let raw = tap.snapshot();
        assert_eq!(raw.len(), 180);
        assert!(raw.starts_with(&fa));
        assert!(raw.ends_with(&fb));
        assert_eq!(tap.len(), 180);
        assert!(!tap.is_empty());
        assert_eq!(format!("{tap:?}"), "WireTap(len=180)");
    }

    #[test]
    fn close_is_idempotent_and_shutdown_after_close_ok() {
        let (mut a, _b) = LoopbackTransport::new_pair();
        a.close().unwrap();
        a.close().unwrap();
        a.shutdown_write().unwrap();
    }

    #[test]
    fn default_capacity_holds_exactly_one_max_frame() {
        assert_eq!(DEFAULT_CAPACITY, crate::MAX_WIRE_FRAME);
    }
}
