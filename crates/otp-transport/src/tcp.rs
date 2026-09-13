//! TCP 适配（WP-12；M1"TCP 双进程加密回显"+ M3 扩展基座）。
//!
//! - 连接建立：[`TcpTransport::connect`] / [`TcpListener::bind`] + [`accept`]
//!   （多连接策略归 M3/WP-14，本层单连接语义）；
//! - 半关闭：[`shutdown_write`](crate::FramedStream::shutdown_write) =
//!   `shutdown(Write)`（本端停发、可继续收）；
//! - 优雅关闭：[`close`](crate::FramedStream::close) = `shutdown(Both)`；
//!   阻塞写已返回的数据留在 kernel 发送缓冲由 TCP 正常送达/重传，不
//!   RST、不 SO_LINGER 特例；
//! - 读写超时：`SO_RCVTIMEO`/`SO_SNDTIMEO`（per-syscall 语义，同一线程
//!   内一次 `recv_frame` 至多消耗帧头/消息体两个窗口）；
//! - 错误映射：`WouldBlock`/`TimedOut` → `Timeout`；`BrokenPipe`/
//!   `ConnectionReset`（写侧）→ `ClosedByPeer`；其余 → `Io`。

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

use crate::TransportError;
use crate::frame::{self, ByteIo};

/// TCP framed 传输（连接的一端）。
pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    /// 连接到 `addr`（`host:port`；解析失败/拒绝/超时均 → `Io`）。
    pub fn connect(addr: &str) -> Result<Self, TransportError> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<SocketAddr> = addr
            .to_socket_addrs()
            .map_err(|_| TransportError::Io)?
            .collect();
        let mut last = TransportError::Io;
        for a in addrs {
            match TcpStream::connect(a) {
                Ok(s) => return Ok(Self { stream: s }),
                Err(_) => last = TransportError::Io,
            }
        }
        Err(last)
    }

    /// 对端地址（`ip:port`；审计白名单字段）。
    pub fn peer_addr(&self) -> Result<String, TransportError> {
        self.stream
            .peer_addr()
            .map(|a| a.to_string())
            .map_err(|_| TransportError::Io)
    }

    /// 本端地址（`ip:port`）。
    pub fn local_addr(&self) -> Result<String, TransportError> {
        self.stream
            .local_addr()
            .map(|a| a.to_string())
            .map_err(|_| TransportError::Io)
    }

    fn shutdown(&self, how: Shutdown) -> Result<(), TransportError> {
        // ENOTCONN（对端已先关闭）视为已达目的：关闭幂等成功
        match self.stream.shutdown(how) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotConnected => Ok(()),
            Err(_) => Err(TransportError::Io),
        }
    }
}

impl ByteIo for TcpTransport {
    fn read_full(&mut self, buf: &mut [u8]) -> Result<bool, TransportError> {
        let mut off = 0;
        while off < buf.len() {
            match self.stream.read(&mut buf[off..]) {
                Ok(0) => {
                    // EOF：起始 = 帧边界干净关闭；中途 = 0x0308
                    return if off == 0 {
                        Ok(false)
                    } else {
                        Err(TransportError::FrameMalformed)
                    };
                }
                Ok(n) => off += n,
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return Err(TransportError::Timeout);
                }
                Err(_) => return Err(TransportError::Io),
            }
        }
        Ok(true)
    }

    fn write_partial(&mut self, buf: &[u8]) -> Result<usize, TransportError> {
        match self.stream.write(buf) {
            // 短写（kernel 缓冲满时部分受理）由 frame::send_frame 循环补齐
            Ok(n) => Ok(n),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                Err(TransportError::Timeout)
            }
            Err(e) if matches!(e.kind(), ErrorKind::BrokenPipe | ErrorKind::ConnectionReset) => {
                Err(TransportError::ClosedByPeer)
            }
            Err(_) => Err(TransportError::Io),
        }
    }
}

impl crate::FramedStream for TcpTransport {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        frame::send_frame(self, frame)
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        frame::recv_frame(self)
    }

    fn set_deadline(&mut self, timeout: Duration) -> Result<(), TransportError> {
        if timeout.is_zero() {
            return Err(TransportError::Io);
        }
        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(|_| TransportError::Io)?;
        self.stream
            .set_write_timeout(Some(timeout))
            .map_err(|_| TransportError::Io)?;
        Ok(())
    }

    fn shutdown_write(&mut self) -> Result<(), TransportError> {
        self.shutdown(Shutdown::Write)
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.shutdown(Shutdown::Both)
    }
}

/// TCP 监听器（`bind` + 循环 `accept`；多连接/并发策略归 WP-14/M3）。
pub struct TcpListener {
    inner: std::net::TcpListener,
}

impl TcpListener {
    /// 监听 `addr`（`host:port`；`127.0.0.1:0` 由内核分配端口，经
    /// [`local_addr`](Self::local_addr) 回读——测试/双进程回显口径）。
    pub fn bind(addr: &str) -> Result<Self, TransportError> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<SocketAddr> = addr
            .to_socket_addrs()
            .map_err(|_| TransportError::Io)?
            .collect();
        let mut last = TransportError::Io;
        for a in addrs {
            match std::net::TcpListener::bind(a) {
                Ok(l) => return Ok(Self { inner: l }),
                Err(_) => last = TransportError::Io,
            }
        }
        Err(last)
    }

    /// 实际监听地址（`ip:port`）。
    pub fn local_addr(&self) -> Result<String, TransportError> {
        self.inner
            .local_addr()
            .map(|a| a.to_string())
            .map_err(|_| TransportError::Io)
    }

    /// 阻塞等待并受理一个连接（无超时；调用方自行以线程/进程编排）。
    pub fn accept(&self) -> Result<TcpTransport, TransportError> {
        match self.inner.accept() {
            Ok((stream, _)) => Ok(TcpTransport { stream }),
            Err(_) => Err(TransportError::Io),
        }
    }

    /// 监听并受理首个连接（骨架 API 保留：单连接便捷路径；多连接策略见
    /// WP-14/M3）。
    pub fn bind_and_accept(addr: &str) -> Result<TcpTransport, TransportError> {
        Self::bind(addr)?.accept()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FramedStream;
    use otp_codec::FRAME_HEADER_LEN;

    /// 在回环口拉起一对已连接的 TcpTransport。
    fn connected_pair() -> (TcpTransport, TcpTransport) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpTransport::connect(&addr).unwrap();
        let server = listener.accept().unwrap();
        (client, server)
    }

    fn consistent_frame(len: usize) -> Vec<u8> {
        let mut f: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        f[4..8].copy_from_slice(&((len - FRAME_HEADER_LEN) as u32).to_be_bytes());
        f
    }

    #[test]
    fn small_frame_roundtrip_both_directions() {
        let (mut c, mut s) = connected_pair();
        let f = consistent_frame(52);
        c.send_frame(&f).unwrap();
        assert_eq!(s.recv_frame().unwrap(), f);
        s.send_frame(&f).unwrap();
        assert_eq!(c.recv_frame().unwrap(), f);
    }

    #[test]
    fn max_size_frame_roundtrip() {
        let (mut c, mut s) = connected_pair();
        let f = consistent_frame(crate::MAX_WIRE_FRAME);
        std::thread::scope(|sc| {
            let sender = sc.spawn(|| c.send_frame(&f).unwrap());
            let got = s.recv_frame().unwrap();
            sender.join().unwrap();
            assert_eq!(got, f);
        });
    }

    #[test]
    fn recv_timeout_when_peer_silent() {
        let (mut c, _s) = connected_pair();
        c.set_deadline(Duration::from_millis(150)).unwrap();
        assert_eq!(c.recv_frame(), Err(TransportError::Timeout));
    }

    #[test]
    fn peer_drop_yields_clean_close_at_boundary() {
        let (mut c, s) = connected_pair();
        drop(s);
        c.set_deadline(Duration::from_secs(30)).unwrap();
        assert_eq!(c.recv_frame(), Err(TransportError::ClosedByPeer));
    }

    #[test]
    fn half_close_preserves_reverse_direction() {
        let (mut c, mut s) = connected_pair();
        let f = consistent_frame(48);
        c.send_frame(&f).unwrap();
        c.shutdown_write().unwrap(); // FIN
        s.set_deadline(Duration::from_secs(30)).unwrap();
        assert_eq!(s.recv_frame().unwrap(), f);
        assert_eq!(s.recv_frame(), Err(TransportError::ClosedByPeer));
        // 反向仍通：S → C
        s.send_frame(&f).unwrap();
        c.set_deadline(Duration::from_secs(30)).unwrap();
        assert_eq!(c.recv_frame().unwrap(), f);
        s.shutdown_write().unwrap();
        assert_eq!(c.recv_frame(), Err(TransportError::ClosedByPeer));
    }

    #[test]
    fn mid_frame_truncation_from_raw_peer() {
        // 对端用裸 TcpStream 注入"声明 100B 只给 30B"后关闭
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let raw = std::thread::spawn(move || {
            let mut peer = TcpStream::connect(addr).unwrap();
            let mut bytes = vec![0u8; FRAME_HEADER_LEN];
            bytes[4..8].copy_from_slice(&100u32.to_be_bytes());
            bytes.extend_from_slice(&[9u8; 30]);
            use std::io::Write as _;
            peer.write_all(&bytes).unwrap();
            peer.shutdown(Shutdown::Both).unwrap();
        });
        let mut t = listener.accept().unwrap();
        t.set_deadline(Duration::from_secs(30)).unwrap();
        assert_eq!(t.recv_frame(), Err(TransportError::FrameMalformed));
        raw.join().unwrap();
    }

    #[test]
    fn overlong_declaration_from_raw_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let raw = std::thread::spawn(move || {
            let mut peer = TcpStream::connect(addr).unwrap();
            let mut bytes = vec![0u8; FRAME_HEADER_LEN];
            bytes[4..8].copy_from_slice(&((otp_codec::MAX_FRAME_PAYLOAD + 1) as u32).to_be_bytes());
            use std::io::Write as _;
            peer.write_all(&bytes).unwrap();
            std::thread::sleep(Duration::from_millis(200)); // 留窗口让读方判定
        });
        let mut t = listener.accept().unwrap();
        t.set_deadline(Duration::from_secs(30)).unwrap();
        assert_eq!(
            t.recv_frame(),
            Err(TransportError::FrameTooLarge {
                len: otp_codec::MAX_FRAME_PAYLOAD + 1
            })
        );
        raw.join().unwrap();
    }

    #[test]
    fn send_after_own_close_fails() {
        let (mut c, _s) = connected_pair();
        c.close().unwrap();
        let f = consistent_frame(52);
        let r = c.send_frame(&f);
        assert!(matches!(
            r,
            Err(TransportError::ClosedByPeer) | Err(TransportError::Io)
        ));
    }

    #[test]
    fn recv_after_own_close_is_closed_by_peer() {
        let (mut c, _s) = connected_pair();
        c.close().unwrap();
        c.set_deadline(Duration::from_secs(30)).unwrap();
        assert_eq!(c.recv_frame(), Err(TransportError::ClosedByPeer));
    }

    #[test]
    fn zero_deadline_rejected() {
        let (mut c, _s) = connected_pair();
        assert_eq!(c.set_deadline(Duration::ZERO), Err(TransportError::Io));
    }

    #[test]
    fn bind_and_accept_single_shot_path() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpTransport::connect(&addr).unwrap();
        drop(client);
        let mut server = listener.accept().unwrap();
        server.set_deadline(Duration::from_secs(30)).unwrap();
        assert_eq!(server.recv_frame(), Err(TransportError::ClosedByPeer));
    }

    #[test]
    fn addr_helpers_expose_public_metadata() {
        let (c, _s) = connected_pair();
        assert!(c.peer_addr().unwrap().starts_with("127.0.0.1:"));
        assert!(c.local_addr().unwrap().starts_with("127.0.0.1:"));
    }
}
