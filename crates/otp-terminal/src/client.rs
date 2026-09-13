//! 终端客户端驱动（WP-16）：附着（新终端/恢复句柄）+ 输入/窗口/心跳 +
//! 输出/退出码接收。`otp-term connect` 的交互式远程终端即由本模块
//! [`TerminalSession::run_interactive`] 落地。
//!
//! 恢复口径（wp02 §5.3）：恢复 = 调用方完成的**完整重新握手（新签发
//! 段）** + [`AttachMode::Recover`] 附着旧句柄——恢复 token 只是索引/
//! 句柄（[`TerminalHandle`]），与段材料零关联；旧段绝不重用。

use std::io::{Read, Write};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use otp_codec::{Message, Role, decode, encode};
use otp_session::{MessageType, Session};
use otp_transport::{FramedStream, TransportError};

use super::frame::{DATA_CHUNK_MAX, TerminalFrame, chunk_input};
use super::{ExitStatus, TerminalError, TerminalHandle, WindowSize};

/// 附着方式：新建终端 / 恢复既有终端（句柄 = 索引，非段材料）。
#[derive(Clone, Copy, Debug)]
pub enum AttachMode {
    /// 服务端 spawn 新 PTY。
    New {
        /// 初始窗口。
        window: WindowSize,
    },
    /// 恢复：附着到句柄对应的既有 PTY（**调用方已完成新握手新段**）。
    Recover {
        /// 恢复句柄（ Granted.handle 回传值）。
        handle: TerminalHandle,
        /// 附着时对齐的当前窗口。
        window: WindowSize,
    },
}

/// 客户端驱动参数。
#[derive(Clone, Copy, Debug)]
pub struct ClientOptions {
    /// 附着（Granted/Denied）等待期限。
    pub attach_timeout: Duration,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            attach_timeout: Duration::from_secs(30),
        }
    }
}

/// 客户端事件。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TerminalEvent {
    /// 终端输出（已解密）。
    Output(Vec<u8>),
    /// 子进程退出码。
    Exit(i32),
}

/// 已附着的终端会话（客户端侧）。
pub struct TerminalSession<T: FramedStream> {
    io: T,
    session: Session,
    handle: TerminalHandle,
    token: u64,
    exit: Option<i32>,
    closed: bool,
}

impl<T: FramedStream> TerminalSession<T> {
    /// 附着：发送 Open/Attach，等待 Granted/Denied。
    ///
    /// - `Denied{Busy}` → [`TerminalError::LeaseHeldByOther`]（单主拒绝）；
    /// - `Denied{Gone}` → [`TerminalError::TerminalGone`]；
    /// - `Denied{Fenced}` → [`TerminalError::StaleWriter`]。
    pub fn attach(
        mut io: T,
        mut session: Session,
        mode: AttachMode,
        opts: &ClientOptions,
    ) -> Result<Self, TerminalError> {
        io.set_deadline(Duration::from_millis(50))
            .map_err(TerminalError::Transport)?;
        let first = match mode {
            AttachMode::New { window } => TerminalFrame::Open {
                rows: window.rows,
                cols: window.cols,
            },
            AttachMode::Recover { handle, window } => TerminalFrame::Attach {
                handle: handle.0,
                rows: window.rows,
                cols: window.cols,
            },
        };
        Self::send(&mut io, &mut session, &first)?;
        let deadline = Instant::now() + opts.attach_timeout;
        loop {
            match Self::recv_raw(&mut io, &mut session)? {
                Some(frame) => match frame {
                    TerminalFrame::Granted { handle, token } => {
                        return Ok(Self {
                            io,
                            session,
                            handle: TerminalHandle(handle),
                            token,
                            exit: None,
                            closed: false,
                        });
                    }
                    TerminalFrame::Denied { reason } => {
                        session.close();
                        let _ = io.close();
                        return Err(match reason {
                            super::frame::DenyReason::Busy => {
                                TerminalError::LeaseHeldByOther { holder: 0 }
                            }
                            super::frame::DenyReason::Gone => TerminalError::TerminalGone,
                            super::frame::DenyReason::Fenced => TerminalError::StaleWriter,
                        });
                    }
                    _ => {
                        session.close();
                        let _ = io.close();
                        return Err(TerminalError::Protocol);
                    }
                },
                None => {
                    if Instant::now() >= deadline {
                        session.close();
                        let _ = io.close();
                        return Err(TerminalError::Timeout);
                    }
                }
            }
        }
    }

    /// 本终端恢复句柄（ Granted 回传；可持久化用于 Recover）。
    #[must_use]
    pub const fn handle(&self) -> TerminalHandle {
        self.handle
    }

    /// 服务端授予的 fencing token（观测元数据）。
    #[must_use]
    pub const fn token(&self) -> u64 {
        self.token
    }

    fn send(
        io: &mut dyn FramedStream,
        session: &mut Session,
        frame: &TerminalFrame,
    ) -> Result<(), TerminalError> {
        let record = session
            .seal(MessageType::Data, &frame.encode())
            .map_err(TerminalError::Session)?;
        let msg = Message::Data {
            epoch: otp_types::Epoch::new(0),
            seq: record.sequence,
            data: record.sealed().to_vec(),
        };
        let wire = encode(&msg).map_err(|_| TerminalError::Protocol)?;
        io.send_frame(&wire).map_err(TerminalError::Transport)
    }

    /// 无 deadline 语义的接收（deadline 由调用方预先设定）。
    fn recv_raw(
        io: &mut dyn FramedStream,
        session: &mut Session,
    ) -> Result<Option<TerminalFrame>, TerminalError> {
        let wire = match io.recv_frame() {
            Ok(w) => w,
            Err(TransportError::Timeout) => return Ok(None),
            Err(e) => return Err(TerminalError::Transport(e)),
        };
        let msg = decode(Role::Client, &wire).map_err(|_| TerminalError::Protocol)?;
        let Message::Data { seq, data, .. } = msg else {
            return Err(TerminalError::Protocol);
        };
        let plain = session
            .open(MessageType::Data, seq, &data)
            .map_err(TerminalError::Session)?;
        TerminalFrame::decode(plain.as_bytes()).map(Some)
    }

    fn ensure_open(&self) -> Result<(), TerminalError> {
        if self.closed || !self.session.is_active() {
            return Err(TerminalError::Closed);
        }
        Ok(())
    }

    /// 发送终端输入（自动按 [`DATA_CHUNK_MAX`] 分块）。
    pub fn send_input(&mut self, data: &[u8]) -> Result<(), TerminalError> {
        self.ensure_open()?;
        debug_assert!(data.len() <= DATA_CHUNK_MAX || chunk_input(data).len() > 1);
        for chunk in chunk_input(data) {
            Self::send(
                &mut self.io,
                &mut self.session,
                &TerminalFrame::Input {
                    data: chunk.to_vec(),
                },
            )?;
        }
        Ok(())
    }

    /// 窗口变更（SIGWINCH 语义）。
    pub fn resize(&mut self, window: WindowSize) -> Result<(), TerminalError> {
        self.ensure_open()?;
        Self::send(
            &mut self.io,
            &mut self.session,
            &TerminalFrame::Resize {
                rows: window.rows,
                cols: window.cols,
            },
        )
    }

    /// 主动关闭（会话密钥焚毁 + 传输优雅关闭；服务端据此观测断线）。
    pub fn close(&mut self) {
        self.session.close();
        let _ = self.io.close();
        self.closed = true;
    }

    /// 心跳（lease 续期）。
    pub fn ping(&mut self) -> Result<(), TerminalError> {
        self.ensure_open()?;
        Self::send(&mut self.io, &mut self.session, &TerminalFrame::Ping)
    }

    /// 轮询事件：`wait` 内无事件返回 None（调用方据此发心跳/查窗口）。
    /// 对端关闭且未见 Exit → [`TerminalError::Transport(ClosedByPeer)`]。
    pub fn poll_event(&mut self, wait: Duration) -> Result<Option<TerminalEvent>, TerminalError> {
        if let Some(code) = self.exit {
            return Ok(Some(TerminalEvent::Exit(code)));
        }
        self.io
            .set_deadline(wait)
            .map_err(TerminalError::Transport)?;
        match Self::recv_raw(&mut self.io, &mut self.session)? {
            Some(TerminalFrame::Output { data }) => Ok(Some(TerminalEvent::Output(data))),
            Some(TerminalFrame::Exit { code }) => {
                self.exit = Some(code);
                Ok(Some(TerminalEvent::Exit(code)))
            }
            Some(_) => Err(TerminalError::Protocol),
            None => Ok(None),
        }
    }

    /// 等待退出码（预算内循环 poll；期间的 Output 交付给 `on_output`）。
    pub fn wait_exit(
        &mut self,
        budget: Duration,
        mut on_output: impl FnMut(&[u8]),
    ) -> Result<ExitStatus, TerminalError> {
        if let Some(code) = self.exit {
            return Ok(ExitStatus { code });
        }
        let deadline = Instant::now() + budget;
        loop {
            let remain = deadline.saturating_duration_since(Instant::now());
            if remain.is_zero() {
                return Err(TerminalError::Timeout);
            }
            match self.poll_event(remain.min(Duration::from_millis(200)))? {
                Some(TerminalEvent::Exit(code)) => return Ok(ExitStatus { code }),
                Some(TerminalEvent::Output(data)) => on_output(&data),
                None => {}
            }
        }
    }

    /// 交互式泵（stdin → Input 帧；Output 帧 → stdout；空闲发 Ping）。
    ///
    /// 单主/活性语义：租约由服务端按心跳维护——空闲时按
    /// `ping_interval` 发 Ping；`window_probe` 每轮探测本地窗口变化
    /// （SIGWINCH 的轮询近似）。输入读取走 scoped thread（借用即可，
    /// 调用方无需 'static）。
    pub fn run_interactive(
        mut self,
        input: impl Read + Send + 'static,
        output: &mut dyn Write,
        ping_interval: Duration,
        mut window_probe: impl FnMut() -> Option<WindowSize>,
    ) -> Result<ExitStatus, TerminalError> {
        let (tx, rx) = mpsc::channel::<Option<Vec<u8>>>();
        // 输入读取线程（所有权移交）：远端退出后若 stdin 仍阻塞于 tty 读
        // （用户未按 Ctrl-D），线程被有意放弃、由进程退出收割——本方法
        // 绝不因 join 等待 stdin 而挂起。
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 8192];
            let mut input = input;
            loop {
                match input.read(&mut buf) {
                    Ok(0) | Err(_) => {
                        let _ = tx.send(None);
                        break;
                    }
                    Ok(n) => {
                        if tx.send(Some(buf[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        let mut last_ping = Instant::now();
        let mut last_window = window_probe();
        let result = self.pump(
            &rx,
            output,
            ping_interval,
            &mut window_probe,
            &mut last_ping,
            &mut last_window,
        );
        self.session.close();
        let _ = self.io.close();
        result
    }

    /// stdin EOF 后的收尾窗口：窗口内继续交付输出/等待 Exit；
    /// 超窗即**detach**（关闭连接、退出码 0——终端继续在服务端存活，
    /// 可经恢复句柄重新附着）。
    const DETACH_GRACE: Duration = Duration::from_millis(800);

    #[allow(clippy::too_many_arguments)]
    fn pump(
        &mut self,
        rx: &mpsc::Receiver<Option<Vec<u8>>>,
        output: &mut dyn Write,
        ping_interval: Duration,
        window_probe: &mut impl FnMut() -> Option<WindowSize>,
        last_ping: &mut Instant,
        last_window: &mut Option<WindowSize>,
    ) -> Result<ExitStatus, TerminalError> {
        let mut stdin_eof_at: Option<Instant> = None;
        loop {
            // detach 收尾：EOF 后的宽限窗耗尽即优雅离开。
            if let Some(at) = stdin_eof_at {
                if at.elapsed() >= Self::DETACH_GRACE {
                    break Ok(ExitStatus { code: 0 }); // detach（终端存活）
                }
            }
            // 输入侧：非阻塞取 stdin 块。
            match rx.try_recv() {
                Ok(Some(chunk)) => {
                    if let Err(e) = self.send_input(&chunk) {
                        break Err(e);
                    }
                    *last_ping = Instant::now();
                }
                Ok(None) => {
                    // stdin EOF：停止输入侧，进入 detach 收尾窗口。
                    if stdin_eof_at.is_none() {
                        stdin_eof_at = Some(Instant::now());
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => {}
                Err(mpsc::TryRecvError::Empty) => {}
            }
            // 窗口探测（tty 时）。
            let current = window_probe();
            if current != *last_window {
                if let Some(w) = current {
                    if let Err(e) = self.resize(w) {
                        break Err(e);
                    }
                }
                *last_window = current;
            }
            // 事件侧。
            match self.poll_event(Duration::from_millis(30)) {
                Ok(Some(TerminalEvent::Output(data))) => {
                    if output.write_all(&data).is_err() {
                        break Err(TerminalError::Io);
                    }
                    let _ = output.flush();
                    *last_ping = Instant::now();
                }
                Ok(Some(TerminalEvent::Exit(code))) => break Ok(ExitStatus { code }),
                Ok(None) => {
                    if last_ping.elapsed() >= ping_interval {
                        if let Err(e) = self.ping() {
                            break Err(e);
                        }
                        *last_ping = Instant::now();
                    }
                }
                Err(e) => break Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_modes_carry_handle_and_window() {
        let w = WindowSize { rows: 7, cols: 9 };
        assert!(matches!(
            AttachMode::New { window: w },
            AttachMode::New { window } if window == w
        ));
        assert!(matches!(
            AttachMode::Recover {
                handle: TerminalHandle(3),
                window: w
            },
            AttachMode::Recover { handle, .. } if handle == TerminalHandle(3)
        ));
    }
}
