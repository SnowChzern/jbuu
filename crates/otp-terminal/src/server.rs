//! 终端服务端连接驱动（WP-16）：**单线程轮询循环**——每连接一个线程，
//! 网络收片与 PTY 排空交替推进，无跨线程共享 Session/io。
//!
//! 时序（在调用方已完成的 WP-11 握手——即"重新仲裁+签发新段"——之后）：
//!
//! ```text
//! 客户端                                    服务端（本模块）
//!   │ Open{rows,cols} / Attach{h,rows,cols}   │  首帧（期限内）
//!   │ ───────────────────────────────────────►│  Open→spawn PTY+登记句柄
//!   │                                          │  Attach→按句柄查找（无→Denied{Gone}）
//!   │                                          │  lease.acquire（单主；忙→Denied{Busy}）
//!   │ Granted{handle, token}                   │  ← fencing token
//!   │ ◄───────────────────────────────────────│
//!   │ Input/Resize/Ping ⇄ Output/Exit          │  数据面（全部 DATA record 加密）
//!   │ （lease 超时/被接管/对端关闭/shell 退出 ⇒ 终止；guard Drop = 放弃租约）
//! ```
//!
//! 单主执行点：一切 Input/Resize 经 [`PtyHub::write_input`/`resize`]
//! （fencing 写门）；每循环校验 token：被接管（token 落后）→ 立即逐出；
//! 客户端心跳停止 → lease 超时自逐出。
//!
//! fail closed：任何 codec/会话/协议/传输错误立即终止该连接（不重试、
//! 不降级）；租约守卫随连接线程 Drop 自动放弃（新连接可立即接管）。

use std::time::{Duration, Instant};

use otp_codec::{Message, Role, decode, encode};
use otp_session::{MessageType, Session};
use otp_transport::{FramedStream, TransportError};

use super::frame::{TerminalFrame, chunk_input};
use super::hub::{PTY_WRITE_SLICE, PtyHub, TerminalRegistry};
use super::lease::{ConnId, FencingToken, LeaseDenied};
use super::{ExitStatus, TerminalError, TerminalHandle, WindowSize};

/// 服务端连接驱动参数。
#[derive(Clone, Copy, Debug)]
pub struct ServeOptions {
    /// 首帧（Open/Attach）等待期限。
    pub first_frame_timeout: Duration,
    /// 网络收片（recv deadline；越小响应越快、唤醒越多）。
    pub poll_slice: Duration,
    /// Exit 帧发出后的收尾排空窗口。
    pub exit_grace: Duration,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            first_frame_timeout: Duration::from_secs(30),
            poll_slice: Duration::from_millis(25),
            exit_grace: Duration::from_millis(250),
        }
    }
}

/// 连接终止原因（审计/状态行观测）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ServeEnd {
    /// shell 退出（退出码已回传）。
    ShellExited { code: i32 },
    /// 对端关闭。
    PeerClosed,
    /// 被新连接接管（fencing token 落后，旧连接被 fence）。
    Fenced,
    /// 客户端停止心跳，lease 超时自逐出。
    LeaseExpired,
    /// 单主拒绝（另一活跃连接持有租约）。
    DeniedBusy,
    /// 恢复句柄不存在/终端已退出。
    DeniedGone,
    /// 应用帧/codec 违规。
    Protocol,
    /// 会话/传输/平台错误（fail closed）。
    Failed(TerminalError),
}

impl core::fmt::Display for ServeEnd {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 状态行/审计面：只输出类别与公开元数据（计数/退出码）。
        let s = match self {
            Self::ShellExited { code } => return write!(f, "shell-exited({code})"),
            Self::PeerClosed => "peer-closed",
            Self::Fenced => "fenced",
            Self::LeaseExpired => "lease-expired",
            Self::DeniedBusy => "denied-busy",
            Self::DeniedGone => "denied-gone",
            Self::Protocol => "protocol",
            Self::Failed(e) => return write!(f, "failed({e})"),
        };
        f.write_str(s)
    }
}

/// 一次连接服务的结果摘要（公开元数据：计数/句柄/token/结束原因）。
#[derive(Clone, Copy, Debug)]
pub struct ServeSummary {
    /// 附着的终端句柄（Denied 路径为请求句柄或 0）。
    pub handle: TerminalHandle,
    /// 授予的 fencing token（未授予为 0）。
    pub token: FencingToken,
    /// 累计输入字节数（fencing 门内已写 master）。
    pub input_bytes: u64,
    /// 累计输出字节数（已加密回传）。
    pub output_bytes: u64,
    /// 子进程退出码（观测到时）。
    pub exit: Option<ExitStatus>,
    /// 终止原因。
    pub end: ServeEnd,
}

/// 服务一条已建立握手（新签发段）的连接直至终止。
///
/// `io` 所有权移交本函数（终止时关闭）；`session` 为 WP-11 Established
/// 产物（恢复连接 = 调用方完成的**新握手新段**，本函数只做会话内附着）。
pub fn serve_connection<T: FramedStream>(
    registry: &TerminalRegistry,
    mut io: T,
    mut session: Session,
    conn: ConnId,
    opts: &ServeOptions,
) -> ServeSummary {
    let summary = match drive(registry, &mut io, &mut session, conn, opts) {
        Ok(s) => s,
        Err(e) => {
            session.close();
            ServeSummary {
                handle: TerminalHandle(0),
                token: FencingToken::ZERO,
                input_bytes: 0,
                output_bytes: 0,
                exit: None,
                end: ServeEnd::Failed(e),
            }
        }
    };
    // 统一优雅关闭：客户端确定性地观测到断线（对端关闭语义）。
    let _ = io.close();
    summary
}

enum RecvOutcome {
    Frame(TerminalFrame),
    Timeout,
    Closed(TerminalError),
}

fn recv_terminal_frame(io: &mut dyn FramedStream, session: &mut Session) -> RecvOutcome {
    let wire = match io.recv_frame() {
        Ok(w) => w,
        Err(TransportError::Timeout) => return RecvOutcome::Timeout,
        Err(e) => return RecvOutcome::Closed(TerminalError::Transport(e)),
    };
    let msg = match decode(Role::Server, &wire) {
        Ok(m) => m,
        Err(_) => return RecvOutcome::Closed(TerminalError::Protocol),
    };
    let Message::Data { seq, data, .. } = msg else {
        return RecvOutcome::Closed(TerminalError::Protocol);
    };
    let plain = match session.open(MessageType::Data, seq, &data) {
        Ok(p) => p,
        Err(e) => return RecvOutcome::Closed(TerminalError::Session(e)),
    };
    match TerminalFrame::decode(plain.as_bytes()) {
        Ok(f) => RecvOutcome::Frame(f),
        Err(_) => RecvOutcome::Closed(TerminalError::Protocol),
    }
}

fn send_terminal_frame(
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

/// 非阻塞排空 master 输出并转发（Output 帧分块）。
///
/// 写入分片之间也调用本函数（F2 返工）：ECHO 开启时 master 写入的
/// 字节被回显到 master 读队列，而读侧正是本连接线程——若不在片间
/// 排空，回显队列塞满后写侧只能在预算内等（旧实现则在阻塞 write
/// 中永久楔死）。每片 ≤ [`PTY_WRITE_SLICE`]，片间排空 → 写读互锁
/// 从根上不发生。
fn drain_pty<T: FramedStream>(
    hub: &PtyHub,
    io: &mut T,
    session: &mut Session,
    out_buf: &mut [u8],
    pending: &mut Vec<u8>,
    pty_eof: &mut bool,
    output_bytes: &mut u64,
) -> Result<(), TerminalError> {
    if *pty_eof {
        return Ok(());
    }
    loop {
        match hub.drain_output(out_buf) {
            Ok(otp_platform::pty::PtyRead::Data(n)) => {
                pending.extend_from_slice(&out_buf[..n]);
                if pending.len() >= super::frame::DATA_CHUNK_MAX {
                    break;
                }
            }
            Ok(otp_platform::pty::PtyRead::Eof) => {
                *pty_eof = true;
                break;
            }
            Ok(otp_platform::pty::PtyRead::Timeout) => break,
            Err(e) => return Err(e),
        }
    }
    if !pending.is_empty() {
        for chunk in chunk_input(pending) {
            send_terminal_frame(
                io,
                session,
                &TerminalFrame::Output {
                    data: chunk.to_vec(),
                },
            )?;
            *output_bytes = output_bytes.saturating_add(chunk.len() as u64);
        }
        pending.clear();
    }
    Ok(())
}

fn drive<T: FramedStream>(
    registry: &TerminalRegistry,
    io: &mut T,
    session: &mut Session,
    conn: ConnId,
    opts: &ServeOptions,
) -> Result<ServeSummary, TerminalError> {
    io.set_deadline(opts.poll_slice)
        .map_err(TerminalError::Transport)?;

    // ① 首帧：Open / Attach（期限内）。
    let (hub, window) = {
        let deadline = Instant::now() + opts.first_frame_timeout;
        loop {
            match recv_terminal_frame(io, session) {
                RecvOutcome::Frame(TerminalFrame::Open { rows, cols }) => {
                    let hub = registry.open(WindowSize { rows, cols })?;
                    break (hub, WindowSize { rows, cols });
                }
                RecvOutcome::Frame(TerminalFrame::Attach { handle, rows, cols }) => {
                    match registry.find(TerminalHandle(handle)) {
                        Some(hub) => break (hub, WindowSize { rows, cols }),
                        None => {
                            send_terminal_frame(
                                io,
                                session,
                                &TerminalFrame::Denied {
                                    reason: super::frame::DenyReason::Gone,
                                },
                            )?;
                            let _ = io.shutdown_write();
                            return Ok(ServeSummary {
                                handle: TerminalHandle(handle),
                                token: FencingToken::ZERO,
                                input_bytes: 0,
                                output_bytes: 0,
                                exit: None,
                                end: ServeEnd::DeniedGone,
                            });
                        }
                    }
                }
                RecvOutcome::Frame(_) => return Err(TerminalError::Protocol),
                RecvOutcome::Closed(e) => return Err(e),
                RecvOutcome::Timeout => {
                    if Instant::now() >= deadline {
                        return Err(TerminalError::Protocol);
                    }
                }
            }
        }
    };

    // ② 单主仲裁：忙 → Denied{Busy}（绝不双主）。
    let grant = match hub.acquire(conn) {
        Ok(g) => g,
        Err(LeaseDenied::Busy { .. }) => {
            send_terminal_frame(
                io,
                session,
                &TerminalFrame::Denied {
                    reason: super::frame::DenyReason::Busy,
                },
            )?;
            let _ = io.shutdown_write();
            return Ok(ServeSummary {
                handle: hub.handle(),
                token: FencingToken::ZERO,
                input_bytes: 0,
                output_bytes: 0,
                exit: None,
                end: ServeEnd::DeniedBusy,
            });
        }
    };
    let token = grant.token();
    send_terminal_frame(
        io,
        session,
        &TerminalFrame::Granted {
            handle: hub.handle().0,
            token: token.0,
        },
    )?;
    // 附着即对齐客户端当前窗口（幂等；SIGWINCH 语义）。
    let _ = hub.resize(token, window);

    // ③ 数据面：单线程轮询（网络收片 ⇄ PTY 排空 ⇄ 控制检查）。
    let mut input_bytes: u64 = 0;
    let mut output_bytes: u64 = 0;
    let mut exit: Option<ExitStatus> = None;
    let mut end: Option<ServeEnd> = None;
    let mut pty_eof = false;
    let mut exit_sent_at: Option<Instant> = None;
    let mut out_buf = vec![0u8; 16 * 1024];
    let mut pending = Vec::new();

    while end.is_none() {
        // 网络：一片。
        match recv_terminal_frame(io, session) {
            RecvOutcome::Frame(f) => {
                // 任何客户端帧都是活性证据：先续期（token 校验内建）。
                let fresh = hub.heartbeat(token).is_ok();
                match f {
                    TerminalFrame::Input { data } => {
                        if fresh {
                            // F2 返工：≤PTY_WRITE_SLICE 分片写 + 片间排空回显
                            //（单线程泵写读互锁的根治；底层写另有非阻塞+预算）。
                            'input: for chunk in chunk_input(&data) {
                                for slice in chunk.chunks(PTY_WRITE_SLICE) {
                                    match hub.write_input(token, slice) {
                                        Ok(()) => {
                                            input_bytes =
                                                input_bytes.saturating_add(slice.len() as u64);
                                        }
                                        Err(TerminalError::StaleWriter) => {
                                            end = Some(ServeEnd::Fenced);
                                            break 'input;
                                        }
                                        Err(e) => {
                                            end = Some(ServeEnd::Failed(e));
                                            break 'input;
                                        }
                                    }
                                    if let Err(e) = drain_pty(
                                        &hub,
                                        io,
                                        session,
                                        &mut out_buf,
                                        &mut pending,
                                        &mut pty_eof,
                                        &mut output_bytes,
                                    ) {
                                        end = Some(ServeEnd::Failed(e));
                                        break 'input;
                                    }
                                }
                            }
                        } else {
                            end = Some(ServeEnd::Fenced);
                            break;
                        }
                    }
                    TerminalFrame::Resize { rows, cols } => {
                        if fresh {
                            if let Err(TerminalError::StaleWriter) =
                                hub.resize(token, WindowSize { rows, cols })
                            {
                                end = Some(ServeEnd::Fenced);
                                break;
                            }
                        } else {
                            end = Some(ServeEnd::Fenced);
                            break;
                        }
                    }
                    TerminalFrame::Ping => {}
                    _ => {
                        end = Some(ServeEnd::Protocol);
                        break;
                    }
                }
            }
            RecvOutcome::Timeout => {}
            RecvOutcome::Closed(e) => {
                // Exit 已回传后的对端关闭是**预期收尾**：等满 grace 后以
                // ShellExited 终止（不误报 PeerClosed）。
                if exit_sent_at.is_some() {
                    // 直接进入收尾判定（下一轮 grace 检查终止）。
                } else {
                    end = Some(match e {
                        TerminalError::Transport(TransportError::ClosedByPeer) => {
                            ServeEnd::PeerClosed
                        }
                        other => ServeEnd::Failed(other),
                    });
                    break;
                }
            }
        }

        // PTY：非阻塞排空输出（输入分片间也调用，见 drain_pty）。
        if let Err(e) = drain_pty(
            &hub,
            io,
            session,
            &mut out_buf,
            &mut pending,
            &mut pty_eof,
            &mut output_bytes,
        ) {
            end = Some(ServeEnd::Failed(e));
            break;
        }

        // 退出路径：排空后回传退出码，短暂收尾即终止。
        if exit.is_none() && (pty_eof || hub.poll_exit().is_some()) {
            if let Some(status) = hub.poll_exit() {
                exit = Some(status);
                send_terminal_frame(io, session, &TerminalFrame::Exit { code: status.code })?;
                let _ = io.shutdown_write();
                exit_sent_at = Some(Instant::now());
            }
        }
        if let Some(at) = exit_sent_at {
            if Instant::now().duration_since(at) >= opts.exit_grace {
                end = Some(ServeEnd::ShellExited {
                    code: exit.map_or(0, |e| e.code),
                });
                break;
            }
        }

        // 控制检查：被接管 / lease 超时。
        if end.is_none() && exit_sent_at.is_none() && !hub.lease_is_current(token) {
            let snap = hub.lease_snapshot();
            end = Some(if snap.token > token {
                ServeEnd::Fenced
            } else {
                ServeEnd::LeaseExpired
            });
        }
    }

    let end = end.unwrap_or(ServeEnd::PeerClosed);
    let handle = hub.handle();
    drop(grant); // 显式放弃（连接终止）
    if hub.has_exited() {
        registry.retire(handle);
    }
    Ok(ServeSummary {
        handle,
        token,
        input_bytes,
        output_bytes,
        exit,
        end,
    })
}

#[cfg(test)]
mod tests {
    // 端到端（loopback + 直接构造的会话对）覆盖见 tests/serve_client.rs；
    // 本模块单测聚焦参数默认值形状。
    use super::*;

    #[test]
    fn default_options_are_sane() {
        let o = ServeOptions::default();
        assert!(o.poll_slice >= Duration::from_millis(5));
        assert!(o.poll_slice < Duration::from_secs(1));
        assert!(o.first_frame_timeout > Duration::ZERO);
        assert!(o.exit_grace > Duration::ZERO);
    }
}
