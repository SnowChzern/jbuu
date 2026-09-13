//! # 端到端加密会话驱动（WP-15 ①）
//!
//! 在任意 [`FramedStream`]（loopback / TCP）上驱动 WP-11 握手状态机与
//! WP-10 会话层，段签发只经 [`SegmentIssuer`]（真实 CLI 路径传入
//! `Allocator`，完整 fail-to-waste 事务）。
//!
//! 数据面口径 = **WP-12 M1 回显口径**：服务端收一条 DATA 即解封、原文
//! 加密回显一条 DATA；客户端 ping-pong（发一块、收一块）。真实 PTY 终端
//! 归 WP-16（规划 §2 otp-terminal），本模块是其在 WP-15 范围内的加密
//! 通道落地。
//!
//! 错误模型：所有失败折叠为 [`SessionFailure`]（错误码 + 错误类别，均
//! 审计白名单可打印）；任何失败即关闭会话、不重试、不降级（fail closed）。

use std::time::Duration;

use otp_allocator::Allocator;
use otp_codec::{self, ArbitrateResult, ErrorCode, Message, ProtocolVersion, decode, encode};
use otp_handshake::{
    ClientConfig, ClientHandshake, HandshakeError, ServerConfig, ServerHandshake, Step,
};
use otp_session::{MessageType, Session, SessionError};
use otp_transport::{FramedStream, TransportError};
use otp_types::{BookId, Epoch, Role, SegmentIndex};

use otp_types::Generation;

/// 单条 DATA 应用明文上限（= codec [`otp_codec::MAX_APP_PLAINTEXT`]）。
pub const MAX_DATA_PLAINTEXT: usize = otp_codec::MAX_APP_PLAINTEXT;

/// 会话/握手失败（公开元数据：错误码 + 类别；无任何载荷内容）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SessionFailure {
    pub code: ErrorCode,
    pub category: otp_types::ErrorCategory,
}

impl SessionFailure {
    pub const fn new(code: ErrorCode, category: otp_types::ErrorCategory) -> Self {
        Self { code, category }
    }

    /// 白名单安全的一行描述（错误码名 + 类别名，无载荷）。
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "code={} category={}",
            self.code,
            audit_category_str(self.category)
        )
    }
}

fn audit_category_str(c: otp_types::ErrorCategory) -> &'static str {
    otp_platform::category_str(c)
}

impl From<HandshakeError> for SessionFailure {
    fn from(e: HandshakeError) -> Self {
        let category = match &e {
            HandshakeError::Issuer(_) => otp_types::ErrorCategory::Allocation,
            _ => otp_types::ErrorCategory::Handshake,
        };
        Self::new(e.code(), category)
    }
}

impl From<TransportError> for SessionFailure {
    fn from(e: TransportError) -> Self {
        Self::new(e.code(), e.category())
    }
}

impl From<SessionError> for SessionFailure {
    fn from(e: SessionError) -> Self {
        let code = e.wire_code().map_or(ErrorCode::INTERNAL, ErrorCode);
        Self::new(code, otp_types::ErrorCategory::Session)
    }
}

/// 会话建立结果（公开元数据）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SessionInfo {
    /// 本会话消耗的段号。
    pub segment: SegmentIndex,
    /// 签发后的锚 generation。
    pub generation: Generation,
}

/// 端点参数（book_id + 总段数，来自密码本头）。
#[derive(Clone, Copy, Debug)]
pub struct Endpoint {
    pub book_id: BookId,
    pub segment_count: u64,
}

// ───────────────────────── 帧收发助手 ─────────────────────────

fn send_msg(io: &mut dyn FramedStream, msg: &Message) -> Result<(), SessionFailure> {
    let wire = encode(msg).map_err(|c| SessionFailure::new(c, otp_types::ErrorCategory::Codec))?;
    io.send_frame(&wire)?;
    Ok(())
}

fn recv_msg(io: &mut dyn FramedStream, role: Role) -> Result<Message, SessionFailure> {
    let wire = io.recv_frame()?;
    decode(role, &wire).map_err(|c| SessionFailure::new(c, otp_types::ErrorCategory::Codec))
}

// ───────────────────────── 服务端 ─────────────────────────

/// 服务端：驱动握手至 Established（段签发经 `alloc` 完整事务）。
///
/// 成功返回会话与公开元数据；失败即 fail closed（调用方必须关闭连接，
/// 本函数已焚毁本地会话密钥——handshake 层 `Step::Failed` 路径保证）。
pub fn server_handshake(
    io: &mut dyn FramedStream,
    alloc: &mut Allocator,
    ep: Endpoint,
    deadline: Duration,
) -> Result<(Session, SessionInfo), SessionFailure> {
    io.set_deadline(deadline)?;
    let (next, _) = alloc.state();
    let mut server = ServerHandshake::new(ServerConfig {
        version: ProtocolVersion::V2,
        book_id: ep.book_id,
        local_pointer: next,
        segment_count: ep.segment_count,
    })
    .map_err(SessionFailure::from)?;

    // S1：HELLO → ARBITRATE。
    let hello = recv_msg(io, Role::Server)?;
    let arbitrate = server.on_hello(&hello).map_err(SessionFailure::from)?;
    send_msg(io, &arbitrate)?;
    // 仲裁即终态（错本/耗尽/CLIENT_AHEAD）时立刻失败，不等待后续消息
    // （wp02 S1′/S1″/S1‴：错误码取自 ARBITRATE 结果，语义与客户端一致）。
    if let Message::Arbitrate {
        server_pointer,
        result,
        ..
    } = &arbitrate
    {
        let terminal = match result {
            ArbitrateResult::BookMismatch => Some(HandshakeError::BookMismatch),
            ArbitrateResult::Exhausted => Some(HandshakeError::Exhausted {
                next: *server_pointer,
            }),
            ArbitrateResult::ClientAhead => {
                let client_pointer = match &hello {
                    Message::Hello { client_pointer, .. } => *client_pointer,
                    _ => *server_pointer,
                };
                Some(HandshakeError::ClientAhead {
                    client: client_pointer,
                    server: *server_pointer,
                })
            }
            ArbitrateResult::Ok | ArbitrateResult::ServerAhead => None,
        };
        if let Some(e) = terminal {
            return Err(e.into());
        }
    }

    // S2：ISSUE_REQUEST → 签发（真实分配器事务）。
    let issue_request = recv_msg(io, Role::Server)?;
    match server.on_issue_request(&issue_request, alloc) {
        Step::AwaitPeer => {}
        Step::Failed(e) => return Err(e.into()),
        _ => {
            return Err(SessionFailure::new(
                ErrorCode::BAD_ORDER,
                otp_types::ErrorCategory::Handshake,
            ));
        }
    }

    // S4：CONFIRM_C2S → CONFIRM_S2C + Established。
    let confirm_c2s = recv_msg(io, Role::Server)?;
    match server.on_confirm(&confirm_c2s) {
        Step::Established {
            outbox,
            session,
            segment,
        } => {
            for m in &outbox {
                send_msg(io, m)?;
            }
            let (_, generation) = alloc.state();
            Ok((
                session,
                SessionInfo {
                    segment,
                    generation,
                },
            ))
        }
        Step::Failed(e) => Err(e.into()),
        _ => Err(SessionFailure::new(
            ErrorCode::BAD_ORDER,
            otp_types::ErrorCategory::Handshake,
        )),
    }
}

/// 服务端回显循环（WP-12 M1 口径）：收一条 DATA → 解封 → 原文加密回显。
/// 对端干净关闭（帧边界 EOF）→ 正常返回累计字节数；任何认证/协议失败
/// → fail closed（关闭会话密钥并报错）。
pub fn server_echo_loop(
    io: &mut dyn FramedStream,
    session: &mut Session,
) -> Result<u64, SessionFailure> {
    let mut bytes: u64 = 0;
    loop {
        let wire = match io.recv_frame() {
            Ok(w) => w,
            Err(TransportError::ClosedByPeer) => return Ok(bytes),
            Err(e) => {
                session.close();
                return Err(e.into());
            }
        };
        let msg = decode(Role::Server, &wire)
            .map_err(|c| SessionFailure::new(c, otp_types::ErrorCategory::Codec))?;
        let Message::Data { seq, data, .. } = msg else {
            session.close();
            return Err(SessionFailure::new(
                ErrorCode::BAD_ORDER,
                otp_types::ErrorCategory::Codec,
            ));
        };
        let plain = session.open(MessageType::Data, seq, &data)?;
        bytes = bytes.saturating_add(plain.as_bytes().len() as u64);
        let record = session.seal(MessageType::Data, plain.as_bytes())?;
        let echo = Message::Data {
            epoch: Epoch::new(0),
            seq: record.sequence,
            data: record.sealed().to_vec(),
        };
        send_msg(io, &echo)?;
    }
}

// ───────────────────────── 客户端 ─────────────────────────

/// 客户端：驱动握手至 Established（本地签发同一约定段）。
pub fn client_handshake(
    io: &mut dyn FramedStream,
    alloc: &mut Allocator,
    ep: Endpoint,
    deadline: Duration,
) -> Result<(Session, SessionInfo), SessionFailure> {
    io.set_deadline(deadline)?;
    let (next, _) = alloc.state();
    let mut client = ClientHandshake::new(ClientConfig {
        version: ProtocolVersion::V2,
        book_id: ep.book_id,
        local_pointer: next,
        segment_count: ep.segment_count,
    })
    .map_err(SessionFailure::from)?;

    // H1：HELLO。
    let hello = client.start().map_err(SessionFailure::from)?;
    send_msg(io, &hello)?;

    // H2/H3+H6：ARBITRATE → 本地签发 + ISSUE_REQUEST + CONFIRM_C2S。
    let arbitrate = recv_msg(io, Role::Client)?;
    match client.handle(&arbitrate, alloc) {
        Step::Send(outbox) => {
            for m in &outbox {
                send_msg(io, m)?;
            }
        }
        Step::Failed(e) => return Err(e.into()),
        _ => {
            return Err(SessionFailure::new(
                ErrorCode::BAD_ORDER,
                otp_types::ErrorCategory::Handshake,
            ));
        }
    }

    // H8：CONFIRM_S2C → Established。
    let confirm_s2c = recv_msg(io, Role::Client)?;
    match client.handle(&confirm_s2c, alloc) {
        Step::Established {
            session, segment, ..
        } => {
            let (_, generation) = alloc.state();
            Ok((
                session,
                SessionInfo {
                    segment,
                    generation,
                },
            ))
        }
        Step::Failed(e) => Err(e.into()),
        _ => Err(SessionFailure::new(
            ErrorCode::BAD_ORDER,
            otp_types::ErrorCategory::Handshake,
        )),
    }
}

/// 客户端：发送一块明文并等待对应回显（ping-pong；回显口径）。
pub fn client_roundtrip(
    io: &mut dyn FramedStream,
    session: &mut Session,
    chunk: &[u8],
) -> Result<Vec<u8>, SessionFailure> {
    debug_assert!(chunk.len() <= MAX_DATA_PLAINTEXT);
    let record = session
        .seal(MessageType::Data, chunk)
        .map_err(SessionFailure::from)?;
    let msg = Message::Data {
        epoch: Epoch::new(0),
        seq: record.sequence,
        data: record.sealed().to_vec(),
    };
    send_msg(io, &msg)?;
    let echo = recv_msg(io, Role::Client)?;
    let Message::Data { seq, data, .. } = echo else {
        session.close();
        return Err(SessionFailure::new(
            ErrorCode::BAD_ORDER,
            otp_types::ErrorCategory::Codec,
        ));
    };
    let plain = session
        .open(MessageType::Data, seq, &data)
        .map_err(SessionFailure::from)?;
    Ok(plain.as_bytes().to_vec())
}

/// 客户端 stdio 泵：stdin → 加密发送 → 回显解密 → stdout。
///
/// 输入 EOF 后半关闭并等待对端收尾（对端回显循环见 EOF 即优雅退出）。
/// 返回传输的总明文字节数（公开元数据；明文本体只经过本进程内存与
/// stdout，不进任何日志）。
pub fn client_stdio_pump<R, W>(
    io: &mut dyn FramedStream,
    session: &mut Session,
    input: &mut R,
    output: &mut W,
) -> Result<u64, SessionFailure>
where
    R: std::io::Read,
    W: std::io::Write,
{
    let mut buf = vec![0u8; MAX_DATA_PLAINTEXT];
    let mut sent: u64 = 0;
    loop {
        let n = input.read(&mut buf).map_err(|_| {
            SessionFailure::new(ErrorCode::IO_ERROR, otp_types::ErrorCategory::Platform)
        })?;
        if n == 0 {
            break;
        }
        let echoed = client_roundtrip(io, session, &buf[..n])?;
        output.write_all(&echoed).map_err(|_| {
            SessionFailure::new(ErrorCode::IO_ERROR, otp_types::ErrorCategory::Platform)
        })?;
        output.flush().map_err(|_| {
            SessionFailure::new(ErrorCode::IO_ERROR, otp_types::ErrorCategory::Platform)
        })?;
        sent = sent.saturating_add(n as u64);
    }
    // 输入完毕：半关闭（服务端回显循环据此退出），等待对端关闭。
    io.shutdown_write()?;
    loop {
        match io.recv_frame() {
            Ok(_) => {} // 回显循环 ping-pong 下不应再有数据；防御性排空。
            Err(TransportError::ClosedByPeer) => return Ok(sent),
            Err(e) => return Err(e.into()),
        }
    }
}

// ───────────────────────── 说明 ─────────────────────────
// secret 扫描助手（明文不可见断言）在集成测试内各自实现（loopback_e2e /
// e2e_tcp），与 WP-12 回归口径一致；库层不携带仅测试用途的 API。
