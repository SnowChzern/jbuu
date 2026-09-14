//! # otp-handshake —— 客/服握手状态机（WP-11，任务 #47）
//!
//! 唯一规格依据（评审冻结）：
//! - `docs/specs/wp02-state-machines-anchors-recovery.md` §4（handshake 状态机、
//!   仲裁语义、CLIENT_AHEAD 人工恢复路径）；
//! - `docs/specs/wp01-wire-format-and-error-model.md` §4（各 [state] 约束）/
//!   §5.2（统一错误码注册表）/§5.3（线上只有 ARBITRATE.result 可见）；
//! - `docs/specs/wp03-nonce-aad-key-lifecycle.md` §4（CONFIRM 占 seq=0、
//!   DATA 自 1 起，归 otp-session 执行，本层不重复实现）。
//!
//! ## 完整消息序列（HELLO→ARBITRATE→ISSUE→双向 CONFIRM→DATA）
//!
//! ```text
//! 客户端                                       服务端
//!   │ HELLO(book_id, c_nonce, cp, features)        │ H1 / S-HELLO-CHK
//!   │ ────────────────────────────────────────────►│ book_id 不符 → BOOK_MISMATCH
//!   │                                              │ （先于仲裁与一切签发，0x0100）
//!   │           ARBITRATE(s_nonce, sp, result)      │ 仲裁（wp02 §4.3 表）：
//!   │ ◄────────────────────────────────────────────│ OK / SERVER_AHEAD / CLIENT_AHEAD
//!   │                                              │ / EXHAUSTED（next ≥ N）
//!   │ [SERVER_AHEAD(j>i)：废弃 [cp,j) 间隙，只前进] │
//!   │ ISSUE_REQUEST(i, c_nonce, s_nonce)            │ H2/H3+H6 / S-ALLOC：
//!   │ ────────────────────────────────────────────►│ i′==next + 双 nonce 回显校验
//!   │                                              │ → 本地 issue()（S 端同段）
//!   │ 本地 issue()（C 端，与服务端同段同内容）        │
//!   │ CONFIRM_C2S(i, ζ, epoch=0, seq=0, sealed)     │ H6 / S-CONFIRM-WAIT
//!   │ ────────────────────────────────────────────►│ tag + 内层副本全绑定校验
//!   │           CONFIRM_S2C(i, ζ, epoch=0, seq=0)   │
//!   │ ◄────────────────────────────────────────────│ → S-ESTABLISHED
//!   │ → C-ESTABLISHED（H8）                          │
//!   │ DATA(epoch=0, seq≥1) ⇄ DATA                   │ （otp-session，本层止于 Established）
//! ```
//!
//! 两端各持**同一密码本的副本与各自的双锚分配器**：段 `i` 由两端各自
//! `issue()`（同一 `book_id` ⇒ 同一段正文 ⇒ 同一双方向密钥），指针在
//! 仲裁约束下保持一致、只前进。
//!
//! ## 客户端转移表（wp02 §4.2 H1–H13 的实现投影）
//!
//! | # | 源状态（phase） | 事件 | 目标 |
//! |---|---|---|---|
//! | H1 | Idle | `start()`（CSPRNG 生成 c_nonce） | HelloSent |
//! | H2 | HelloSent | ARBITRATE OK（sp==cp，否则 0x0307） | ConfirmSent（内联 H6：issue + 发 ISSUE/CONFIRM_C2S） |
//! | H3 | HelloSent | ARBITRATE SERVER_AHEAD（sp>cp，否则 0x0307）：废弃 [cp,sp) 后同 H6 | ConfirmSent |
//! | H4 | HelloSent | ARBITRATE CLIENT_AHEAD（sp<cp） | AheadRecovery（冻结本地分配器） |
//! | H5 | HelloSent | BOOK_MISMATCH / EXHAUSTED（sp==N 否则 0x0307）/ 非法组合 | Failed |
//! | H7 | （H6 内联）本地 issue() 失败（EXHAUSTED/IO/持久化不确定） | Failed（未发任何消息，保守 fail-closed） |
//! | H8 | ConfirmSent | CONFIRM_S2C 外层字段 + tag + 内层副本全部通过 | Established |
//! | H9 | ConfirmSent | tag 失败 / 副本不符 / 时序错 | Failed（本段 SPENT，T6/T11） |
//! | H13 | 任一非终态 | `abort(reason)`（传输错误/对端关闭） | Failed |
//! | H10 | Established | （会话层事件，归 otp-session） | — |
//! | H11/H12 | AheadRecovery | （人工恢复结论，wp02 §4.4；运维执行 EV-OP-ADVANCE 后全新握手实例重连） | — |
//!
//! ## 服务端转移表（wp02 §4.3 的实现投影）
//!
//! | # | 源状态（phase） | 事件 | 目标 |
//! |---|---|---|---|
//! | S1 | Idle | `on_hello`：book_id 校验 → ARBITRATE(result) | IssueWait（OK/SERVER_AHEAD，指针不动） |
//! | S1′ | Idle | book_id 不符（先于仲裁） | Failed（ARBITRATE BOOK_MISMATCH，sp 恒 0） |
//! | S1″ | Idle | next ≥ N | Failed（ARBITRATE EXHAUSTED，sp=N） |
//! | S1‴ | Idle | cp > next | AheadPending（指针冻结，绝不回退） |
//! | S2 | IssueWait | `on_issue_request`：i′==仲裁约定 i + 双 nonce 回显 → issue() | ConfirmWait |
//! | S3 | IssueWait | i′ 不符（0x0307）/ nonce 回显不符（0x0203）/ issue() 失败 | Failed（预留前拒绝不耗段；签发后耗段不降级） |
//! | S4 | ConfirmWait | `on_confirm`：外层 + tag + 内层副本通过 → 发 CONFIRM_S2C | Established |
//! | S5 | ConfirmWait | tag/副本/时序失败 | Failed（本段 SPENT） |
//! | S13 | 任一非终态 | `abort(reason)` | Failed |
//!
//! 非法转移（错状态、错消息类型、终态复用）一律
//! [`ErrorCode::BAD_ORDER`]（0x0309）fail closed。
//!
//! ## 模块边界（规划 §2/§2.2，架构测试见 tests/architecture.rs）
//!
//! - 取段**只能**经 `SegmentIssuer::issue()`：本 crate 不依赖 otp-book /
//!   otp-anchor-spec，编译单元上不存在直读密码本段的路径；
//! - SERVER_AHEAD 的间隙废弃通过**逐段正常 issue() 后丢弃**实现（每次
//!   issue 都走完整双锚事务）：等价于 wp02 §1.3 T12 的"只前进、gap 全记
//!   浪费"，且不引入任何绕过分配器事务的捷径；
//! - CLIENT_AHEAD 无自动路径（wp02 §4.4 禁止清单）：服务端指针冻结于
//!   AheadPending，客户端进 AheadRecovery，人工恢复（EV-OP-ADVANCE）
//!   属运维域，之后以**全新握手实例**重连（本类型终态无出边）；
//! - 失败后不复用该段：任何 Failed 路径焚毁持有的会话密钥
//!   （`Session::close()` + Drop 清零），段的持久消耗由分配器事务保证。
//!
//! ## 已知集成债（另报，不擅改）
//!
//! `otp-allocator::CommittedSegment` 与 `otp-session::CommittedSegment` 是
//! 两个同名类型（wp03 §5.2 注：归并原计划在 WP-07/WP-11 集成时统一）。
//! 本任务卡硬边界禁止改动 otp-book/otp-session 生产语义，故以
//! [`bridge_segment`] 做**一次定长拷贝**的受控移交（源段立即 Drop 清零，
//! 两份副本生命周期均以 zeroize 收尾，无派生/无第三路径）。类型归并
//! 需 CODEOWNERS（栋梁+安全审计）另行裁决——见任务 #47 交付帖。
//!
//! 实现归属：榫卯 WP-11（任务 #47）。

#![forbid(unsafe_code)]

use otp_allocator::{IssueError, SegmentIssuer};
use otp_codec::{
    ArbitrateResult, ConfirmBody, ErrorCode, FeatureFlags, Message, MsgType, ProtocolVersion,
    SEALED_LEN, decode_confirm_body, encode_confirm_body,
};
use otp_session::{
    CommittedSegment as SessionSegment, MessageType, Session, SessionContext, SessionError,
};
use otp_types::{
    BookId, ClientNonce, Direction, Epoch, Role, SegmentIndex, Sequence, ServerNonce, SessionNonce,
};

#[cfg(test)]
use otp_types::SEGMENT_LEN;

/// CONFIRM 内层 label（WP-01 §4.4：C2S 恰 14B `"client-confirm"`）。
pub const CONFIRM_LABEL_C2S: &[u8; 14] = b"client-confirm";
/// CONFIRM 内层 label（S2C 恰 14B `"server-confirm"`）。
pub const CONFIRM_LABEL_S2C: &[u8; 14] = b"server-confirm";

/// 握手状态机一步的产物。
///
/// 一条入站消息的处理可能产出**多条**待发消息（ARBITRATE 处理内联本地
/// 签发：ISSUE_REQUEST 与 CONFIRM_C2S 之间无对端消息，wp02 H2/H3+H6），
/// `outbox` 按序交由 transport 发送。
pub enum Step {
    /// 待发消息（按序），本端继续等待对端。
    Send(Vec<Message>),
    /// 握手完成：附带收尾消息（服务端 CONFIRM_S2C；客户端为空）与已建立
    /// 会话；DATA 阶段归 [`Session`]（epoch=0，seq 自 1 起）。
    Established {
        /// 收尾待发消息（按序）。
        outbox: Vec<Message>,
        /// 已建立的加密会话（双方向密钥 + 双方向序号状态机）。
        session: Session,
        /// 本会话消耗的段号 i。
        segment: SegmentIndex,
    },
    /// 等待对端下一条消息（本地无需动作）。
    AwaitPeer,
    /// 失败：fail-closed 终态；已签发段按 T6/T11 计浪费，绝不重试同段、
    /// 绝不降级明文。错误码见 [`HandshakeError::code`]（审计白名单）。
    Failed(HandshakeError),
}

/// 客户端状态机的可观测阶段（wp02 §4.1 状态枚举的实现投影）。
///
/// 规格的 C-SYNC-JUMP/C-ISSUE-SENT 是 C-HELLO-SENT 处理 ARBITRATE 过程中
/// 的瞬时子阶段（本地签发内联在 [`ClientHandshake::handle`] 中一次完成），
/// 不作为独立可观测状态暴露；C-CLOSED 归会话层（握手层终态为
/// [`ClientPhase::Failed`] / [`ClientPhase::Established`]）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClientPhase {
    /// C-IDLE：未发起。
    Idle,
    /// C-HELLO-SENT：已发 HELLO，等 ARBITRATE。
    HelloSent,
    /// C-CONFIRM-SENT：已发 ISSUE_REQUEST + CONFIRM_C2S，等 CONFIRM_S2C。
    ConfirmSent,
    /// C-ESTABLISHED：双向确认通过，会话已移交调用方。
    Established,
    /// C-AHEAD-RECOVERY：CLIENT_AHEAD，本地分配器冻结，人工恢复（wp02 §4.4）。
    AheadRecovery,
    /// C-FAILED(sub)：失败终态，无出边。
    Failed,
}

/// 服务端状态机的可观测阶段（wp02 §4.3 状态枚举的实现投影）。
///
/// S-HELLO-CHK/S-ARB-SENT/S-ALLOC 是 `on_hello`/`on_issue_request` 调用内的
/// 瞬时子阶段；S-CLOSED 归会话层。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ServerPhase {
    /// S-IDLE：监听。
    Idle,
    /// S-ISSUE-WAIT：ARBITRATE(OK/SERVER_AHEAD) 已发，等 ISSUE_REQUEST。
    IssueWait,
    /// S-CONFIRM-WAIT：已签发段，等 CONFIRM_C2S 并验证 tag。
    ConfirmWait,
    /// S-ESTABLISHED：双向确认通过，会话已移交调用方。
    Established,
    /// S-AHEAD-PENDING：CLIENT_AHEAD，指针冻结不动（绝不回退），等人工。
    AheadPending,
    /// S-FAILED(sub)：失败终态，无出边。
    Failed,
}

/// 客户端握手配置。
pub struct ClientConfig {
    /// 协议版本（本实现只接受 0x0002）。
    pub version: ProtocolVersion,
    /// 期望 book_id（= 本端密码本 ID；错本由对端 BOOK_MISMATCH 揭示）。
    pub book_id: BookId,
    /// 本地指针（来自本地锚）。**契约**：必须等于传入
    /// [`ClientHandshake::handle`] 的 issuer 当前 next；失配最迟在
    /// CONFIRM tag 处 fail closed（密钥不一致 ⇒ 0x0201）。
    pub local_pointer: SegmentIndex,
    /// 本端密码本总段数 N（EXHAUSTED 一致性校验，WP-01 §4.2 [state]）。
    pub segment_count: u64,
}

/// 服务端握手配置。
pub struct ServerConfig {
    /// 协议版本（本实现只接受 0x0002）。
    pub version: ProtocolVersion,
    /// 本端 book_id（与 HELLO 逐字节比对；不符 → BOOK_MISMATCH，先于仲裁）。
    pub book_id: BookId,
    /// 本地指针（来自本地锚/分配器 state）。
    pub local_pointer: SegmentIndex,
    /// 本端密码本总段数 N（next ≥ N ⇒ EXHAUSTED）。
    pub segment_count: u64,
}

/// 握手错误。只携带指针/类别等公开元数据（WP-01 §5.3 审计白名单），
/// [`HandshakeError::code`] 给出统一错误码。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandshakeError {
    /// 0x0100：两端错本（HELLO.book_id ≠ 服务端配置）。
    BookMismatch,
    /// 0x0101：密码本耗尽。
    Exhausted {
        /// 耗尽时的指针。
        next: SegmentIndex,
    },
    /// 0x0102：CLIENT_AHEAD——客户端指针更高。服务端绝不回退；两端进入
    /// 人工恢复路径（wp02 §4.4：无自动路径，不允许凭网络声明前推）。
    ClientAhead {
        /// 客户端指针。
        client: SegmentIndex,
        /// 服务端指针。
        server: SegmentIndex,
    },
    /// 0x0201–0x0204：认证失败（tag/副本绑定/nonce 回显/序号重放）。
    /// 线上静默关闭，不区分子类（WP-01 §5.3）。
    Authentication(ErrorCode),
    /// 0x0301–0x030B：协议违规（时序 0x0309 / 指针组合 0x0307 / epoch
    /// 0x030A / 序号 0x030B / 内层解码 0x0302、0x0304 等）。
    Violation(ErrorCode),
    /// 段签发失败（分配器侧 EXHAUSTED/IO/持久化不确定等，映射 0x01xx/0x04xx）。
    Issuer(IssueError),
    /// 0x0403：OS CSPRNG 失败，握手立即终止（规划 §1.2）。
    Csprng,
}

impl HandshakeError {
    /// 对应 WP-01 §5.2 统一错误码（审计白名单"错误类别"字段）。
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::BookMismatch => ErrorCode::BOOK_MISMATCH,
            Self::Exhausted { .. } => ErrorCode::EXHAUSTED,
            Self::ClientAhead { .. } => ErrorCode::CLIENT_AHEAD,
            Self::Authentication(code) | Self::Violation(code) => *code,
            Self::Issuer(e) => match e {
                IssueError::Exhausted { .. } => ErrorCode::EXHAUSTED,
                IssueError::BookMismatch => ErrorCode::BOOK_MISMATCH,
                IssueError::PersistenceUncertain => ErrorCode::PERSISTENCE_UNVERIFIED,
                IssueError::LockUnavailable | IssueError::AnchorCorrupt | IssueError::Io => {
                    ErrorCode::IO_ERROR
                }
                // reserve_range 参数误用（本地 bug 面上：握手路径不调用范围预留）
                IssueError::InvalidRange => ErrorCode::INTERNAL,
            },
            Self::Csprng => ErrorCode::CSPRNG_FAILURE,
        }
    }

    const fn auth(code: ErrorCode) -> Self {
        Self::Authentication(code)
    }

    const fn violation(code: ErrorCode) -> Self {
        Self::Violation(code)
    }
}

/// 已提交段的受控桥接（集成债，见模块文档"已知集成债"）：
/// allocator 侧 [`otp_allocator::CommittedSegment`] → 会话侧
/// [`otp_session::CommittedSegment`]。一次定长拷贝，源段随即 Drop 清零；
/// 两份副本均以 zeroize 收尾，无派生、无日志、无第三路径。
fn bridge_segment(seg: otp_allocator::CommittedSegment) -> SessionSegment {
    let bytes = *seg.as_bytes();
    drop(seg);
    SessionSegment::from_bytes(bytes)
}

/// OS CSPRNG 生成 16B nonce（失败即 0x0403 fail closed，绝不降级伪随机）。
fn csprng16() -> Result<[u8; 16], HandshakeError> {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).map_err(|_| HandshakeError::Csprng)?;
    Ok(buf)
}

/// CONFIRM 内层副本的期望值（全部公开元数据）。
struct ConfirmExpectations {
    book_id: BookId,
    segment: SegmentIndex,
    client_nonce: ClientNonce,
    server_nonce: ServerNonce,
    direction: Direction,
    msg_type: u16,
    label: [u8; 14],
}

/// 会话层错误 → 握手错误（open 侧；WP-01 §5.2 映射）。
fn map_session_open_err(e: SessionError) -> HandshakeError {
    match e {
        SessionError::AuthenticationFailed => HandshakeError::auth(ErrorCode::TAG_INVALID),
        SessionError::SequenceReplay => HandshakeError::auth(ErrorCode::SEQ_REPLAY),
        SessionError::SequenceUnexpected | SessionError::SequenceOverflow => {
            HandshakeError::violation(ErrorCode::SEQ_UNEXPECTED)
        }
        SessionError::WrongDirection => HandshakeError::violation(ErrorCode::WRONG_DIRECTION),
        SessionError::Closed => HandshakeError::violation(ErrorCode::BAD_ORDER),
    }
}

/// 会话层错误 → 握手错误（seal 侧；正常路径不可达，防御性 fail closed）。
fn map_session_seal_err(e: SessionError) -> HandshakeError {
    match e {
        SessionError::SequenceOverflow => HandshakeError::violation(ErrorCode::SEQ_UNEXPECTED),
        _ => HandshakeError::violation(ErrorCode::INTERNAL),
    }
}

/// 封装一条 CONFIRM（WP-01 §4.4）：内层 87B 副本 + 外层恒 103B sealed。
/// seq 由会话序号状态机分配（CONFIRM 恒占该方向 seq=0，wp03 §4.1）。
fn seal_confirm(
    session: &mut Session,
    book_id: BookId,
    segment: SegmentIndex,
    client_nonce: &ClientNonce,
    server_nonce: &ServerNonce,
    direction: Direction,
) -> Result<Message, HandshakeError> {
    let (mt, wire_type, label) = match direction {
        Direction::ClientToServer => (
            MessageType::ClientConfirm,
            MsgType::ConfirmC2s.wire(),
            *CONFIRM_LABEL_C2S,
        ),
        Direction::ServerToClient => (
            MessageType::ServerConfirm,
            MsgType::ConfirmS2c.wire(),
            *CONFIRM_LABEL_S2C,
        ),
    };
    let body = ConfirmBody {
        book_id,
        segment_index: segment,
        client_nonce: *client_nonce,
        server_nonce: *server_nonce,
        direction,
        epoch: Epoch::new(0),
        seq: Sequence::ZERO,
        msg_type: wire_type,
        label,
    };
    let plain = encode_confirm_body(&body).map_err(HandshakeError::violation)?;
    let record = session.seal(mt, &plain).map_err(map_session_seal_err)?;
    let mut sealed = [0u8; SEALED_LEN];
    sealed.copy_from_slice(record.sealed());
    let zeta = session.context().session_nonce();
    let (segment_index, session_nonce, epoch, seq, sealed) =
        (segment, zeta, Epoch::new(0), record.sequence, sealed);
    Ok(match direction {
        Direction::ClientToServer => Message::ConfirmC2s {
            segment_index,
            session_nonce,
            epoch,
            seq,
            sealed,
        },
        Direction::ServerToClient => Message::ConfirmS2c {
            segment_index,
            session_nonce,
            epoch,
            seq,
            sealed,
        },
    })
}

/// CONFIRM 外层字段校验（WP-01 §4.4 外层表 [state]）：
/// 段号 0x0202 / session_nonce 0x0203 / epoch 0x030A / seq 0x030B。
fn verify_confirm_outer(
    segment_index: SegmentIndex,
    session_nonce: &SessionNonce,
    epoch: Epoch,
    seq: Sequence,
    expect_segment: SegmentIndex,
    expect_nonce: &SessionNonce,
) -> Result<(), HandshakeError> {
    if segment_index != expect_segment {
        return Err(HandshakeError::auth(ErrorCode::SEGMENT_BINDING));
    }
    if session_nonce != expect_nonce {
        return Err(HandshakeError::auth(ErrorCode::NONCE_MISMATCH));
    }
    if epoch.get() != 0 {
        return Err(HandshakeError::violation(ErrorCode::EPOCH_MISMATCH));
    }
    if seq.get() != 0 {
        return Err(HandshakeError::violation(ErrorCode::SEQ_UNEXPECTED));
    }
    Ok(())
}

/// CONFIRM 内层副本校验（WP-01 §4.4 内层表 [state]，tag 已通过后执行）。
fn verify_confirm_body(body: &ConfirmBody, e: &ConfirmExpectations) -> Result<(), HandshakeError> {
    if body.book_id != e.book_id || body.segment_index != e.segment {
        return Err(HandshakeError::auth(ErrorCode::SEGMENT_BINDING));
    }
    if body.client_nonce != e.client_nonce || body.server_nonce != e.server_nonce {
        return Err(HandshakeError::auth(ErrorCode::NONCE_MISMATCH));
    }
    if body.direction != e.direction || body.msg_type != e.msg_type || body.label != e.label {
        return Err(HandshakeError::auth(ErrorCode::SEGMENT_BINDING));
    }
    if body.epoch.get() != 0 {
        return Err(HandshakeError::violation(ErrorCode::EPOCH_MISMATCH));
    }
    if body.seq.get() != 0 {
        return Err(HandshakeError::violation(ErrorCode::SEQ_UNEXPECTED));
    }
    Ok(())
}

// ─────────────────────────────── 客户端 ───────────────────────────────

/// 客户端握手状态机（wp02 §4.1/§4.2）。
pub struct ClientHandshake {
    cfg: ClientConfig,
    phase: ClientPhase,
    client_nonce: Option<ClientNonce>,
    server_nonce: Option<ServerNonce>,
    /// 仲裁约定指针 i。
    agreed: Option<SegmentIndex>,
    session: Option<Session>,
    /// SERVER_AHEAD 跳段审计（WASTED_GAP 端点，白名单字段）。
    wasted_gap: Option<(SegmentIndex, SegmentIndex)>,
}

impl ClientHandshake {
    /// 以本地配置启动。版本 ≠0x0002 即拒绝（0x0301）。
    pub fn new(cfg: ClientConfig) -> Result<Self, HandshakeError> {
        if cfg.version != ProtocolVersion::V2 {
            return Err(HandshakeError::violation(ErrorCode::BAD_VERSION));
        }
        Ok(Self {
            cfg,
            phase: ClientPhase::Idle,
            client_nonce: None,
            server_nonce: None,
            agreed: None,
            session: None,
            wasted_gap: None,
        })
    }

    /// 当前阶段（审计/测试可见）。
    #[must_use]
    pub const fn phase(&self) -> ClientPhase {
        self.phase
    }

    /// 仲裁约定段号（H2/H3 后有值）。
    #[must_use]
    pub const fn arbitrated_segment(&self) -> Option<SegmentIndex> {
        self.agreed
    }

    /// SERVER_AHEAD 跳段区间 `[from, to)`（审计 WASTED_GAP；无跳段为 None）。
    #[must_use]
    pub const fn wasted_gap(&self) -> Option<(SegmentIndex, SegmentIndex)> {
        self.wasted_gap
    }

    /// H1：产生 HELLO(version, book_id, client_nonce, client_pointer, features)。
    /// nonce 来自 OS CSPRNG；失败即终止握手（0x0403）。
    pub fn start(&mut self) -> Result<Message, HandshakeError> {
        if self.phase != ClientPhase::Idle {
            self.phase = ClientPhase::Failed;
            return Err(HandshakeError::violation(ErrorCode::BAD_ORDER));
        }
        let nonce = ClientNonce::from_bytes(csprng16()?);
        self.client_nonce = Some(nonce);
        self.phase = ClientPhase::HelloSent;
        Ok(Message::Hello {
            book_id: self.cfg.book_id,
            client_nonce: nonce,
            client_pointer: self.cfg.local_pointer,
            features: FeatureFlags::default(),
        })
    }

    /// H2–H9：推进状态机。ARBITRATE 处理内联本地签发（H6：issue +
    /// ISSUE_REQUEST + CONFIRM_C2S）；CONFIRM_S2C 验证通过即 Established。
    pub fn handle(&mut self, msg: &Message, issuer: &mut dyn SegmentIssuer) -> Step {
        match self.phase {
            ClientPhase::HelloSent => match msg {
                Message::Arbitrate { .. } => self.on_arbitrate(msg, issuer),
                _ => self.order_violation(),
            },
            ClientPhase::ConfirmSent => match msg {
                Message::ConfirmS2c { .. } => self.on_confirm_s2c(msg),
                _ => self.order_violation(),
            },
            _ => self.order_violation(),
        }
    }

    /// H13：底层传输错误/对端关闭/上层取消。焚毁持有的会话密钥，
    /// 进入失败终态（未 ESTABLISHED 者其段 SPENT，T11）。
    pub fn abort(&mut self, reason: ErrorCode) -> Step {
        self.burn_session();
        self.phase = ClientPhase::Failed;
        Step::Failed(HandshakeError::Violation(reason))
    }

    /// H2–H5：仲裁。
    fn on_arbitrate(&mut self, msg: &Message, issuer: &mut dyn SegmentIssuer) -> Step {
        let Message::Arbitrate {
            server_nonce,
            server_pointer,
            result,
        } = msg
        else {
            return self.order_violation();
        };
        let sp = *server_pointer;
        let cp = self.cfg.local_pointer;
        let n = self.cfg.segment_count;
        match result {
            ArbitrateResult::BookMismatch => {
                // H5：错本（codec 已保证 sp==0）。
                self.phase = ClientPhase::Failed;
                Step::Failed(HandshakeError::BookMismatch)
            }
            ArbitrateResult::Exhausted => {
                if sp.get() != n {
                    return self.reject_pointer_combination();
                }
                self.phase = ClientPhase::Failed;
                Step::Failed(HandshakeError::Exhausted { next: sp })
            }
            ArbitrateResult::ClientAhead => {
                if sp.get() >= cp.get() {
                    return self.reject_pointer_combination();
                }
                // H4：本地分配器冻结（本实例不再 issue），人工恢复。
                self.phase = ClientPhase::AheadRecovery;
                Step::Failed(HandshakeError::ClientAhead {
                    client: cp,
                    server: sp,
                })
            }
            ArbitrateResult::Ok => {
                if sp != cp {
                    return self.reject_pointer_combination();
                }
                self.server_nonce = Some(*server_nonce);
                self.agreed = Some(sp);
                self.issue_and_confirm(issuer)
            }
            ArbitrateResult::ServerAhead => {
                if sp.get() <= cp.get() {
                    return self.reject_pointer_combination();
                }
                // H3：只前进。废弃 [cp, sp) 孤立段（审计 WASTED_GAP），
                // 指针跳至 sp，随后与 OK 同路（i = sp）。
                self.wasted_gap = Some((cp, sp));
                self.server_nonce = Some(*server_nonce);
                self.agreed = Some(sp);
                self.issue_and_confirm(issuer)
            }
        }
    }

    /// 0x0307：ARBITRATE 结果与指针组合矛盾（WP-01 §4.2 [state]）。
    fn reject_pointer_combination(&mut self) -> Step {
        self.phase = ClientPhase::Failed;
        Step::Failed(HandshakeError::violation(ErrorCode::ISSUE_POINTER_MISMATCH))
    }

    /// 非法转移（错消息类型/错状态/终态复用）→ 0x0309 fail closed。
    fn order_violation(&mut self) -> Step {
        self.burn_session();
        self.phase = ClientPhase::Failed;
        Step::Failed(HandshakeError::violation(ErrorCode::BAD_ORDER))
    }

    /// H6/H7：SERVER_AHEAD 间隙废弃（只前进）+ 本地签发 + 发
    /// ISSUE_REQUEST 与 CONFIRM_C2S。
    fn issue_and_confirm(&mut self, issuer: &mut dyn SegmentIssuer) -> Step {
        let Some(i) = self.agreed else {
            return self.order_violation();
        };
        let cp = self.cfg.local_pointer;
        // H3 间隙废弃：逐段经完整分配器事务消耗后丢弃（内容不进入任何
        // 密钥路径，Drop 即清零）。任何失败即 H7 fail closed。
        for _ in cp.get()..i.get() {
            if let Err(e) = issuer.issue() {
                return self.fail_issuer(e);
            }
        }
        // H6：本次会话段（两端同段同内容 ⇒ 同一双方向密钥）。
        let seg = match issuer.issue() {
            Ok(seg) => seg,
            Err(e) => return self.fail_issuer(e),
        };
        let (Some(client_nonce), Some(server_nonce)) = (self.client_nonce, self.server_nonce)
        else {
            return self.order_violation();
        };
        let ctx = SessionContext {
            role: Role::Client,
            book_id: self.cfg.book_id,
            segment: i,
            client_nonce,
            server_nonce,
        };
        let mut session = Session::new(bridge_segment(seg), ctx);
        let confirm = match seal_confirm(
            &mut session,
            self.cfg.book_id,
            i,
            &client_nonce,
            &server_nonce,
            Direction::ClientToServer,
        ) {
            Ok(msg) => msg,
            Err(e) => {
                self.burn_session();
                self.phase = ClientPhase::Failed;
                return Step::Failed(e);
            }
        };
        let issue_request = Message::IssueRequest {
            chosen_pointer: i,
            client_nonce,
            server_nonce,
        };
        self.session = Some(session);
        self.phase = ClientPhase::ConfirmSent;
        Step::Send(vec![issue_request, confirm])
    }

    fn fail_issuer(&mut self, e: IssueError) -> Step {
        self.burn_session();
        self.phase = ClientPhase::Failed;
        Step::Failed(HandshakeError::Issuer(e))
    }

    /// H8/H9：验证 CONFIRM_S2C。
    fn on_confirm_s2c(&mut self, msg: &Message) -> Step {
        let Message::ConfirmS2c {
            segment_index,
            session_nonce,
            epoch,
            seq,
            sealed,
        } = msg
        else {
            return self.order_violation();
        };
        let Some(i) = self.agreed else {
            return self.order_violation();
        };
        let (Some(client_nonce), Some(server_nonce)) = (self.client_nonce, self.server_nonce)
        else {
            return self.order_violation();
        };
        let Some(mut session) = self.session.take() else {
            return self.order_violation();
        };
        let zeta = session.context().session_nonce();
        // 外层字段（先于 AEAD，WP-01 §4.4 外层 [state]）。
        if let Err(e) = verify_confirm_outer(*segment_index, session_nonce, *epoch, *seq, i, &zeta)
        {
            session.close();
            self.phase = ClientPhase::Failed;
            return Step::Failed(e);
        }
        // tag 验证（record 层；失败即焚毁密钥并关闭，wp03 §4.4）。
        let payload = match session.open(MessageType::ServerConfirm, *seq, sealed) {
            Ok(p) => p,
            Err(e) => {
                self.phase = ClientPhase::Failed;
                return Step::Failed(map_session_open_err(e));
            }
        };
        // 内层副本（tag 通过后）。
        let body = match decode_confirm_body(payload.as_bytes()) {
            Ok(b) => b,
            Err(code) => {
                session.close();
                self.phase = ClientPhase::Failed;
                return Step::Failed(HandshakeError::violation(code));
            }
        };
        let expect = ConfirmExpectations {
            book_id: self.cfg.book_id,
            segment: i,
            client_nonce,
            server_nonce,
            direction: Direction::ServerToClient,
            msg_type: MsgType::ConfirmS2c.wire(),
            label: *CONFIRM_LABEL_S2C,
        };
        if let Err(e) = verify_confirm_body(&body, &expect) {
            session.close();
            self.phase = ClientPhase::Failed;
            return Step::Failed(e);
        }
        self.phase = ClientPhase::Established;
        Step::Established {
            outbox: Vec::new(),
            session,
            segment: i,
        }
    }

    /// 焚毁持有的会话（立即清零双方向密钥；Drop 再清一次，幂等）。
    fn burn_session(&mut self) {
        if let Some(mut session) = self.session.take() {
            session.close();
        }
    }
}

// ─────────────────────────────── 服务端 ───────────────────────────────

/// 服务端握手状态机（wp02 §4.3）。
pub struct ServerHandshake {
    cfg: ServerConfig,
    phase: ServerPhase,
    client_nonce: Option<ClientNonce>,
    server_nonce: Option<ServerNonce>,
    /// 仲裁约定指针 i（= 仲裁时的本地 next；ISSUE.chosen 必须等于它）。
    agreed: Option<SegmentIndex>,
    session: Option<Session>,
}

impl ServerHandshake {
    /// 以服务端配置启动。版本 ≠0x0002 即拒绝（0x0301）。
    pub fn new(cfg: ServerConfig) -> Result<Self, HandshakeError> {
        if cfg.version != ProtocolVersion::V2 {
            return Err(HandshakeError::violation(ErrorCode::BAD_VERSION));
        }
        Ok(Self {
            cfg,
            phase: ServerPhase::Idle,
            client_nonce: None,
            server_nonce: None,
            agreed: None,
            session: None,
        })
    }

    /// 当前阶段（审计/测试可见）。
    #[must_use]
    pub const fn phase(&self) -> ServerPhase {
        self.phase
    }

    /// 仲裁约定段号。
    #[must_use]
    pub const fn arbitrated_segment(&self) -> Option<SegmentIndex> {
        self.agreed
    }

    /// 处理 HELLO → 产出 ARBITRATE（wp02 §4.3 仲裁表）。
    ///
    /// 校验顺序：消息类型/状态 → book_id（错本**先于仲裁**与一切签发，
    /// 0x0100）→ 指针仲裁（OK / SERVER_AHEAD / CLIENT_AHEAD / EXHAUSTED）。
    /// server_nonce 由 CSPRNG 生成（0x0403 失败即终止，不出 ARBITRATE）。
    pub fn on_hello(&mut self, hello: &Message) -> Result<Message, HandshakeError> {
        if self.phase != ServerPhase::Idle {
            self.burn_session();
            self.phase = ServerPhase::Failed;
            return Err(HandshakeError::violation(ErrorCode::BAD_ORDER));
        }
        let Message::Hello {
            book_id,
            client_nonce,
            client_pointer,
            features: _,
        } = hello
        else {
            self.phase = ServerPhase::Failed;
            return Err(HandshakeError::violation(ErrorCode::BAD_ORDER));
        };
        self.client_nonce = Some(*client_nonce);
        let server_nonce = ServerNonce::from_bytes(csprng16()?);
        // 错本先于仲裁（WP-01 §4.2/§5.2：BOOK_MISMATCH 时 sp 恒 0）。
        if *book_id != self.cfg.book_id {
            self.phase = ServerPhase::Failed;
            return Ok(Message::Arbitrate {
                server_nonce,
                server_pointer: SegmentIndex::ZERO,
                result: ArbitrateResult::BookMismatch,
            });
        }
        let sp = self.cfg.local_pointer;
        let cp = *client_pointer;
        let n = self.cfg.segment_count;
        // 仲裁（wp02 §4.3）。错本已在上文先行早退，此处不可能再出现
        // BookMismatch；EXHAUSTED 判定次之：next ≥ N 时无段可签。
        let (result, sp_out) = if sp.get() >= n {
            (ArbitrateResult::Exhausted, SegmentIndex::new(n))
        } else if sp > cp {
            (ArbitrateResult::ServerAhead, sp)
        } else if cp > sp {
            (ArbitrateResult::ClientAhead, sp)
        } else {
            (ArbitrateResult::Ok, sp)
        };
        match result {
            ArbitrateResult::Ok | ArbitrateResult::ServerAhead => {
                // 指针不动；SERVER_AHEAD 由客户端跳段（服务端零动作）。
                self.server_nonce = Some(server_nonce);
                self.agreed = Some(sp);
                self.phase = ServerPhase::IssueWait;
            }
            ArbitrateResult::Exhausted | ArbitrateResult::ClientAhead => {
                // EXHAUSTED → 失败终态；CLIENT_AHEAD → 指针冻结
                // （绝不按网络声明前推/回退，wp02 §4.4 禁止清单）。
                self.phase = if result == ArbitrateResult::ClientAhead {
                    ServerPhase::AheadPending
                } else {
                    ServerPhase::Failed
                };
            }
            ArbitrateResult::BookMismatch => {}
        }
        Ok(Message::Arbitrate {
            server_nonce,
            server_pointer: sp_out,
            result,
        })
    }

    /// S-ALLOC：处理 ISSUE_REQUEST——校验 `chosen == 仲裁约定 i` 与双 nonce
    /// 回显，全部通过后经 [`SegmentIssuer`] 签发新段（fail-to-waste 全事务），
    /// 产出 CONFIRM_S2C 并等待 CONFIRM_C2S。
    ///
    /// 校验失败在预留前拒绝（不消耗段）；签发失败（耗尽/持久化不确定）
    /// → Failed，段按规则消耗不降级、不复用。
    pub fn on_issue_request(&mut self, req: &Message, issuer: &mut dyn SegmentIssuer) -> Step {
        if self.phase != ServerPhase::IssueWait {
            return self.order_violation();
        }
        let Message::IssueRequest {
            chosen_pointer,
            client_nonce,
            server_nonce,
        } = req
        else {
            return self.order_violation();
        };
        let Some(i) = self.agreed else {
            return self.order_violation();
        };
        // i′ ≠ 仲裁约定 i → 0x0307，不消耗段（预留前拒绝）。
        if *chosen_pointer != i {
            self.phase = ServerPhase::Failed;
            return Step::Failed(HandshakeError::violation(ErrorCode::ISSUE_POINTER_MISMATCH));
        }
        let (Some(hello_client_nonce), Some(self_server_nonce)) =
            (self.client_nonce, self.server_nonce)
        else {
            return self.order_violation();
        };
        // 双 nonce 回显（WP-01 §4.3 [state]：0x0203；预留前拒绝）。
        if *client_nonce != hello_client_nonce || *server_nonce != self_server_nonce {
            self.burn_session();
            self.phase = ServerPhase::Failed;
            return Step::Failed(HandshakeError::auth(ErrorCode::NONCE_MISMATCH));
        }
        let seg = match issuer.issue() {
            Ok(seg) => seg,
            Err(e) => {
                self.phase = ServerPhase::Failed;
                return Step::Failed(HandshakeError::Issuer(e));
            }
        };
        let ctx = SessionContext {
            role: Role::Server,
            book_id: self.cfg.book_id,
            segment: i,
            client_nonce: hello_client_nonce,
            server_nonce: self_server_nonce,
        };
        let session = Session::new(bridge_segment(seg), ctx);
        self.session = Some(session);
        self.phase = ServerPhase::ConfirmWait;
        Step::AwaitPeer
    }

    /// S-CONFIRM-WAIT：处理 CONFIRM_C2S。外层字段 + tag + 内层副本全部
    /// 通过后封装 CONFIRM_S2C（该方向 seq=0）并 Established。
    pub fn on_confirm(&mut self, confirm: &Message) -> Step {
        if self.phase != ServerPhase::ConfirmWait {
            return self.order_violation();
        }
        let Message::ConfirmC2s {
            segment_index,
            session_nonce,
            epoch,
            seq,
            sealed,
        } = confirm
        else {
            return self.order_violation();
        };
        let Some(i) = self.agreed else {
            return self.order_violation();
        };
        let (Some(client_nonce), Some(server_nonce)) = (self.client_nonce, self.server_nonce)
        else {
            return self.order_violation();
        };
        let Some(mut session) = self.session.take() else {
            return self.order_violation();
        };
        let zeta = session.context().session_nonce();
        if let Err(e) = verify_confirm_outer(*segment_index, session_nonce, *epoch, *seq, i, &zeta)
        {
            session.close();
            self.phase = ServerPhase::Failed;
            return Step::Failed(e);
        }
        let payload = match session.open(MessageType::ClientConfirm, *seq, sealed) {
            Ok(p) => p,
            Err(e) => {
                self.phase = ServerPhase::Failed;
                return Step::Failed(map_session_open_err(e));
            }
        };
        let body = match decode_confirm_body(payload.as_bytes()) {
            Ok(b) => b,
            Err(code) => {
                session.close();
                self.phase = ServerPhase::Failed;
                return Step::Failed(HandshakeError::violation(code));
            }
        };
        let expect = ConfirmExpectations {
            book_id: self.cfg.book_id,
            segment: i,
            client_nonce,
            server_nonce,
            direction: Direction::ClientToServer,
            msg_type: MsgType::ConfirmC2s.wire(),
            label: *CONFIRM_LABEL_C2S,
        };
        if let Err(e) = verify_confirm_body(&body, &expect) {
            session.close();
            self.phase = ServerPhase::Failed;
            return Step::Failed(e);
        }
        // tag+副本全部通过 → 封装 CONFIRM_S2C（seq=0）并 Established。
        let confirm_s2c = match seal_confirm(
            &mut session,
            self.cfg.book_id,
            i,
            &client_nonce,
            &server_nonce,
            Direction::ServerToClient,
        ) {
            Ok(msg) => msg,
            Err(e) => {
                self.phase = ServerPhase::Failed;
                return Step::Failed(e);
            }
        };
        self.phase = ServerPhase::Established;
        Step::Established {
            outbox: vec![confirm_s2c],
            session,
            segment: i,
        }
    }

    /// S13（H13 镜像）：底层传输错误/对端关闭/上层取消 → Failed。
    pub fn abort(&mut self, reason: ErrorCode) -> Step {
        self.burn_session();
        self.phase = ServerPhase::Failed;
        Step::Failed(HandshakeError::Violation(reason))
    }

    /// 非法转移（错消息类型/错状态/终态复用）→ 0x0309 fail closed。
    fn order_violation(&mut self) -> Step {
        self.burn_session();
        self.phase = ServerPhase::Failed;
        Step::Failed(HandshakeError::violation(ErrorCode::BAD_ORDER))
    }

    fn burn_session(&mut self) {
        if let Some(mut session) = self.session.take() {
            session.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirm_labels_are_frozen_14_bytes() {
        // WP-01 §4.4：label 恰 14B，逐字节冻结。
        assert_eq!(CONFIRM_LABEL_C2S.len(), 14);
        assert_eq!(CONFIRM_LABEL_C2S, b"client-confirm");
        assert_eq!(CONFIRM_LABEL_S2C.len(), 14);
        assert_eq!(CONFIRM_LABEL_S2C, b"server-confirm");
        assert_eq!(14, otp_codec::CONFIRM_LABEL_LEN);
    }

    #[test]
    fn version_mismatch_is_rejected_at_construction() {
        let bad = ClientConfig {
            version: ProtocolVersion(3),
            book_id: BookId::from_bytes([1; 16]),
            local_pointer: SegmentIndex::ZERO,
            segment_count: 1,
        };
        let err = match ClientHandshake::new(bad) {
            Err(e) => e,
            Ok(_) => panic!("非法版本必须被拒绝"),
        };
        assert_eq!(err.code(), ErrorCode::BAD_VERSION);
        let bad_server = ServerConfig {
            version: ProtocolVersion(1),
            book_id: BookId::from_bytes([1; 16]),
            local_pointer: SegmentIndex::ZERO,
            segment_count: 1,
        };
        let err = match ServerHandshake::new(bad_server) {
            Err(e) => e,
            Ok(_) => panic!("非法版本必须被拒绝"),
        };
        assert_eq!(err.code(), ErrorCode::BAD_VERSION);
    }

    #[test]
    fn error_codes_follow_wp01_registry() {
        assert_eq!(
            HandshakeError::BookMismatch.code(),
            ErrorCode::BOOK_MISMATCH
        );
        assert_eq!(
            HandshakeError::Exhausted {
                next: SegmentIndex::new(3)
            }
            .code(),
            ErrorCode::EXHAUSTED
        );
        assert_eq!(
            HandshakeError::ClientAhead {
                client: SegmentIndex::new(5),
                server: SegmentIndex::new(2)
            }
            .code(),
            ErrorCode::CLIENT_AHEAD
        );
        assert_eq!(
            HandshakeError::auth(ErrorCode::TAG_INVALID).code(),
            ErrorCode::TAG_INVALID
        );
        assert_eq!(
            HandshakeError::violation(ErrorCode::SEQ_UNEXPECTED).code(),
            ErrorCode::SEQ_UNEXPECTED
        );
        assert_eq!(
            HandshakeError::Issuer(IssueError::Exhausted {
                next: SegmentIndex::new(9)
            })
            .code(),
            ErrorCode::EXHAUSTED
        );
        assert_eq!(
            HandshakeError::Issuer(IssueError::PersistenceUncertain).code(),
            ErrorCode::PERSISTENCE_UNVERIFIED
        );
        assert_eq!(
            HandshakeError::Issuer(IssueError::Io).code(),
            ErrorCode::IO_ERROR
        );
        assert_eq!(HandshakeError::Csprng.code(), ErrorCode::CSPRNG_FAILURE);
    }

    #[test]
    fn bridge_is_a_single_fixed_length_handoff() {
        // 桥接只做 64B 定长移交（无派生、无缩放）：两侧类型同宽，
        // 证明拷贝不引入任何长度/语义变换。
        assert_eq!(SEGMENT_LEN, 64);
        assert_eq!(
            core::mem::size_of::<otp_allocator::CommittedSegment>(),
            SEGMENT_LEN
        );
        assert_eq!(core::mem::size_of::<SessionSegment>(), SEGMENT_LEN);
    }
}
