//! AEAD record 会话层核心：[`Session`]、[`SessionContext`]、错误分类与
//! 收发序号算法（WP-03 §4）。

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce as AeadNonce, Tag,
    aead::{AeadInPlace, KeyInit},
};
use otp_types::{
    BookId, ClientNonce, Direction, Epoch, Role, SegmentIndex, Sequence, ServerNonce, SessionNonce,
    TAG_LEN,
};
use zeroize::Zeroize;

use crate::aad::{AAD_LEN, MessageType, VERSION};
use crate::keys::{CommittedSegment, SessionKeys};
use crate::nonce::{SessionNonceDomain, record_nonce};

/// 收发序号计数器按方向索引（0 = C2S，1 = S2C；§4.1"每方向独立"）。
const fn direction_index(direction: Direction) -> usize {
    match direction {
        Direction::ClientToServer => 0,
        Direction::ServerToClient => 1,
    }
}

/// record 类型与方向的固定配对（§2.2：0x0004→C2S、0x0005→S2C；DATA 按角色）。
/// 违反即本地误用，fail closed（终止会话，不产生任何帧）。
const fn pairing_valid(mt: MessageType, direction: Direction) -> bool {
    matches!(
        (mt, direction),
        (MessageType::ClientConfirm, Direction::ClientToServer)
            | (MessageType::ServerConfirm, Direction::ServerToClient)
            | (MessageType::Data, _)
    )
}

/// 会话上下文：进入 AAD 的全部绑定材料 + 本端角色（均为公开值，v2 §4）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SessionContext {
    /// 本端角色（决定发送/接收方向与所用方向密钥）。
    pub role: Role,
    /// 会话密码本 ID（AAD 防错本/错会话搬运）。
    pub book_id: BookId,
    /// 本会话已签发段号 i（AAD 防跨段/跨会话拼接）。
    pub segment: SegmentIndex,
    /// HELLO 的 client_nonce（AAD 防跨连接重放）。
    pub client_nonce: ClientNonce,
    /// ARBITRATE 的 server_nonce。
    pub server_nonce: ServerNonce,
}

impl SessionContext {
    /// 会话 nonce ζ = client_nonce ⊕ server_nonce（WP-01 D3；双方确定性一致）。
    pub fn session_nonce(&self) -> SessionNonce {
        let mut z = [0u8; 16];
        for (z, (c, s)) in z.iter_mut().zip(
            self.client_nonce
                .as_bytes()
                .iter()
                .zip(self.server_nonce.as_bytes()),
        ) {
            *z = c ^ s;
        }
        SessionNonce::from_bytes(z)
    }

    /// 96-bit nonce 的会话域（ζ[0..3] 纯切片，WP-03 §1.1）。
    pub fn nonce_domain(&self) -> SessionNonceDomain {
        SessionNonceDomain::from_session_nonce(&self.session_nonce())
    }

    /// AAD 构造（§2.1 规范性定义，恰 73B 定长；CONFIRM 与 DATA 共用）：
    ///
    /// ```text
    /// BE16(0x0002) ‖ BE16(msg_type) ‖ enc8(direction)
    /// ‖ book_id ‖ BE64(segment_index) ‖ client_nonce ‖ server_nonce
    /// ‖ BE32(epoch) ‖ BE64(seq)
    /// ```
    pub fn build_aad(
        &self,
        mt: MessageType,
        direction: Direction,
        epoch: Epoch,
        seq: Sequence,
    ) -> [u8; AAD_LEN] {
        let mut aad = [0u8; AAD_LEN];
        aad[0..2].copy_from_slice(&VERSION.to_be_bytes());
        aad[2..4].copy_from_slice(&mt.wire_code().to_be_bytes());
        aad[4] = crate::nonce::direction_wire(direction);
        aad[5..21].copy_from_slice(self.book_id.as_bytes());
        aad[21..29].copy_from_slice(&self.segment.get().to_be_bytes());
        aad[29..45].copy_from_slice(self.client_nonce.as_bytes());
        aad[45..61].copy_from_slice(self.server_nonce.as_bytes());
        aad[61..65].copy_from_slice(&epoch.get().to_be_bytes());
        aad[65..73].copy_from_slice(&seq.get().to_be_bytes());
        aad
    }
}

/// 单条已封装 record：密文 ‖ 16B tag（不透明；密文/tag 非秘密，v2 §4，
/// 但 Debug 仍只打印长度，避免测试输出堆积大段 hex）。
pub struct Record {
    /// record 序号（与帧内 seq、nonce 低 8 字节同值）。
    pub sequence: Sequence,
    /// 密文 + 16B Poly1305 tag。
    ciphertext_and_tag: Vec<u8>,
}

impl Record {
    /// sealed 视图（密文 ‖ tag）。
    pub fn sealed(&self) -> &[u8] {
        &self.ciphertext_and_tag
    }
}

impl core::fmt::Debug for Record {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 审计安全：只打印序号与长度
        write!(
            f,
            "Record{{sequence: {}, len: {}}}",
            self.sequence.get(),
            self.ciphertext_and_tag.len()
        )
    }
}

/// 解密后的明文载荷：Drop 清零（§5.2 类型义务），只能经 [`Payload::as_bytes`] 读取。
#[derive(zeroize::ZeroizeOnDrop)]
pub struct Payload(Vec<u8>);

impl Payload {
    pub(crate) fn from_vec(v: Vec<u8>) -> Self {
        Self(v)
    }

    /// 明文字节视图（存活期间由调用方负责不落日志）。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// 会话层错误（映射 WP-01 §5.2 错误码注册表；对外行为统一为静默关闭，
/// WP-01 §5.3——错误分类仅供本端审计白名单使用）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionError {
    /// 0x0201 TAG_INVALID：tag 验证失败（含截断、篡改、一切上下文错配）。
    AuthenticationFailed,
    /// 0x0204 SEQ_REPLAY：精确重复序号。
    SequenceReplay,
    /// 0x030B SEQ_UNEXPECTED：跳号/回退/回绕、CONFIRM seq≠0、DATA 首序号≠1。
    SequenceUnexpected,
    /// 序号空间耗尽（2^64−1 之后还需发送；§4.3。审计类别映射 0x030B，D4）。
    SequenceOverflow,
    /// 0x0306 方向/类型配对非法（本地误用，fail closed）。
    WrongDirection,
    /// 会话已终止（正常关闭或此前失败已焚毁密钥）。
    Closed,
}

impl SessionError {
    /// 对应 WP-01 错误码（审计白名单"错误类别"字段）；无线上对应者返回 None
    /// （溢出/关闭不出现在线上，仅本地审计）。
    pub const fn wire_code(self) -> Option<u16> {
        match self {
            Self::AuthenticationFailed => Some(0x0201),
            Self::SequenceReplay => Some(0x0204),
            Self::SequenceUnexpected | Self::SequenceOverflow => Some(0x030B),
            Self::WrongDirection => Some(0x0306),
            Self::Closed => None,
        }
    }
}

/// 终止原因（内部；决定终止后的后续调用返回何种错误）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Termination {
    /// §4.3：序号空间耗尽。
    SequenceOverflow,
    /// §4.4：tag 失败/截断。
    Authentication,
    /// §4.2：序号违规（重放/乱序/类型序号纪律）。
    SequenceViolation,
    /// 本地误用（方向/类型配对）。
    Misuse,
    /// 正常关闭。
    Closed,
}

/// 已建立的加密会话：双方向密钥 + 双方向收发序号状态机。
///
/// - 发送（§4.1）：CONFIRM 占 seq=0，DATA 自 1 起，每方向每段内严格 +1，
///   绝不复用/跳发/回绕；消耗 2^64−1 后立即整会话终止（§4.3 路径 (b)）。
/// - 接收（§4.2）：先判 seq（重复 → [`SessionError::SequenceReplay`]；
///   非期望 → [`SessionError::SequenceUnexpected`]），后 open；无窗口、
///   无乱序容忍；仅在 open 成功后推进 `last_accepted`。
/// - 任何认证/序号失败 → 立即焚毁密钥并终止会话，绝不输出未认证明文
///   （§4.4 / RFC 5116）。
pub struct Session {
    ctx: SessionContext,
    domain: SessionNonceDomain,
    keys: Option<SessionKeys>,
    /// 每方向下一发送序号（初值 0：首条 record 是该方向 CONFIRM）。
    send_seq: [Sequence; 2],
    /// 每方向最后已接受序号（None ⇒ 期望 0）。
    recv_last: [Option<Sequence>; 2],
    terminated: Option<Termination>,
}

impl Session {
    /// 由已提交段建立会话：64B 直接拆 32+32 方向密钥（无任何 KDF/哈希，
    /// §3.1）。输入必须来自 `SegmentIssuer::issue()`（规划 §2.2；M1 测试
    /// 夹具路径见 [`CommittedSegment`]）。
    pub fn new(segment: CommittedSegment, ctx: SessionContext) -> Self {
        let domain = ctx.nonce_domain();
        Self {
            ctx,
            domain,
            keys: Some(SessionKeys::split(segment)),
            send_seq: [Sequence::ZERO, Sequence::ZERO],
            recv_last: [None, None],
            terminated: None,
        }
    }

    /// 会话上下文（公开值）。
    pub fn context(&self) -> &SessionContext {
        &self.ctx
    }

    /// 本端角色。
    pub fn role(&self) -> Role {
        self.ctx.role
    }

    /// 会话是否仍在活动（未因任何路径终止）。
    pub fn is_active(&self) -> bool {
        self.terminated.is_none()
    }

    /// 下一发送序号（本端发送方向；审计/测试可见）。
    pub fn next_send_sequence(&self) -> Sequence {
        self.send_seq[direction_index(self.ctx.role.send_direction())]
    }

    /// 指定方向最后已接受序号（接收侧状态；审计/测试可见）。
    pub fn last_accepted(&self, direction: Direction) -> Option<Sequence> {
        self.recv_last[direction_index(direction)]
    }

    /// 封装一条 record（§4.1 发送算法）。方向 = 本角色发送方向；序号由会话
    /// 状态自动分配（与 nonce/AAD/帧内 seq 同源，杜绝 §1.4 禁令 2 的
    /// "双计数器不同步"）。
    ///
    /// 明文缓冲在库整体 `encrypt_in_place_detached` 内封装（§5.2.6：禁止
    /// 手工拼 ChaCha20+Poly1305 两段流程）；成功即得 `密文‖tag`。
    pub fn seal(&mut self, mt: MessageType, plaintext: &[u8]) -> Result<Record, SessionError> {
        self.ensure_active()?;
        let direction = self.ctx.role.send_direction();
        if !pairing_valid(mt, direction) {
            self.terminate(Termination::Misuse);
            return Err(SessionError::WrongDirection);
        }
        let idx = direction_index(direction);
        let seq = self.send_seq[idx];

        // 类型序号纪律（WP-01 §4.4/§4.5 [state] 的本地镜像）：
        // CONFIRM 占 seq=0 且只此一条；DATA 自 1 起。
        let seq_discipline_ok = if mt.is_confirm() {
            seq == Sequence::ZERO
        } else {
            seq.get() >= 1
        };
        if !seq_discipline_ok {
            self.terminate(Termination::SequenceViolation);
            return Err(SessionError::SequenceUnexpected);
        }

        let (nonce, aad, cipher) = self.aead_material(mt, direction, seq);
        let mut sealed = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(&nonce, &aad, &mut sealed)
            .map_err(|_| {
                // AEAD 封装失败（缓冲长度病态，正常输入不可达）：fail closed
                sealed.zeroize();
                self.terminate(Termination::Authentication);
                SessionError::AuthenticationFailed
            })?;
        sealed.extend_from_slice(tag.as_slice());

        // §4.1：移交后推进；s == 2^64−1 ⇒ 序号空间耗尽，整会话终止
        // （§4.3 路径 (b)：本 record 照常返回，此后不再构造任何新帧）。
        match seq.next() {
            Some(next) => self.send_seq[idx] = next,
            None => self.terminate(Termination::SequenceOverflow),
        }
        Ok(Record {
            sequence: seq,
            ciphertext_and_tag: sealed,
        })
    }

    /// 解封并验证一条 record（§4.2 接收算法）。`seq` 与 `sealed` 取自
    /// codec 解码成功的帧字段；方向 = 本角色接收方向。
    ///
    /// 判定顺序（确定性）：seq 纪律 → 重复 → 期望 → open。
    /// 任何失败：先清工作缓冲、焚毁密钥、终止会话，再返回错误——
    /// 绝不输出未认证明文。
    pub fn open(
        &mut self,
        mt: MessageType,
        seq: Sequence,
        sealed: &[u8],
    ) -> Result<Payload, SessionError> {
        self.ensure_active()?;
        let direction = self.ctx.role.send_direction().opposite();
        if !pairing_valid(mt, direction) {
            self.terminate(Termination::Misuse);
            return Err(SessionError::WrongDirection);
        }

        // 类型序号纪律：CONFIRM seq=0；DATA seq>=1（0x030B 语义覆盖面）。
        let seq_discipline_ok = if mt.is_confirm() {
            seq == Sequence::ZERO
        } else {
            seq.get() >= 1
        };
        if !seq_discipline_ok {
            self.terminate(Termination::SequenceViolation);
            return Err(SessionError::SequenceUnexpected);
        }

        // §4.2：先判 seq 后 open
        let idx = direction_index(direction);
        let last = self.recv_last[idx];
        if last == Some(seq) {
            self.terminate(Termination::SequenceViolation);
            return Err(SessionError::SequenceReplay);
        }
        let expected = match last {
            None => Some(Sequence::ZERO),
            Some(l) => l.next(), // l == 2^64−1 时无后继 ⇒ 一切到达均非期望
        };
        if expected != Some(seq) {
            self.terminate(Termination::SequenceViolation);
            return Err(SessionError::SequenceUnexpected);
        }

        // 截断拒绝：短于 tag 的 sealed 不可能通过认证
        if sealed.len() < TAG_LEN {
            self.terminate(Termination::Authentication);
            return Err(SessionError::AuthenticationFailed);
        }

        let (nonce, aad, cipher) = self.aead_material(mt, direction, seq);
        let mut buf = sealed.to_vec();
        let cut = buf.len() - TAG_LEN;
        let (ct, tag) = buf.split_at_mut(cut);
        let tag = Tag::from_slice(tag);
        match cipher.decrypt_in_place_detached(&nonce, &aad, ct, tag) {
            // 库整体 open：tag 先验证、失败不释放明文（RFC 8439 构造）
            Ok(()) => {
                buf.truncate(buf.len() - TAG_LEN);
                self.recv_last[idx] = Some(seq);
                Ok(Payload::from_vec(buf))
            }
            Err(_) => {
                buf.zeroize(); // §5.2：失败先清缓冲再返回错误
                self.terminate(Termination::Authentication);
                Err(SessionError::AuthenticationFailed)
            }
        }
    }

    /// 正常关闭（§4.4 路径 1 的密钥处置部分；flush/等待由传输层负责）。
    /// 幂等：关闭后一切 seal/open 返回 [`SessionError::Closed`]。
    pub fn close(&mut self) {
        if self.terminated.is_none() {
            self.terminate(Termination::Closed);
        }
    }

    /// 组装一次 AEAD 调用所需的 nonce/AAD/cipher（cipher 从方向密钥定长
    /// 数组**视图**瞬时构造，用后即弃——不在会话对象中驻留第三副本，
    /// §3.2 实现锚：`Key::from_slice` 是唯一密钥装配路径）。
    fn aead_material(
        &self,
        mt: MessageType,
        direction: Direction,
        seq: Sequence,
    ) -> (AeadNonce, [u8; AAD_LEN], ChaCha20Poly1305) {
        let nonce = record_nonce(&self.domain, direction, seq);
        let aad = self.ctx.build_aad(mt, direction, Epoch::new(0), seq);
        let key = self
            .keys
            .as_ref()
            .expect("活动会话必然持有密钥（terminated ⇒ keys==None 不变量）")
            .key_for(direction);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        (AeadNonce::from(*nonce.as_bytes()), aad, cipher)
    }

    fn ensure_active(&self) -> Result<(), SessionError> {
        match self.terminated {
            None => Ok(()),
            Some(Termination::SequenceOverflow) => Err(SessionError::SequenceOverflow),
            Some(_) => Err(SessionError::Closed),
        }
    }

    /// 终止（§4.3 第 1/2/4 步）：停止构造/发送、焚毁双方向密钥、记录原因。
    fn terminate(&mut self, reason: Termination) {
        if let Some(keys) = self.keys.as_mut() {
            keys.burn();
        }
        self.keys = None;
        self.terminated = Some(reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn fixture_ctx(role: Role) -> SessionContext {
        SessionContext {
            role,
            book_id: BookId::from_bytes([0x30; 16]),
            segment: SegmentIndex::ZERO,
            client_nonce: ClientNonce::from_bytes([0x11; 16]),
            server_nonce: ServerNonce::from_bytes([0x22; 16]),
        }
    }

    fn fixture_session(role: Role) -> Session {
        let mut seg = [0u8; 64];
        for (i, b) in seg.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(role_byte(role));
        }
        Session::new(CommittedSegment::from_bytes(seg), fixture_ctx(role))
    }

    const fn role_byte(role: Role) -> u8 {
        match role {
            Role::Client => 0,
            Role::Server => 0x80,
        }
    }

    #[test]
    fn session_nonce_is_xor_of_both_nonces() {
        let ctx = fixture_ctx(Role::Client);
        let z = ctx.session_nonce();
        assert!(
            z.as_bytes()
                .iter()
                .zip(
                    ctx.client_nonce
                        .as_bytes()
                        .iter()
                        .zip(ctx.server_nonce.as_bytes())
                )
                .all(|(&z, (&c, &s))| z == c ^ s)
        );
    }

    #[test]
    fn confirm_occupies_seq_zero_then_data_increments() {
        // §4.1：CONFIRM=0，DATA 自 1 起严格 +1
        let mut s = fixture_session(Role::Client);
        let c = s.seal(MessageType::ClientConfirm, b"confirm-body").unwrap();
        assert_eq!(c.sequence, Sequence::ZERO);
        assert_eq!(s.next_send_sequence().get(), 1);
        let d1 = s.seal(MessageType::Data, b"one").unwrap();
        assert_eq!(d1.sequence.get(), 1);
        let d2 = s.seal(MessageType::Data, b"two").unwrap();
        assert_eq!(d2.sequence.get(), 2);
    }

    #[test]
    fn data_before_confirm_is_rejected_and_terminates() {
        // 类型序号纪律：s=0 时发 DATA ⇒ 0x030B 且整会话终止
        let mut s = fixture_session(Role::Client);
        assert!(matches!(
            s.seal(MessageType::Data, b"x"),
            Err(SessionError::SequenceUnexpected)
        ));
        assert!(!s.is_active());
        assert!(matches!(
            s.seal(MessageType::Data, b"x"),
            Err(SessionError::Closed)
        ));
    }

    #[test]
    fn wrong_pairing_is_rejected_and_terminates() {
        // 客户端不能发 ServerConfirm（0x0306 语义）
        let mut s = fixture_session(Role::Client);
        assert!(matches!(
            s.seal(MessageType::ServerConfirm, b"x"),
            Err(SessionError::WrongDirection)
        ));
        assert!(!s.is_active());
    }

    #[test]
    fn second_confirm_attempt_is_rejected() {
        let mut s = fixture_session(Role::Client);
        s.seal(MessageType::ClientConfirm, b"a").unwrap();
        assert!(matches!(
            s.seal(MessageType::ClientConfirm, b"b"),
            Err(SessionError::SequenceUnexpected)
        ));
        assert!(!s.is_active());
    }

    #[test]
    fn send_overflow_terminates_whole_session_no_wrap() {
        // §4.3：seq=2^64−1 的 record 照常产出；此后任何发送 ⇒ 终止、不回绕
        let mut s = fixture_session(Role::Client);
        s.seal(MessageType::ClientConfirm, b"").unwrap();
        // 直接置位（等价于已发送 2^64−2 条 DATA 后的状态）
        s.send_seq[0] = Sequence::new(u64::MAX - 1);
        let d = s.seal(MessageType::Data, b"last").unwrap();
        assert_eq!(d.sequence.get(), u64::MAX - 1);
        let final_rec = s.seal(MessageType::Data, b"final").unwrap();
        assert_eq!(final_rec.sequence.get(), u64::MAX);
        assert!(!s.is_active(), "2^64-1 移交后立即整会话终止");
        assert!(s.keys.is_none(), "密钥已焚毁");
        assert!(matches!(
            s.seal(MessageType::Data, b"x"),
            Err(SessionError::SequenceOverflow)
        ));
        assert!(matches!(
            s.open(MessageType::Data, Sequence::new(1), final_rec.sealed()),
            Err(SessionError::SequenceOverflow)
        ));
    }

    #[test]
    fn recv_seq_algorithm_edge_at_max() {
        // §4.2 注：last==2^64−1 之后任何到达 ⇒ 重复(0x0204) 或非期望(0x030B)
        let mut s = fixture_session(Role::Server);
        s.seal(MessageType::ServerConfirm, b"").unwrap();
        s.recv_last[0] = Some(Sequence::new(u64::MAX));
        let sealed = [0u8; TAG_LEN + 1];
        assert!(matches!(
            s.open(MessageType::Data, Sequence::new(u64::MAX), &sealed),
            Err(SessionError::SequenceReplay)
        ));
        let mut s2 = fixture_session(Role::Server);
        s2.seal(MessageType::ServerConfirm, b"").unwrap();
        s2.recv_last[0] = Some(Sequence::new(u64::MAX));
        assert!(matches!(
            s2.open(MessageType::Data, Sequence::new(5), &sealed),
            Err(SessionError::SequenceUnexpected)
        ));
    }

    #[test]
    fn confirm_seq_nonzero_rejected() {
        // WP-01 §4.4 [state]：CONFIRM seq≠0 ⇒ 0x030B
        let mut s = fixture_session(Role::Server);
        let sealed = [0u8; TAG_LEN + 1];
        assert!(matches!(
            s.open(MessageType::ClientConfirm, Sequence::new(1), &sealed),
            Err(SessionError::SequenceUnexpected)
        ));
    }

    #[test]
    fn data_seq_zero_rejected() {
        // DATA 不得占用 seq=0（0x030B）
        let mut s = fixture_session(Role::Server);
        let sealed = [0u8; TAG_LEN + 1];
        assert!(matches!(
            s.open(MessageType::Data, Sequence::ZERO, &sealed),
            Err(SessionError::SequenceUnexpected)
        ));
    }

    #[test]
    fn termination_burns_keys_immediately() {
        // §4.3 第 4 步：终止时点先行清零（burn）+ 密钥移出即 Drop 清零；
        // Drop 事件计数按实例精确观察
        let mut s = fixture_session(Role::Client);
        s.seal(MessageType::ClientConfirm, b"").unwrap();
        let ctr = s.keys.as_ref().unwrap().zeroize_counter();
        assert_eq!(ctr.load(Ordering::SeqCst), 0);
        s.close();
        assert_eq!(
            ctr.load(Ordering::SeqCst),
            1,
            "终止即焚毁：burn + Drop 清零"
        );
        assert!(s.keys.is_none());
        drop(s);
        assert_eq!(
            ctr.load(Ordering::SeqCst),
            1,
            "后续 Drop 不再触碰已焚毁密钥"
        );
    }

    #[test]
    fn record_debug_prints_never_secret_material() {
        let mut s = fixture_session(Role::Client);
        let r = s.seal(MessageType::ClientConfirm, b"c").unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("sequence: 0"));
        assert!(dbg.contains("len: 17"), "Debug 只含序号与长度：{dbg}");
        assert!(!dbg.contains("63"), "不含明文/密文 hex 字符");
    }
}
