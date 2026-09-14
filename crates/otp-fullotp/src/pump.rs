//! full-OTP 数据泵状态机（设计书 §2.3/§4.1/§8.2）。
//!
//! 职责与冻结语义：
//!
//! - **双向独立推进**：每方向维护 `(bundle_id, base_segment, cursor)`
//!   （§2.3）；两方向可处在不同 bundle 序号上（方向失衡只浪费失衡方向
//!   尾部，§2.2），但材料持有量恒受"当前 + 下一 bundle 两套/方向"约束；
//! - **服务端唯一协调者**（§2.3）：`PAD_NEED` → fail-to-waste 预留下一
//!   整个 bundle（经 [`PadSource`]）→ `PAD_OFFER` → 客户端本地安全指针
//!   恰能采纳才同样预留并回 `PAD_ACK`；任一侧失败 ⇒ 已预留范围全浪费并
//!   关闭，**不得回退**；
//! - **单一未决约束**：同一会话至多一套"下一 bundle"材料（两方向 next
//!   半区同时空才允许新预取），杜绝无限缓存；
//! - **backpressure**（§2.3）：当前空间不足且下一 bundle 未就绪 ⇒
//!   [`SendOutcome::Backpressure`]——不裸发、不改回 AEAD、记录不跨
//!   bundle；剩余 `<=32B` 时该方向尾部整体浪费后切换；
//! - **可缩短 L**（§2.3）：剩余不足以容纳完整明文时按
//!   `max_record_len` 截断发送，`consumed_plaintext < plaintext.len()`
//!   由调用方续发（§8.2 批量填充摊薄 32B key）；
//! - **旧 bundle 缓冲切换即 zeroize**（§2.3/§9.1.8）；
//! - **任何数据面/控制面失败 ⇒ 关闭并浪费全部材料**（§3.2/§9.2）；
//!   断线/崩溃不恢复 cursor，本类型不提供跨连接恢复 API（§4.2：
//!   重新连接走新握手 + 新 `reserve_range`，由接线卡保证）。
//!
//! 首个握手段不属于 bundle：构造 [`FullOtpPump`] 的 bundle 0 材料必须来自
//! 握手段之后的 `reserve_range(128)`（接线卡负责顺序，本类型只收材料）。
//! 接收侧切换只需本端持有材料；**ACK 门只约束本端发送方向**（发送的数据
//! 必须来自对端已采纳的 bundle），与 §2.3"切换只到已 ACK 的下一 bundle"
//! 一致且避免跨通道排序死锁。
//!
//! **有序通道契约**：调用方必须按单一有序传输（同一 TCP 连接上的控制与
//! 数据帧）同序投递控制消息与 OTP_DATA（§4.1：同步由自定界 frame +
//! 四重约束保证，不引入乱序容忍）。在此前提下 PAD_OFFER(N+1) 不会领先
//! bundle N 的末条 OTP_DATA 到达，泵对重复/乱序控制消息 fail closed。

use otp_types::{Direction, Role};

use crate::control::PadControl;
use crate::error::{OtpError, PadSourceError, PumpError, SendError};
use crate::pad::{BUNDLE_BYTES, PadSource, PadStream, direction_index, split_bundle};
use crate::record::{OpenExpectation, OtpPayload, open_record, seal_record};
use crate::wire::OtpDataRecord;

/// 泵要求调用方在 AEAD 控制通道上发送的消息（由调用方密封为控制 record）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PumpAction {
    /// 某方向可用量低于 [`crate::LOW_WATER`]：向服务端协调者发 `PAD_NEED`
    /// （客户端路径；服务端自身低水位直接走 [`FullOtpPump::server_prefetch`]）。
    SendPadNeed,
    /// 服务端协调者已完成预取：向客户端发 `PAD_OFFER`。
    SendPadOffer { bundle_id: u64, base_segment: u64 },
    /// 客户端已采纳：回 `PAD_ACK`。
    SendPadAck { bundle_id: u64 },
}

/// [`FullOtpPump::send`] 的结局。
pub enum SendOutcome {
    /// 成功封装一条记录（可能按 bundle 剩余缩短了 L，§2.3）。
    Record {
        /// 已生成的 wire 记录。
        record: OtpDataRecord,
        /// 本条吸收的明文字节数（`<= plaintext.len()`；剩余由调用方续发）。
        consumed_plaintext: usize,
        /// 发送方向是否已低于低水位（是 ⇒ 调用方应触发 PAD_NEED 路径）。
        need_pad: bool,
    },
    /// 背压：当前方向剩余 `<33B` 且下一 bundle 未就绪。调用方稍后重试，
    /// **不得**裸发、不得改回 AEAD 数据模式（§2.3）。
    Backpressure,
}

impl core::fmt::Debug for SendOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Record {
                record,
                consumed_plaintext,
                need_pad,
            } => write!(
                f,
                "Record{{record: {record:?}, consumed_plaintext: {consumed_plaintext}, \
                 need_pad: {need_pad}}}"
            ),
            Self::Backpressure => f.write_str("Backpressure"),
        }
    }
}

/// [`FullOtpPump::receive`] 的产物。
pub struct Received {
    /// 完整且 MAC 成功的明文（一次性交付，§3.2）。
    pub plaintext: OtpPayload,
    /// 接收方向是否已低于低水位。
    pub need_pad: bool,
}

/// 单方向平面：当前流 + 下一流（材料持有量 ≤ 两套/方向，§2.3）。
struct DirPlane {
    current: PadStream,
    next: Option<PadStream>,
}

/// full-OTP 数据泵。
pub struct FullOtpPump {
    role: Role,
    planes: [DirPlane; 2],
    /// 本端发送方向下一 record_seq（每方向从 0 严格 +1，§3.1）。
    send_seq: u64,
    /// 本端接收方向下一期望 record_seq。
    recv_seq: u64,
    /// 下一次预取/公告的 bundle 分配序号（会话内从 0 严格递增，§3.1）。
    next_bundle_id: u64,
    /// 服务端视角：当前"下一 bundle"是否已被客户端 PAD_ACK（发送方向
    /// 切换门；客户端采纳即就绪，由角色分支保证）。
    next_acked: bool,
    /// 服务端视角：等待 PAD_ACK 的 bundle 分配序号（单一未决约束的精确状态：
    /// 任一时刻至多一个未 ACK 的 offer）。
    pending_ack: Option<u64>,
    /// 会话累计消耗/方向（跨 bundle 求和：`32*records + sum(L)`，§2.1 记账）。
    session_consumed: [usize; 2],
    closed: bool,
}

impl FullOtpPump {
    /// 以 bundle 0 材料建立泵（设计书 §2.3：会话建立后先预留 bundle 0，
    /// 完成双方 PAD_OFFER/PAD_ACK 后才允许首条 OTP_DATA——接线卡保证）。
    ///
    /// `bundle0_flat` 必须来自握手段之后的 `reserve_range(128)`
    /// （C2S 前 64 段 / S2C 后 64 段，见 [`split_bundle`]）。
    #[must_use]
    pub fn new(role: Role, base_segment: u64, bundle0_flat: [u8; BUNDLE_BYTES]) -> Self {
        let (c2s, s2c) = split_bundle(0, base_segment, bundle0_flat);
        Self {
            role,
            planes: [
                DirPlane {
                    current: c2s,
                    next: None,
                },
                DirPlane {
                    current: s2c,
                    next: None,
                },
            ],
            send_seq: 0,
            recv_seq: 0,
            next_bundle_id: 1,
            next_acked: false,
            pending_ack: None,
            session_consumed: [0, 0],
            closed: false,
        }
    }

    /// 本端角色。
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    /// 会话是否仍在活动。
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.closed
    }

    /// 指定方向当前 bundle 内的游标（0..=4096；bundle 内记账）。
    #[must_use]
    pub fn cursor(&self, d: Direction) -> usize {
        self.planes[direction_index(d)].current.consumed()
    }

    /// 指定方向**会话累计**消耗字节数（跨 bundle：`32*records + sum(L)`，
    /// §2.1 对账口径；只统计成功封装/成功验证交付的记录）。
    #[must_use]
    pub fn session_consumed(&self, d: Direction) -> usize {
        self.session_consumed[direction_index(d)]
    }

    /// 指定方向的剩余可用量。
    #[must_use]
    pub fn remaining(&self, d: Direction) -> usize {
        self.planes[direction_index(d)].current.remaining()
    }

    /// 指定方向当前流的 `(bundle_id, base_segment)`（公开元数据，审计/测试）。
    #[must_use]
    pub fn current_bundle(&self, d: Direction) -> (u64, u64) {
        let p = &self.planes[direction_index(d)].current;
        (p.bundle_id(), p.base_segment())
    }

    /// 本端发送方向下一 record_seq（审计/测试）。
    #[must_use]
    pub fn next_send_seq(&self) -> u64 {
        self.send_seq
    }

    /// 本端发送方向。
    fn send_dir(&self) -> Direction {
        self.role.send_direction()
    }

    /// 本端接收方向。
    fn recv_dir(&self) -> Direction {
        self.send_dir().opposite()
    }

    /// 关闭（正常/失败共用）：浪费全部材料（尾部 SPENT/WASTED，§4.2）。
    /// 幂等；此后一切数据面/控制面操作返回 [`OtpError::Closed`]。
    pub fn close(&mut self) {
        if !self.closed {
            self.fail_waste_all();
            self.closed = true;
        }
    }

    /// 发送一条（或一段）明文（§2.3 发送算法）。
    ///
    /// - 能容纳：封装记录；明文超长/剩余不足则按 `max_record_len` 缩短，
    ///   `consumed_plaintext` 告知调用方续发；
    /// - 剩余 `<=32B`：尾部整体浪费并切到已就绪的下一 bundle；下一 bundle
    ///   未就绪 ⇒ [`SendOutcome::Backpressure`]。
    ///
    /// # Errors
    /// [`SendError::Closed`] / [`SendError::EmptyPlaintext`] /
    /// [`SendError::SequenceExhausted`]（record_seq 空间耗尽 ⇒ 关闭，§3.1）。
    pub fn send(&mut self, plaintext: &[u8]) -> Result<SendOutcome, SendError> {
        if self.closed {
            return Err(SendError::Closed);
        }
        if plaintext.is_empty() {
            return Err(SendError::EmptyPlaintext);
        }
        let dir = self.send_dir();
        let idx = direction_index(dir);
        let seq = self.send_seq;

        // 剩余 <=32B（放不下任何记录）：尾部浪费，切到已就绪的下一 bundle
        if self.planes[idx].current.max_record_len() == 0 {
            if !self.next_ready_for_send(dir) {
                return Ok(SendOutcome::Backpressure);
            }
            let next = self.planes[idx].next.take().expect("就绪判定已保证存在");
            self.planes[idx].current.retire_into(next); // 旧缓冲立即 zeroize
            self.refresh_ack_state_after_switch();
        }
        let fit = self.planes[idx].current.max_record_len();
        debug_assert!(fit >= 1, "切换后必然可容纳至少 1B 记录");
        let l = plaintext.len().min(fit);

        let sealed = {
            let plane = &mut self.planes[idx];
            seal_record(&mut plane.current, dir, seq, &plaintext[..l])
        };
        let record = match sealed {
            Ok(r) => r,
            Err(e) => {
                // 调用方已保证 fit：此路仅内部不变量破坏，fail closed
                self.fail(e);
                return Err(SendError::Internal);
            }
        };
        // §3.1：seq 严格 +1；2^64−1 之后无后继 ⇒ 关闭（不回绕）
        match self.send_seq.checked_add(1) {
            Some(next) => self.send_seq = next,
            None => {
                self.close();
                return Err(SendError::SequenceExhausted);
            }
        }
        self.session_consumed[idx] += crate::pad::MAC_KEY_LEN + l;
        let need_pad = self.planes[idx].current.below_low_water();
        Ok(SendOutcome::Record {
            record,
            consumed_plaintext: l,
            need_pad,
        })
    }

    /// 接收并验证一条 OTP_DATA 记录（§3.2 接收顺序：格式 → 方向 → bundle →
    /// seq → offset → tag → 一次性交付）。
    ///
    /// # Errors
    /// 任何 [`OtpError`] ⇒ 泵已关闭、全部材料浪费；绝不输出部分明文。
    pub fn receive(&mut self, frame: &[u8]) -> Result<Received, OtpError> {
        if self.closed {
            return Err(OtpError::Closed);
        }
        let dir = self.recv_dir();
        let idx = direction_index(dir);

        // 结构预判：方向、以及是否为对端已切换的下一 bundle 记录
        let peek = crate::wire::decode(frame)?;
        if peek.direction != dir {
            return Err(self.fail(OtpError::Direction));
        }
        let cur_id = self.planes[idx].current.bundle_id();
        if peek.bundle_id == cur_id + 1 {
            let next_ok = self.planes[idx]
                .next
                .as_ref()
                .is_some_and(|n| n.bundle_id() == peek.bundle_id);
            if !next_ok {
                return Err(self.fail(OtpError::Bundle));
            }
            let next = self.planes[idx].next.take().expect("next_ok 已保证存在");
            self.planes[idx].current.retire_into(next); // 旧缓冲立即 zeroize
            self.refresh_ack_state_after_switch();
        }
        // bundle_id/base 与本端状态不符（含 cur_id+1 之外的任何跳变）在
        // open_record 的 Bundle 判定统一拒绝
        let expect = OpenExpectation {
            direction: dir,
            bundle_id: self.planes[idx].current.bundle_id(),
            base_segment: self.planes[idx].current.base_segment(),
            record_seq: self.recv_seq,
        };
        let opened = open_record(&mut self.planes[idx].current, &expect, frame);
        let plaintext = match opened {
            Ok(p) => p,
            Err(e) => return Err(self.fail(e)),
        };
        let l = peek.ciphertext.len();
        self.session_consumed[idx] += crate::pad::MAC_KEY_LEN + l;
        let need_pad = self.planes[idx].current.below_low_water();
        match self.recv_seq.checked_add(1) {
            Some(next) => self.recv_seq = next,
            None => {
                self.close();
                return Err(OtpError::Closed);
            }
        }
        Ok(Received {
            plaintext,
            need_pad,
        })
    }

    /// 服务端协调者：本地低水位自预取（语义等价收到 `PAD_NEED`，§2.3）。
    ///
    /// 单一未决约束：任一方向仍持有 next 材料 ⇒ 不再预取（返回 `None`）。
    ///
    /// # Errors
    /// [`PadSourceError`] ⇒ 已 fail closed（预取失败/角色误用 ⇒ 全浪费）。
    pub fn server_prefetch(
        &mut self,
        source: &mut dyn PadSource,
    ) -> Result<Option<PumpAction>, PadSourceError> {
        if self.closed {
            return Ok(None);
        }
        if self.role != Role::Server {
            self.fail_waste_all();
            self.closed = true;
            return Err(PadSourceError::Reserve("coordinator-must-be-server"));
        }
        if self.planes[0].next.is_some() || self.planes[1].next.is_some() {
            return Ok(None); // 至多一套未决/已 ACK 材料（§2.3）
        }
        self.prefetch(source)
    }

    /// 处理一条控制面消息（payload 由调用方从 AEAD 控制通道解出）。
    ///
    /// # Errors
    /// [`PumpError::Data`]：角色/序号违规或会话已关闭（fail closed）；
    /// [`PumpError::Source`]：材料来源失败（已 fail closed，全浪费）。
    pub fn on_control(
        &mut self,
        msg: &PadControl,
        source: &mut dyn PadSource,
    ) -> Result<Vec<PumpAction>, PumpError> {
        if self.closed {
            return Err(PumpError::Data(OtpError::Closed));
        }
        match *msg {
            PadControl::PadNeed => {
                // 唯一协调者：客户端收到 PadNeed 属协议违规（fail closed）
                if self.role != Role::Server {
                    return Err(PumpError::Data(self.fail(OtpError::Closed)));
                }
                self.server_prefetch(source)
                    .map(|action| action.into_iter().collect())
                    .map_err(PumpError::Source)
            }
            PadControl::PadOffer {
                bundle_id,
                base_segment,
            } => {
                if self.role != Role::Client {
                    return Err(PumpError::Data(self.fail(OtpError::Closed)));
                }
                if bundle_id != self.next_bundle_id {
                    return Err(PumpError::Data(self.fail(OtpError::Bundle)));
                }
                if self.planes[0].next.is_some() || self.planes[1].next.is_some() {
                    // 单一未决约束被打破（重复/乱序 offer）
                    return Err(PumpError::Data(self.fail(OtpError::Bundle)));
                }
                // 客户端只在本地安全指针恰能采纳该范围后同样预留（§2.3）
                let flat = match source.reserve_bundle_at(base_segment) {
                    Ok(f) => f,
                    Err(e) => {
                        self.fail_waste_all();
                        self.closed = true;
                        return Err(PumpError::Source(e));
                    }
                };
                let (c2s, s2c) = split_bundle(bundle_id, base_segment, flat);
                self.planes[0].next = Some(c2s);
                self.planes[1].next = Some(s2c);
                self.next_bundle_id += 1;
                Ok(vec![PumpAction::SendPadAck { bundle_id }])
            }
            PadControl::PadAck { bundle_id } => {
                if self.role != Role::Server {
                    return Err(PumpError::Data(self.fail(OtpError::Closed)));
                }
                // 精确匹配唯一未决 offer（接收面可能已先行切换并消耗 next 材料，
                // 故不以此判定，而以 pending_ack 为准）
                if self.pending_ack != Some(bundle_id) {
                    return Err(PumpError::Data(self.fail(OtpError::Bundle)));
                }
                self.next_acked = true;
                self.pending_ack = None;
                Ok(Vec::new())
            }
            PadControl::Close => {
                self.close();
                Ok(Vec::new())
            }
        }
    }

    /// 发送方向切换门（§2.3：只切到已 ACK 且更高 base 的 bundle；
    /// 客户端采纳即就绪）。
    fn next_ready_for_send(&self, dir: Direction) -> bool {
        self.planes[direction_index(dir)].next.is_some()
            && (self.role == Role::Client || self.next_acked)
    }

    /// 预取并公告下一 bundle（仅服务端协调者；两方向 next 均空才允许）。
    fn prefetch(
        &mut self,
        source: &mut dyn PadSource,
    ) -> Result<Option<PumpAction>, PadSourceError> {
        let bundle_id = self.next_bundle_id;
        let (base, flat) = match source.reserve_next_bundle() {
            Ok(v) => v,
            Err(e) => {
                self.fail_waste_all();
                self.closed = true;
                return Err(e);
            }
        };
        let (c2s, s2c) = split_bundle(bundle_id, base, flat);
        self.planes[0].next = Some(c2s);
        self.planes[1].next = Some(s2c);
        self.next_bundle_id += 1;
        self.next_acked = false;
        self.pending_ack = Some(bundle_id);
        Ok(Some(PumpAction::SendPadOffer {
            bundle_id,
            base_segment: base,
        }))
    }

    /// 两方向都已切走 next 时复位 ACK 门（下一轮预取由
    /// `server_prefetch` 的空槽判定实际放行）。
    fn refresh_ack_state_after_switch(&mut self) {
        if self.planes[0].next.is_none() && self.planes[1].next.is_none() {
            self.next_acked = false;
        }
    }

    /// 数据面失败：浪费全部材料并标记关闭（§3.2/§9.2）。
    fn fail(&mut self, e: OtpError) -> OtpError {
        self.fail_waste_all();
        self.closed = true;
        e
    }

    fn fail_waste_all(&mut self) {
        for plane in &mut self.planes {
            if let Some(n) = plane.next.as_mut() {
                n.waste();
            }
            plane.next = None;
            plane.current.waste();
        }
    }
}
