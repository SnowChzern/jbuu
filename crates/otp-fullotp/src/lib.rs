//! # otp-fullotp —— `FULL_OTP_POLY1305` 数据面【核心】
//!
//! 唯一设计依据：`docs/specs/fullotp-design.md`（任务 #68 评审稿，芥末 09-14
//! 已批；任务 #75 实现批 1+批 2）。本 crate 实现其中 §2（密钥消耗模型与双向
//! 段分配）、§3（OTP 数据记录与游标推进）与 §4（流同步/断线/崩溃——数据面
//! 部分）；控制面消息载体（PAD_OFFER/PAD_ACK/PAD_NEED/CLOSE 的 canonical
//! payload）在 [`control`] 定义，**由现有 AEAD 控制通道密封承载**（设计书
//! §1.3），其序号空间与 OTP 数据的 `record_seq` 天然分离。
//!
//! 握手挂载（HELLO/CONFIRM 绑定 mode）与 CLI `--full-otp` 不在本 crate：
//! 等 CLI redesign 批准后另卡接线；本 crate 只暴露可独立测试的数据面。
//!
//! ## 冻结的线格式值（设计书 §3.1 + 本卡实现冻结）
//!
//! | 项 | 值 | 说明 |
//! |---|---|---|
//! | `version` | `0x0003` | 新协议主版本；旧 decoder（v2=0x0002）不会误收 |
//! | `msg_type`（OTP_DATA） | `0x0010` | v3 命名空间内独立类型；0x0001..0x000F 预留 |
//! | `mode` | `0x01` | `FULL_OTP_POLY1305`；不注册裸 XOR（FOD-1） |
//! | `direction` | `0x01` C2S / `0x02` S2C | 与 WP-01 body direction 同值域 |
//!
//! 数值注册的最终确认归 WP-01 修订卡（设计书 §10/§11 阻断项）；本卡冻结
//! 上述值并以 golden vectors 固化（`tests/golden.rs`）。修订若改值必须同步
//! golden vectors 与本表。
//!
//! ## OTP_DATA 记录（设计书 §3.1，全部大端、canonical、公开）
//!
//! ```text
//!  0  2  version          = 0x0003
//!  2  2  msg_type         = 0x0010 (OTP_DATA)
//!  4  1  mode             = 0x01 (FULL_OTP_POLY1305)
//!  5  1  direction        = 0x01 C2S / 0x02 S2C
//!  6  8  bundle_id        会话内从 0 严格递增（分配序号，两方向共用）
//! 14  8  base_segment     bundle 公开基址（128 段对齐不是安全前提）
//! 22  8  record_seq       每方向从 0 严格 +1，不跨连接恢复
//! 30  2  pad_offset       本方向期望 cursor；<=4096
//! 32  2  ciphertext_len   1..=4064 且 offset+32+len<=4096
//! 34  L  ciphertext       = P xor Q（与明文等长）
//! 34+L 16 tag             一次性 Poly1305
//! ```
//!
//! MAC 输入（设计书 §3.1 域分隔要求，逐字节冻结）：
//!
//! ```text
//! DOMAIN_SEP(25B, ASCII "otp-term/full-otp/data/v1")
//! || BE16(DOMAIN_SEP.len()=25)
//! || canonical_header(34B)
//! || ciphertext(L)
//! ```
//!
//! 每 record 消耗（§2.1）：`32B 一次性 Poly1305 key + L B XOR pad`，
//! 从该方向 pad 流顺序切出，用后即弃（消费区原位清零），绝不复用。
//!
//! ## bundle 结构（§2.2/FOD-2）
//!
//! - `PAD_HALF = 4096B`/方向；一个 bundle = 连续 128 段（8192B）；
//! - **C2S 取前半 `B[b..b+64)`，S2C 取后半 `B[b+64..b+128)`**（方向映射由
//!   角色决定，与发起方无关）；
//! - 每方向独立维护 `(bundle_id, base_segment, cursor)`，`cursor ∈ 0..=4096`；
//! - 记录不跨 bundle；剩余 `<=32B` 时该方向尾部整体浪费并切到已 ACK 的下一
//!   bundle；
//! - 首个握手段不属于 bundle，也不得作为 OTP 数据字节。
//!
//! ## 数据泵（§2.3/§8，FOD-6）
//!
//! - `LOW_WATER = 1024B`：任一方向可用量低于低水位即触发 `PAD_NEED`；
//! - **服务端是唯一 bundle 协调者**：先按 fail-to-waste 预留（allocator
//!   `reserve_range(128)`，见 `otp-book::allocator`）再发 `PAD_OFFER`；
//!   同一会话至多一套未决/已 ACK 的下一 bundle 材料；
//! - 客户端只在本地安全指针恰能采纳公告范围后执行同样预留并回 `PAD_ACK`；
//! - 下一 bundle 未 ACK 且当前空间不足 → **backpressure**：不裸发、不改回
//!   AEAD 数据模式、不允许记录跨 bundle；
//! - 切换后旧 bundle 缓冲立即 zeroize（设计书 §2.3/§9.1.8）。
//!
//! ## 安全不变量（设计书 §9.1）
//!
//! 1. 任一 pad 字节至多进入一次 MAC key 或 XOR pad，且二者用途不重叠；
//! 2. C2S/S2C 预留范围不重叠，方向不可交换（direction 绑定进 MAC）；
//! 3. 记录不跨 bundle；切换只到已 ACK 且更高 base 的 bundle；
//! 4. 先持久预留范围（allocator `reserve_range`），后读取 pad；
//! 5. MAC 验证成功前不向 PTY/终端输出任何明文；失败立即关闭、
//!    当前+预取 bundle 尾部全部浪费；
//! 6. 断线/崩溃不恢复 cursor，不续用范围（新连接永远新范围——由调用方
//!    重新握手+`reserve_range` 保证，本 crate 不提供跨连接恢复 API）；
//! 7. mode 不可在连接内切换，不可静默降级（本 crate 无 AEAD 数据路径）；
//! 8. pad/MAC key 类型无 Clone/Debug/Serialize，Drop/失败/切 bundle 时
//!    zeroize；消费区在用后立即原位清零。
//!
//! 禁止事项：不做 KDF/哈希派生（一次性 key 直接取 pad，§5.2）；不调用
//! ChaCha20-Poly1305 冒充 full OTP（与现有 AEAD 不是同一 key 或构造）；
//! 不接受重放/乱序/窗口（接收窗口恒为 1，§6）。
//!
//! 实现归属：榫卯（任务 #75，批 1+批 2）；设计书 docs/specs/fullotp-design.md。

#![forbid(unsafe_code)]

mod control;
mod error;
mod pad;
mod pump;
mod record;
mod wire;

pub use control::{
    CONTROL_CLOSE, CONTROL_PAD_ACK, CONTROL_PAD_NEED, CONTROL_PAD_OFFER, PadControl,
    decode as decode_control,
};
pub use error::{ControlError, OtpError, PadSourceError, PumpError, SendError, WireError};
pub use pad::{
    BUNDLE_BYTES, C2S_HALF_LEN, MAC_KEY_LEN, PAD_HALF, PadSource, PadStream, split_bundle,
};
pub use pump::{FullOtpPump, PumpAction, Received, SendOutcome};
pub use record::{OpenExpectation, OtpPayload, open_record, seal_record};
pub use wire::{
    HEADER_LEN, MAX_CIPHERTEXT_LEN, MAX_FRAME_LEN, MODE_FULL_OTP_POLY1305, MSG_TYPE_OTP_DATA,
    OTP_VERSION, OtpDataRecord, decode as decode_frame,
};

/// 低水位阈值（设计书 §2.3/FOD-2：任一方向可用量低于此值即触发 PAD_NEED）。
pub const LOW_WATER: usize = 1024;
/// MAC 域分隔符（设计书 §3.1：ASCII `otp-term/full-otp/data/v1`，25 字节）。
pub const DOMAIN_SEPARATOR: &[u8; 25] = b"otp-term/full-otp/data/v1";
/// 一个 bundle 的段数（设计书 §2.2：128 段 = 双向各 4096B）。
pub const BUNDLE_SEGMENTS: u64 = 128;

const _: () = assert!(PAD_HALF == 4096, "FOD-2: PAD_HALF 固定 4096B");
const _: () = assert!(BUNDLE_BYTES == 2 * PAD_HALF, "bundle = 双向两个 PAD_HALF");
const _: () = assert!(
    BUNDLE_SEGMENTS * 64 == BUNDLE_BYTES as u64,
    "128 段 = 8192B"
);
const _: () = assert!(
    MAX_CIPHERTEXT_LEN == 4064,
    "最大记录明文 4064B（设计书 §2.1）"
);
const _: () = assert!(
    MAC_KEY_LEN + MAX_CIPHERTEXT_LEN == PAD_HALF,
    "满记录恰耗尽方向流"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_frozen_design() {
        assert_eq!(OTP_VERSION, 0x0003);
        assert_eq!(MSG_TYPE_OTP_DATA, 0x0010);
        assert_eq!(MODE_FULL_OTP_POLY1305, 0x01);
        assert_eq!(LOW_WATER, 1024);
        assert_eq!(HEADER_LEN, 34);
        assert_eq!(DOMAIN_SEPARATOR, b"otp-term/full-otp/data/v1");
    }
}
