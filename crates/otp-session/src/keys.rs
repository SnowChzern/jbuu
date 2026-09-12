//! 密钥材料类型与 64B→2×32B 拆分（WP-03 §3/§5，冻结）。
//!
//! 拆分规则（§3.1）：`K_c2s = B[i][0..32]`、`K_s2c = B[i][32..64]`——
//! 原字节原顺序直接作为 ChaCha20 的 256-bit key，**不做任何派生**
//! （§3.2 六条禁令：无 KDF/哈希、无代数重组、无双向复用、不混入上下文、
//! 无 derive 接口、无套件替换）。拆分恰在此处执行一次（split-once），
//! 64B 原缓冲在拆分返回前清零（§5.1 L2）。
//!
//! 生命周期（§5.2）：运行期秘密密钥材料至多以两个定长数组存在
//! （"恰两副本"不变量）；类型不实现 Clone/Debug/Display/Eq/序列化；
//! Drop = zeroize；禁止 Vec/String/Box 持有密钥。AEAD 密钥装配的唯一
//! 合规路径是 RustCrypto `Key::from_slice(&half)`（§3.2 实现锚），
//! 由 [`crate::Session`] 在每次 seal/open 时从本类型的定长数组视图构造
//! 瞬时 cipher，不在会话对象中长期驻留第三副本。
//!
//! 测试可观测性：每实例携带 cfg(test) 计数器，Drop 清零事件按实例精确
//! 计数（并行测试无共享状态竞态）；生产编译零开销。

use otp_types::{DIRECTION_KEY_LEN, Direction, SEGMENT_LEN};
use zeroize::Zeroize;

/// 每实例的 zeroize 事件计数器（仅测试编译；Drop 时 +1）。
#[cfg(test)]
type ZeroizeCounter = std::sync::Arc<std::sync::atomic::AtomicUsize>;

/// 已提交段（64B）：会话密钥的唯一合法来源。
///
/// 合法生产者是 `otp-allocator` 的 `SegmentIssuer::issue()`（WP-07，双锚
/// 最终 fsync 成功后的唯一产出；规划 §2.2）。M1 阶段（allocator 未落地）
/// 由测试密码本夹具经 [`CommittedSegment::from_bytes`] 构造；WP-07 落地时
/// 由握手层把 issue() 的段**按值**移交给 [`SessionKeys::split`]（本类型与
/// allocator 侧同名类型的归并在 WP-07/WP-11 集成时统一，见任务 #37 交付帖）。
///
/// 类型义务（§5.2.2）：不实现 Clone/Debug/Display/Eq/序列化；Drop 清零。
pub struct CommittedSegment {
    inner: [u8; SEGMENT_LEN],
    #[cfg(test)]
    zeroize_events: ZeroizeCounter,
}

impl CommittedSegment {
    /// 由 64B 段正文构造（按值移入，无第二副本）。
    pub fn from_bytes(bytes: [u8; SEGMENT_LEN]) -> Self {
        Self {
            inner: bytes,
            #[cfg(test)]
            zeroize_events: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// 本实例的 zeroize 事件计数句柄（仅测试）。
    #[cfg(test)]
    pub(crate) fn zeroize_counter(&self) -> ZeroizeCounter {
        std::sync::Arc::clone(&self.zeroize_events)
    }
}

impl Drop for CommittedSegment {
    fn drop(&mut self) {
        self.inner.zeroize();
        #[cfg(test)]
        self.zeroize_events
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// 会话双方向密钥：`[c2s, s2c]` 两个 32B 定长数组（运行期密钥材料的
/// 唯一驻留形态，§5.2.1）。
///
/// 客户端以 c2s 发送、s2c 接收；服务端对称（§3.1）。
pub struct SessionKeys {
    c2s: [u8; DIRECTION_KEY_LEN],
    s2c: [u8; DIRECTION_KEY_LEN],
    #[cfg(test)]
    zeroize_events: ZeroizeCounter,
}

impl SessionKeys {
    /// 拆分（§3.1，恰一次）：按值消耗 [`CommittedSegment`]，前半 → K_c2s、
    /// 后半 → K_s2c；拆分返回前清零 64B 原缓冲（随后段 Drop 会再清一次，
    /// 幂等无害）。
    pub fn split(segment: CommittedSegment) -> Self {
        let mut segment = segment;
        let keys = Self {
            c2s: segment.inner[..DIRECTION_KEY_LEN]
                .try_into()
                .expect("前半恰 32B（编译期常量切片）"),
            s2c: segment.inner[DIRECTION_KEY_LEN..]
                .try_into()
                .expect("后半恰 32B（编译期常量切片）"),
            #[cfg(test)]
            zeroize_events: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        segment.inner.zeroize();
        keys
    }

    /// 取指定方向的密钥视图（仅 crate 内部用于装配瞬时 AEAD cipher）。
    pub(crate) fn key_for(&self, direction: Direction) -> &[u8; DIRECTION_KEY_LEN] {
        match direction {
            Direction::ClientToServer => &self.c2s,
            Direction::ServerToClient => &self.s2c,
        }
    }

    /// 立即焚毁（§4.3 第 4 步 / §5.1 L4：任一终止时点先行清零，不等 Drop）。
    /// 幂等；清零本身不产生计数事件（Drop 事件才是生命周期证据）。
    pub(crate) fn burn(&mut self) {
        self.c2s.zeroize();
        self.s2c.zeroize();
    }

    /// 本实例的 zeroize 事件计数句柄（仅测试）。
    #[cfg(test)]
    pub(crate) fn zeroize_counter(&self) -> ZeroizeCounter {
        std::sync::Arc::clone(&self.zeroize_events)
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.c2s.zeroize();
        self.s2c.zeroize();
        #[cfg(test)]
        self.zeroize_events
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn fixture_segment() -> CommittedSegment {
        // WP-03 §6.1 测试段 0：00 01 .. 3F（夹具值，非秘密）
        let mut seg = [0u8; SEGMENT_LEN];
        for (i, b) in seg.iter_mut().enumerate() {
            *b = i as u8;
        }
        CommittedSegment::from_bytes(seg)
    }

    #[test]
    fn split_takes_halves_in_order_without_derivation() {
        // §3.1：K_c2s = 前半 00..1F，K_s2c = 后半 20..3F（直接切片，无重组）
        let first_half: [u8; 32] = core::array::from_fn(|i| i as u8);
        let second_half: [u8; 32] = core::array::from_fn(|i| 0x20 + i as u8);
        let keys = SessionKeys::split(fixture_segment());
        assert_eq!(keys.key_for(Direction::ClientToServer), &first_half);
        assert_eq!(keys.key_for(Direction::ServerToClient), &second_half);
    }

    #[test]
    fn split_and_drop_zeroize_everything() {
        // §5.1 L2/L4：64B 原缓冲在拆分内清零 + 双密钥 Drop 清零
        let seg = fixture_segment();
        let seg_ctr = seg.zeroize_counter();
        let keys = SessionKeys::split(seg);
        assert_eq!(
            seg_ctr.load(Ordering::SeqCst),
            1,
            "split 按值消耗段：64B 缓冲已清零一次"
        );
        let key_ctr = keys.zeroize_counter();
        assert_eq!(key_ctr.load(Ordering::SeqCst), 0);
        drop(keys);
        assert_eq!(key_ctr.load(Ordering::SeqCst), 1, "SessionKeys Drop 清零");
        assert_eq!(seg_ctr.load(Ordering::SeqCst), 1, "段缓冲未被二次触碰");
    }

    #[test]
    fn burn_zeroizes_immediately_and_drop_zeroizes_again() {
        // §4.3 第 4 步：终止时点先行清零；Drop 再清一次（幂等，计数两次事件）
        let mut keys = SessionKeys::split(fixture_segment());
        keys.burn();
        assert!(
            keys.key_for(Direction::ClientToServer)
                .iter()
                .all(|&b| b == 0)
        );
        assert!(
            keys.key_for(Direction::ServerToClient)
                .iter()
                .all(|&b| b == 0)
        );
        let ctr = keys.zeroize_counter();
        assert_eq!(ctr.load(Ordering::SeqCst), 0, "burn 不计事件");
        drop(keys);
        assert_eq!(ctr.load(Ordering::SeqCst), 1, "Drop 清零事件恰一次");
    }

    #[test]
    fn committed_segment_drop_zeroizes() {
        let seg = fixture_segment();
        let ctr = seg.zeroize_counter();
        drop(seg);
        assert_eq!(ctr.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn zero_bytes_segment_still_yields_all_zero_keys() {
        // 边界：全零段拆出全零密钥（不拒绝——段内容检查归签发层，v2 §9 测试 1）
        let keys = SessionKeys::split(CommittedSegment::from_bytes([0u8; SEGMENT_LEN]));
        assert!(
            keys.key_for(Direction::ClientToServer)
                .iter()
                .all(|&b| b == 0)
        );
        assert!(
            keys.key_for(Direction::ServerToClient)
                .iter()
                .all(|&b| b == 0)
        );
    }
}
