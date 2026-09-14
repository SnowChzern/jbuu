//! bundle/pad 材料层：方向流缓冲、游标与材料提取（设计书 §2.2/§2.3）。
//!
//! - [`PadStream`]：单方向 4096B pad 流 + `(bundle_id, base_segment, cursor)`；
//! - [`split_bundle`]：把 `reserve_range(128)` 产出的 8192B 平面字节按
//!   **C2S 前半 / S2C 后半**切成两个方向流（方向映射由角色决定，
//!   §2.2：C2S 恒取前半，与发起方无关）；
//! - [`PadSource`]：数据泵向分配器的材料取用口（服务端预取 / 客户端采纳）。
//!
//! 消费纪律（§2.1/§3.2）：每条记录顺序切出 `32B 一次性 MAC key ‖ L B XOR
//! pad`；**消费区在提取时原位清零**（用后即弃），cursor 只增不减；
//! 记录不跨 bundle（`fit` 判定）。类型义务（§9.1.8）：无 Clone/Debug 暴露
//! pad 内容，Drop = zeroize。

use otp_types::{Direction, SEGMENT_LEN};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::PadSourceError;

/// 每方向 pad 流长度（FOD-2：4096B = 64 段）。
pub const PAD_HALF: usize = 4096;
/// 一次性 Poly1305 key 长度（每记录前置 32B，§2.1）。
pub const MAC_KEY_LEN: usize = 32;
/// C2S 半区长度（= PAD_HALF；独立常量便于布局断言）。
pub const C2S_HALF_LEN: usize = PAD_HALF;
/// 一个 bundle 的总字节数（128 段 × 64B）。
pub const BUNDLE_BYTES: usize = 2 * PAD_HALF;

const _: () = assert!(BUNDLE_BYTES == 128 * SEGMENT_LEN);

/// 一次性 Poly1305 key（从 pad 流直接切出；§5.2：无 KDF、无哈希、
/// clamp 归 Poly1305 算法定义而非密钥派生）。
///
/// 无 Clone/Debug/Display；Drop = zeroize；用后即弃（§9.1.8）。
#[derive(ZeroizeOnDrop)]
pub(crate) struct MacKey([u8; MAC_KEY_LEN]);

impl MacKey {
    pub(crate) fn as_array(&self) -> &[u8; MAC_KEY_LEN] {
        &self.0
    }
}

/// 单方向 pad 流：4096B 缓冲 + 游标状态（§2.3：每方向维护
/// `(bundle_id, base_segment, cursor)`，`cursor ∈ 0..=4096`）。
pub struct PadStream {
    bundle_id: u64,
    base_segment: u64,
    buf: Zeroizing<[u8; PAD_HALF]>,
    cursor: usize,
    #[cfg(test)]
    zeroize_events: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl PadStream {
    /// 由方向半区构造（生产路径：`split_bundle`；首 bundle 由会话建立时
    /// 的 PAD_OFFER/PAD_ACK 预留产出，见 crate 文档）。
    pub(crate) fn from_half(bundle_id: u64, base_segment: u64, half: [u8; PAD_HALF]) -> Self {
        Self {
            bundle_id,
            base_segment,
            buf: Zeroizing::new(half),
            cursor: 0,
            #[cfg(test)]
            zeroize_events: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// 会话内 bundle 分配序号（两方向共用同一分配序号空间，§2.2）。
    #[must_use]
    pub fn bundle_id(&self) -> u64 {
        self.bundle_id
    }

    /// bundle 公开基址（段号）。
    #[must_use]
    pub fn base_segment(&self) -> u64 {
        self.base_segment
    }

    /// 该方向已消耗字节数 = `32*records + sum(L)`（记账基准，§2.1）。
    #[must_use]
    pub fn consumed(&self) -> usize {
        self.cursor
    }

    /// 该方向剩余可用量（含尚未切出的 MAC key 空间）。
    #[must_use]
    pub fn remaining(&self) -> usize {
        PAD_HALF - self.cursor
    }

    /// 本流可容纳的最大记录明文长（记录不跨 bundle；可缩短 L 的上限，
    /// §2.3）。
    #[must_use]
    pub fn max_record_len(&self) -> usize {
        self.remaining()
            .saturating_sub(MAC_KEY_LEN)
            .min(crate::wire::MAX_CIPHERTEXT_LEN)
    }

    /// 长度 `l` 的明文是否放得下（`32 + l <= remaining`）。
    #[must_use]
    pub fn fits(&self, l: usize) -> bool {
        self.remaining() >= MAC_KEY_LEN + l
    }

    /// 剩余是否已低于低水位（§2.3：LOW_WATER=1024 触发 PAD_NEED）。
    #[must_use]
    pub fn below_low_water(&self) -> bool {
        self.remaining() < crate::LOW_WATER
    }

    /// 本实例显式 zeroize 事件计数（仅测试）。
    #[cfg(test)]
    pub(crate) fn zeroize_counter(&self) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        std::sync::Arc::clone(&self.zeroize_events)
    }

    /// 切出本条记录的 32B 一次性 MAC key（§2.1：key 先于 XOR pad）。
    ///
    /// 源区在拷出后**立即原位清零**；cursor 不在此推进（由 [`Self::advance`]
    /// 在记录构造/验证完成后一次性推进，§3.2 消费规则）。
    pub(crate) fn take_mac_key(&mut self) -> MacKey {
        debug_assert!(self.remaining() >= MAC_KEY_LEN, "调用方已判 fit");
        let mut key = [0u8; MAC_KEY_LEN];
        key.copy_from_slice(&self.buf[self.cursor..self.cursor + MAC_KEY_LEN]);
        self.buf[self.cursor..self.cursor + MAC_KEY_LEN].zeroize();
        MacKey(key)
    }

    /// 把本条记录的 L B XOR pad 混入 `dst`（发送侧：`dst` 起始为明文副本，
    /// 得密文；接收侧：`dst` 起始为密文副本，得明文）。
    ///
    /// 源区在混入时逐字节清零（用后即弃）；cursor 不在此推进。
    pub(crate) fn xor_burn_pad(&mut self, dst: &mut [u8]) {
        let start = self.cursor + MAC_KEY_LEN;
        debug_assert!(start + dst.len() <= PAD_HALF, "调用方已判 fit");
        for (i, d) in dst.iter_mut().enumerate() {
            *d ^= self.buf[start + i];
            self.buf[start + i] = 0;
        }
    }

    /// 一次性推进游标 `32 + l`（仅记录构造/验证成功后调用）。
    pub(crate) fn advance(&mut self, l: usize) {
        debug_assert!(self.fits(l), "推进前必须可容纳");
        self.cursor += MAC_KEY_LEN + l;
    }

    /// 切换：把 next 流按值移入当前位并清零旧缓冲（§2.3：切换后旧 bundle
    /// 缓冲立即 zeroize）。返回消耗掉（已清零）的旧流游标，供记账/审计。
    pub(crate) fn retire_into(&mut self, next: PadStream) -> usize {
        let old_consumed = self.cursor;
        self.waste();
        *self = next;
        old_consumed
    }

    /// 整流废弃（关闭/失败路径）：缓冲清零，游标推进至满（尾部浪费，
    /// §4.2 规则 1 的内存面投影）。
    pub(crate) fn waste(&mut self) {
        self.buf.zeroize();
        self.cursor = PAD_HALF;
        #[cfg(test)]
        {
            let _ = self
                .zeroize_events
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

impl core::fmt::Debug for PadStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 公开元数据 + 游标；pad 内容不落任何日志面
        write!(
            f,
            "PadStream{{bundle_id: {}, base_segment: {}, cursor: {}/4096}}",
            self.bundle_id, self.base_segment, self.cursor
        )
    }
}

/// 把 `reserve_range(128)` 的 8192B 平面字节切为 (C2S, S2C) 方向流
/// （§2.2：C2S 取 `B[b..b+64)` 前半，S2C 取 `B[b+64..b+128)` 后半）。
#[must_use]
pub fn split_bundle(
    bundle_id: u64,
    base_segment: u64,
    flat: [u8; BUNDLE_BYTES],
) -> (PadStream, PadStream) {
    let mut c2s = [0u8; PAD_HALF];
    let mut s2c = [0u8; PAD_HALF];
    c2s.copy_from_slice(&flat[..PAD_HALF]);
    s2c.copy_from_slice(&flat[PAD_HALF..]);
    (
        PadStream::from_half(bundle_id, base_segment, c2s),
        PadStream::from_half(bundle_id, base_segment + 64, s2c),
    )
}

/// 方向索引（0 = C2S，1 = S2C）。
pub(crate) const fn direction_index(d: Direction) -> usize {
    match d {
        Direction::ClientToServer => 0,
        Direction::ServerToClient => 1,
    }
}

/// pad 材料来源：数据泵向分配器（`otp-allocator::RangeIssuer::reserve_range`）
/// 的取用口。生产实现（握手/CLI 接线卡）把 `Allocator` 适配到本 trait；
/// 本 crate 的测试用内存实现验证语义。
///
/// 实现义务：
/// - `reserve_next_bundle`（服务端协调者）：fail-to-waste 预留下一个 128 段
///   范围，返回 (base_segment, 8192B)；
/// - `reserve_bundle_at`（客户端）：**仅当**本地安全指针恰为
///   `expected_base` 时采纳公告范围并返回 8192B；指针不符 ⇒
///   [`PadSourceError::PointerMismatch`]（fail closed，不得回退，§2.3）。
pub trait PadSource {
    fn reserve_next_bundle(&mut self) -> Result<(u64, [u8; BUNDLE_BYTES]), PadSourceError>;
    fn reserve_bundle_at(
        &mut self,
        expected_base: u64,
    ) -> Result<[u8; BUNDLE_BYTES], PadSourceError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LOW_WATER;
    use std::sync::atomic::Ordering;

    fn half(seed: u8) -> [u8; PAD_HALF] {
        core::array::from_fn(|i| i as u8 ^ seed)
    }

    #[test]
    fn split_maps_c2s_front_and_s2c_back() {
        let mut flat = [0u8; BUNDLE_BYTES];
        for (i, b) in flat.iter_mut().enumerate() {
            *b = i as u8;
        }
        let (c2s, s2c) = split_bundle(0, 0, flat);
        // §2.2：C2S 前半 = flat[0..4096]，S2C 后半 = flat[4096..8192]
        assert_eq!(c2s.base_segment(), 0);
        assert_eq!(s2c.base_segment(), 64);
        assert_eq!(&c2s.buf[..8], &flat[..8]);
        assert_eq!(&s2c.buf[..8], &flat[4096..4104]);
    }

    #[test]
    fn consumption_slices_never_overlap_and_burn_on_take() {
        // §9.1.1：任一字节至多进入一次 MAC key 或 XOR pad，用途不重叠；
        // 切片顺序 = §2.1 stream slice：key[32] 在前、XOR pad[L] 紧随
        let orig = half(0x00);
        let mut s = PadStream::from_half(0, 0, orig);
        let mut cursor = 0usize;
        for l in [1usize, 100, 33] {
            assert!(s.fits(l));
            let key = s.take_mac_key();
            assert_eq!(key.as_array(), &orig[cursor..cursor + 32]);
            // 发送侧语义：明文副本异或 pad 得密文
            let mut body = vec![0x5Au8; l];
            s.xor_burn_pad(&mut body);
            let pad_slice = &orig[cursor + 32..cursor + 32 + l];
            for (i, b) in body.iter().enumerate() {
                assert_eq!(*b, 0x5A ^ pad_slice[i]);
            }
            s.advance(l);
            cursor += 32 + l;
            assert_eq!(s.consumed(), cursor);
            assert!(s.burned_region_is_zero(0, cursor), "已消费区全部清零");
        }
        assert_eq!(s.consumed(), 32 * 3 + 1 + 100 + 33);
    }

    impl PadStream {
        /// 测试探针：`[from, from+len)` 消费区是否已清零。
        fn burned_region_is_zero(&self, from: usize, len: usize) -> bool {
            self.buf[from..from + len].iter().all(|&b| b == 0)
        }
    }

    #[test]
    fn max_record_len_and_low_water_boundaries() {
        let s = PadStream::from_half(0, 0, half(1));
        assert_eq!(s.max_record_len(), 4064);
        assert!(!s.below_low_water());
        let mut t = PadStream::from_half(0, 0, half(2));
        t.consume_exactly(PAD_HALF - LOW_WATER);
        assert_eq!(t.remaining(), LOW_WATER);
        assert!(!t.below_low_water(), "== LOW_WATER 不触发（低于才触发）");
        t.consume_exactly(MAC_KEY_LEN + 1); // 一条 1B 记录
        assert!(t.below_low_water());
        // remaining=33：恰可容纳 1B 记录；remaining=32：不可再容纳
        let mut u = PadStream::from_half(0, 0, half(3));
        u.consume_exactly(PAD_HALF - 33);
        assert_eq!(u.max_record_len(), 1);
        u.consume_exactly(MAC_KEY_LEN + 1);
        assert_eq!(u.max_record_len(), 0);
        assert!(!u.fits(1));
    }

    impl PadStream {
        /// 测试探针：按 §2.1 切片纪律精确消耗 n 字节（n>=33，可被 32+l 切分）。
        fn consume_exactly(&mut self, mut n: usize) {
            assert!(n > MAC_KEY_LEN, "夹具目标不可达：{n}B 不足一条最小记录");
            while n > 0 {
                let l = self.max_record_len().min(n - 32);
                assert!(l >= 1, "夹具目标不可达：剩余 {n}B 不足一条最小记录");
                let _ = self.take_mac_key();
                let mut body = vec![0u8; l];
                self.xor_burn_pad(&mut body);
                self.advance(l);
                n -= 32 + l;
            }
        }
    }

    #[test]
    fn retire_zeroizes_old_buffer_and_resets_state() {
        let mut cur = PadStream::from_half(3, 384, half(3));
        let ctr = cur.zeroize_counter();
        let _ = cur.take_mac_key();
        let mut body = vec![0u8; 10];
        cur.xor_burn_pad(&mut body);
        cur.advance(10);
        let next = PadStream::from_half(4, 512, half(4));
        let old = cur.retire_into(next);
        assert_eq!(old, 42);
        assert_eq!(ctr.load(Ordering::SeqCst), 1, "旧缓冲显式清零一次");
        assert_eq!(cur.bundle_id(), 4);
        assert_eq!(cur.base_segment(), 512);
        assert_eq!(cur.consumed(), 0);
        assert_eq!(cur.max_record_len(), 4064);
    }

    #[test]
    fn drop_zeroizes_buffer() {
        let s = PadStream::from_half(0, 0, half(5));
        drop(s); // Zeroizing 内部缓冲 Drop 清零（编译期保证，此处仅冒烟）
    }
}
