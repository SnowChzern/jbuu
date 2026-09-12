//! # otp-types —— 共享基础类型与错误分类
//!
//! 实现规划 §2 职责：`BookId`、`SegmentIndex`、`Generation`、方向、epoch、
//! sequence、错误分类；整数边界全部用 newtype 收敛。
//!
//! 禁止事项（规划 §2）：不做 I/O；不持有段正文（64B 段只存在于
//! `otp-book`/`otp-allocator` 的受控世界）。
//!
//! 本 crate 是 workspace 依赖图的根，不依赖任何其他 crate。

#![forbid(unsafe_code)]

use core::fmt;

/// 固定段长：64 字节 = 2 × 256-bit 方向密钥（设计书 §1.2/§3）。
pub const SEGMENT_LEN: usize = 64;
/// 单个方向密钥长度：32 字节。
pub const DIRECTION_KEY_LEN: usize = 32;
/// Poly1305 认证标签长度：16 字节。
pub const TAG_LEN: usize = 16;
/// AEAD nonce 长度：96-bit（RFC 8439）。
pub const NONCE_LEN: usize = 12;

/// 密码本标识。可公开（设计书 §3），但必须绑定两端配置防错拿。
///
/// 字节长度与线格式由 WP-01 冻结；骨架先取 16 字节不透明 ID，
/// 如需调整只能经 WP-01 评审变更，不得在实现中私改。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BookId([u8; 16]);

impl BookId {
    /// 从 16 字节原始值构造。
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    /// 原始字节视图。
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for BookId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // book_id 非秘密（设计书 §3），十六进制打印便于审计比对
        f.write_str("BookId(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// 段索引 / 单调指针。只允许前进，永不回退（设计书 §5/§6）。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SegmentIndex(u64);

impl SegmentIndex {
    /// 指针 0。
    pub const ZERO: Self = Self(0);
    /// 构造。
    pub const fn new(v: u64) -> Self {
        Self(v)
    }
    /// 取原始值。
    pub const fn get(self) -> u64 {
        self.0
    }
    /// 前进一步（预留/提交后 next = i + 1）。
    /// 溢出直接 panic（fail-closed）：指针绝不回卷。
    pub fn next(self) -> Self {
        Self(
            self.0
                .checked_add(1)
                .expect("segment index overflow: pointer must never wrap"),
        )
    }
}

/// 锚 generation：单调递增，用于两副本“采用较高状态”比较。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Generation(u64);

impl Generation {
    /// 构造。
    pub const fn new(v: u64) -> Self {
        Self(v)
    }
    /// 取原始值。
    pub const fn get(self) -> u64 {
        self.0
    }
    /// 递增一代；溢出即 panic（锚 generation 不允许回卷）。
    pub fn succ(self) -> Self {
        Self(
            self.0
                .checked_add(1)
                .expect("generation overflow: must never wrap"),
        )
    }
}

/// record 层单调序号（同方向同段内唯一）。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Sequence(u64);

impl Sequence {
    /// 序号 0（确认消息使用）。
    pub const ZERO: Self = Self(0);
    /// 构造。
    pub const fn new(v: u64) -> Self {
        Self(v)
    }
    /// 取原始值。
    pub const fn get(self) -> u64 {
        self.0
    }
    /// 下一序号；溢出返回 `None`，会话必须立即终止（设计书 §9）。
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }
}

/// 会话 epoch（初始 0；rekey 场景保留）。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Epoch(u32);

impl Epoch {
    /// 构造。
    pub const fn new(v: u32) -> Self {
        Self(v)
    }
    /// 取原始值。
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// 方向。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Direction {
    /// 客户端 -> 服务端。
    ClientToServer,
    /// 服务端 -> 客户端。
    ServerToClient,
}

impl Direction {
    /// 反方向。
    pub const fn opposite(self) -> Self {
        match self {
            Self::ClientToServer => Self::ServerToClient,
            Self::ServerToClient => Self::ClientToServer,
        }
    }
}

/// 本端角色。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Role {
    /// 客户端。
    Client,
    /// 服务端。
    Server,
}

impl Role {
    /// 本角色的发送方向。
    pub const fn send_direction(self) -> Direction {
        match self {
            Self::Client => Direction::ClientToServer,
            Self::Server => Direction::ServerToClient,
        }
    }
}

/// 不透明 nonce（长度按用途区分）。非秘密：只用于区分连接和 nonce 域，
/// 不参与密钥派生（设计书 §4）。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce<const N: usize>([u8; N]);

impl<const N: usize> Nonce<N> {
    /// 从原始字节构造。
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
    /// 原始字节视图。
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> fmt::Debug for Nonce<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Nonce(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// HELLO 中的客户端 nonce（16 字节；WP-01 §4.1 冻结：BYTES(16)）。
pub type ClientNonce = Nonce<16>;
/// ARBITRATE 中的服务端 nonce（16 字节；WP-01 §4.2 决策 D2）。
pub type ServerNonce = Nonce<16>;
/// 会话级 nonce（16 字节；= client_nonce ⊕ server_nonce，WP-01 决策 D3；
/// 是否进入 96-bit nonce 域由 WP-03 定义）。
pub type SessionNonce = Nonce<16>;
/// AEAD 96-bit nonce。
pub type Nonce96 = Nonce<12>;

/// Poly1305 认证标签（16 字节）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthTag([u8; TAG_LEN]);

impl AuthTag {
    /// 从原始字节构造。
    pub const fn from_bytes(bytes: [u8; TAG_LEN]) -> Self {
        Self(bytes)
    }
    /// 原始字节视图。
    pub const fn as_bytes(&self) -> &[u8; TAG_LEN] {
        &self.0
    }
}

impl fmt::Debug for AuthTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthTag(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// 错误分类（审计日志白名单字段之一，规划 §2.2）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ErrorCategory {
    /// 密码本读取/校验。
    Book,
    /// 编解码。
    Codec,
    /// 锚记录/校验。
    Anchor,
    /// 段分配。
    Allocation,
    /// 崩溃恢复。
    Recovery,
    /// 握手/仲裁。
    Handshake,
    /// AEAD 会话。
    Session,
    /// 传输。
    Transport,
    /// 终端/PTY。
    Terminal,
    /// 平台（锁/fsync/环境）。
    Platform,
    /// 内部不变量被破坏（fail-closed）。
    Internal,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_index_is_monotonic() {
        assert!(SegmentIndex::new(0) < SegmentIndex::new(1));
        assert_eq!(SegmentIndex::new(41).next(), SegmentIndex::new(42));
    }

    #[test]
    #[should_panic(expected = "never wrap")]
    fn segment_index_never_wraps() {
        let _ = SegmentIndex::new(u64::MAX).next();
    }

    #[test]
    fn sequence_overflow_is_none_not_wrap() {
        assert_eq!(Sequence::new(u64::MAX).next(), None);
        assert_eq!(Sequence::new(0).next(), Some(Sequence::new(1)));
    }

    #[test]
    fn direction_and_role_pairing() {
        assert_eq!(
            Direction::ClientToServer.opposite(),
            Direction::ServerToClient
        );
        assert_eq!(Role::Client.send_direction(), Direction::ClientToServer);
        assert_eq!(Role::Server.send_direction(), Direction::ServerToClient);
    }

    #[test]
    fn layout_constants_match_design() {
        // 设计书 §1.2/§3：64B 段 = 两个 32B 方向密钥；RFC 8439：96-bit nonce + 16B tag
        assert_eq!(SEGMENT_LEN, 2 * DIRECTION_KEY_LEN);
        assert_eq!(NONCE_LEN, 12);
        assert_eq!(TAG_LEN, 16);
    }
}
