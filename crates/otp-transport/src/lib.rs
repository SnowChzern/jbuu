//! # otp-transport —— framed stream 传输层
//!
//! 实现规划 §2 职责：framed stream、loopback/TCP 适配、超时和关闭。
//! 本 crate 是规划 §4 WP-12（任务 #50）的落地，唯一行为依据为
//! `docs/specs/wp01-wire-format-and-error-model.md` §1.1/§3.2 的**流式读取
//! 等价语义**（先攒 8 字节帧头、按 payload_len 收齐消息体、EOF 中途 →
//! 0x0308），不引入任何新线格式。
//!
//! ## FramedStream 异步形态决策（wp-04 基线评审点 ② 终裁）
//!
//! wp-04 基线文档（`docs/specs/wp-04-rust-workspace-baseline.md` §评审点）
//! 预留"transport 异步形态"由 WP-12 评审定稿。**决策：保持同步阻塞形态
//! （std::net + 每连接一线程），不引入异步运行时**。理由：
//!
//! 1. **规划只约束语义，不指定运行时**。规划 §2 要求"异步 framed stream"
//!    指并发/不互相阻塞的*语义*（多连接并行、读写超时可控、半关闭语义
//!    明确），而非特定 async 框架。同步阻塞 + 线程同样满足该语义，且
//!    M1 验收（loopback 1 MiB 回显 + TCP 双进程回显）均以本形态实测。
//! 2. **依赖基线不含异步运行时**。规划 §1.2 拍板的依赖清单（rustix/
//!    chacha20poly1305/getrandom/zeroize/secrecy/sha2/proptest/clap）没有
//!    tokio/async-std；引入任一将新增约百个传递依赖，直接扩大 cargo-deny
//!    与供应链审计面（M0 验收 5、M5 SBOM/漏洞审计），与"最小依赖、可审计"
//!    的基线原则冲突。
//! 3. **workspace 全同步，单独异步化只会增加桥接层**。allocator 真实
//!    fsync 事务、handshake 显式消息驱动、session 纯计算均为同步 API；
//!    async transport 上层仍是同步状态机，必须 spawn_blocking 回线程池，
//!    代码与审计复杂度双升而收益为零。
//! 4. **对象安全（dyn 兼容）是硬需求**。Rust 原生 AFIT（1.75+ `async fn`
//!    in trait）不兼容 `dyn`，而本 trait 需要以 `&mut dyn FramedStream`
//!    供会话驱动/终端层复用（与 handshake 的 `dyn SegmentIssuer` 同构）；
//!    `#[async_trait]` 搬运方案则引入隐藏分配与 Send 约束噪音。
//! 5. **关闭语义直接映射 syscall**。半关闭 = `shutdown(Write)`、优雅关闭 =
//!    `shutdown(Both)`，读写超时 = `SO_RCVTIMEO`/`SO_SNDTIMEO`（loopback
//!    侧为等价的 condvar 超时）。fail-closed 路径（超时/EOF/对端关闭均
//!    立即报错并关闭）在同步形态下逐条可审计。
//! 6. **反悔成本受控**。trait 面最小（5 个方法、纯字节语义）；未来 WP-16
//!    若需要事件循环，可平行增设 async twin trait 或线程桥接，不动本
//!    trait 及其调用方。
//!
//! ## 边界（规划 §2 禁止事项 + 任务 #50 硬边界）
//!
//! - **零协议语义解析**：本层只搬运长度前缀帧——读满 8 字节帧头、取
//!   `BE32(frame[4..8])` 为 payload_len、按上限 [`MAX_WIRE_FRAME`] 防御性
//!   校验后收齐消息体。version/msg_type/payload 结构**一律不查**，归
//!   otp-codec；密文开封归 otp-session。不吞掉解析/认证错误：帧字节
//!   原样上抛。
//! - **零段材料/锚接触**：生产依赖仅 otp-types（错误类别）与 otp-codec
//!   （帧常量/错误码注册表），名称解析上不可达 otp-book/otp-allocator/
//!   otp-session/otp-handshake（机械证明见 `tests/architecture.rs`）。
//! - **无状态**：不赋予网络消息持久化语义；连接与消息不落盘。
//! - 错误对接 WP-01 §5.2 注册表（[`TransportError::code`]），不新造平行
//!   错误体系。
//!
//! 实现归属：榫卯 WP-12（任务 #50）。

#![forbid(unsafe_code)]

mod frame;
mod loopback;
mod tcp;

pub use loopback::{LoopbackTransport, WireTap};
pub use tcp::{TcpListener, TcpTransport};

use std::time::Duration;

use otp_codec::ErrorCode;
use otp_types::ErrorCategory;

/// 帧搬运的长度上界（联防 DoS：拒绝为超长声明帧分配缓冲）。
///
/// 值恒等于 `otp_codec::MAX_FRAME`（8B 帧头 + payload 上限），编译期钉死，
/// 不做第二套上限。
pub const MAX_WIRE_FRAME: usize = otp_codec::MAX_FRAME;

/// framed 流抽象（形态决策见模块文档"异步形态决策"节）。
///
/// 实现契约：
/// - [`send_frame`](FramedStream::send_frame)：完整写——短写循环补齐，
///   大帧按内部块大小分片推进（背压由底层容量/kernel 缓冲施加）；
/// - [`recv_frame`](FramedStream::recv_frame)：返回完整帧（8B 帧头 +
///   payload 原样字节）；对端干净关闭（帧边界处 EOF）→
///   [`TransportError::ClosedByPeer`]；帧中途 EOF/超时分别报
///   [`TransportError::FrameMalformed`]/[`TransportError::Timeout`]，
///   绝不交付半帧；
/// - 任一错误后连接视为不可用（fail closed），调用方必须关闭，不重试。
pub trait FramedStream {
    /// 发送一帧（内部保证完整写：短写循环补齐 + 分块推进）。
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransportError>;
    /// 接收一帧（返回完整帧字节；截断/超时/对端关闭分别报错，不吞错）。
    fn recv_frame(&mut self) -> Result<Vec<u8>, TransportError>;
    /// 设置读写超时（同一时长同时作用于收发）。`Duration::ZERO` 非法
    /// （与 SO_RCVTIMEO/SO_SNDTIMEO 语义一致）。
    fn set_deadline(&mut self, timeout: Duration) -> Result<(), TransportError>;
    /// 半关闭：本端不再发送，但仍可接收（TCP = shutdown(Write)）。
    /// 已关闭后调用为幂等成功。
    fn shutdown_write(&mut self) -> Result<(), TransportError>;
    /// 优雅关闭：停发停收（TCP = shutdown(Both)；阻塞写已完成的数据
    /// 不回收）。已关闭后调用为幂等成功。
    fn close(&mut self) -> Result<(), TransportError>;
}

/// 传输错误（对接 WP-01 §5.2 错误码注册表，不新造平行错误体系）。
///
/// 只携带长度等公开元数据；[`Debug`]/[`Display`] 不输出任何帧内容。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransportError {
    /// I/O 错误（短写耗尽、连接重置、底层故障等本地/对端 I/O 异常）。
    Io,
    /// 读或写在期限内无进展（SO_RCVTIMEO/SO_SNDTIMEO 或 condvar 超时）。
    /// WP-01 §5.3：超时表现为本地关闭，无专门线上码。
    Timeout,
    /// 对端关闭：帧边界处的干净 EOF（recv 侧），或对端已关闭后的发送
    /// （EPIPE 语义，send 侧）。
    ClosedByPeer,
    /// 帧长声明超限（防 DoS；上限联动 [`MAX_WIRE_FRAME`]）。
    FrameTooLarge {
        /// 声明帧 payload 长度。
        len: usize,
    },
    /// 帧结构非法：帧头/payload 中途 EOF（WP-01 §3.2 步 5"EOF 中断"）、
    /// 长度前缀与实际字节数失配、短于帧头的输入。
    FrameMalformed,
}

impl TransportError {
    /// 映射到 WP-01 §5.2 统一错误码注册表（审计白名单可直接打印）。
    ///
    /// - `Io`/`Timeout` → `IO_ERROR`(0x0401)：本地平台类失败/超时关闭；
    /// - `ClosedByPeer`/`FrameMalformed` → `FRAME_TRUNCATED`(0x0308)：
    ///   EOF 中断类（含帧边界干净关闭，注册表无独立"正常关闭"码）；
    /// - `FrameTooLarge` → `BAD_LENGTH`(0x0302)：payload_len 越界
    ///   （与 codec §3.2 步 4 同源判定，本层提前拒绝以约束分配）。
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::Io | Self::Timeout => ErrorCode::IO_ERROR,
            Self::ClosedByPeer | Self::FrameMalformed => ErrorCode::FRAME_TRUNCATED,
            Self::FrameTooLarge { .. } => ErrorCode::BAD_LENGTH,
        }
    }

    /// 审计日志错误类别（规划 §2.2 白名单字段）：传输层错误一律
    /// [`ErrorCategory::Transport`]。
    #[must_use]
    pub const fn category(self) -> ErrorCategory {
        ErrorCategory::Transport
    }

    /// 是否为对端方向的条件（对端关闭/帧中断），供上层区分本地故障与
    /// 对端行为选择 H13 路径。
    #[must_use]
    pub const fn is_peer_condition(self) -> bool {
        matches!(self, Self::ClosedByPeer | Self::FrameMalformed)
    }
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 只输出错误名与注册表码，绝不携带帧内容/长度以外信息
        match self {
            Self::FrameTooLarge { len } => {
                write!(f, "FrameTooLarge(len={len})")
            }
            other => f.write_str(match other {
                Self::Io => "Io",
                Self::Timeout => "Timeout",
                Self::ClosedByPeer => "ClosedByPeer",
                Self::FrameMalformed => "FrameMalformed",
                Self::FrameTooLarge { .. } => unreachable!(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_variants_are_public_metadata_only() {
        let e = TransportError::FrameTooLarge { len: 99999 };
        assert!(matches!(e, TransportError::FrameTooLarge { .. }));
    }

    #[test]
    fn error_codes_map_to_wp01_registry() {
        // 对接 wp01 §5.2 注册表，不新造码（任务 #50 验收 ④）
        assert_eq!(TransportError::Io.code(), ErrorCode::IO_ERROR);
        assert_eq!(TransportError::Timeout.code(), ErrorCode::IO_ERROR);
        assert_eq!(
            TransportError::ClosedByPeer.code(),
            ErrorCode::FRAME_TRUNCATED
        );
        assert_eq!(
            TransportError::FrameMalformed.code(),
            ErrorCode::FRAME_TRUNCATED
        );
        assert_eq!(
            TransportError::FrameTooLarge { len: 1 }.code(),
            ErrorCode::BAD_LENGTH
        );
        for e in [
            TransportError::Io,
            TransportError::Timeout,
            TransportError::ClosedByPeer,
            TransportError::FrameMalformed,
            TransportError::FrameTooLarge { len: 1 },
        ] {
            assert_eq!(e.category(), ErrorCategory::Transport);
        }
    }

    #[test]
    fn display_carries_no_frame_content() {
        let s = format!("{}", TransportError::FrameTooLarge { len: 7 });
        assert_eq!(s, "FrameTooLarge(len=7)");
        assert_eq!(format!("{}", TransportError::Timeout), "Timeout");
    }

    #[test]
    fn max_wire_frame_is_pinned_to_codec_constant() {
        assert_eq!(MAX_WIRE_FRAME, otp_codec::MAX_FRAME);
        assert_eq!(MAX_WIRE_FRAME, 8 + otp_codec::MAX_FRAME_PAYLOAD);
    }
}
