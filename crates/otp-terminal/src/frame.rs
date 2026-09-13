//! 终端应用帧（WP-16）：PTY 会话在已建立 AEAD 会话（WP-10 DATA record）
//! 之上的**明文内层**帧格式。
//!
//! 本层不引入任何新线格式：全部终端帧都作为 DATA record 的应用明文
//! 传输，机密性/完整性完全由 WP-10 record 层承担（任务 #54 硬边界：
//! "PTY 数据流同样走 WP-10 record 加密，明文不出传输层"）。
//!
//! 帧布局（type 字节 + 定长/长度前缀字段，大端）：
//!
//! | type | 变体 | 方向 | 布局 |
//! |---|---|---|---|
//! | 0x01 | Open | C→S | rows u16, cols u16 |
//! | 0x02 | Attach | C→S | handle u64, rows u16, cols u16 |
//! | 0x03 | Input | C→S | len u16, bytes |
//! | 0x04 | Resize | C→S | rows u16, cols u16 |
//! | 0x05 | Ping | C→S | — |
//! | 0x11 | Granted | S→C | handle u64, token u64 |
//! | 0x12 | Denied | S→C | reason u8 |
//! | 0x13 | Output | S→C | len u16, bytes |
//! | 0x14 | Exit | S→C | code i32 |
//!
//! 解码严格：长度精确匹配、未知 type/尾随字节/超限一律拒绝（fail
//! closed，对端违规即关闭会话）。
//!
//! **恢复 token 只能是索引/句柄**（wp02 §5.3）：`Attach.handle` 为服务端
//! 句柄计数器（[`TerminalHandle`](crate::TerminalHandle)），不含任何段
//! 材料/密钥位——类型层即无构造路径。

use super::TerminalError;

/// 单帧应用明文上限（type+len 头 + u16 长度域）。
pub const FRAME_OVERHEAD: usize = 3;
/// Input/Output 数据上限（65536 - 3；受 codec `MAX_APP_PLAINTEXT` 约束）。
pub const DATA_CHUNK_MAX: usize = otp_codec::MAX_APP_PLAINTEXT - FRAME_OVERHEAD;

const T_OPEN: u8 = 0x01;
const T_ATTACH: u8 = 0x02;
const T_INPUT: u8 = 0x03;
const T_RESIZE: u8 = 0x04;
const T_PING: u8 = 0x05;
const T_GRANTED: u8 = 0x11;
const T_DENIED: u8 = 0x12;
const T_OUTPUT: u8 = 0x13;
const T_EXIT: u8 = 0x14;

/// 拒绝原因（Denied.reason）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DenyReason {
    /// PTY 写租约被其他活跃连接持有（单主拒绝，规划 M4 验收）。
    Busy,
    /// 恢复句柄不存在或终端已退出。
    Gone,
    /// 陈旧 writer（fencing token 落后）。
    Fenced,
}

impl DenyReason {
    const WIRE: [Self; 3] = [Self::Busy, Self::Gone, Self::Fenced];
    const fn wire(self) -> u8 {
        match self {
            Self::Busy => 1,
            Self::Gone => 2,
            Self::Fenced => 3,
        }
    }
}

/// 终端应用帧。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TerminalFrame {
    /// 建立新终端（服务端 spawn 新 PTY）。
    Open { rows: u16, cols: u16 },
    /// 恢复既有终端（句柄 = 服务端索引计数器，非段材料）。
    Attach { handle: u64, rows: u16, cols: u16 },
    /// 终端输入（C→S；服务端 fencing 校验后写 master）。
    Input { data: Vec<u8> },
    /// 窗口变更（SIGWINCH 语义 → TIOCSWINSZ）。
    Resize { rows: u16, cols: u16 },
    /// 保活心跳（lease 续期）。
    Ping,
    /// 服务端授予写租约（附恢复句柄与 fencing token）。
    Granted { handle: u64, token: u64 },
    /// 服务端拒绝（单主/句柄失效/fenced）。
    Denied { reason: DenyReason },
    /// 终端输出（S→C）。
    Output { data: Vec<u8> },
    /// 子进程退出码回传。
    Exit { code: i32 },
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

impl TerminalFrame {
    /// 编码为应用明文（调用方负责经会话层 seal 后发送）。
    ///
    /// # Panics
    /// `Input`/`Output` 超过 [`DATA_CHUNK_MAX`]（构造侧必须先分块；
    /// 服务端/客户端驱动均已内建分块）。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        match self {
            Self::Open { rows, cols } => {
                out.push(T_OPEN);
                put_u16(&mut out, *rows);
                put_u16(&mut out, *cols);
            }
            Self::Attach { handle, rows, cols } => {
                out.push(T_ATTACH);
                put_u64(&mut out, *handle);
                put_u16(&mut out, *rows);
                put_u16(&mut out, *cols);
            }
            Self::Input { data } => {
                assert!(data.len() <= DATA_CHUNK_MAX, "Input 帧超出单帧上限，须分块");
                out.push(T_INPUT);
                put_u16(&mut out, data.len() as u16);
                out.extend_from_slice(data);
            }
            Self::Output { data } => {
                assert!(
                    data.len() <= DATA_CHUNK_MAX,
                    "Output 帧超出单帧上限，须分块"
                );
                out.push(T_OUTPUT);
                put_u16(&mut out, data.len() as u16);
                out.extend_from_slice(data);
            }
            Self::Resize { rows, cols } => {
                out.push(T_RESIZE);
                put_u16(&mut out, *rows);
                put_u16(&mut out, *cols);
            }
            Self::Ping => out.push(T_PING),
            Self::Granted { handle, token } => {
                out.push(T_GRANTED);
                put_u64(&mut out, *handle);
                put_u64(&mut out, *token);
            }
            Self::Denied { reason } => {
                out.push(T_DENIED);
                out.push(reason.wire());
            }
            Self::Exit { code } => {
                out.push(T_EXIT);
                out.extend_from_slice(&code.to_be_bytes());
            }
        }
        out
    }

    /// 严格解码：未知 type、长度失配、尾随字节均拒绝。
    pub fn decode(bytes: &[u8]) -> Result<Self, TerminalError> {
        let bad = || TerminalError::Protocol;
        let Some((&t, rest)) = bytes.split_first() else {
            return Err(bad());
        };
        match t {
            T_OPEN => {
                if rest.len() != 4 {
                    return Err(bad());
                }
                Ok(Self::Open {
                    rows: u16::from_be_bytes([rest[0], rest[1]]),
                    cols: u16::from_be_bytes([rest[2], rest[3]]),
                })
            }
            T_ATTACH => {
                if rest.len() != 12 {
                    return Err(bad());
                }
                let mut h = [0u8; 8];
                h.copy_from_slice(&rest[..8]);
                Ok(Self::Attach {
                    handle: u64::from_be_bytes(h),
                    rows: u16::from_be_bytes([rest[8], rest[9]]),
                    cols: u16::from_be_bytes([rest[10], rest[11]]),
                })
            }
            T_INPUT => decode_chunk(rest, T_INPUT).map(|data| Self::Input { data }),
            T_OUTPUT => decode_chunk(rest, T_OUTPUT).map(|data| Self::Output { data }),
            T_RESIZE => {
                if rest.len() != 4 {
                    return Err(bad());
                }
                Ok(Self::Resize {
                    rows: u16::from_be_bytes([rest[0], rest[1]]),
                    cols: u16::from_be_bytes([rest[2], rest[3]]),
                })
            }
            T_PING => {
                if !rest.is_empty() {
                    return Err(bad());
                }
                Ok(Self::Ping)
            }
            T_GRANTED => {
                if rest.len() != 16 {
                    return Err(bad());
                }
                let mut h = [0u8; 8];
                h.copy_from_slice(&rest[..8]);
                let mut k = [0u8; 8];
                k.copy_from_slice(&rest[8..]);
                Ok(Self::Granted {
                    handle: u64::from_be_bytes(h),
                    token: u64::from_be_bytes(k),
                })
            }
            T_DENIED => {
                let Some((&r, tail)) = rest.split_first() else {
                    return Err(bad());
                };
                if !tail.is_empty() {
                    return Err(bad());
                }
                let reason = DenyReason::WIRE
                    .iter()
                    .copied()
                    .find(|c| c.wire() == r)
                    .ok_or_else(bad)?;
                Ok(Self::Denied { reason })
            }
            T_EXIT => {
                if rest.len() != 4 {
                    return Err(bad());
                }
                let mut b = [0u8; 4];
                b.copy_from_slice(rest);
                Ok(Self::Exit {
                    code: i32::from_be_bytes(b),
                })
            }
            _ => Err(bad()),
        }
    }
}

fn decode_chunk(rest: &[u8], tag: u8) -> Result<Vec<u8>, TerminalError> {
    if rest.len() < 2 {
        return Err(TerminalError::Protocol);
    }
    let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    let body = &rest[2..];
    if body.len() != len || len > DATA_CHUNK_MAX {
        return Err(TerminalError::Protocol);
    }
    debug_assert!(tag == T_INPUT || tag == T_OUTPUT);
    Ok(body.to_vec())
}

/// 把任意长输入切成 ≤[`DATA_CHUNK_MAX`] 的块（调用方逐块发 Input 帧）。
pub fn chunk_input(data: &[u8]) -> Vec<&[u8]> {
    data.chunks(DATA_CHUNK_MAX).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_roundtrip_exactly() {
        for f in [
            TerminalFrame::Open { rows: 24, cols: 80 },
            TerminalFrame::Attach {
                handle: 7,
                rows: 33,
                cols: 111,
            },
            TerminalFrame::Input {
                data: b"ls -l\r\n".to_vec(),
            },
            TerminalFrame::Resize { rows: 1, cols: 2 },
            TerminalFrame::Ping,
            TerminalFrame::Granted {
                handle: 9,
                token: 4,
            },
            TerminalFrame::Denied {
                reason: DenyReason::Busy,
            },
            TerminalFrame::Output {
                data: vec![1, 2, 3],
            },
            TerminalFrame::Exit { code: -1 },
        ] {
            assert_eq!(TerminalFrame::decode(&f.encode()).unwrap(), f);
        }
    }

    #[test]
    fn decode_rejects_unknown_type_trailing_and_bad_lengths() {
        assert_eq!(
            TerminalFrame::decode(&[]).unwrap_err(),
            TerminalError::Protocol
        );
        assert_eq!(
            TerminalFrame::decode(&[0x00]).unwrap_err(),
            TerminalError::Protocol
        );
        assert_eq!(
            TerminalFrame::decode(&[0x99]).unwrap_err(),
            TerminalError::Protocol
        );
        // Open 尾随字节
        assert_eq!(
            TerminalFrame::decode(&[T_OPEN, 0, 24, 0, 80, 0]).unwrap_err(),
            TerminalError::Protocol
        );
        // Ping 尾随字节
        assert_eq!(
            TerminalFrame::decode(&[T_PING, 0]).unwrap_err(),
            TerminalError::Protocol
        );
        // Input 长度失配
        assert_eq!(
            TerminalFrame::decode(&[T_INPUT, 0, 3, b'a']).unwrap_err(),
            TerminalError::Protocol
        );
        // Denied 未知 reason
        assert_eq!(
            TerminalFrame::decode(&[T_DENIED, 9]).unwrap_err(),
            TerminalError::Protocol
        );
    }

    #[test]
    fn chunking_covers_max_and_boundaries() {
        let max = DATA_CHUNK_MAX;
        assert_eq!(chunk_input(b"").len(), 0);
        assert_eq!(chunk_input(&vec![0u8; max]).len(), 1);
        assert_eq!(chunk_input(&vec![0u8; max + 1]).len(), 2);
        assert_eq!(chunk_input(&vec![0u8; 3 * max + 7]).len(), 4);
    }

    #[test]
    fn chunk_max_fits_codec_app_plaintext() {
        // 单帧（含 3B 头）必须落在 codec 应用明文上限内。
        assert_eq!(
            FRAME_OVERHEAD + DATA_CHUNK_MAX,
            otp_codec::MAX_APP_PLAINTEXT
        );
        assert_eq!(DATA_CHUNK_MAX, 65533);
    }
}
