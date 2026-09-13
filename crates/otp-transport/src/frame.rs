//! 帧搬运核心：长度前缀帧的收发循环（WP-12）。
//!
//! 唯一行为依据 WP-01 §3.2"流式读取等价"：先攒 8 字节帧头，取
//! `BE32(header[4..8])` 为 payload_len，按上界防御校验后收齐消息体；
//! EOF 出现在帧头或 payload 中途 → `FrameMalformed`（注册表 0x0308），
//! 帧边界处干净 EOF → `ClosedByPeer`。
//!
//! **边界**：version/msg_type/payload 结构一律不查（归 otp-codec）；
//! 唯一的本地判定是长度上界（防 DoS 分配）与发送侧长度前缀自洽
//! （防字节流失步，仍是纯 framing 一致性，非消息语义）。

use otp_codec::{FRAME_HEADER_LEN, MAX_FRAME, MAX_FRAME_PAYLOAD};

use crate::TransportError;

/// 发送分块上限：单次底层写请求的最大字节数（大帧分片推进，天然配合
/// 底层容量/kernel 缓冲形成背压；对 64 KiB DATA 帧约 4 块）。
pub(crate) const WRITE_CHUNK: usize = 16 * 1024;

// 上限钉死在 codec 注册表常量上（不另设第二套上限）。
const _: () = assert!(MAX_FRAME == FRAME_HEADER_LEN + MAX_FRAME_PAYLOAD);

/// 有序可靠字节流原语（阻塞、可超时；TCP/loopback 各自实现）。
pub(crate) trait ByteIo {
    /// 读满 `buf`。`Ok(true)` = 读满；`Ok(false)` = 起始即 EOF（帧边界
    /// 干净关闭）；`Err(FrameMalformed)` = 中途 EOF（0x0308）；其余错误
    /// 原样上抛（超时/对端关闭/I/O）。
    fn read_full(&mut self, buf: &mut [u8]) -> Result<bool, TransportError>;
    /// 尽力写：返回本次写入字节数（保证 ≥1 或报错）。短写由
    /// [`send_frame`] 的外层循环补齐（分片 + 背压点）。
    fn write_partial(&mut self, buf: &[u8]) -> Result<usize, TransportError>;
}

/// 接收一帧：8B 帧头 + payload，原样字节返回（不查语义）。
pub(crate) fn recv_frame(io: &mut dyn ByteIo) -> Result<Vec<u8>, TransportError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    if !io.read_full(&mut header)? {
        // 帧边界处的干净 EOF：对端正常关闭
        return Err(TransportError::ClosedByPeer);
    }
    let payload_len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    // 防 DoS：声明超限即拒，不为越界帧分配缓冲（codec 步 4 的提前拒绝）
    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(TransportError::FrameTooLarge { len: payload_len });
    }
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload_len);
    frame.extend_from_slice(&header);
    frame.resize(FRAME_HEADER_LEN + payload_len, 0);
    if !io.read_full(&mut frame[FRAME_HEADER_LEN..])? {
        // WP-01 §3.2：EOF 出现在 payload 中途 → 0x0308
        return Err(TransportError::FrameMalformed);
    }
    Ok(frame)
}

/// 发送一帧：完整性校验 + 分块短写循环（完整写保证）。
pub(crate) fn send_frame(io: &mut dyn ByteIo, frame: &[u8]) -> Result<(), TransportError> {
    // 发送侧防御：帧必须至少含完整帧头、不超协议上界，且长度前缀与实际
    // 字节数自洽（防把失配字节推入流造成对端解析失步——纯 framing 一致性，
    // 不涉及消息语义）。
    if frame.len() < FRAME_HEADER_LEN {
        return Err(TransportError::FrameMalformed);
    }
    let declared = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize;
    // 防 DoS 上界先行（与接收侧同序）：拒绝为越界帧做任何推进
    if declared > MAX_FRAME_PAYLOAD {
        return Err(TransportError::FrameTooLarge { len: declared });
    }
    if declared != frame.len() - FRAME_HEADER_LEN {
        return Err(TransportError::FrameMalformed);
    }
    // 大帧分片 + 短写循环：write_partial 保证 ≥1 或错误，故必然前进。
    let mut off = 0;
    while off < frame.len() {
        let want = (frame.len() - off).min(WRITE_CHUNK);
        let n = io.write_partial(&frame[off..off + want])?;
        off += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 环形回放 IO：按预置脚本回放读结果/写行为（短写/错误注入）。
    struct ScriptIo {
        reads: Vec<Vec<u8>>, // 每次底层 read 返回的块
        writes: Vec<usize>,  // 每次底层 write 的返回值（短写模拟）
        read_pos: usize,
        write_pos: usize,
    }

    impl ByteIo for ScriptIo {
        fn read_full(&mut self, buf: &mut [u8]) -> Result<bool, TransportError> {
            let mut off = 0;
            while off < buf.len() {
                let Some(src) = self.reads.get(self.read_pos) else {
                    return if off == 0 {
                        Ok(false)
                    } else {
                        Err(TransportError::FrameMalformed)
                    };
                };
                self.read_pos += 1;
                let n = src.len().min(buf.len() - off);
                buf[off..off + n].copy_from_slice(&src[..n]);
                off += n;
                if n < src.len() {
                    // 块长于请求：裁剪后续（脚本粒度接于请求粒度即可）
                    self.reads[self.read_pos - 1] = src[n..].to_vec();
                    self.read_pos -= 1;
                }
            }
            Ok(true)
        }
        fn write_partial(&mut self, buf: &[u8]) -> Result<usize, TransportError> {
            let n = match self.writes.get(self.write_pos) {
                Some(n) => *n,
                None => buf.len(),
            };
            self.write_pos += 1;
            Ok(n.min(buf.len()))
        }
    }

    fn header(payload_len: u32) -> Vec<u8> {
        let mut h = vec![0u8; FRAME_HEADER_LEN];
        h[4..8].copy_from_slice(&payload_len.to_be_bytes());
        h
    }

    #[test]
    fn recv_assembles_header_and_payload_verbatim() {
        let frame = [header(4), vec![0xAA, 0xBB, 0xCC, 0xDD]].concat();
        let mut io = ScriptIo {
            reads: vec![frame.clone()],
            writes: vec![],
            read_pos: 0,
            write_pos: 0,
        };
        assert_eq!(recv_frame(&mut io).unwrap(), frame);
    }

    #[test]
    fn recv_clean_eof_at_boundary_is_closed_by_peer() {
        let mut io = ScriptIo {
            reads: vec![],
            writes: vec![],
            read_pos: 0,
            write_pos: 0,
        };
        assert_eq!(recv_frame(&mut io), Err(TransportError::ClosedByPeer));
    }

    #[test]
    fn recv_eof_mid_payload_is_frame_malformed() {
        let mut io = ScriptIo {
            reads: vec![header(100), vec![1u8; 30]], // 声明 100 只到 30
            writes: vec![],
            read_pos: 0,
            write_pos: 0,
        };
        assert_eq!(recv_frame(&mut io), Err(TransportError::FrameMalformed));
    }

    #[test]
    fn recv_rejects_overlong_declaration_without_allocating() {
        let over = (MAX_FRAME_PAYLOAD + 1) as u32;
        let mut io = ScriptIo {
            reads: vec![header(over)],
            writes: vec![],
            read_pos: 0,
            write_pos: 0,
        };
        assert_eq!(
            recv_frame(&mut io),
            Err(TransportError::FrameTooLarge { len: over as usize })
        );
    }

    #[test]
    fn send_rejects_frames_shorter_than_header() {
        let mut io = ScriptIo {
            reads: vec![],
            writes: vec![],
            read_pos: 0,
            write_pos: 0,
        };
        assert_eq!(
            send_frame(&mut io, &[0u8; 4]),
            Err(TransportError::FrameMalformed)
        );
    }

    #[test]
    fn send_rejects_length_prefix_mismatch() {
        let mut bad = header(8);
        bad.extend_from_slice(&[0u8; 4]); // 声明 8 实给 4
        let mut io = ScriptIo {
            reads: vec![],
            writes: vec![],
            read_pos: 0,
            write_pos: 0,
        };
        assert_eq!(
            send_frame(&mut io, &bad),
            Err(TransportError::FrameMalformed)
        );
    }

    #[test]
    fn send_rejects_overlong_frame() {
        let mut io = ScriptIo {
            reads: vec![],
            writes: vec![],
            read_pos: 0,
            write_pos: 0,
        };
        assert_eq!(
            send_frame(&mut io, &vec![0u8; MAX_FRAME + 1]),
            Err(TransportError::FrameMalformed) // 前缀(usize 放不下 u32 声明)失配先判
        );
    }

    #[test]
    fn send_loops_over_short_writes_in_chunks() {
        // 8 帧头 + 60B payload = 68B，底层每次只收 7 字节：ceil(68/7)=10 次
        let mut frame = header(60);
        frame.extend_from_slice(&(0u8..60).collect::<Vec<_>>());
        let mut io = ScriptIo {
            reads: vec![],
            writes: vec![7, 7, 7, 7, 7, 7, 7, 7, 7], // 第 10 次无脚本→全额
            read_pos: 0,
            write_pos: 0,
        };
        send_frame(&mut io, &frame).unwrap();
        assert_eq!(io.write_pos, 10, "短写必须循环补齐至完整写");
    }

    #[test]
    fn write_chunk_bounds_are_sane() {
        const _: () = assert!(WRITE_CHUNK >= 1024);
        const _: () = assert!(WRITE_CHUNK <= MAX_FRAME_PAYLOAD);
    }
}
