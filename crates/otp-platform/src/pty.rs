//! PTY 与终端平台原语（WP-16，任务 #54）。
//!
//! 本模块是 PTY/termios 系统调用的**唯一**落点（任务 #54 硬边界："libc
//! 调用集中在既有 platform 层模式"）：`otp-terminal` 等业务 crate
//! `forbid(unsafe_code)`，只消费本模块的安全封装。
//!
//! 安全政策：与 crate 其余部分一致——`#![deny(unsafe_code)]` + 每处
//! `unsafe` 逐点 `#[allow(unsafe_code)]` + SAFETY 注释（见 doctor.rs
//! 既有模式）。所有 unsafe 块均为单次 syscall，无跨调用指针保留。
//!
//! 提供能力：
//! - [`open_pty_master`]：posix_openpt/grantpt/unlockpt（O_NOCTTY——
//!   master 绝不成为本进程控制终端）；
//! - [`spawn_on_pty`]：子进程以 slave 为 stdio、`setsid()`+`TIOCSCTTY`
//!   获得新会话与控制终端（真实作业控制）；生命周期用 `std::process`
//!   的安全 Child 管理（wait/kill 不经本模块）；
//! - 窗口协商：`TIOCSWINSZ`/`TIOCGWINSZ`；
//! - master 读写：`write_all`（完整写）/ [`PtyRead`]（`poll(2)` 超时读，
//!   子进程退出后的 `EIO` 归一化为 EOF）；
//! - 客户端原始模式：[`RawMode`]（tcgetattr/cfmakeraw/tcsetattr，
//!   Drop 恢复；非 tty 输入返回 None，测试管道路径不失效）。
//!
//! ## 阻塞纪律（任务 #56 F2 返工）
//!
//! master fd 一律 `O_NONBLOCK`：ECHO 开启时，写入 master 的每个字节
//! 都被行规程回显到 master 读队列，若读侧（服务端连接泵——与写侧
//! 同一线程）不排空，**阻塞 fd 上的 `write(ptmx)` 会在内核内无限期
//! 睡眠**，任何用户态写预算都对已进入内核的 write 无效。非阻塞 fd +
//! poll(POLLOUT) 预算循环使预算真正生效（EAGAIN 即回 poll，超时即
//! [`PlatformError::Io`]——fail closed）。调用方（服务端泵）另按小
//! 分片写入并在片间排空回显（`otp-terminal` 的 `PTY_WRITE_SLICE`）。
//!
//! ## 子进程收割（任务 #56 F4 返工）
//!
//! `spawn_on_pty` 在子进程内设置 `PR_SET_PDEATHSIG(SIGKILL)`：父
//! （serve）被 SIGKILL 硬杀后内核代为投递 SIGKILL，PTY shell 不残留
//! 为 ppid=1 的 pts 孤儿。用 SIGKILL 而非 SIGTERM 的原因：PTY shell
//! 以 tty 为 stdio → **交互式 shell 按惯例忽略 SIGTERM**（实测
//! dash），只有不可捕获/不可忽略的 SIGKILL 保证收割。注意 PDEATHSIG
//! 的投递锚点是**创建该子进程的线程**——因此业务侧
//! （`TerminalRegistry`）经专用长寿命 spawn 线程派生 PTY 子进程，连接
//! 线程退出（detach/断线）不会误杀 shell；正常退出路径的语义不变
//! （hub Drop 仍 kill+reap，退出码 128+9 与显式 kill 一致）。
//!
//! 本模块不做任何协议/密钥语义，也不记录任何数据内容（日志面仅
//! 元数据：字节数/行数/错误类别）。

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use super::PlatformError;

/// 窗口大小（行/列；像素域协议不使用，恒 0）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PtyWinsize {
    /// 行数。
    pub rows: u16,
    /// 列数。
    pub cols: u16,
}

/// 一次 master 读的结果。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PtyRead {
    /// 读到 n 字节。
    Data(usize),
    /// 对端已关闭（子进程退出后 slave 全关，Linux 返回 EIO——归一化为 EOF）。
    Eof,
    /// 期限内无可读数据（含 EINTR 后剩余期限耗尽）。
    Timeout,
}

/// PTY master 端（owned fd；Drop 关闭即释放 master）。
pub struct PtyMaster {
    fd: OwnedFd,
}

impl PtyMaster {
    /// 以初始窗口大小打开一对新 PTY，返回 master 端。slave 端由
    /// [`spawn_on_pty`] 按 `ptsname_r` 重新打开（master 全程不持有
    /// slave fd，避免本进程成为会话占用者）。
    pub fn open(winsize: PtyWinsize) -> Result<Self, PlatformError> {
        // SAFETY: posix_openpt 是纯 fd 创建 syscall，flags 常量由 libc 定义。
        #[allow(unsafe_code)]
        let master_fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        if master_fd < 0 {
            return Err(PlatformError::Io);
        }
        // SAFETY: master_fd >= 0 且来自刚成功的 posix_openpt，所有权移交 OwnedFd。
        #[allow(unsafe_code)]
        let master = unsafe { OwnedFd::from_raw_fd(master_fd) };
        // SAFETY: grantpt/unlockpt 只消费有效 fd（void 返回；失败时 errno
        // 只能表现为后续 open 失败，被调用方捕获），无输出指针。
        #[allow(unsafe_code)]
        unsafe {
            libc::grantpt(master.as_raw_fd());
            libc::unlockpt(master.as_raw_fd());
        }
        // master 恒非阻塞（模块级阻塞纪律）：阻塞 write(ptmx) 在回显
        // 队列满时会无限期睡眠于内核，任何用户态预算都救不回来。
        // SAFETY: fcntl 为纯 fd 标志读 syscall；fd 有效。
        #[allow(unsafe_code)]
        let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(PlatformError::Io);
        }
        // SAFETY: F_SETFL 仅修改标志位，失败即返回负值。
        #[allow(unsafe_code)]
        let rc =
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if rc < 0 {
            return Err(PlatformError::Io);
        }
        let pty = Self { fd: master };
        if winsize.rows > 0 && winsize.cols > 0 {
            pty.set_winsize(winsize)?;
        }
        Ok(pty)
    }

    /// 带总预算的完整写：poll(POLLOUT) 有界等待 + 短写循环。
    ///
    /// 语义：预算内必须写完全部数据，否则 [`PlatformError::Io`]（调用方
    /// fail closed 关闭连接）——绝不无限阻塞（PTY 输入队列满且对端
    /// 长期不读时，master 写会无限阻塞）。
    ///
    /// master fd 恒为 `O_NONBLOCK`（见 [`PtyMaster::open`]，任务 #56 F2
    /// 返工）：`write` 返回 `EAGAIN` 时回到 poll 循环继续等预算内的可
    /// 写窗口——预算对每一次内核进入都生效（阻塞 fd 的 write 一旦进入
    /// 内核睡眠，本函数的预算无从生效）。
    pub fn write_all_bounded(
        &self,
        mut data: &[u8],
        budget: Duration,
    ) -> Result<(), PlatformError> {
        let deadline = Instant::now() + budget;
        while !data.is_empty() {
            let remain = deadline.saturating_duration_since(Instant::now());
            if remain.is_zero() {
                return Err(PlatformError::Io);
            }
            let mut pfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: pfd 指向单个已初始化 pollfd；poll 同步返回，不保留指针。
            #[allow(unsafe_code)]
            let rc =
                unsafe { libc::poll(&mut pfd, 1, remain.as_millis().min(i32::MAX as u128) as i32) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(PlatformError::Io);
            }
            if rc == 0 {
                return Err(PlatformError::Io); // 预算耗尽
            }
            if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(PlatformError::Io);
            }
            // SAFETY: fd 有效，buf 指针/长度取自存活切片，write 同步完成；
            // O_NONBLOCK 下队列满返回 EAGAIN（回 poll 循环，预算继续消耗）。
            #[allow(unsafe_code)]
            let n = unsafe {
                libc::write(
                    self.fd.as_raw_fd(),
                    data.as_ptr().cast(),
                    data.len() as libc::size_t,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    // 非阻塞饱和：回到 poll 等待可写窗口（预算内）。
                    Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK => continue,
                    Some(code) if code == libc::EINTR => continue,
                    _ => return Err(PlatformError::Io),
                }
            }
            if n == 0 {
                return Err(PlatformError::WriteZero);
            }
            data = &data[n as usize..];
        }
        Ok(())
    }

    /// slave 设备路径（ptsname_r，线程安全变体）。
    pub fn slave_path(&self) -> Result<CString, PlatformError> {
        let mut buf = vec![0u8; 256];
        // SAFETY: fd 有效；buf 指向 256 字节可写内存且长度同步传入；
        // ptsname_r 只在期限内写入 NUL 结尾路径，不保留指针。
        #[allow(unsafe_code)]
        let rc = unsafe {
            libc::ptsname_r(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len() as libc::size_t,
            )
        };
        if rc != 0 {
            return Err(PlatformError::Io);
        }
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        buf.truncate(len);
        CString::new(buf).map_err(|_| PlatformError::InvalidData)
    }

    /// 完整写（阻塞语义：poll 等待可写 + 短写循环；无预算上限）。
    /// master 写入即成为 slave 侧输入。基于非阻塞 fd + poll 实现（模块
    /// 级阻塞纪律）：`EAGAIN` 表示回显/输入队列暂满，等待对端消费后继
    /// 续。服务端数据面必须使用 [`PtyMaster::write_all_bounded`]；本方
    /// 法保留给测试与无预算场景。
    pub fn write_all(&self, mut data: &[u8]) -> Result<(), PlatformError> {
        while !data.is_empty() {
            let mut pfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: pfd 指向单个已初始化 pollfd；poll 同步返回，不保留指针。
            #[allow(unsafe_code)]
            let rc = unsafe { libc::poll(&mut pfd, 1, -1) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(PlatformError::Io);
            }
            if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(PlatformError::Io);
            }
            // SAFETY: fd 有效，buf 指针/长度取自存活切片，write 同步完成；
            // O_NONBLOCK 下饱和返回 EAGAIN（回 poll 继续等）。
            #[allow(unsafe_code)]
            let n = unsafe {
                libc::write(
                    self.fd.as_raw_fd(),
                    data.as_ptr().cast(),
                    data.len() as libc::size_t,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK => continue,
                    Some(code) if code == libc::EINTR => continue,
                    _ => return Err(PlatformError::Io),
                }
            }
            if n == 0 {
                return Err(PlatformError::WriteZero);
            }
            data = &data[n as usize..];
        }
        Ok(())
    }

    /// 带超时读。`Duration::ZERO` = 立即返回（非阻塞探测）。
    /// EINTR 期间剩余期限继续消耗；EIO（子进程退出）归一化 [`PtyRead::Eof`]。
    pub fn read_timeout(
        &self,
        buf: &mut [u8],
        timeout: Duration,
    ) -> Result<PtyRead, PlatformError> {
        let deadline = Instant::now() + timeout;
        loop {
            let remain = deadline.saturating_duration_since(Instant::now());
            let ms = if timeout.is_zero() {
                0
            } else {
                remain.as_millis().min(i32::MAX as u128) as i32
            };
            let mut pfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pfd 指向单个已初始化 pollfd；poll 同步返回，不保留指针。
            #[allow(unsafe_code)]
            let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted && !timeout.is_zero() {
                    continue;
                }
                return Err(PlatformError::Io);
            }
            if rc == 0 {
                return Ok(PtyRead::Timeout);
            }
            // SAFETY: fd 有效，buf 指针/长度取自存活切片，read 同步完成。
            #[allow(unsafe_code)]
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len() as libc::size_t,
                )
            };
            return if n > 0 {
                Ok(PtyRead::Data(n as usize))
            } else if n == 0 {
                Ok(PtyRead::Eof)
            } else {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(code) if code == libc::EIO => Ok(PtyRead::Eof),
                    Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK => {
                        Ok(PtyRead::Timeout)
                    }
                    _ => Err(PlatformError::Io),
                }
            };
        }
    }

    /// 窗口协商：TIOCSWINSZ（内核向 slave 前台进程组投递 SIGWINCH）。
    pub fn set_winsize(&self, w: PtyWinsize) -> Result<(), PlatformError> {
        let ws = libc::winsize {
            ws_row: w.rows,
            ws_col: w.cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: fd 有效；ws 指向单个已初始化 winsize，ioctl 同步返回。
        #[allow(unsafe_code)]
        let rc = unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
        if rc < 0 {
            return Err(PlatformError::Io);
        }
        Ok(())
    }

    /// 读取当前窗口（TIOCGWINSZ）。
    pub fn get_winsize(&self) -> Result<PtyWinsize, PlatformError> {
        let mut ws = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: fd 有效；ws 指向可写存储，ioctl 成功时完成初始化。
        #[allow(unsafe_code)]
        let rc = unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) };
        if rc < 0 {
            return Err(PlatformError::Io);
        }
        Ok(PtyWinsize {
            rows: ws.ws_row,
            cols: ws.ws_col,
        })
    }
}

impl io::Write for &PtyMaster {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        PtyMaster::write_all(self, buf)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "pty master write failed"))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// 在既有 master 上派生子进程：slave 为 stdio 三端，`setsid` + `TIOCSCTTY`
/// 使其成为新会话首领并取得控制终端（真实作业控制）；子进程内设置
/// `PR_SET_PDEATHSIG(SIGKILL)`——serve 被硬杀后内核代杀 PTY shell，
/// 不残留 pts 孤儿（任务 #56 F4；交互式 shell 忽略 SIGTERM，故用
/// SIGKILL；见模块文档）。
///
/// 安全边界：`pre_exec` 回调运行于 fork 后的子进程，只包含四个
/// async-signal-safe syscall（setsid、ioctl、prctl、getppid），
/// 无分配/无锁/无 std 依赖。
pub fn spawn_on_pty(
    master: &PtyMaster,
    argv: &[String],
    winsize: PtyWinsize,
) -> Result<Child, PlatformError> {
    use std::os::unix::process::CommandExt;
    if argv.is_empty() {
        return Err(PlatformError::InvalidData);
    }
    if winsize.rows > 0 && winsize.cols > 0 {
        master.set_winsize(winsize)?;
    }
    let slave_path = master.slave_path()?;
    let slave_os = {
        use std::os::unix::ffi::OsStringExt as _;
        std::ffi::OsString::from_vec(slave_path.into_bytes())
    };
    let open_slave = || -> Result<File, PlatformError> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&slave_os)
            .map_err(|_| PlatformError::Io)
    };
    let stdin = open_slave()?;
    let stdout = open_slave()?;
    let stderr = open_slave()?;
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    // PDEATHSIG 锚点：捕获派生时点的父进程 pid（竞争闭合用，见下）。
    // SAFETY: getpid 为纯 syscall，无副作用。
    #[allow(unsafe_code)]
    let parent_pid = unsafe { libc::getpid() };
    // SAFETY: 回调体仅四次纯 syscall（见函数文档与各点注释）；fd 0 在
    // pre_exec 阶段已由 std 完成 dup2（slave），ioctl 目标有效。
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(move || {
            // SAFETY（子进程内）：async-signal-safe：setsid 与 ioctl 均为
            // 纯 syscall，失败即以 errno 终止 exec。
            #[allow(unsafe_code)]
            let sid = libc::setsid();
            if sid < 0 {
                return Err(io::Error::last_os_error());
            }
            #[allow(unsafe_code)]
            let rc = libc::ioctl(0, libc::TIOCSCTTY as libc::c_ulong, 0u64);
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            // PDEATHSIG（任务 #56 F4）：父进程（serve）死亡——包括无法
            // 拦截的 SIGKILL——时内核向本进程投递 SIGKILL，PTY shell
            // 不残留为 ppid=1 的 pts 孤儿。信号选 SIGKILL：PTY shell 以
            // tty 为 stdio → 交互式 shell 按惯例忽略 SIGTERM（实测
            // dash），只有 SIGKILL 保证收割。业务侧保证派生发生在长寿命
            // spawn 线程（连接线程退出/detach 不触发投递）。
            // SAFETY（子进程内）：prctl 为纯 syscall（int 返回）。
            #[allow(unsafe_code)]
            let rc = libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0,
                0,
                0,
            );
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            // 竞争闭合：若 prctl 生效前父进程已死，信号永不投递（投递
            // 点已错过）——以 getppid 变化检测，放弃 exec 直接退出。
            // SAFETY（子进程内）：getppid 为纯 syscall。
            #[allow(unsafe_code)]
            if libc::getppid() != parent_pid {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(())
        });
    }
    cmd.spawn().map_err(|_| PlatformError::Io)
}

/// stdin 原始模式守卫：进入时保存并置 raw（cfmakeraw），Drop 恢复。
/// stdin 非 tty（管道/重定向）时返回 None，调用方按无 tty 降级。
pub struct RawMode {
    fd: libc::c_int,
    saved: libc::termios,
}

impl RawMode {
    /// 在 stdin 上进入原始模式。非 tty → None（不报错）。
    pub fn enter_stdin() -> Option<Self> {
        let fd = libc::STDIN_FILENO;
        let mut saved = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: fd 恒为 0（本进程标准输入）；saved 指向可写 termios 存储。
        #[allow(unsafe_code)]
        let rc = unsafe { libc::tcgetattr(fd, saved.as_mut_ptr()) };
        if rc != 0 {
            return None; // 非 tty（管道/文件）
        }
        // SAFETY: 成功的 tcgetattr 已完成初始化。
        #[allow(unsafe_code)]
        let saved = unsafe { saved.assume_init() };
        let mut raw = saved;
        // SAFETY: raw 为已初始化 termios；cfmakeraw 仅就地修改标志位。
        #[allow(unsafe_code)]
        unsafe {
            libc::cfmakeraw(&mut raw)
        };
        // SAFETY: &raw 指向已初始化 termios；TCSANOW 立即生效。
        #[allow(unsafe_code)]
        let rc = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) };
        if rc != 0 {
            return None;
        }
        Some(Self { fd, saved })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: fd 与 saved 均为本类型构造时验证过的有效值。
        #[allow(unsafe_code)]
        let _ = unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) };
    }
}

/// stdin 的 tty 窗口大小（非 tty → None；CLI/测试用，免 libc 依赖）。
pub fn tty_winsize_stdin() -> Option<PtyWinsize> {
    tty_winsize(libc::STDIN_FILENO)
}

/// 读取 tty 窗口大小（非 tty → None）。
pub fn tty_winsize(fd: libc::c_int) -> Option<PtyWinsize> {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: ws 指向可写存储；ioctl 同步完成。
    #[allow(unsafe_code)]
    let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
    if rc != 0 {
        return None;
    }
    Some(PtyWinsize {
        rows: ws.ws_row,
        cols: ws.ws_col,
    })
}

use std::time::Instant;

#[cfg(test)]
mod tests {
    use super::*;

    fn sh() -> Vec<String> {
        vec!["/bin/sh".to_string()]
    }

    fn read_until(master: &PtyMaster, needle: &str, budget: Duration) -> Vec<u8> {
        let deadline = Instant::now() + budget;
        let mut acc = Vec::new();
        let mut buf = [0u8; 4096];
        while Instant::now() < deadline {
            match master
                .read_timeout(&mut buf, Duration::from_millis(100))
                .unwrap()
            {
                PtyRead::Data(n) => {
                    acc.extend_from_slice(&buf[..n]);
                    if acc.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                        return acc;
                    }
                }
                PtyRead::Eof => return acc,
                PtyRead::Timeout => {}
            }
        }
        acc
    }

    #[test]
    fn pty_roundtrip_echo_and_exit_zero() {
        let master = PtyMaster::open(PtyWinsize { rows: 24, cols: 80 }).unwrap();
        let mut child = spawn_on_pty(&master, &sh(), PtyWinsize { rows: 24, cols: 80 }).unwrap();
        master.write_all(b"echo pty-ok-123\n").unwrap();
        let out = read_until(&master, "pty-ok-123", Duration::from_secs(10));
        assert!(
            out.windows(b"pty-ok-123".len()).any(|w| w == b"pty-ok-123"),
            "应在 master 侧读到回显：{:?}",
            String::from_utf8_lossy(&out)
        );
        master.write_all(b"exit 0\n").unwrap();
        let status = child.wait().unwrap();
        assert!(status.success());
        assert_eq!(status.code(), Some(0));
    }

    #[test]
    fn pty_exit_code_propagates() {
        let master = PtyMaster::open(PtyWinsize { rows: 24, cols: 80 }).unwrap();
        let mut child = spawn_on_pty(&master, &sh(), PtyWinsize { rows: 24, cols: 80 }).unwrap();
        master.write_all(b"exit 7\n").unwrap();
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(7));
    }

    #[test]
    fn pty_winsize_negotiation_roundtrip() {
        let ws = PtyWinsize {
            rows: 50,
            cols: 120,
        };
        let master = PtyMaster::open(ws).unwrap();
        assert_eq!(master.get_winsize().unwrap(), ws);
        let mut child = spawn_on_pty(&master, &sh(), ws).unwrap();
        // stty size 反映协商结果（slave 侧视角）。
        master.write_all(b"stty size\n").unwrap();
        let out = read_until(&master, "120", Duration::from_secs(10));
        assert!(
            out.windows(5).any(|w| w == b"50 12"),
            "stty size 应报告 50 120：{:?}",
            String::from_utf8_lossy(&out)
        );
        // 动态 resize：TIOCSWINSZ + SIGWINCH。
        let ws2 = PtyWinsize {
            rows: 33,
            cols: 111,
        };
        master.set_winsize(ws2).unwrap();
        assert_eq!(master.get_winsize().unwrap(), ws2);
        master.write_all(b"stty size\n").unwrap();
        let out = read_until(&master, "111", Duration::from_secs(10));
        assert!(
            out.windows(6).any(|w| w == b"33 111"),
            "resize 后 stty size 应为 33 111：{:?}",
            String::from_utf8_lossy(&out)
        );
        master.write_all(b"exit 0\n").unwrap();
        assert!(child.wait().unwrap().success());
        let mut buf = [0u8; 4096];
        let _ = master.read_timeout(&mut buf, Duration::from_millis(50));
    }

    #[test]
    fn master_read_eof_after_child_exit() {
        let master = PtyMaster::open(PtyWinsize { rows: 24, cols: 80 }).unwrap();
        let mut child = spawn_on_pty(
            &master,
            &["/bin/sh".into(), "-c".into(), "true".into()],
            PtyWinsize { rows: 24, cols: 80 },
        )
        .unwrap();
        assert!(child.wait().unwrap().success());
        let mut buf = [0u8; 64];
        // 子进程退出且 slave 全关 → EIO 归一化为 Eof（期限内必然出现）。
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match master
                .read_timeout(&mut buf, Duration::from_millis(200))
                .unwrap()
            {
                PtyRead::Eof => break,
                PtyRead::Data(_) => {}
                PtyRead::Timeout => {}
            }
            assert!(Instant::now() < deadline, "子进程退出后应观察到 EOF");
        }
    }

    #[test]
    fn read_timeout_respects_zero_and_poll_slice() {
        let master = PtyMaster::open(PtyWinsize { rows: 24, cols: 80 }).unwrap();
        let mut buf = [0u8; 16];
        let t0 = Instant::now();
        assert_eq!(
            master.read_timeout(&mut buf, Duration::ZERO).unwrap(),
            PtyRead::Timeout
        );
        assert!(t0.elapsed() < Duration::from_millis(250));
        let t0 = Instant::now();
        assert_eq!(
            master
                .read_timeout(&mut buf, Duration::from_millis(120))
                .unwrap(),
            PtyRead::Timeout
        );
        assert!(t0.elapsed() >= Duration::from_millis(100));
    }

    #[test]
    fn raw_mode_enter_skips_non_tty() {
        // 测试进程 stdin 通常为管道/空 → enter_stdin 返回 None（不 panic）。
        // 若恰在 tty 下运行则守卫立即恢复原设置。
        if let Some(guard) = RawMode::enter_stdin() {
            drop(guard);
        }
    }

    #[test]
    fn write_then_read_large_payload() {
        // master 写大块数据应完整到达（回显路径），验证短写循环。
        let master = PtyMaster::open(PtyWinsize {
            rows: 200,
            cols: 400,
        })
        .unwrap();
        let mut child = spawn_on_pty(
            &master,
            &sh(),
            PtyWinsize {
                rows: 200,
                cols: 400,
            },
        )
        .unwrap();
        // canonical 模式单行上限约 4096B：逐行写+读（避免 PTY 双向队列互锁），
        // 每行 2 KiB 足以覆盖跨多次底层 write 的完整写循环。
        let payload = "0123456789abcdef".repeat(128); // 2048B/行
        for i in 0..16u32 {
            let line = format!("echo m{i:02}x{payload}\n");
            master.write_all(line.as_bytes()).unwrap();
            let needle = format!("m{i:02}x{}", &payload[..64]);
            let out = read_until(&master, &needle, Duration::from_secs(20));
            assert!(
                out.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "第 {i} 行回显未完整到达（完整写失败）"
            );
        }
        master.write_all(b"exit 0\n").unwrap();
        assert!(child.wait().unwrap().success());
        let mut buf = [0u8; 4096];
        let _ = master.read_timeout(&mut buf, Duration::from_millis(50));
    }

    #[test]
    fn master_accepts_std_io_write() {
        let master = PtyMaster::open(PtyWinsize { rows: 24, cols: 80 }).unwrap();
        let mut w = &master;
        // 显式走 trait 方法（区别于同名的固有 write_all）。
        std::io::Write::write_all(&mut w, b"").unwrap();
    }
}
