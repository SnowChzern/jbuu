# SECURITY NOTES — jbuu-doorkeeper

> 本文件随包安装到 `/usr/share/doc/jbuu-doorkeeper/SECURITY-NOTES.md`（systemd 单元
> `Documentation=` 指向此文件）。

## 安全边界声明（设计书冻结原文，任务卡已定决策 5）

**门卫不增强 SSH 会话安全。门卫模式下，SSH 会话的安全上限 = SSH 自身
（host key + 用户密钥 + SSH 加密）。**

门卫的全部价值 = 三件事：

1. **暴露面收缩**：公网只能到达门卫，sshd 仅回环可达；
2. **迁移期兼容**：存量 SSH 链路不断；
3. **可观测性**：连接日志 = 迁移仪表盘数据源。

推论（实现与运维约束）：

- 门卫**不得**宣称或暗示提供任何认证、加密、防重放能力；
- 门卫**不得**做任何 SSH 协议解析与判定（唯一例外：客户端版本串**旁路观察**，
  只看不改不拦，8 KiB 无状态扫描窗）；
- 门卫**不得**成为长期组件：出生即带日落条件（runbook §7.7），过期退役。

## 事实勘误（F1，芥末已知悉）

OpenSSH 客户端对前置行默认**忽略**（仅 `-v` 下 debug 级显示），并非“显示并忽略”。
可见性主通道由 sshd 自身 `Banner` 配置承担（认证阶段终端原生显示），
门卫警告行保留作零成本补充。

## 依赖面

生产依赖：`std` + `clap`（CLI）+ `rustix`（socket 选项安全封装：IPV6_V6ONLY /
SO_KEEPALIVE+TCP_KEEP* / SO_SNDTIMEO；workspace 既有同步基线）+ `signal-hook`
（SIGHUP/SIGTERM/SIGINT 同步信号处理）。无异步运行时、无 SSH 协议库、无内部
crate 依赖。`#![forbid(unsafe_code)]` 全域生效。

## 日志数据面

`/var/log/jbuu/doorkeeper.log`（JSONL）包含：来源 IP/端口、连接时间、字节数、
客户端版本串（前 128 字节）。不含任何会话内容（数据面零知识，仅上述旁路观察）。
