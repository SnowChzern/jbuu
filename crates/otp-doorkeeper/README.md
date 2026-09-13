# otp-doorkeeper（二进制名 `jbuu-doorkeeper`）

SSH 过渡兼容垫：listen → 发一行前置警告（RFC 4253 §4.2）→ 原样 pipe 到上游 sshd。
唯一规格：`docs/specs/wp14-doorkeeper-design.md`（任务 #49 评审冻结 v1.0，D1–D11）。

## 安全边界声明（首段，原文复述设计书）

门卫不增强 SSH 会话安全。门卫模式下，SSH 会话的安全上限 = SSH 自身
（host key + 用户密钥 + SSH 加密）。门卫的全部价值 = 三件事：暴露面收缩（公网只能
到达门卫，sshd 仅回环可达）+ 迁移期兼容（存量 SSH 链路不断）+ 可观测性（连接日志
= 迁移仪表盘数据源）。门卫不做任何 SSH 协议解析与判定（唯一例外：客户端版本串
旁路观察，只看不改不拦）；门卫不是长期组件：出生即带日落条件，过期退役。

详见 [SECURITY-NOTES.md](SECURITY-NOTES.md)。

## 形态与依赖（§2/§6）

- 独立二进制 `jbuu-doorkeeper`（独立 systemd 单元，见 `jbuu-doorkeeper.service`）；
- thread-per-conn + `std::net`（D1）：每连接 1 处理线程 + 2 pipe 线程，
  256 KiB 栈，16 KiB 缓冲，阻塞式 copy 天然承载 TCP 背压；
- 生产依赖 `std` + `clap` + `rustix`（socket 选项；workspace 既有同步基线）
  + `signal-hook`（SIGHUP/SIGTERM 同步信号），零异步依赖；
- `#![forbid(unsafe_code)]` 全域。

## 用法

```text
jbuu-doorkeeper [--listen [::]:22] [--upstream 127.0.0.1:2222]
                [--warn-mode on|off] [--warn-line <内容不含终止符>]
                [--failure-line on|off] [--max-conns 128]
                [--log-file /var/log/jbuu/doorkeeper.log] [--verbose]
```

默认值即设计书全部裁决值。`--warn-line` 启动时强制校验 §3.2 W1–W5
（SSH- 前缀 / 控制符 / >200B / CRLF 由程序追加），任一违规拒绝启动。

## 模块

| 文件 | 职责 |
|---|---|
| `src/main.rs` | CLI/配置校验/监听生命周期/SIGHUP 轮转与优雅退出 |
| `src/proxy.rs` | accept 循环、连接上限、双向 pipe、半关闭传播、socket 策略 |
| `src/warn.rs` | 警告行冻结 golden 与 W1–W5 校验 |
| `src/obs.rs` | 客户端版本串旁路观察器（8 KiB 无状态扫描窗） |
| `src/log.rs` | JSONL 单 write 原子日志 + reopen |

## 日志事件（§5.5）

`listen_start` / `conn_accept` / `warn_sent` / `upstream_connect` /
`client_version` / `conn_close` / `conn_refused_over_limit` / `log_reopened`，
JSONL，`ts` RFC 3339 UTC 毫秒，`conn_id` 单调 u64。仪表盘指标全部离线
`jq` 聚合得出（门卫保持哑的）。

## 实现备注（对照设计书的两个事实修正，非偏离）

- §3.4 失败提示行实际为 61 字节（含 CRLF），设计书标注“30 字节”系笔误；
  行内容以设计书冻结文本为准，逐字节一致。
- 任务卡括注“listen 0.0.0.0:22 → pipe 到 127.0.0.1:22”为简述；冻结裁决 D5/D10
  为 `[::]:22`（显式 IPV6_V6ONLY=0 双栈）与上游 `127.0.0.1:2222`，CLI 可覆写。

## 部署

runbook（sshd 收缩/迁端口/Banner/防火墙/回滚/日落）见设计书 §7，
**属生产变更，由芥末执行，不在本 crate 范围**。
