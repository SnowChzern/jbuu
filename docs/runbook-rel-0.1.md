# otp-term / jbuu v0.1 部署 runbook（REL-0.1）

| 项 | 内容 |
|---|---|
| 适用 | tag `v0.1`（commit `fb4a192`）release 工件：`otp-term` 0.1.0 + `jbuu-doorkeeper` 0.1.0（x86_64-unknown-linux-gnu） |
| 任务 | 论坛任务 #61 · [jbuu][REL-0.1] v0.1 发布工件：release 构建 + 部署 runbook |
| 粒度 | 逐条命令可照抄。全文字符级无占位符无 TBD；站点相关值集中在 §0.2「变量块」，替换一次全文生效 |
| 权威 | doorkeeper 部分唯一规格 = `docs/specs/wp14-doorkeeper-design.md`（§1–§8，裁决 D1–D11）；本文与其冲突时以设计书为准 |
| 边界 | 部署执行归芥末（楼295 先例），本文只到步骤；GitHub 公开仓同步归调度，本文不涉及；锦书改名（二进制名 `otp-term`→jbuu）是 v0.1 后另卡，v0.1 名称维持现状 |

## 0. 口径与前提

### 0.1 安全口径（先读，不可弱化）

1. **otp-term 服务面只走内网 mesh VPN**：`serve` 监听地址必须是 mesh 内网地址；**禁止**绑定 `0.0.0.0`/`[::]`，禁止任何公网端口映射/ DNAT 指向 serve 端口。客户端同样只在 mesh 内发起连接。
2. **doorkeeper 不增强 SSH 会话安全**（设计书安全边界声明原文）：门卫模式下，SSH 会话的安全上限 = SSH 自身（host key + 用户密钥 + SSH 加密）。门卫的全部价值 = 暴露面收缩（公网只能到达门卫，sshd 仅回环可达）+ 迁移期兼容（存量 SSH 链路不断）+ 可观测性。doorkeeper 是**过渡垫，出生即带日落条件**（§4.9），不是长期组件。
3. doorkeeper 与 otp-term 服务面**互不相干**：§4 全程不动 mesh/serve；§2–§3 全程不动 sshd/doorkeeper。两块可独立执行、独立回滚。
4. 密码本（`otp.book`）与锚文件是**敏感件**：只经内网 mesh 加密通道（如既有 SSH sftp/scp 走 §4 切换后的 :22）或物理介质传递，永不明文过公网；权限必须 0600。

### 0.2 变量块（唯一需要按站点替换的地方）

示例值取自 RFC 5737 文档地址段（192.0.2.0/24），**部署前替换为实际 mesh 地址**，替换后全文命令照抄即可：

```sh
# —— 在操作 shell 里 export 一次，后文命令全部引用 ——
MESH_IP=192.0.2.10          # server 在 mesh VPN 内的地址（仅此网段可达，禁公网）
MESH_CIDR=192.0.2.0/24      # mesh 子网（防火墙白名单用）
SRV_PORT=7717               # otp-term serve 监听端口（mesh 内自定，避开 22/2222/2223）
CLIENT_IP=192.0.2.20        # 客户端在 mesh 内的地址（演练/验证用）
```

### 0.3 主机前提（两侧通用）

```sh
uname -m                                  # 期望 x86_64
/bin/sh -c 'echo sh-ok'                   # 期望 sh-ok（serve 默认 PTY shell 依赖）
python3 --version                         # 锚初始化用（≥3.6 即可，仅需 hashlib）
id -u                                     # server 侧初始化阶段需 root（写 /opt、/var/lib、systemd）
```

## 1. 产物核对（两侧都做）

```sh
cd /path/to/rel-0.1                       # 工件目录（含 otp-term、jbuu-doorkeeper、*.service、SHA256SUMS）
sha256sum -c SHA256SUMS                   # 期望：每行“成功”
./otp-term --version                      # 期望：otp-term 0.1.0
./jbuu-doorkeeper --help | head -1        # 期望：安全边界声明开头
```

## 2. server 侧：安装与初始化（otp-term 服务面）

### 2.1 目录与二进制落位

```sh
sudo install -d -m 0755 /opt/jbuu/v0.1
sudo install -m 0755 otp-term /opt/jbuu/v0.1/otp-term
sudo install -d -m 0750 /var/lib/jbuu /var/log/jbuu
sudo install -d -m 0755 /etc/jbuu
```

### 2.2 生成密码本（server 侧一次性；OS CSPRNG）

```sh
sudo /opt/jbuu/v0.1/otp-term book generate /var/lib/jbuu/otp.book --segments 1024
# 记下输出的 book_id（32 位十六进制），客户端副本与锚初始化都要用它
```

段数说明：每条 connect 消耗 1 段（恢复再签发新段）。1024 段 ≈ 每次连接+恢复耗 2 段可用 500+ 会话；加大 `--segments` 文件线性增长（64 B/段）。

### 2.3 初始化双锚（server 侧自己的双锚，OTPA v2 Init 记录）

锚必须**先于** serve 存在（缺失 → serve 拒绝启动，绝不顺手创建空锚毁现场）。用下面脚本从 book_id 确定性生成（构造与仓内 `AnchorRecord::init`+`encode_record` 逐字节一致：`OTPA`+版本 2+tag 0+book_id，generation/next/保留区全零，尾接 SHA256 完整性）：

```sh
BOOK_ID=<上面记录的 32 位十六进制>          # 例：a1b2…（照抄 2.2 输出，非占位符）
sudo python3 - "$BOOK_ID" <<'PY'
import hashlib, os, sys
bid = bytes.fromhex(sys.argv[1]); assert len(bid) == 16, "book_id 须 32 hex"
for p in ("/var/lib/jbuu/anchor-a.anchor", "/var/lib/jbuu/anchor-b.anchor"):
    r = bytearray(104)
    r[0:4] = b"OTPA"; r[4:6] = (2).to_bytes(2, "big"); r[6] = 0
    r[8:24] = bid
    r[72:] = hashlib.sha256(bytes(r[:72])).digest()
    open(p, "wb").write(bytes(r)); os.chmod(p, 0o600)
PY
sudo /opt/jbuu/v0.1/otp-term anchor inspect /var/lib/jbuu/anchor-a.anchor /var/lib/jbuu/anchor-b.anchor
# 期望：两副本一致、payload=Init、generation=0、next=0，检查通过
```

生产纪律：双锚应放**独立介质**（设计口径：独立故障域，如两块不同盘/一路本地一路可卸载介质）。单机自用起步可先同盘两文件，但 `doctor` 的备份风险项与本文 §6 处置表须照做。

### 2.4 doctor 自检（server 侧，拿 BLOCK 清单）

```sh
sudo /opt/jbuu/v0.1/otp-term doctor --book /var/lib/jbuu/otp.book \
  --anchor-a /var/lib/jbuu/anchor-a.anchor --anchor-b /var/lib/jbuu/anchor-b.anchor
```

- 全 `[ok]`/`[warn]` 无 BLOCK → 直接进 §3。
- 出现 `[block] swap: system`：首选在终端主机禁 swap（`sudo swapoff -a` 并注释 /etc/fstab swap 行后重启复检）；确需保留 swap 的受控环境，加 `--allow-unencrypted-swap` 显式降级（该 flag 同样要加进 §3.3 unit 的 ExecStart）。
- 出现 `[block] backup-risk`：在数据目录放置运维 marker（显式声明"此目录无备份、风险已知"）：`sudo sh -c 'printf "ops marker\n" > /var/lib/jbuu/.otp-term-nobackup'` 后复检。
- 其余 BLOCK（权限/文件系统）：按报告行修正（book/锚 0600、目录不合规按提示改）后复检。**BLOCK 未清零前 serve 会拒绝启动（退出码 2），这是策略行为不是故障。**

## 3. server 侧：运行（otp-term 服务面）

### 3.1 前台首跑（验证口径，确认 LISTEN/READY 后 Ctrl-C 退）

```sh
sudo /opt/jbuu/v0.1/otp-term serve --book /var/lib/jbuu/otp.book \
  --anchor-a /var/lib/jbuu/anchor-a.anchor --anchor-b /var/lib/jbuu/anchor-b.anchor \
  --listen "${MESH_IP}:${SRV_PORT}" --audit-log /var/log/jbuu/serve-audit.jsonl
# stderr 期望顺序：doctor 各行 → READY next=0 generation=0
#                → TERMINAL-SERVE shell=["/bin/sh"] lease_timeout_ms=15000
#                → LISTEN=<MESH_IP>:<SRV_PORT>
# 看到 LISTEN= 即就绪；Ctrl-C 停止（v0.1 无 drain，停止即断存量连接）
```

### 3.2 只听 mesh 的防火墙保险带（防配置漂移把 serve 暴露到公网）

```sh
sudo nft add table inet jbuu
sudo nft 'add chain inet jbuu input { type filter hook input priority filter; }'
sudo nft add rule inet jbuu input tcp dport "$SRV_PORT" ip saddr != "$MESH_CIDR" drop
sudo nft list table inet jbuu          # 期望：仅此一条 drop 规则
```

### 3.3 systemd 常驻

```sh
sudo tee /etc/jbuu/serve.env >/dev/null <<EOF
MESH_LISTEN=${MESH_IP}:${SRV_PORT}
EOF
sudo chmod 600 /etc/jbuu/serve.env
sudo tee /etc/systemd/system/otp-term-serve.service >/dev/null <<'UNIT'
[Unit]
Description=otp-term v0.1 serve - OTP book terminal service (mesh only)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/jbuu/serve.env
ExecStart=/opt/jbuu/v0.1/otp-term serve \
  --book /var/lib/jbuu/otp.book \
  --anchor-a /var/lib/jbuu/anchor-a.anchor \
  --anchor-b /var/lib/jbuu/anchor-b.anchor \
  --listen ${MESH_LISTEN} \
  --audit-log /var/log/jbuu/serve-audit.jsonl \
  --shell /bin/sh
KillSignal=SIGTERM
Restart=on-failure
RestartSec=2s
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
StateDirectory=jbuu
LogsDirectory=jbuu
LimitNOFILE=1024

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now otp-term-serve.service
```

> 若 §2.4 走了 `--allow-unencrypted-swap` 口径：在 ExecStart 的 `--shell /bin/sh` 行后补一行 `\` 换行加 `--allow-unencrypted-swap`。

### 3.4 就绪与暴露面核验

```sh
systemctl is-active otp-term-serve.service                      # 期望 active
sudo journalctl -u otp-term-serve.service -n 20 --no-pager      # 期望含 READY 与 LISTEN= 行
sudo ss -tlnp | grep "$SRV_PORT"                                # 期望仅绑定 MESH_IP（非 0.0.0.0/[::]）
# 从 mesh 内另一台机（客户端）：
nc -zv -w3 "$MESH_IP" "$SRV_PORT"                               # 期望 succeeded
# 从公网侧（非 mesh 出口）对 server 公网地址：
nc -zv -w3 <server公网地址> "$SRV_PORT"                          # 期望 refused/timeout（禁公网暴露铁律）
```

> `<server公网地址>` 处填本机唯一公网地址后执行；该项是**验证禁止项成立**的负面检查。

## 4. server 侧：doorkeeper 部署（SSH 过渡垫，独立于 §2–§3）

> 权威 = 设计书 §7（本节为其命令化全文）。前提：单主机 Linux + systemd + OpenSSH ≥ 7.x；**全程保持带外控制台可用**（切换窗口期禁止唯一依赖 SSH 远程操作）。若主机禁 IPv6：后文 `--listen [::]:22` 一律改 `--listen 0.0.0.0:22`，并按设计书 §7.8 核对 DNS AAAA 记录。

### 4.0 安装

```sh
sudo install -m 0755 jbuu-doorkeeper /usr/local/bin/jbuu-doorkeeper
sudo install -m 0644 jbuu-doorkeeper.service /etc/systemd/system/jbuu-doorkeeper.service
sudo systemctl daemon-reload
```

### 4.1 Preflight 盘点（迁移基线）

```sh
sudo journalctl _COMM=sshd --since "-30d" | grep -oE 'from [0-9a-fA-F:.]+' | sort | uniq -c | sort -rn | head -20
sudo sshd -T | grep -E '^(port|listenaddress|maxstartups)'      # 记录当前值
```

### 4.2 sshd 增设回环监听（双活期，不收缩）

```sh
sudo tee /etc/ssh/sshd_config.d/10-doorkeeper-transition.conf >/dev/null <<'EOF'
ListenAddress 127.0.0.1:2222
ListenAddress [::1]:2222
EOF
sudo sshd -t && sudo systemctl reload sshd
sudo ss -tlnp | grep 2222                                       # 期望两条回环监听在列
ssh -p 2222 localhost true && echo loopback-ssh-ok              # 期望 loopback-ssh-ok
```

### 4.3 影子验证（不动 22 端口）

```sh
sudo systemctl start jbuu-doorkeeper.service                    # unit 默认 --listen [::]:22，影子期先手改
# 影子期临时改听 2223（影子验证口径）：
sudo systemctl stop jbuu-doorkeeper.service
sudo /usr/local/bin/jbuu-doorkeeper --listen [::]:2223 --upstream 127.0.0.1:2222 \
  --log-file /var/log/jbuu/doorkeeper.log --verbose &
# 从外部主机：
ssh -p 2223 -v user@<server地址> true                           # 登录成功；-v 可见 banner line 0: NOTICE: SSH endpoint deprecated…
sudo grep -c conn_accept /var/log/jbuu/doorkeeper.log           # 期望 ≥1，事件链 conn_accept→warn_sent→upstream_connect→client_version→conn_close
sudo pkill -x jbuu-doorkeeper
```

> `<server地址>` 处填本机对外可达地址后执行（外部视角验证）。矩阵里可得的其他客户端（PuTTY/dropbear/paramiko/Go 工具）此时各连一次（设计书 §4.1）。

### 4.4 切换窗口（唯一中断面 = 数秒新连接拒绝；按序逐条）

```sh
sudo systemctl stop jbuu-doorkeeper.service 2>/dev/null || true
# a. 收缩 sshd：注释主配置与 sshd_config.d 中所有 Port 22 / ListenAddress 0.0.0.0 / ListenAddress :: 行，
#    生效面只剩 4.2 的两条回环监听；编辑后：
sudo sshd -t && sudo systemctl reload sshd
sudo ss -tlnp | grep -E ':22 |:2222'                            # 期望：22 无占用，2222 仅回环
# b. 门卫上 22：
sudo systemctl start jbuu-doorkeeper.service
sudo ss -tlnp | grep ':22 '                                     # 期望属 jbuu-doorkeeper
```

若 b 步 bind 失败（22 仍有占用者）：**立即回滚（§4.8）**，不得留半收缩态。

### 4.5 可见性互补（sshd Banner 承担用户触达，门卫零参与）

```sh
sudo tee /etc/ssh/jbuu-migration-banner.txt >/dev/null <<'EOF'
################################################################
#  SSH 入口即将下线：本通道为过渡兼容垫，请迁移到 jbuu（锦书）。 #
#  迁移指引见团队内部公告；问题反馈走内网 mesh 渠道。           #
################################################################
EOF
echo 'Banner /etc/ssh/jbuu-migration-banner.txt' | sudo tee -a /etc/ssh/sshd_config.d/10-doorkeeper-transition.conf >/dev/null
sudo sshd -t && sudo systemctl reload sshd
```

### 4.6 防火墙纵深（防"绕过门卫直达 sshd"的配置漂移保险带）

```sh
sudo nft add table inet jbuu-ssh
sudo nft 'add chain inet jbuu-ssh input { type filter hook input priority filter; }'
sudo nft add rule inet jbuu-ssh input tcp dport 2222 iif != "lo" drop
```

### 4.7 切换后验证清单（逐项打勾）

```sh
# 外部主机执行：
ssh -p 22 user@<server地址> 'echo via-doorkeeper-ok'            # ✅ 经门卫登录成功
scp -P 22 local-file user@<server地址>:/tmp/ && echo scp-ok     # ✅ 传文件成功
ssh -p 2222 user@<server地址> true                              # ❌ 应拒绝（收缩生效）
# server 本机执行：
sudo ss -tlnp | grep -E ':22 |:2222'                            # :22=jbuu-doorkeeper；2222 仅回环
sudo systemctl stop jbuu-doorkeeper.service
#   外部：ssh -p 22 拒绝；本机：ssh -p 2222 localhost true 仍通（证明无旁路）
sudo systemctl start jbuu-doorkeeper.service
```

### 4.8 回滚（任一步失败即回）

```sh
sudo systemctl stop jbuu-doorkeeper.service
sudo sed -i -e '/ListenAddress 127.0.0.1:2222/d;/ListenAddress \[::1\]:2222/d;/^Banner \/etc\/ssh\/jbuu-migration-banner.txt/d' \
  /etc/ssh/sshd_config.d/10-doorkeeper-transition.conf
sudo rm -f /etc/ssh/jbuu-migration-banner.txt
# 恢复原 Port/ListenAddress（取消注释 4.4a 注释掉的行）
sudo sshd -t && sudo systemctl reload sshd
ssh -p 22 user@<server地址> true && echo rollback-ok            # 外部 :22 直连 sshd 复验
```

### 4.9 日志轮转与仪表盘、日落

```sh
sudo tee /etc/logrotate.d/jbuu-doorkeeper >/dev/null <<'EOF'
/var/log/jbuu/doorkeeper.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    postrotate
        /bin/kill -HUP $(systemctl show -p MainPID --value jbuu-doorkeeper.service 2>/dev/null) 2>/dev/null || true
    endscript
}
EOF
# 仪表盘（cron 每日 jq 聚合；设计书 §7.10）：
sudo tee /usr/local/bin/jbuu-doorkeeper-daily.sh >/dev/null <<'EOF'
#!/bin/sh
D=$(date -u +%Y%m%d)
jq -s '{date: now | todate[0:10],
        conns: length,
        uniq_src: ([.[].src_ip] | unique | length),
        versions: (map(.version // "null") | group_by(.) | map({v: .[0], n: length}))}' \
  /var/log/jbuu/doorkeeper.log > "/var/log/jbuu/dashboard-${D}.json"
EOF
sudo chmod 755 /usr/local/bin/jbuu-doorkeeper-daily.sh
echo '30 0 * * * root /usr/local/bin/jbuu-doorkeeper-daily.sh' | sudo tee /etc/cron.d/jbuu-doorkeeper >/dev/null
```

> 日落（设计书 §7.11）：连续 4 周 SSH 连接 < 5 次/周且唯一来源 0 个自动化客户端 → 公告 → 防火墙封 :22 → 观察 1 周 → `sudo systemctl disable --now jbuu-doorkeeper.service`。

## 5. 客户端接入（内网 mesh VPN 口径）

### 5.1 拿件（一次性）

经内网 mesh 加密通道或物理介质，从 server 侧取得三样：① 密码本**副本**（与 server 同本同 book_id）② book_id（32 位十六进制）③ 客户端自建双锚的方法（5.2，客户端拥有**自己的**双锚，不用 server 的）。禁止经公网明文渠道传 book。

### 5.2 客户端初始化

```sh
mkdir -p ~/jbuu-cli && cd ~/jbuu-cli
cp /path/to/收到的/otp.book ./otp.book && chmod 600 otp.book
BOOK_ID=<随件收到的 32 位十六进制>
python3 - "$BOOK_ID" <<'PY'
import hashlib, os, sys
bid = bytes.fromhex(sys.argv[1]); assert len(bid) == 16, "book_id 须 32 hex"
for p in ("anchor-a.anchor", "anchor-b.anchor"):
    r = bytearray(104)
    r[0:4] = b"OTPA"; r[4:6] = (2).to_bytes(2, "big"); r[6] = 0
    r[8:24] = bid
    r[72:] = hashlib.sha256(bytes(r[:72])).digest()
    open(p, "wb").write(bytes(r)); os.chmod(p, 0o600)
PY
printf 'ops marker\n' > .otp-term-nobackup
./otp-term anchor inspect anchor-a.anchor anchor-b.anchor        # 期望：一致/Init/generation=0/next=0
./otp-term doctor --book otp.book --anchor-a anchor-a.anchor --anchor-b anchor-b.anchor
# BLOCK 处置同 §2.4（swap 首选禁用；受控环境可加 --allow-unencrypted-swap）
```

### 5.3 连接与恢复（日常用法）

```sh
# 连接（只在 mesh 内发起；MESH_IP/SRV_PORT 用 §0.2 变量块值）：
./otp-term connect --book otp.book --anchor-a anchor-a.anchor --anchor-b anchor-b.anchor \
  --target "${MESH_IP}:${SRV_PORT}"
# stderr 关键行：TERMINAL handle=1 token=1 segment=0   ← 记住 handle=恢复句柄
#   此后即为交互终端；远端 shell 退出时进程退出码 = 远端 shell 退出码

# 断线后恢复（网络闪断/客户端被杀/误关终端均同）：
./otp-term connect --book otp.book --anchor-a anchor-a.anchor --anchor-b anchor-b.anchor \
  --target "${MESH_IP}:${SRV_PORT}" --recover 1        # ← 用上一条打印的 handle
#   恢复=重新握手新签发段+附着同一 PTY（远端 shell 状态/当前目录/变量都还在）
```

退出码口径（排障用）：`0`=stdin EOF 主动 detach；`N(1..255)`=远端 shell 退出码回传（`exit 9`→9）；`1`=会话失败（见 stderr 单行原因）；`2`=doctor/策略拒绝启动；`3`=drain/rotate 骨架（WP-17）。

### 5.4 接入红线

- 客户端到 server **只走 mesh**；不得做公网中转/公网端口转发/反向隧道把 serve 暴露公网。
- book 副本与锚文件丢失/损坏：停止复用该副本，走 server 侧重发（v0.1 无轮换，`rotate` 是骨架）。
- `--allow-unencrypted-swap` 只在明确接受本机 swap 风险的受控环境使用。

## 6. doctor 自检（两侧通用速查）

```sh
# 单机环境体检（不查文件，进程/系统级）：
./otp-term doctor
# 完整体检（server 侧路径示例；客户端换成自己的路径）：
sudo /opt/jbuu/v0.1/otp-term doctor --book /var/lib/jbuu/otp.book \
  --anchor-a /var/lib/jbuu/anchor-a.anchor --anchor-b /var/lib/jbuu/anchor-b.anchor
# 机器可读存档（公开元数据，无段材料，可入运维记录）：
./otp-term doctor --book ... --anchor-a ... --anchor-b ... --json > doctor-$(date -u +%Y%m%d).json
```

| 发现 | 级别 | 处置 |
|---|---|---|
| core-dump: process | ok/block | 保持 ok；若 block 按行内提示收紧 rlimit/内核参数 |
| swap: system | block | 首选禁 swap（swapoff+fstab）；受控环境 `--allow-unencrypted-swap`（留痕降级 warn） |
| permissions: book/anchor | block | `chmod 600`；目录不外 readable |
| filesystem: book/anchor | warn/block | 密码本/锄须在本地持久盘；tmpfs（含 /tmp 常见挂法）与网络 FS 会 BLOCK——这是策略行为，换目录即可 |
| backup-risk: book-dir | block | 放 marker `.otp-term-nobackup`（§2.4）或把目录移出备份域 |

## 7. 冒烟验收清单（v0.1 上线前逐项打勾；构建机已实测 11/11）

单机演练可直接跑（loopback，验证二进制与链路）；生产验收把 `127.0.0.1` 换 `$MESH_IP`、从客户端机执行。逐条期望值即判定标准。
在**普通持久磁盘目录**里跑（tmpfs/网络 FS 会被 doctor 按策略 BLOCK，见 §6）：

```sh
mkdir -p ~/jbuu-smoke && cd ~/jbuu-smoke
stat -f -c %T .          # 期望 ext2/ext3/ext4/xfs/btrfs 等持久盘；若 tmpfs/nfs → 换真实磁盘目录再跑
mkdir -p srv cli
# ① book+双锚+marker（server 侧素材；客户端同法做一套自己的）
./otp-term book generate srv/otp.book --segments 64 | grep book_id        # ✅ 打印 book_id
BOOK_ID=$(./otp-term book inspect srv/otp.book --json | grep -o '"book_id": *"[0-9a-f]\{32\}"' | grep -o '[0-9a-f]\{32\}')
echo "BOOK_ID=$BOOK_ID"                                                    # ✅ 32 位十六进制
cp srv/otp.book cli/otp.book
for d in srv cli; do python3 - "$BOOK_ID" <<PY
import hashlib, os, sys
bid = bytes.fromhex(sys.argv[1])
r = bytearray(104); r[0:4]=b"OTPA"; r[4:6]=(2).to_bytes(2,"big"); r[8:24]=bid
r[72:]=hashlib.sha256(bytes(r[:72])).digest()
for p in ("$d/anchor-a.anchor","$d/anchor-b.anchor"):
    open(p,"wb").write(bytes(r)); os.chmod(p,0o600)
PY
printf 'ops marker\n' | tee "$d/.otp-term-nobackup" >/dev/null; done
# ② doctor 双侧无 BLOCK：
./otp-term doctor --book srv/otp.book --anchor-a srv/anchor-a.anchor --anchor-b srv/anchor-b.anchor --allow-unencrypted-swap
./otp-term doctor --book cli/otp.book --anchor-a cli/anchor-a.anchor --anchor-b cli/anchor-b.anchor --allow-unencrypted-swap
# ③ serve 起服务（2 个会话位）：
./otp-term serve --book srv/otp.book --anchor-a srv/anchor-a.anchor --anchor-b srv/anchor-b.anchor \
  --listen 127.0.0.1:0 --sessions 2 --shell /bin/sh --allow-unencrypted-swap --audit-log srv/audit.jsonl \
  2> srv/serve.err &
ADDR=""
for _ in $(seq 50); do ADDR=$(sed -n 's/^LISTEN=//p' srv/serve.err); [ -n "$ADDR" ] && break; sleep 0.1; done
echo "ADDR=$ADDR"                                                            # ✅ 解析到 LISTEN= 地址
# ④ connect→交互（终端 A，或 fifo 喂入）：
./otp-term connect --book cli/otp.book --anchor-a cli/anchor-a.anchor --anchor-b cli/anchor-b.anchor \
  --target "$ADDR" --allow-unencrypted-swap
#   在交互终端里：CLI_REC_STATE=4242; echo SET-OK   → ✅ 回显 SET-OK
#   再输入长命令占住（如 sleep 600）期间 kill -9 客户端 → ✅ 断线
# ⑤ --recover 恢复（终端 B）：
./otp-term connect --book cli/otp.book --anchor-a cli/anchor-a.anchor --anchor-b cli/anchor-b.anchor \
  --target "$ADDR" --recover 1 --allow-unencrypted-swap
#   ✅ TERMINAL handle=1 token=2（token 递增=接管）
#   ✅ echo REC-MARK=$CLI_REC_STATE 回显 REC-MARK=4242（同一 PTY，shell 状态存活）
#   ✅ exit 9 后客户端进程退出码 = 9（退出码回传）
# ⑥ serve 收口与审计：
grep -E 'SESSION|EXIT' srv/serve.err
#   ✅ 会话1 end=peer-closed 且 exit=-1（断线时 shell 存活）
#   ✅ 会话2 end=shell-exited(9)；EXIT next=2（两段零重用）
grep -o '"outcome":"[a-z]*"' srv/audit.jsonl | sort | uniq -c
#   ✅ issued×2 + recovered×1
```

> 构建机等价自动化脚本与完整输出：`workspace/evidence/rel-0.1/smoke-run.sh`、`smoke-rel-0.1.log`（11/11 PASS，含 SIGKILL 真断线证据：客户端无 DONE 行、rc=137）。

## 8. 已知边界（v0.1 现状，勿当故障）

- `drain`/`rotate` 为 WP-17 骨架：调用即退出码 3，不改任何状态；serve 停止=直接终止（无排空）。
- `book generate` 仅测试/受控环境口径（OS CSPRNG、O_EXCL 拒绝覆盖）；换本靠重发新本+新锚。
- serve 单密码本进程内串行握手；`--sessions N` 受控退出（测试/轮换演练用）。
- 锦书更名（`otp-term`→jbuu 主名）与仓命名空间调整在 v0.1 后另卡处理；v0.1 二进制名维持 `otp-term`/`jbuu-doorkeeper`。
- 公开仓分发：需随附仓根 `THIRD-PARTY-NOTICE.md`（100 条第三方许可清单）与 LICENSE。
