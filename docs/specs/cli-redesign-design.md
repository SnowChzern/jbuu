# [jbuu][CLI-REDESIGN] CLI 形态 redesign 设计书（直连语义 + 默认端口 + ssh 风格别名）

| 项 | 内容 |
|---|---|
| 任务卡 | 论坛任务 #69 · [jbuu][CLI-REDESIGN] CLI 形态 redesign 设计书（直连语义+默认端口+ssh 风格别名）；灰测来源：论坛帖 42 楼 356/358/360（Bug #6：直连、默认端口、别名三需求） |
| 执行人 | 斗拱（designer） |
| 设计依据 | 芥末 09-14 产品形态定案两条**原文**（本文不得替换等价物，见 §0.2）；`crates/otp-cli/src/main.rs` 现状 clap 表面（v0.1.1：serve/connect/book/anchor/doctor/drain/rotate 七子命令）；v0.1 runbook（`docs/runbook-rel-0.1.md`：§0.1 mesh-only 铁律、§0.2 SRV_PORT=7717 示例"避开 22/2222/2223"、§5.3 connect/--recover 现行用法）；wp14 门卫设计书（`docs/specs/wp14-doorkeeper-design.md`：22=doorkeeper、sshd 收缩 127.0.0.1:2222、日落条件）；otp-transport `TcpTransport::connect(&str)`（`ToSocketAddrs`，支持主机名）；`--full-otp` 参数挂载点由另一设计书并行定义（本卡只预留 CLI 位，§7） |
| 状态 | 待芥末批；批准后据此开实现卡（本文不含实现代码） |
| 范围含 | ①子命令矩阵与直连语义 ②默认端口定值与覆盖链 ③别名配置文件路径/schema/ssh 映射 ④参数与别名优先级规则 ⑤零破坏迁移与 deprecation 策略 ⑥doorkeeper 部署视角配合——任务卡要求全部六项 |
| 范围不含 | 实现代码与测试代码；协议/线格式/握手/lease 任何变更（WP-01/02/03/12/16 冻结面零触碰）；`--full-otp` 的语义定义（并行卡所有）；serve 侧多路复用/配置中心等新能力；别名通配符、Include、ProxyJump 等 ssh 高级面（§3.6 弃用清单） |
| 冲突处理 | 本设计与产品定案两条原文冲突＝无效；与冻结规格（WP-01/02/03、wp14）冲突时 fail closed 走设计缺陷流程（规划 §7.2）。硬偏差=0，解读细化 4 条（§14） |

> 修订记录：v1.0（本次，任务 #69）：初版。

---

## 0. 结论速览与不变式

### 0.1 十条结论（TL;DR）

| # | 结论 | 详节 |
|---|---|---|
| 1 | 顶层增设可选位置参数 `<host|别名>`：`jbuu 192.0.2.10 --book b.book` 直接连（不带子命令=connect 语义）；七个子命令原样保留，精确子命令词优先于 host 解析 | §3 |
| 2 | `jbuu` 无参数 → 打印简短帮助（stderr），退出码 2（沿用 clap 既有 usage 口径），**不**隐式连接任何默认目标 | §3.3 |
| 3 | 默认端口定值 **7717/tcp**（`DEFAULT_JBUU_PORT=7717`）：runbook 现行示例值即 7717（零迁移）、避开 22/2222/2223、避开 Linux 临时端口范围；冻结前须 IANA 注册表复核（冲突则备选 9778） | §4 |
| 4 | `serve --listen` 缺省 `127.0.0.1:0` → `127.0.0.1:7717`（仍回环安全、`:0`=随机保留；e2e 全部显式 `--listen`，实证零影响） | §4.3 |
| 5 | 别名配置：`$XDG_CONFIG_HOME/jbuu/config.toml`（缺省 `~/.config/jbuu/config.toml`），TOML，`[alias.<名>]` 表；**只有路径与拓扑，无任何秘密**；serve 侧与 doorkeeper 永不读它 | §5 |
| 6 | ssh 字段映射核心一条：`IdentityFile`（密钥）→ `book`（密码本），芥末原文②"配置密钥就改成配置密码书" | §5.4 |
| 7 | 优先级四层阶梯：CLI 旗标 > `host:port` 内嵌端口 > 别名字段 > 内置常量；`host:port` 与 `-p` 同时给且不等 → 报错拒绝 | §6.1 |
| 8 | 凭据三件套捆绑规则：`--book/--anchor-a/--anchor-b` 一旦 CLI 给出任一件，别名里的凭据三字段**整体不参与**，未给的两件走"同目录锚约定"（book 兄弟 `anchor-a.anchor`/`anchor-b.anchor`） | §6.2/§6.3 |
| 9 | 迁移零破坏：七子命令、全部现有旗标、退出码语义不动；`connect` 不设 deprecation 时钟（脚本/人机两套入口长期并存，直连为主推口径）；版本 0.2.0（minor） | §8 |
| 10 | `--full-otp`：仅登记保留名（直连面与 connect 同位挂载），语义归并行设计书；其余卡不得占用该名 | §7 |

### 0.2 产品定案不变式（芥末 09-14 原文，逐字保真）

> ① 「规定一个默认端口；jbuu 就是要去连接的，不带子命令直接走 connect：`jbuu 192.0.2.10 --book <密码书路径>` 就能连上」
> ② 「后期做成和 ssh 那样可以配别名，ssh 配置密钥就改成配置密码书，其他的不变」

本文全部设计受此两条约束，验收命令即原文命令（§11 E2 必测）：**`jbuu 192.0.2.10 --book <密码书路径>` 必须能连上**（前提：对端 serve 在 7717、锚按约定摆放，见 §6.3——这是"密码书路径"之外唯一新增的前提，申报为解读细化 R1）。②的"后期"= 分期里的 P1（§12），不进 P0。

### 0.3 设计总则

1. **零破坏**：任何现有命令行（runbook、e2e 测试、论坛帖子里的历史命令）行为不变；唯一申报的行为微变是 §4.3 serve 缺省监听端口。
2. **最小面**：别名只做"名字→连接参数"一张表，不做 ssh 的 pattern/Include/ProxyJump/多文件合并（§3.6 逐条弃用并给理由）。
3. **安全口径不放松**：config.toml 无秘密；`allow_unencrypted_swap` **不入**配置（降级开关必须每次显式敲，防配置漂移静默降级）；别名不绕过 doctor/自加固（直连与 connect 走同一条 `run_connect` 路径，doctor 策略原样生效）。
4. **fail closed + 报错可指路**：解析歧义（双端口来源）、未知别名、缺锚，一律退出码 2 并在报错里给出下一步指针（期望路径/配置文件路径）。

---

## 1. 现状盘点与灰测痛点

### 1.1 现有 CLI 表面（v0.1.1，`crates/otp-cli/src/main.rs`）

| 子命令 | 关键旗标 | 现状语义 |
|---|---|---|
| `serve` | `--book --anchor-a --anchor-b --listen(缺省 127.0.0.1:0) --audit-log --sessions --deadline-secs --shell --lease-timeout-ms --allow-unencrypted-swap` | 服务端（mesh-only 口径靠运维遵守，代码不强制） |
| `connect` | `--book* --anchor-a* --anchor-b* --target*(host:port) --recover --audit-log --deadline-secs --allow-unencrypted-swap`（*=必填） | 客户端；`--target` 只收字面地址 |
| `book` | `generate PATH --segments/--book-id`；`inspect PATH --json` | 离线工具 |
| `anchor` | `inspect PATH [PATH_B] --json` | 只读检查 |
| `doctor` | `--book --anchor-a --anchor-b --json --allow-unencrypted-swap` | 环境体检 |
| `drain` / `rotate` | （骨架，退出码 3，WP-17） | 骨架 |

顶层为**必选子命令**（`command: Cmd` 无 Option），`jbuu` 裸跑即 clap usage 错误。

### 1.2 灰测痛点（帖 42 楼 356/358/360，Bug #6 三需求）

1. 每次连接要敲四个长旗标（book+双锚+target），比 `ssh 别名` 长得多；
2. 端口是站点自选的裸值，无产品级缺省，客户端/服务端要互相问；
3. 没有别名机制，跨多台 server 时凭路径记忆操作。

本设计一次性回应三条 + 芥末定案两条。

---

## 2. 总体形态：一张表面登记表

CLI 表面自此按**登记表**管理（新旗标/新名须先登记再实现，防名字被抢注）：

```
jbuu                              → 简短帮助（stderr，exit 2）
jbuu --help | -h | -V | --version → 帮助/版本（exit 0）
jbuu <子命令> [旗标…]              → 七子命令，全部现状语义不变
jbuu [旗标…] <host|别名> [旗标…]    → 直连 = connect 语义（新）
jbuu -- <host|别名> …              → 直连；-- 之后 token 不再匹配子命令（逃生门）
```

直连旗面（v1，与 connect 子命令旗面同构、收敛到同一 `run_connect`）：
`--book`、`--anchor-a`、`--anchor-b`、`-p/--port <u16>`、`--recover <u64>`、`--audit-log`、`--deadline-secs`、`--allow-unencrypted-swap`、`--config <path>`（别名文件定位，§5.1）；
**预留**：`--full-otp`（§7）。

---

## 3. ① 子命令矩阵与直连语义

### 3.1 解析总规则（clap 落地方式）

- `Cli { #[command(subcommand)] command: Option<Cmd>, #[command(flatten)] direct: DirectForm }`，`DirectForm { host: Option<String> /* 顶层位置参数 */, …connect 旗面 }`。
- 分派：`command=Some` → 现状路径（一行不改）；`command=None 且 host=Some` → 直连；`command=None 且 host=None 且直连旗面全空` → 帮助+exit 2；`command=None 且 host=None 但直连旗面非空`（如 `jbuu --book b`）→ usage 错误 exit 2（"给了连接旗标但缺 <host>"）。
- **子命令词优先**：第一个非旗标 token 精确等于七个子命令名（大小写敏感）→ 一律按子命令。`jbuu connect` 永远是子命令，不会被当作别名/主机名。
- **`--` 逃生门**：`jbuu -- serve` 中 `serve` 在 `--` 之后，clap 不再作子命令匹配 → 按位置参数处理（host="serve"，走别名/地址解析）。极端情况（主机名真叫 serve）的唯一逃生门；日常用不到，登记备查。

### 3.2 完整矩阵（每行一条单测，§11 T 组）

| 命令行 | 解析结果 | 退出码 |
|---|---|---|
| `jbuu` | 简短帮助（stderr） | 2 |
| `jbuu --help` / `--version` | 帮助/版本 | 0 |
| `jbuu serve --book b …` | 子命令（现状） | 现状 |
| `jbuu connect --target 10.0.0.1:7717 …` | 子命令（现状；`--target` 只收字面地址，**不**解析别名，D5） | 现状 |
| `jbuu book|anchor|doctor|drain|rotate …` | 子命令（现状） | 现状 |
| `jbuu 192.0.2.10 --book b.book` | **直连**（芥末原文①命令） | 远端 shell 码/1/2 |
| `jbuu 192.0.2.10:7790 --book b.book` | 直连，内嵌端口 7790 | 同上 |
| `jbuu ops`（ops=已配置别名） | 直连，别名展开（P1 起） | 同上 |
| `jbuu ::1 --book b` | 直连，IPv6 字面量（多冒号=纯地址，默认端口） | 同上 |
| `jbuu [2001:db8::1]:7790 --book b` | 直连，IPv6+端口必须方括号 | 同上 |
| `jbuu -p 7790 ops` | 直连，别名+旗标端口 | 同上 |
| `jbuu -- serve` | 直连（-- 逃生门） | 同上 |
| `jbuu --book b`（无 host） | usage 错误："连接旗标已给但缺 <host>" | 2 |
| `jbuu 1.2.3.4 2.3.4.5` | usage 错误：直连只收一个位置参数 | 2 |
| `jbuu nosuch` | 未知别名/无法解析为地址（报错含配置路径提示） | 2 |
| `jbuu --book X serve …` | `serve` 是首个非旗标 token → 子命令路径；顶层旗标与子命令不同层不共享 → serve 自身 usage 错误（提示 serve 需要自己的 `--book`） | 2 |

### 3.3 无参数默认行为（裁决 D2）

**打印简短帮助，退出码 2。** 备选与否决：
- 默认连"默认别名"——**否**：隐式连接是危险魔法（连错机器、消耗段），且与"锚/本是否就绪"耦合，报错路径反而深；
- 进交互选单/TUI——**否**：YAGNI，团队三人；
- 帮助+exit 0——**否**：与 clap `arg_required_else_help` 既有口径一致（exit 2），脚本可区分"成功"与"没给参数"。

退出码 2 在现状已双役（clap usage 错误与策略拒绝共用，`EXIT_POLICY_REFUSED=2`），本设计不新增混淆，仅登记（§10）。

### 3.4 `<host|别名>` token 文法

```
token     := 子命令词（7 个，精确匹配）          → 子命令
           | 别名键（config 命中，键精确匹配）    → 别名展开（P1）
           | addr                                  → 直连地址
addr      := host | host ":" port | "[" host6 "]" ":" port
host      := IPv4 字面量 | IPv6 字面量 | 主机名/DNS 名
port      := u16 十进制
```

- 判定序**别名先于 DNS**（ssh 同款：`Host ops` 优先于解析 `ops.` 域名）；别名名校验（§5.3）禁止形似地址/含 `:`，二者无交集。
- 无 `user@` 前缀：锦书无用户概念（身份=book_id，握手内核对），芥末②"其他的不变"下**故意省略**（登记表不收该语法）。
- 主机名交给 `TcpTransport::connect` 的 `ToSocketAddrs` 解析（现状能力，无新增解析器）。

### 3.5 直连旗面与既有旗面的关系

- 直连旗面与 `connect` 旗面**同构**（`--target` 除外——位置参数替代之），实现上 flatten 后共用 `ConnectArgs` 构造，`run_connect` 一条路径：doctor、自加固、审计、恢复、握手、PTY、退出码传递全部复用，**直连不引入任何策略旁路**。
- 顶层旗标与子命令旗标不同层、不共享（clap 语义），§3.2 末行行为登记。

### 3.6 明确不做（防蔓延清单，评审可增不可减）

| ssh 能力 | 不做理由 |
|---|---|
| `Host` 通配 pattern、多段叠加、`Host *.lan` | 三人团队无此规模；叠加语义是 ssh config 复杂度之首 |
| `Include`、多配置文件合并 | 同上；单文件 `--config` 旗标足矣 |
| `ProxyJump`/`ProxyCommand` | 网络可达性由 mesh VPN 承担（runbook §0.1 铁律），CLI 层做跳板等于鼓励绕过 mesh-only |
| `user@host` | 无用户概念（§3.4） |
| 别名里嵌 shell 命令/`LocalForward` 等 | 远超"名字→参数"最小面 |
| `connect --target` 解析别名 | 冻结面不加隐式行为；直连=人机入口、connect=脚本/测试入口，两套口径清晰（D5） |

---

## 4. ② 默认端口：定值建议与覆盖方式

### 4.1 定值裁决（D6）：`7717/tcp`

| 准则 | 7717 的表现 |
|---|---|
| 避开部署现役端口 | 22（doorkeeper 公网）、2222（sshd 回环收缩，wp14 D10）、2223（门卫影子期，runbook §4.4b）——runbook §0.2 注释本就要求"避开 22/2222/2223"，7717 正是现行示例值 |
| 避开 Linux 临时端口范围 | 默认 `ip_local_port_range` 32768–60999，7717 在其下 |
| 不需特权 | >1024，systemd DynamicUser 无 CAP_NET_BIND_SERVICE 也能绑 |
| 迁移成本 | **零**：v0.1 runbook 的 SRV_PORT 示例即 7717，已按此部署的站点无感 |
| 记忆 | "七七一七"，四键节奏；产品常量名 `DEFAULT_JBUU_PORT` |

**冻结前置条件**：对 IANA Service Name and Transport Protocol Port Number Registry 复核 7717/tcp 未注册（本设计离线撰写无法联网复核，**申报为批准前检查项**）；若已被注册，备选序：`9778`、`15717`（同准则筛选），定值只改本节与常量，矩阵/schema 不动。

**否决的候选**：22（与门卫冲突且冒充 ssh 端口引人误解）；2222/2223（runbook 已占）；<1024（需特权，与 systemd 加固单元冲突）；32768–60999（临时端口，bind 可能失败或抢走出站端口）；随机端口（违反"规定一个默认端口"的定案①本身）。

### 4.2 覆盖链（客户端，端口解析优先级）

```
内嵌端口 host:port / [v6]:port     ←最高
    └─ 与 -p/--port 同给且不等 → usage 错误 exit 2（拒绝二义，不静默择一）
-p/--port <u16>
别名 port 字段（§5）
DEFAULT_JBUU_PORT = 7717（编译期常量，无配置文件级全局覆盖）
```

全局 `default_port` 配置项**不设**（YAGNI 申报）：改默认端口只有产品发布一条路，测试/多站点用 `-p`/`--listen` 显式表达；开放配置项等于第二真相源。

### 4.3 serve 侧配合（申报的行为微变）

`serve --listen` 缺省 `127.0.0.1:0` → **`127.0.0.1:7717`**：
- 仍默认回环（不扩大暴露面，mesh-only 靠运维传 `--listen ${MESH_IP}:7717` 的口径不变）；
- `:0`=随机的语义保留（并行测试逃生门）；
- 风险评估：`LISTEN=` stderr 行照打实际地址（行格式冻结），解析脚本零影响；e2e 三处 serve 全部显式 `--listen 127.0.0.1:0`（`e2e_tcp.rs:369/515/639`，实证），唯一受影响场景是"同机裸跑两个不传 `--listen` 的 serve"，属开发边角，报 EADDRINUSE 即自解释；
- 收益：`jbuu serve` + `jbuu 127.0.0.1 --book b` 两个裸命令即可本机冒烟，闭环定案①。

---

## 5. ③ 别名配置文件：路径、schema、ssh 映射

### 5.1 路径与发现规则（D7）

- 唯一来源：`$XDG_CONFIG_HOME/jbuu/config.toml`；`XDG_CONFIG_HOME` 未设时 `~/.config/jbuu/config.toml`（XDG Base Directory 规范缺省）。
- 顶层旗标 `--config <path>` 覆盖（ssh `-F` 的对应物；测试/多环境用）。
- 文件不存在＝空别名表（**不是错误**，首次使用体验：`jbuu ops` → "未知别名 ops（配置文件 <路径> 不存在；初始化示例见 --help）"）。
- 不设 `/etc/jbuu/` 系统级客户端配置：book 本就是每用户一份，多用户共享别名只会诱导共享 book 副本的误操作。
- 权限建议 0600（含拓扑信息，非秘密但属侦察面）；`doctor --config`（P2）对其 >0600 给 warn。

### 5.2 Schema（TOML，`[alias.<名>]`）

```toml
# ~/.config/jbuu/config.toml —— 锦书客户端别名（无任何秘密，只有路径与拓扑）
# 字段名与 connect 旗标一一对应；未知字段按错误处理（拒绝 typo 静默失效）。

[alias.ops]                     # jbuu ops → 直连此表
host  = "192.0.2.10"         # 必填：IPv4/IPv6/主机名（无 user@）
port  = 7717                    # 可选：缺省 DEFAULT_JBUU_PORT
book  = "~/jbuu-cli/otp.book"   # 可选：密码本路径（芥末②：密钥位改密码书位）
anchor_a = "~/jbuu-cli/anchor-a.anchor"   # 可选：缺省走同目录锚约定（§6.3）
anchor_b = "~/jbuu-cli/anchor-b.anchor"   # 可选：同上
deadline_secs = 120             # 可选：缺省 120（同 connect）
audit_log = "~/jbuu-cli/audit.jsonl"      # 可选：缺省不落盘

[alias.lab]
host = "lab-mesh.internal"      # 主机名交给 ToSocketAddrs
book = "~/lab/otp.book"         # 不给 anchor_*：用 ~/lab/ 下约定锚
```

| 字段 | 类型 | 必填 | 缺省 | 对应 connect 旗标 |
|---|---|---|---|---|
| `host` | string | 是 | — | `--target` 的地址部分 |
| `port` | u16 | 否 | 7717 | `-p/--port`（及 `host:port` 内嵌） |
| `book` | path | 否¹ | — | `--book` |
| `anchor_a` / `anchor_b` | path | 否¹ | book 同目录约定 | `--anchor-a/-b` |
| `deadline_secs` | u64 | 否 | 120 | `--deadline-secs` |
| `audit_log` | path | 否 | 不落盘 | `--audit-log` |
| `recover` | — | **不设** | — | 会话态（TERMINAL 行打印的 handle）不入持久配置 |
| `allow_unencrypted_swap` | — | **不设** | — | 安全降级开关必须每次显式敲（§0.3 总则 3，D11） |
| `full_otp` | — | **预留** | — | §7 并行卡定，本表不收 |

¹ 别名不给 `book` 时：连接前必须从 CLI `--book` 得到，否则 exit 2（"别名 ops 未配置 book，且未给 --book"）。

解析纪律：`serde` + `#[serde(deny_unknown_fields)]`（未知字段=错误，退出码 2，报错含行列号）；路径支持前导 `~` 展开（其余位置 `~` 按字面）；TOML 同名 `[alias.ops]` 重复由 TOML 解析器天然拒绝。

### 5.3 别名校验规则（config 加载时，违规=exit 2 并点名）

1. 非空；字符集 `[A-Za-z0-9_-]`（首字符字母/数字）；
2. 不得等于七个子命令名（`serve/connect/book/anchor/doctor/drain/rotate`）；
3. 不得形似地址：不得匹配 IPv4/IPv6 字面量，不得含 `:` `/` `\` 空格。

### 5.4 与 ssh config 的字段映射表（芥末②"其他的不变"的对照基准）

| OpenSSH `ssh_config` | jbuu 对应 | 差异说明 |
|---|---|---|
| `Host <别名>` | `[alias.<名>]` | 单别名单表；不支持 pattern 通配（§3.6） |
| `HostName` | `host` | 同义 |
| `Port`（缺省 22） | `port`（缺省 7717） | 缺省值不同 |
| **`IdentityFile`（密钥）** | **`book`（密码本）** | **芥末②核心映射："配置密钥就改成配置密码书"** |
| `CertificateFile` / `AddKeysToAgent` / `IdentitiesOnly` | — | 无对应（无证书/代理概念） |
| `User` | — | 无用户概念：身份=book_id，握手内核对（§3.4） |
| `UserKnownHostsFile` / `StrictHostKeyChecking` | — | 无 TOFU 知名主机库：对端真实性由"同本同 book_id"E2E 互证承载，故意不引入 |
| `ProxyJump` / `ProxyCommand` | — | mesh VPN 是网络层答案（§3.6） |
| `ServerAliveInterval` | — | connect 心跳固定 1s（协议无 lease 协商通道，main.rs 既有注释），不开放配置 |
| `ConnectTimeout` | `deadline_secs` | 语义近似（锦书=握手+附着整体超时） |
| `Compression` / `Ciphers` / `MACs` | — | 协议冻结（WP-01/03），无算法协商面 |
| `LogLevel` / `Verbose` | — | 状态面统一 stderr，无级别旋钮 |
| `Include` | — | v1 不做（§3.6） |
| `-F <file>`（命令行） | `--config <path>` | 同位 |
| `-p <port>`（命令行） | `-p/--port` | 同位；另支持 `host:port` 内嵌（ssh 无此语法，属 ssh scp/sftp 家族习惯） |
| `-i <keyfile>`（命令行） | `--book` | 同位映射 |

---

## 6. ④ 参数与别名的优先级/覆盖规则

### 6.1 总阶梯（ssh 同构：命令行 > 配置 > 内置）

```
① CLI 旗标（--book/--anchor-*/-p/--recover/--deadline-secs/--audit-log/--allow-unencrypted-swap）
② host token 内嵌端口（host:port）
③ 别名表字段（port/book/anchor_*/deadline_secs/audit_log）
④ 同目录锚约定（仅 anchor_a/anchor_b，且仅当 book 已知且旗标未显式给锚）
⑤ 内置常量（DEFAULT_JBUU_PORT=7717、deadline 120s 等）
```

特例（拒绝二义）：②与 `-p` 同给且不等 → exit 2。`--recover`、`--allow-unencrypted-swap` 只存在于旗标层（配置不收，§5.2）。

### 6.2 凭据三件套捆绑规则（D10，与逐字段覆盖的取舍）

`book`/`anchor_a`/`anchor_b` 是一组**同 book_id 凭据**（allocator 会做 `expected_book_id` 核对，混配必然启动失败）。若采用 ssh 式逐字段覆盖，`jbuu ops --book /新本` 会得到"别名锚 × 新本"的混配，错误迟至 allocator 打开才爆，报错远离肇事参数。**故裁定捆绑**：

> CLI 一旦显式给出三件套中**任一**旗标，别名表中的**三个凭据字段整体不参与**本次解析；解析结果=CLI 旗标 + 同目录锚约定补缺。CLI 一件未给时，三件套整体取别名（缺 book 参见 §5.2 脚注¹）。

效果示例：
- `jbuu ops --book ~/lab/otp.book` → 用 ~/lab/otp.book + ~/lab/ 下约定锚（别名凭据全弃，host/port 沿用别名）——正是"拿新本副本试连"的正确行为；
- `jbuu ops` → 三件全取别名；
- `jbuu 1.2.3.4 --book b` → CLI 凭据 + 内置端口（别名根本没参与，`host` 是地址不是别名）。

### 6.3 同目录锚约定（D11）

`--book P`（或别名 `book=P`）且未显式给锚时：取 `P` 所在目录下 `anchor-a.anchor`、`anchor-b.anchor`。依据：runbook §5.2 客户端初始化本就把三件并排放在 `~/jbuu-cli/`（book/anchor-a.anchor/anchor-b.anchor），约定=把现行最佳实践升格为缺省。**缺失时不自动创建**（"绝不顺手创建空锚毁现场"纪律，serve 侧既有口径同源）：报错 exit 2，并列出两个期望路径与 `--anchor-a/-b` 用法。这让芥末命令① `jbuu 192.0.2.10 --book <密码书路径>` 的"只给一个路径"成立（解读细化 R1 申报：原文未提锚，本设计以约定补足而非省略锚）。

---

## 7. `--full-otp` CLI 位预留（并行卡接口）

- **本卡只做登记**：名字 `--full-otp` 在表面登记表（§2）标记为"预留，语义由并行设计书定"；P0/P1 实现**不**添加该旗标，避免抢跑语义。
- **挂载位约定**（并行卡可直接引用）：直连旗面与 `connect` 旗面**同位**挂载（两者收敛于同一 `ConnectArgs`，天然一致）；旗标长名 `--full-otp`，短名不预留。
- 实现顺序协调：若并行卡先批，实现卡合并其挂载；若后批，加旗标属纯增量（新增 flag 不破坏任何现有调用）。

---

## 8. ⑤ 迁移路径：零破坏与 deprecation 策略

### 8.1 兼容矩阵（现状命令逐条裁定）

| 现有面 | 裁定 |
|---|---|
| 七个子命令 | 原样保留，语义/旗标/必填性零改动 |
| `connect --target` | 原样保留；仍只收字面 `host:port`（D5） |
| 全部退出码口径（0/N 回传/1/2/3） | 不变；新增使用错误仍落 2（§10 登记） |
| `serve --listen` 缺省 | **唯一申报微变**：`127.0.0.1:0`→`127.0.0.1:7717`（§4.3，风险已评估≈0） |
| `LISTEN=`/`READY=` stderr 行格式 | 冻结不动 |
| e2e/集成测试 | 全部显式 `--listen`，零改动实证 |

### 8.2 deprecation 策略（D13）

- **不设 deprecation 时钟，不删任何入口**：直连=人机主推口径（文档/帮助首例），`connect`=脚本/CI/测试入口，长期并存。理由：无遥测可依，人工判据（论坛反馈）不足以定时钟；两入口同收敛 `run_connect`，维护成本≈单入口。
- 若未来确要收口，另开 RFC 卡，届时以"帮助面降权→发布说明弃用告警→大版本移除"三步走，不在本卡预支。
- runbook §5.3 的 connect 命令**不要求改写**（照抄仍有效），但 v0.2 文档增补直连/别名为首选示例（§8.4）。

### 8.3 版本与依赖

- 版本 **0.2.0**（minor：新增用户可见表面+一处缺省值变更，无移除）。
- 新依赖：`toml = "0.8"` + `serde`（derive）入 `otp-cli`（workspace 无 TOML 解析器；手写解析器=bug 温床，否决；JSON 无注释不适合手运维文件，否决——见 §5 取舍）。实现卡须过 `cargo-deny`（deny.toml）复核新依赖树（toml 系纯 Rust、cargo 自身同源，预期无 advisories）。
- CODEOWNERS 影响：改动集中于 `crates/otp-cli`，不触协议/allocator/recovery/session 仓段。

### 8.4 文档与帮助面增补（实现卡内完成）

1. `--help` 首行用法串改为 `jbuu [选项] <主机|别名> / jbuu <子命令>`，Usage 示例首条=芥末命令①原文；
2. runbook §0.2：`SRV_PORT` 注释更新为"产品默认 7717（不设即用默认）"；§5.3 增直连与别名两例（原 connect 例保留）；新增 §5.5 客户端 config.toml 初始化（示例文件 + 0600 + `doctor --config`）；
3. README 快速开始改两行（serve 默认端口说明 + 直连一行）；
4. 仓内附 `docs/examples/jbuu-config.toml`（§5.2 同款注释版）。

---

## 9. ⑥ 与 doorkeeper（jbuu-doorkeeper）的部署视角配合

### 9.1 端口拓扑（目标态一张图）

```
公网 ──:22──> doorkeeper ──> 127.0.0.1:2222 sshd        （SSH 过渡垫，wp14，有日落）
mesh ──:7717─> jbuu serve（MESH_IP:7717）                （锦书服务面，常驻）
客户端：~/.config/jbuu/config.toml（别名/密码书路径）      （纯客户端制品）
```

- 7717 与门卫三端口（22/2222/2223）零重叠（runbook §0.2 既有避让注释正是为此）；nft 保险带（runbook §3.2）白名单从 `SRV_PORT` 变量改为默认值后照抄成立。
- **边界重申**：config.toml 只被**发起连接的 jbuu 进程**读取；serve 不读（服务端无别名概念）、doorkeeper 不读（门卫不做协议判定，wp14 安全边界声明）。别名机制不改变任何服务端/门卫行为。

### 9.2 SSH→锦书的别名迁移对照（运维视角，芥末②的落地动作）

```text
# ~/.ssh/config（迁移前）              # ~/.config/jbuu/config.toml（迁移后）
Host ops                               [alias.ops]
  HostName 192.0.2.10                 host  = "192.0.2.10"
  Port 22                                port  = 7717
  User ops                #→无对应       book  = "~/jbuu-cli/otp.book"
  IdentityFile ~/.ssh/id_ed25519  #→book（密钥位改密码书位）
```

过渡期两文件并存（ssh 别名指向 :22 门卫链路，jbuu 别名指向 mesh :7717），互不干扰；门卫日志（wp14 §7.10 仪表盘）仍是 SSH 流量日落的唯一判据，jbuu 别名推广不参与、不阻塞该判据。运维者从 `ssh ops` 切到 `jbuu ops` 的最小步骤：拿件（book 副本+book_id，runbook §5.1）→ 初始化双锚+同目录摆放（§5.2/§6.3）→ 写 config.toml（0600）→ `jbuu doctor --book …` → `jbuu ops`。

### 9.3 直连语义对门卫链路的无交集声明

直连/别名只走 mesh 直达 serve，**不存在**"经 doorkeeper 中转 jbuu 会话"的形态（门卫是 SSH 垫，非通用转发器；锦书流量过门卫既无必要也未被 wp14 覆盖）。本设计不新增任何公网暴露路径，mesh-only 铁律（runbook §0.1）原样继承：别名文件里的 host 应为 mesh 地址，公网地址+公网端口映射仍属站点违规配置，doctor/代码不放松（与 v0.1 同口径：代码不强制、runbook 纪律+nft 保险带兜底）。

---

## 10. 错误面与退出码登记（新增行）

| 触发 | 消息要点（stderr 一行） | 退出码 |
|---|---|---|
| 裸 `jbuu` | 简短帮助 | 2 |
| 直连旗标给了但缺 `<host>` | "缺少 <host>；直连用法见 --help" | 2 |
| 双端口来源冲突（`host:port` + `-p` 不等） | 两值并列回显 | 2 |
| token 既非地址也非已知别名 | "未知别名/地址 X（配置：<路径>；--help 看初始化示例）" | 2 |
| 配置文件存在但解析失败 | TOML 行列号+未知字段名 | 2 |
| 别名校验违规（§5.3） | 点名别名与违规项 | 2 |
| 别名/直连缺 book | "未配置 book：别名 X 未给 book 字段且未传 --book" | 2 |
| 同目录锚缺失 | 两个期望路径 + `--anchor-a/-b` 用法 | 2 |
| 其余（连接失败/doctor BLOCK/远端退出码） | **复用现状 connect 口径** | 1/2/N |

新增错误一律发生在"连接发起前"（纯本地解析），不触碰既有运行期错误分类。

---

## 11. 测试清单（实现卡直接转用例）

**T 组（解析矩阵单测，`try_parse_from`）**：T1 `jbuu`→help+2；T2 直连最小式（芥末命令①的解析等价）；T3 `host:port`；T4 IPv6 裸/方括号两形态；T5 别名命中；T6 `-p` 与内嵌端口冲突→2；T7 缺 host 带旗标→2；T8 双位置参数→2；T9 `--` 逃生门；T10 大小写（`Serve`→别名/地址路径，非子命令）；T11 顶层旗标+子命令不串层；T12 既有 `command_surface_parses` 全绿零改动（回归锚）。

**P 组（优先级/捆绑单测）**：P1 旗标>别名；P2 内嵌>别名 port；P3 别名>常量 7717；P4 凭据捆绑三例（§6.2 三行场景）；P5 同目录锚命中；P6 锚缺失报错文案含双路径；P7 `--recover` 只在旗标层；P8 别名不给 book 且无 `--book`→2。

**C 组（config 解析单测）**：C1 坏 TOML 行列号；C2 未知字段拒绝；C3 同名别名重复拒绝；C4 别名违规三规则逐条；C5 `~` 展开与前导字面 `~`；C6 文件不存在=空表；C7 `--config` 覆盖发现路径；C8 0600 权限 warn（P2）。

**E 组（e2e，loopback）**：E1 serve `:0`+`jbuu 127.0.0.1 -p $port --book`（读 LISTEN= 取端口，避免并发抢占默认端口）；E2 **芥末命令①端到端**：serve 默认 `--listen`（127.0.0.1:7717）+ 同目录三件套摆放 + `jbuu 127.0.0.1 --book b` 连通拿到 shell 退出码（7717 被占则 skip 并标注，CI 串行段跑）；E3 别名端到端（`--config` 指 tempdir，覆盖旗标/捆绑各一例）；E4 未知别名/缺锚两条错误路径 exit 2；E5 runbook §5.3 旧 connect 命令照抄回归（零破坏验收）。

---

## 12. 分期与实现卡建议

| 期 | 内容 | 规模 |
|---|---|---|
| P0 | 直连形态（位置参数+旗面+分派）、默认端口常量+覆盖链、同目录锚约定、serve 缺省监听变更、T/P5-6/E1-2 用例、帮助面首例 | ~1 人日 |
| P1 | config.toml（toml/serde 依赖+deny 复核）、别名解析+捆绑规则、`--config`、C 组+E3/E4 | ~1.5 人日 |
| P2 | `doctor --config` 校验、clap_complete 补全、runbook/README/示例文件增补、E5 | ~0.5 人日 |

建议**一张实现卡承载 P0+P1**（同一 CLI 表面拆卡会互相踩解析结构），P2 并入同卡尾部或另开小卡；芥末批注"后期"（定案②）由 P1 承接，P0 先行满足定案①。

---

## 13. 决策点汇总（提请芥末/评审逐条确认）

| # | 决策 | 摘要 | 风险面 |
|---|---|---|---|
| D1 | 直连形态 | 顶层可选位置参数+connect 旗面，收敛 `run_connect` | 无（纯增量） |
| D2 | 无参默认 | 帮助+exit 2，不隐式连接 | 用户体验预期 |
| D3 | host 文法 | `host[:port]`/`[v6]:port`，无 `user@` | 与 ssh 习惯差一个 `user@`（无用户概念） |
| D4 | 别名先于 DNS | ssh 同款 | 字面主机名撞别名时需删别名（极边角） |
| D5 | connect 不解析别名 | 冻结面不加隐式行为 | `connect --target ops` 报"连接失败"需用户自学（§3.6 理由） |
| D6 | 默认端口 7717 | 五准则+IANA 复核前置；备选 9778/15717 | 定值本身 |
| D7 | 配置路径 | XDG 单文件，`--config` 覆盖 | 无系统级配置（多用户机各自维护） |
| D8 | TOML+deny_unknown_fields | 新增 toml/serde 依赖 | 依赖树（cargo-deny 复核） |
| D9 | schema 字段面 | §5.2 表；recover/allow_unencrypted_swap/full_otp 不收 | 少数 ssh 用户想要 recover 预设（会话态，拒绝） |
| D10 | 凭据三件套捆绑 | 混配 fail early | 与 ssh 逐字段习惯不同（文档示例覆盖） |
| D11 | 同目录锚约定+不自动创建 | 原文①只给 --book 的成立前提 | 布局不符者需显式给锚（报错指路） |
| D12 | `--full-otp` 只登记不实现 | 并行卡所有 | 无 |
| D13 | 不设 deprecation 时钟 | 直连/connect 长期并存 | 表面双入口（收敛同实现，成本低） |
| D14 | serve 缺省监听 127.0.0.1:7717 | 唯一行为微变 | 同机双裸 serve 边角冲突 |
| D15 | 端口二义拒绝 | `host:port`+`-p` 不等→exit 2 | 无 |
| D16 | allow_unencrypted_swap 不入配置 | 降级须每次显式 | 高 swap 站点每台机器要敲 flag（安全收益优先） |

## 14. 偏差与解读细化申报（硬偏差=0）

| # | 类型 | 内容 |
|---|---|---|
| R1 | 解读细化 | 定案①命令只出现 `--book`：锚由"同目录约定"补足（§6.3），非省略锚——锚仍是硬前提，只是缺省位置化 |
| R2 | 解读细化 | "不带子命令直接走 connect"落为"顶层位置参数=host 的 connect 语义"；`connect` 子命令本身保留（零破坏总则） |
| R3 | 解读细化 | 定案②"和 ssh 那样"取其**别名+身份文件映射**子集（§5.4 映射表），pattern/Include/ProxyJump 等明确不做（§3.6）；"其他的不变"以兼容矩阵（§8.1）兑现 |
| R4 | 解读细化 | "后期"=P1 分期（§12），P0 只交付定案①；若芥末要求①②同期，P0+P1 一卡交付即可 |

——全文完——
