# 第三方依赖 NOTICE 清单（THIRD-PARTY-NOTICE）

项目 **jbuu**（锦书；仓库名 `otp-term` 沿用，公开仓同步归调度）以 **GPL-3.0-or-later** 发布（根目录 LICENSE）。本清单按
`Cargo.lock`（基线 commit `617a3a4`，生成日 2026-09-14）**全量**列出
全部第三方 Rust 依赖（crates.io 来源，直接 + 传递依赖，共 **100** 个条目：
直接声明 11 种、lock 中 13 条（getrandom 锁 3 个版本），传递 87 条；另 14 个
`otp-*` 为本 workspace 内部 crate，属本项目自身，不在此列）。

每条 license 均为上游发布清单（crates.io 索引元数据）中的**原始 license 字段**，
未做改写。本项目发布物如随附这些依赖（源码或编译产物），须遵守对应许可条款：
MIT/Apache-2.0/BSD/Unicode 等均要求保留版权与许可声明（Apache-2.0 另要求
保留 NOTICE 文件内容，见上游各仓库）。

## 许可分布汇总

| license（原始字段） | 数量 |
|---|---:|
| MIT OR Apache-2.0 | 64 |
| Apache-2.0 OR MIT | 12 |
| Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 5 |
| MIT/Apache-2.0 | 4 |
| MIT | 4 |
| Unlicense OR MIT | 3 |
| MIT OR Apache-2.0 OR LGPL-2.1-or-later | 2 |
| BSD-2-Clause OR Apache-2.0 OR MIT | 2 |
| (MIT OR Apache-2.0) AND Unicode-3.0 | 1 |
| BSD-3-Clause | 1 |
| Apache-2.0 / MIT | 1 |
| Apache-2.0/MIT | 1 |

## 与本项目 GPL-3.0-or-later 的兼容口径（楼321 明镜结论，发布前逐条复核过）

- **Rust 第三方依赖无阻 GPL-3.0-or-later 的许可问题**：上表 100 项全部为
  MIT / Apache-2.0 / BSD-2-Clause / BSD-3-Clause / Unlicense / Unicode-3.0 /
  Apache-2.0 WITH LLVM-exception 的组合；`cargo deny check licenses` 以
  deny.toml 白名单（MIT、Apache-2.0、Apache-2.0 WITH LLVM-exception、
  Unicode-3.0、BSD-2-Clause、BSD-3-Clause）**实跑全绿**，无任何 copyleft
  强制项被实际采纳。
- **Apache-2.0 与 GPLv3 单向兼容**：Apache-2.0 依赖可并入 GPL-3.0-or-later
  发布（ GPLv3 §7 附加条款允许；口径为 **GPLv3 兼容**，勿写作 GPLv2——
  Apache-2.0 与 GPLv2 不兼容，本项目 license 是 GPL-3.0-or-later，不受影响）。
- **多许可（OR）项按宽松分支采纳**：
  - \`r-efi\`（2 个版本）为 "MIT OR Apache-2.0 OR **LGPL-2.1-or-later**"——
    本项目按 **MIT 或 Apache-2.0 分支**采纳，不触发 LGPL 义务（LGPL 分支未采纳）；
  - \`memchr\` / \`termcolor\` / \`winapi-util\` 为 "Unlicense OR MIT"——按 MIT 采纳；
  - 其余 OR 组合均含 MIT/Apache-2.0 分支，按宽松分支采纳。
- **AND 组合**：\`unicode-ident\` "(MIT OR Apache-2.0) AND Unicode-3.0"——
  Unicode-3.0 已在白名单内，两项条款并存均满足。
- **Apache-2.0 WITH LLVM-exception**（rustix 系、wasi 系、wit-bindgen）：
  LLVM-exception 只放宽 Apache-2.0（允许与 GPL 组合更自由），对合规只松不紧。
- 白名单只约束**第三方依赖**，不限制项目自身采用 GPL；本项目各 crate 的
  \`license = "GPL-3.0-or-later"\` 字段统一不动（merge 70a5f77 已完成统一）。

## 明细（100 项，按名称排序；"直接"= 任一 workspace 成员直接声明）

| # | crate | 版本 | license（上游原始字段） | 直接/传递 |
|---:|---|---|---|---|
| 1 | `aead` | 0.5.2 | MIT OR Apache-2.0 | 传递 |
| 2 | `anstream` | 1.0.0 | MIT OR Apache-2.0 | 传递 |
| 3 | `anstyle` | 1.0.14 | MIT OR Apache-2.0 | 传递 |
| 4 | `anstyle-parse` | 1.0.0 | MIT OR Apache-2.0 | 传递 |
| 5 | `anstyle-query` | 1.1.5 | MIT OR Apache-2.0 | 传递 |
| 6 | `anstyle-wincon` | 3.0.11 | MIT OR Apache-2.0 | 传递 |
| 7 | `autocfg` | 1.5.1 | Apache-2.0 OR MIT | 传递 |
| 8 | `bitflags` | 2.13.2 | MIT OR Apache-2.0 | 传递 |
| 9 | `bit-set` | 0.8.0 | Apache-2.0 OR MIT | 传递 |
| 10 | `bit-vec` | 0.8.0 | Apache-2.0 OR MIT | 传递 |
| 11 | `block-buffer` | 0.10.4 | MIT OR Apache-2.0 | 传递 |
| 12 | `cfg-if` | 1.0.4 | MIT OR Apache-2.0 | 传递 |
| 13 | `chacha20` | 0.9.1 | Apache-2.0 OR MIT | 传递 |
| 14 | `chacha20poly1305` | 0.10.1 | Apache-2.0 OR MIT | 直接 |
| 15 | `cipher` | 0.4.4 | MIT OR Apache-2.0 | 传递 |
| 16 | `clap` | 4.6.6 | MIT OR Apache-2.0 | 直接 |
| 17 | `clap_builder` | 4.6.6 | MIT OR Apache-2.0 | 传递 |
| 18 | `clap_derive` | 4.6.4 | MIT OR Apache-2.0 | 传递 |
| 19 | `clap_lex` | 1.1.0 | MIT OR Apache-2.0 | 传递 |
| 20 | `colorchoice` | 1.0.5 | MIT OR Apache-2.0 | 传递 |
| 21 | `cpufeatures` | 0.2.17 | MIT OR Apache-2.0 | 传递 |
| 22 | `crypto-common` | 0.1.7 | MIT OR Apache-2.0 | 传递 |
| 23 | `digest` | 0.10.7 | MIT OR Apache-2.0 | 传递 |
| 24 | `equivalent` | 1.0.2 | Apache-2.0 OR MIT | 传递 |
| 25 | `errno` | 0.3.14 | MIT OR Apache-2.0 | 传递 |
| 26 | `fastrand` | 2.5.0 | Apache-2.0 OR MIT | 传递 |
| 27 | `fnv` | 1.0.7 | Apache-2.0 / MIT | 传递 |
| 28 | `generic-array` | 0.14.7 | MIT | 传递 |
| 29 | `getrandom` | 0.2.17 | MIT OR Apache-2.0 | 直接 |
| 30 | `getrandom` | 0.3.4 | MIT OR Apache-2.0 | 直接 |
| 31 | `getrandom` | 0.4.3 | MIT OR Apache-2.0 | 直接 |
| 32 | `glob` | 0.3.4 | MIT OR Apache-2.0 | 传递 |
| 33 | `hashbrown` | 0.17.1 | MIT OR Apache-2.0 | 传递 |
| 34 | `heck` | 0.5.0 | MIT OR Apache-2.0 | 传递 |
| 35 | `indexmap` | 2.14.2 | Apache-2.0 OR MIT | 传递 |
| 36 | `inout` | 0.1.4 | MIT OR Apache-2.0 | 传递 |
| 37 | `is_terminal_polyfill` | 1.70.2 | MIT OR Apache-2.0 | 传递 |
| 38 | `itoa` | 1.0.18 | MIT OR Apache-2.0 | 传递 |
| 39 | `libc` | 0.2.189 | MIT OR Apache-2.0 | 直接 |
| 40 | `linux-raw-sys` | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 传递 |
| 41 | `memchr` | 2.8.3 | Unlicense OR MIT | 传递 |
| 42 | `num-traits` | 0.2.19 | MIT OR Apache-2.0 | 传递 |
| 43 | `once_cell` | 1.21.4 | MIT OR Apache-2.0 | 传递 |
| 44 | `once_cell_polyfill` | 1.70.2 | MIT OR Apache-2.0 | 传递 |
| 45 | `opaque-debug` | 0.3.1 | MIT OR Apache-2.0 | 传递 |
| 46 | `poly1305` | 0.8.0 | Apache-2.0 OR MIT | 传递 |
| 47 | `ppv-lite86` | 0.2.21 | MIT OR Apache-2.0 | 传递 |
| 48 | `proc-macro2` | 1.0.107 | MIT OR Apache-2.0 | 传递 |
| 49 | `proptest` | 1.11.0 | MIT OR Apache-2.0 | 直接 |
| 50 | `quick-error` | 1.2.3 | MIT/Apache-2.0 | 传递 |
| 51 | `quote` | 1.0.47 | MIT OR Apache-2.0 | 传递 |
| 52 | `rand` | 0.9.5 | MIT OR Apache-2.0 | 传递 |
| 53 | `rand_chacha` | 0.9.0 | MIT OR Apache-2.0 | 传递 |
| 54 | `rand_core` | 0.6.4 | MIT OR Apache-2.0 | 传递 |
| 55 | `rand_core` | 0.9.5 | MIT OR Apache-2.0 | 传递 |
| 56 | `rand_xorshift` | 0.4.0 | MIT OR Apache-2.0 | 传递 |
| 57 | `r-efi` | 5.3.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | 传递 |
| 58 | `r-efi` | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | 传递 |
| 59 | `regex-syntax` | 0.8.11 | MIT OR Apache-2.0 | 传递 |
| 60 | `rustix` | 1.1.4 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 直接 |
| 61 | `rusty-fork` | 0.3.1 | MIT/Apache-2.0 | 传递 |
| 62 | `serde` | 1.0.229 | MIT OR Apache-2.0 | 传递 |
| 63 | `serde_core` | 1.0.229 | MIT OR Apache-2.0 | 传递 |
| 64 | `serde_derive` | 1.0.229 | MIT OR Apache-2.0 | 传递 |
| 65 | `serde_json` | 1.0.151 | MIT OR Apache-2.0 | 直接 |
| 66 | `serde_spanned` | 1.1.1 | MIT OR Apache-2.0 | 传递 |
| 67 | `sha2` | 0.10.9 | MIT OR Apache-2.0 | 直接 |
| 68 | `signal-hook` | 0.3.18 | Apache-2.0/MIT | 直接 |
| 69 | `signal-hook-registry` | 1.4.8 | MIT OR Apache-2.0 | 传递 |
| 70 | `strsim` | 0.11.1 | MIT | 传递 |
| 71 | `subtle` | 2.6.1 | BSD-3-Clause | 传递 |
| 72 | `syn` | 2.0.119 | MIT OR Apache-2.0 | 传递 |
| 73 | `syn` | 3.0.5 | MIT OR Apache-2.0 | 传递 |
| 74 | `target-triple` | 1.0.1 | MIT OR Apache-2.0 | 传递 |
| 75 | `tempfile` | 3.27.0 | MIT OR Apache-2.0 | 传递 |
| 76 | `termcolor` | 1.4.1 | Unlicense OR MIT | 传递 |
| 77 | `toml` | 1.1.6+spec-1.1.0 | MIT OR Apache-2.0 | 传递 |
| 78 | `toml_datetime` | 1.1.1+spec-1.1.0 | MIT OR Apache-2.0 | 传递 |
| 79 | `toml_parser` | 1.1.3+spec-1.1.0 | MIT OR Apache-2.0 | 传递 |
| 80 | `toml_writer` | 1.1.2+spec-1.1.0 | MIT OR Apache-2.0 | 传递 |
| 81 | `trybuild` | 1.0.119 | MIT OR Apache-2.0 | 直接 |
| 82 | `typenum` | 1.20.1 | MIT OR Apache-2.0 | 传递 |
| 83 | `unarray` | 0.1.4 | MIT OR Apache-2.0 | 传递 |
| 84 | `unicode-ident` | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 | 传递 |
| 85 | `universal-hash` | 0.5.1 | MIT OR Apache-2.0 | 传递 |
| 86 | `utf8parse` | 0.2.2 | Apache-2.0 OR MIT | 传递 |
| 87 | `version_check` | 0.9.5 | MIT/Apache-2.0 | 传递 |
| 88 | `wait-timeout` | 0.2.1 | MIT/Apache-2.0 | 传递 |
| 89 | `wasi` | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 传递 |
| 90 | `wasip2` | 1.0.1+wasi-0.2.4 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 传递 |
| 91 | `winapi-util` | 0.1.11 | Unlicense OR MIT | 传递 |
| 92 | `windows-link` | 0.2.1 | MIT OR Apache-2.0 | 传递 |
| 93 | `windows-sys` | 0.61.2 | MIT OR Apache-2.0 | 传递 |
| 94 | `winnow` | 1.0.4 | MIT | 传递 |
| 95 | `wit-bindgen` | 0.46.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 传递 |
| 96 | `zerocopy` | 0.8.57 | BSD-2-Clause OR Apache-2.0 OR MIT | 传递 |
| 97 | `zerocopy-derive` | 0.8.57 | BSD-2-Clause OR Apache-2.0 OR MIT | 传递 |
| 98 | `zeroize` | 1.9.0 | Apache-2.0 OR MIT | 直接 |
| 99 | `zeroize_derive` | 1.5.0 | Apache-2.0 OR MIT | 传递 |
| 100 | `zmij` | 1.0.23 | MIT | 传递 |

## 再生成方法

```sh
cargo metadata --locked --format-version 1 \
  | jq -r '.packages[] | select(.source != null)
           | [.name, .version, (.license // "NO-LICENSE-FIELD")] | @tsv' | sort
```

升级依赖（Cargo.lock 变更）后须同步再生成本清单并过质量门
（`scripts/quality-gate.sh` 第 5 项 `cargo deny check licenses bans sources`）。
