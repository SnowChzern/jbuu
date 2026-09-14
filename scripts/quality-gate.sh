#!/usr/bin/env bash
# otp-term 质量门（WP-04，任务 #33）—— CI 入口 / 合并前置门。
#
# 用法：
#   ./scripts/quality-gate.sh                # fmt / clippy / test / unsafe 检查 / deny(licenses,bans,sources)
#   SKIP_DENY=1 ./scripts/quality-gate.sh    # 显式跳过 cargo-deny（特殊环境临时用，交付帖须注明）
#   DENY_ADVISORIES=1 ./scripts/quality-gate.sh  # 附加 advisories（需联网拉漏洞库）
#
# 全绿要求：五项检查全部通过；deny 项为默认必跑（工具缺失即 FAIL，不再静默跳过；
# SKIP_DENY=1 时为四项，且必须在交付帖注明）——v0.1 发布前置（任务 #60）。
set -euo pipefail
cd "$(dirname "$0")/.."

pass() { printf '\033[32m[PASS]\033[0m %s\n' "$1"; }
fail() { printf '\033[31m[FAIL]\033[0m %s\n' "$1"; }
step() { printf '\033[36m==== %s ====\033[0m\n' "$1"; }

overall=0
run_check() {
    # run_check <名称> <命令...>
    local name="$1"; shift
    step "$name"
    if "$@"; then
        pass "$name"
    else
        fail "$name"
        overall=1
    fi
}

printf '工具链: %s | cargo %s\n' \
    "$(rustc --version 2>/dev/null || echo 'rustc 缺失')" \
    "$(cargo --version 2>/dev/null || echo '缺失')"

# 1. 格式检查
run_check "cargo fmt --check" cargo fmt --all -- --check

# 2. clippy -D warnings（全 workspace、含测试目标）
run_check "cargo clippy -D warnings" \
    cargo clippy --workspace --all-targets -- -D warnings

# 3. 测试（--locked：禁止悄悄改写 Cargo.lock）
run_check "cargo test --locked" cargo test --workspace --locked

# 4. 核心 crate unsafe 检查（forbid(unsafe_code) + 源码零 unsafe）
run_check "unsafe 检查（allocator/recovery/session）" bash scripts/check-unsafe.sh

# 5. cargo deny（依赖许可/禁用/来源；advisories 需联网）
if command -v cargo-deny >/dev/null 2>&1; then
    if [[ "${SKIP_DENY:-0}" == "1" ]]; then
        printf '\033[33m[SKIP]\033[0m cargo-deny（SKIP_DENY=1 显式跳过，交付帖须注明）\n'
    else
        checks="${DENY_CHECKS:-licenses bans sources}"
        if [[ "${DENY_ADVISORIES:-0}" == "1" ]]; then
            checks="advisories $checks"
        fi
        # shellcheck disable=SC2086
        run_check "cargo deny check ($checks)" cargo deny check --hide-inclusion-graph $checks
    fi
else
    fail "cargo-deny 不可用（安装：cargo install cargo-deny --locked）；deny 项为默认必跑，装不上即本门不绿（旧版 SKIP_DENY=1 兜底已移除，工具缺失不再有静默跳过出口）"
    overall=1
fi

step "总结"
if (( overall == 0 )); then
    pass "质量门全绿"
else
    fail "质量门未通过"
fi
exit "$overall"
