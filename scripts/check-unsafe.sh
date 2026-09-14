#!/usr/bin/env bash
# 核心 crate unsafe 检查（WP-04，任务 #33）—— 质量门第 4 项。
#
# 规则（规划 §1.2）：
#   1. 核心 crate（otp-allocator / otp-recovery / otp-session）lib.rs 必须带
#      `#![forbid(unsafe_code)]`；
#   2. 上述 crate 的 src/ 下不得出现任何 unsafe 用法；
#   3. 其余业务 crate 必须 forbid（otp-platform 为 deny + 审计豁免政策，
#      见其 crate 文档）。
set -euo pipefail
cd "$(dirname "$0")/.."

core_crates=(otp-allocator otp-recovery otp-session otp-fullotp)
other_crates=(otp-types otp-codec otp-book otp-anchor-spec otp-handshake
              otp-transport otp-terminal otp-testkit otp-cli)
status=0

for c in "${core_crates[@]}"; do
    lib="crates/$c/src/lib.rs"
    if [[ ! -f "$lib" ]]; then
        printf '[FAIL] 缺少 %s\n' "$lib"
        status=1
        continue
    fi
    if ! grep -q 'forbid(unsafe_code)' "$lib"; then
        printf '[FAIL] %s 缺少 #![forbid(unsafe_code)]\n' "$lib"
        status=1
    fi
    # 源码中出现 unsafe token（排除 forbid 声明行与注释里的“forbid(unsafe_code)”）
    hits=$(grep -rn --include='*.rs' -w 'unsafe' "crates/$c/src" \
        | grep -v 'forbid(unsafe_code)' \
        | grep -v 'deny(unsafe_code)' || true)
    if [[ -n "$hits" ]]; then
        printf '[FAIL] %s 存在 unsafe 用法（须单独审计卡批准，核心 crate 一律禁止）:\n%s\n' \
            "crates/$c" "$hits"
        status=1
    fi
done

for c in "${other_crates[@]}"; do
    lib="crates/$c/src/lib.rs"
    main="crates/$c/src/main.rs"
    found=0
    [[ -f "$lib" && $(grep -c 'forbid(unsafe_code)' "$lib") -gt 0 ]] && found=1
    [[ -f "$main" && $(grep -c 'forbid(unsafe_code)' "$main") -gt 0 ]] && found=1
    if (( found == 0 )); then
        printf '[FAIL] %s 未声明 #![forbid(unsafe_code)]（unsafe 政策见 otp-platform 文档）\n' "crates/$c"
        status=1
    fi
done

if (( status == 0 )); then
    # 核心加密材料 crate 新增说明：otp-fullotp（full-OTP 数据面：pad/bundle/
    # 一次性 Poly1305 key，任务 #75）与 session 同级，一律禁止 unsafe。
    printf '[PASS] unsafe 检查：核心 crate（%s）forbid 且零 unsafe；其余业务 crate forbid\n' \
        "${core_crates[*]}"
fi
exit "$status"
