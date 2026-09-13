//! §8 测试 2：端到端——临时 sshd（测试密钥）+ 门卫 + 本机 ssh/scp。
//! openssh 二进制缺席则 SKIP 并标注。
#![allow(dead_code)]
mod support;

use std::process::Command;

use support::{DkHandle, SshdRig, TempDir, dk_config, wait_for_event};

fn ssh_bin() -> Option<std::path::PathBuf> {
    support::which("ssh")
}

/// 登录 + 执行命令：whoami 输出正确，且 -v 可见警告行（§7 步骤 3 验证链）
#[test]
fn t02_e2e_ssh_login_and_command() {
    let (Some(_), Ok(sshd)) = (ssh_bin(), SshdRig::start()) else {
        eprintln!("SKIP: ssh 二进制缺席或测试 sshd 不可用（保留『实测』仅限环境内）");
        return;
    };
    let dir = TempDir::new("t02");
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        sshd.addr,
        dir.join("dk.log"),
    ));

    // 登录 + 命令
    let out = Command::new("ssh")
        .args(sshd.ssh_base_args())
        .arg("-p")
        .arg(dk.addr.port().to_string())
        .arg(format!("{}@127.0.0.1", sshd.user))
        .arg("echo SSH-THROUGH-DOORKEEPER; id -un")
        .output()
        .expect("执行 ssh 失败");
    assert!(
        out.status.success(),
        "ssh 登录失败：{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("SSH-THROUGH-DOORKEEPER"), "{stdout}");
    assert!(stdout.contains(&sshd.user), "{stdout}");

    // 完整事件链（§7 步骤 3：conn_accept→warn_sent→upstream_connect→client_version→conn_close）
    let _ = wait_for_event(&dk.log_path, "conn_accept", |v| {
        v["conn_id"].as_u64() == Some(1)
    });
    let warn = wait_for_event(&dk.log_path, "warn_sent", |_| true);
    assert_eq!(warn["bytes"].as_u64(), Some(101));
    let _ = wait_for_event(&dk.log_path, "upstream_connect", |v| {
        v["ok"] == serde_json::json!(true)
    });
    let ver = wait_for_event(&dk.log_path, "client_version", |_| true);
    assert!(
        ver["version"]
            .as_str()
            .unwrap_or("")
            .starts_with("SSH-2.0-OpenSSH"),
        "客户端版本串必须被观察记录：{}",
        ver["version"]
    );
    let close = wait_for_event(&dk.log_path, "conn_close", |_| true);
    assert_eq!(close["reason"].as_str(), Some("normal"));

    // -v 可见前置警告行（E2：默认忽略，debug 级显示）
    let out = Command::new("ssh")
        .arg("-v")
        .args(sshd.ssh_base_args())
        .arg("-p")
        .arg(dk.addr.port().to_string())
        .arg(format!("{}@127.0.0.1", sshd.user))
        .arg("true")
        .output()
        .expect("执行 ssh -v 失败");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("banner line 0"),
        "-v 必须能看到 banner 行：\n{stderr}"
    );
    assert!(
        stderr.contains("NOTICE: SSH endpoint deprecated, migrating to jbuu"),
        "banner 行内容必须是冻结警告行 ASCII 主干：\n{stderr}"
    );
}

/// scp 传文件过门卫
#[test]
fn t02_e2e_scp_file_transfer() {
    let (Some(_), Ok(sshd)) = (ssh_bin(), SshdRig::start()) else {
        eprintln!("SKIP: ssh/scp 缺席或测试 sshd 不可用");
        return;
    };
    let dir = TempDir::new("t02s");
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        sshd.addr,
        dir.join("dk.log"),
    ));

    let src = dir.join("payload.bin");
    let dst = dir.join("payload.roundtrip");
    let payload: Vec<u8> = (0..128 * 1024u32).map(|i| (i * 7 + 13) as u8).collect();
    std::fs::write(&src, &payload).unwrap();

    let out = Command::new("scp")
        .args(sshd.ssh_base_args())
        .arg("-P")
        .arg(dk.addr.port().to_string())
        .arg(&src)
        .arg(format!("{}@127.0.0.1:{}", sshd.user, dst.display()))
        .output()
        .expect("执行 scp 失败");
    assert!(
        out.status.success(),
        "scp 失败：{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let back = std::fs::read(&dst).expect("回传文件必须存在");
    assert_eq!(
        support::md5_hex(&back),
        support::md5_hex(&payload),
        "scp 字节精确"
    );
}
