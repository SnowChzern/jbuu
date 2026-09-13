//! §4.1 兼容矩阵回填（本机可安装客户端实测）：paramiko。
//! 本机不可得时 SKIP 并保留原证据等级标注（由 evidence 汇总维护）。
#![allow(dead_code)]
mod support;

use std::process::Command;

use support::{DkHandle, SshdRig, TempDir, dk_config};

fn paramiko_available() -> bool {
    Command::new("python3")
        .arg("-c")
        .arg("import paramiko; print(paramiko.__version__)")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// paramiko（Ansible/自动化链路）经门卫 + 真 sshd：connect + exec + sftp-open
#[test]
fn matrix_paramiko_client() {
    if !paramiko_available() {
        eprintln!("SKIP: 本机无 paramiko（保留『文献预期，待实测』标注）");
        return;
    }
    let Ok(sshd) = SshdRig::start() else {
        eprintln!("SKIP: 测试 sshd 不可用");
        return;
    };
    let dir = TempDir::new("mx1");
    let dk = DkHandle::start(dk_config(
        "127.0.0.1:0".parse().unwrap(),
        sshd.addr,
        dir.join("dk.log"),
    ));

    let script = format!(
        r#"
import sys
import paramiko
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(
    "127.0.0.1", port={port}, username="{user}",
    key_filename="{key}", look_for_keys=False, allow_agent=False,
    banner_timeout=15, timeout=15,
)
stdin, stdout, stderr = client.exec_command("echo PARAMIKO-THROUGH-DOORKEEPER", timeout=15)
out = stdout.read().decode().strip()
assert out == "PARAMIKO-THROUGH-DOORKEEPER", out
sftp = client.open_sftp()
with sftp.open("/tmp/jbuu-dk-paramiko-probe", "w") as f:
    f.write("sftp-ok")
sftp.close()
client.close()
print("PARAMIKO-CLIENT-OK", paramiko.__version__)
"#,
        port = dk.addr.port(),
        user = sshd.user,
        key = sshd.identity.display(),
    );

    let out = Command::new("python3")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("执行 python3 失败");
    assert!(
        out.status.success(),
        "paramiko 经门卫失败：{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("PARAMIKO-CLIENT-OK"), "{stdout}");
    eprintln!("matrix: {stdout}");

    // 门卫侧版本串观察也应记录 paramiko 的版本行
    let ver = support::wait_for_event(&dk.log_path, "client_version", |_| true);
    assert!(
        ver["version"].as_str().unwrap_or("").starts_with("SSH-2.0"),
        "paramiko 版本串应被观察：{}",
        ver["version"]
    );
}
