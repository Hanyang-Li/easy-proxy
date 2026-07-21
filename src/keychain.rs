//! 密码存 macOS 钥匙串（service = easy-proxy, account = 用户名）。
//! 首次没有则由调用方交互索取后 set；密码变更时 set 会覆盖更新。

use anyhow::{anyhow, Context, Result};
use std::process::Command;

const SERVICE: &str = "easy-proxy";

/// 从钥匙串取密码；不存在返回 None。
pub fn get_password(account: &str) -> Option<String> {
    let out = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", SERVICE, "-a", account, "-w"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let pwd = String::from_utf8_lossy(&out.stdout).trim_end_matches('\n').to_string();
    if pwd.is_empty() {
        None
    } else {
        Some(pwd)
    }
}

/// 写入/更新密码（-U 已存在则覆盖）。
pub fn set_password(account: &str, password: &str) -> Result<()> {
    let out = Command::new("/usr/bin/security")
        .args([
            "add-generic-password", "-s", SERVICE, "-a", account, "-w", password, "-U",
        ])
        .output()
        .context("无法执行 security add-generic-password")?;
    if out.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "写入钥匙串失败: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// 删除密码（忽略不存在）。
#[allow(dead_code)]
pub fn delete_password(account: &str) {
    let _ = Command::new("/usr/bin/security")
        .args(["delete-generic-password", "-s", SERVICE, "-a", account])
        .output();
}
