//! 后台守护的启停、就绪等待与延迟探测。

use crate::capsule::Delay;
use crate::config::{AppConfig, Paths, RuntimeState};
use anyhow::{anyhow, Context, Result};
use std::fs::{self, File};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const SOCKS_UPSTREAM: &str = "127.0.0.1:1080";
pub const HTTP_UPSTREAM: &str = "127.0.0.1:1081";

pub fn pid_alive(pid: i32) -> bool {
    pid > 0 && unsafe { libc::kill(pid, 0) } == 0
}

/// 以会话首进程（setsid）方式启动脱离终端的守护进程。
pub fn spawn_daemon(paths: &Paths, cfg: &AppConfig, twfid: &str) -> Result<()> {
    fs::create_dir_all(&paths.config_dir)?;
    paths.clear_state();
    let exe = std::env::current_exe().context("无法定位自身可执行文件")?;
    let log = File::create(&paths.daemon_log)
        .with_context(|| format!("无法创建 {}", paths.daemon_log.display()))?;
    let mut cmd = Command::new(exe);
    cmd.arg("__serve")
        .arg("--twfid").arg(twfid)
        .arg("--server").arg(&cfg.server)
        .arg("--https-port").arg(cfg.port.to_string())
        .arg("--mixed-port").arg(cfg.mixed_port.to_string())
        .arg("--socks").arg(SOCKS_UPSTREAM)
        .arg("--http").arg(HTTP_UPSTREAM)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd.spawn().context("无法启动后台守护进程")?;
    Ok(())
}

/// 轮询状态文件直到守护报告 connected / error / 超时。
pub fn wait_ready(paths: &Paths, timeout: Duration) -> Result<RuntimeState> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(st) = paths.read_state() {
            if st.connected {
                return Ok(st);
            }
            if let Some(err) = st.error {
                return Err(anyhow!(
                    "隧道启动失败: {err}\n详见 {}",
                    paths.tunnel_log.display()
                ));
            }
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "等待隧道就绪超时\n--- tunnel.log 末尾 ---\n{}",
                read_tail(paths, 1000)
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn read_tail(paths: &Paths, bytes: usize) -> String {
    let text = fs::read_to_string(&paths.tunnel_log).unwrap_or_default();
    let start = text.len().saturating_sub(bytes);
    text[start..].to_string()
}

/// 通过混合端口探测到网关的延迟（毫秒）。预算 3s，失败重试一次，两次失败为 Timeout。
pub fn probe_latency(port: u16, server: &str) -> Delay {
    for _ in 0..2 {
        let mut cmd = Command::new("/usr/bin/curl");
        for v in crate::login::PROXY_ENV {
            cmd.env_remove(v);
        }
        let out = cmd
            .args([
                "-x",
                &format!("http://127.0.0.1:{port}"),
                "-sk",
                "-o",
                "/dev/null",
                "--max-time",
                "3",
                "-w",
                "%{time_total}",
                &format!("https://{server}/"),
            ])
            .output();
        if let Ok(out) = out {
            if out.status.success() {
                if let Ok(secs) = String::from_utf8_lossy(&out.stdout).trim().parse::<f64>() {
                    if secs > 0.0 {
                        return Delay::Value((secs * 1000.0).round() as u64);
                    }
                }
            }
        }
    }
    Delay::Timeout
}

/// 停止守护：先给守护发 SIGTERM（其会杀掉 zju-connect 子进程），再兜底清理并清状态。
pub fn stop_daemon(paths: &Paths) {
    if let Some(st) = paths.read_state() {
        if st.daemon_pid > 0 && pid_alive(st.daemon_pid) {
            unsafe {
                libc::kill(st.daemon_pid, libc::SIGTERM);
            }
        }
    }
    std::thread::sleep(Duration::from_millis(300));
    // 兜底：清掉可能残留的、由我们释放的 zju-connect
    let _ = Command::new("pkill")
        .arg("-f")
        .arg(paths.zju_bin.display().to_string())
        .output();
    paths.clear_state();
}
