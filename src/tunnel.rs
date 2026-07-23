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
pub fn spawn_daemon(paths: &Paths, cfg: &AppConfig, twfid: &str, last_sms_sent: u64) -> Result<()> {
    fs::create_dir_all(&paths.runtime_dir)?; // 日志/状态都写在这里
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
        .arg("--last-sms-sent").arg(last_sms_sent.to_string())
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
            if st.phase == crate::config::Phase::Online {
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
    crate::config::read_tail_bytes(&paths.tunnel_log, bytes)
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

/// 面向 CLI(status/connect)的延迟探测:state 带 vpn_dns → SOCKS5 穿隧道探测
/// (经 mixed_port,首字节 0x05 会被 relay 到 socks 上游,顺带验证转发层);
/// 否则回退 curl 直连网关(旧行为,对隧道假死不敏感)。预算 3s×2 次,与旧探针一致。
pub fn probe_state_latency(st: &RuntimeState) -> Delay {
    if let Some(ip) = st.vpn_dns.as_deref().and_then(|d| d.parse().ok()) {
        let mixed = format!("127.0.0.1:{}", st.port);
        for _ in 0..2 {
            if let Some(d) = socks_probe(&mixed, ip, 53, Duration::from_secs(3)) {
                return Delay::Value((d.as_millis() as u64).max(1));
            }
        }
        return Delay::Timeout;
    }
    probe_latency(st.port, &st.server)
}

/// 穿隧道活性探针：经 SOCKS5 代理向 target:port 发起 CONNECT，测的是隧道数据面本身。
///
/// 判活标准：收到完整 SOCKS 应答且 rep ∈ {0x00 成功, 0x05 对端拒绝}——两者都要求 TCP 握手
/// （SYN/SYN-ACK 或 RST）真正穿过隧道往返；超时、无应答、其他 rep（unreachable/failure
/// 多为本地快速失败）均判死。返回 Some(耗时) 表示活。
///
/// 背景：旧探针 curl 到 `https://{server}/`，而网关地址被 zju-connect 路由为 DIRECT
/// （tunnel.log:`111.207.219.226:443 -> DIRECT`），测的只是本机直连网关，切网后隧道
/// 已死探针仍绿，看门狗形同虚设。
pub fn socks_probe(
    socks_addr: &str,
    target: std::net::Ipv4Addr,
    port: u16,
    timeout: Duration,
) -> Option<Duration> {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};

    let addr: SocketAddr = socks_addr.parse().ok()?;
    let start = Instant::now();
    let mut s = TcpStream::connect_timeout(&addr, timeout).ok()?;
    s.set_read_timeout(Some(timeout)).ok()?;
    s.set_write_timeout(Some(timeout)).ok()?;
    let _ = s.set_nodelay(true);

    // 协商：无认证
    s.write_all(&[0x05, 0x01, 0x00]).ok()?;
    let mut method = [0u8; 2];
    s.read_exact(&mut method).ok()?;
    if method != [0x05, 0x00] {
        return None;
    }

    // CONNECT target:port（ATYP=IPv4）
    let o = target.octets();
    let p = port.to_be_bytes();
    s.write_all(&[0x05, 0x01, 0x00, 0x01, o[0], o[1], o[2], o[3], p[0], p[1]])
        .ok()?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).ok()?;
    match reply {
        [0x05, 0x00] | [0x05, 0x05] => Some(start.elapsed()),
        _ => None,
    }
}

/// 停止守护并等待其退出（至多 timeout）：SIGTERM（守护会杀掉 zju-connect 子进程）→ 轮询 pid 直到退出
/// → 兜底 pkill zju-connect → 清状态。connect 方案 Z 靠「等它真退出再 spawn」避免抢 mixed_port。
pub fn stop_daemon_and_wait(paths: &Paths, timeout: Duration) {
    if let Some(st) = paths.read_state() {
        if st.daemon_pid > 0 && pid_alive(st.daemon_pid) {
            unsafe {
                libc::kill(st.daemon_pid, libc::SIGTERM);
            }
            let deadline = Instant::now() + timeout;
            while pid_alive(st.daemon_pid) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    // 兜底：清掉可能残留的、由我们释放的 zju-connect
    let _ = Command::new("pkill")
        .arg("-f")
        .arg(paths.zju_bin.display().to_string())
        .output();
    paths.clear_state();
}

/// 停止守护（默认给 300ms 让其退出），供 disconnect 使用。
pub fn stop_daemon(paths: &Paths) {
    stop_daemon_and_wait(paths, Duration::from_millis(300));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::thread;

    /// 假 SOCKS5 服务器：完成无认证协商后按 `reply` 回应 CONNECT；reply 为空则收下请求但不回应答。
    fn fake_socks(reply: Vec<u8>) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut greeting = [0u8; 3];
            let _ = s.read_exact(&mut greeting);
            let _ = s.write_all(&[0x05, 0x00]); // 无认证
            let mut req = [0u8; 10];
            let _ = s.read_exact(&mut req);
            if !reply.is_empty() {
                let _ = s.write_all(&reply);
            }
            // 挂住连接直到对端关闭，模拟「不应答」时探针只能靠超时
            let mut sink = [0u8; 16];
            let _ = s.read(&mut sink);
        });
        addr
    }

    const TARGET: Ipv4Addr = Ipv4Addr::new(10, 0, 104, 104);
    const SHORT: Duration = Duration::from_millis(500);

    fn ok_reply(rep: u8) -> Vec<u8> {
        vec![0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    }

    #[test]
    fn socks_probe_success_reply_is_alive() {
        let addr = fake_socks(ok_reply(0x00));
        assert!(socks_probe(&addr, TARGET, 53, SHORT).is_some());
    }

    #[test]
    fn socks_probe_connection_refused_reply_is_alive() {
        // rep=0x05（对端拒绝）说明 RST 穿隧道回来了，数据面是活的
        let addr = fake_socks(ok_reply(0x05));
        assert!(socks_probe(&addr, TARGET, 53, SHORT).is_some());
    }

    #[test]
    fn socks_probe_unreachable_reply_is_dead() {
        // rep=0x04 host unreachable：没有证据流量穿过了隧道
        let addr = fake_socks(ok_reply(0x04));
        assert!(socks_probe(&addr, TARGET, 53, SHORT).is_none());
    }

    #[test]
    fn socks_probe_no_reply_times_out_dead() {
        let addr = fake_socks(Vec::new());
        assert!(socks_probe(&addr, TARGET, 53, SHORT).is_none());
    }

    #[test]
    fn socks_probe_no_listener_is_dead() {
        // 端口未监听（zju-connect 未起）→ 死
        assert!(socks_probe("127.0.0.1:1", TARGET, 53, SHORT).is_none());
    }

    #[test]
    fn socks_probe_garbage_reply_is_dead() {
        let addr = fake_socks(vec![0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0]);
        assert!(socks_probe(&addr, TARGET, 53, SHORT).is_none());
    }
}
