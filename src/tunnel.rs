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
pub fn spawn_daemon(
    paths: &Paths,
    cfg: &AppConfig,
    twfid: &str,
    last_sms_sent: u64,
    tun: bool,
) -> Result<()> {
    fs::create_dir_all(&paths.state_dir)?; // 日志/状态都写在这里
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
        .arg("--last-sms-sent").arg(last_sms_sent.to_string());
    if tun {
        cmd.arg("--tun");
    }
    cmd.stdin(Stdio::null())
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

/// 面向 CLI(status/connect)的延迟探测,按模式分流:
/// - TUN + vpn_dns:UDP DNS 查询直发 VPN DNS(内核路由送进 utun,测真数据面)。
///   绝不能经代理探网关——TUN 下网关流量被 zju-connect 决策为 VPN 回环,健康隧道
///   也会 Timeout,status 永远假黄(2026-07-28 真机事故)。
/// - TUN 无 vpn_dns:直连网关 TCP 测延迟(豁免路由保证走物理口)。
/// - Proxy + vpn_dns:SOCKS5 穿隧道探测(经 mixed_port,首字节 0x05 会被 relay 到
///   socks 上游,顺带验证转发层)。
/// - Proxy 无 vpn_dns:回退 curl 直连网关(旧行为,对隧道假死不敏感)。
/// 单次 1.5s:交互命令要快——健康隧道的往返远小于此,判死则立即出黄胶囊,
/// 不为重试多等;偶发误判下一次 status 自然纠正。daemon 侧看门狗仍是 3s×2(稳定优先)。
pub fn probe_state_latency(st: &RuntimeState) -> Delay {
    let vpn_dns: Option<std::net::Ipv4Addr> = st.vpn_dns.as_deref().and_then(|d| d.parse().ok());
    if st.mode == crate::config::Mode::Tun {
        let probed = match vpn_dns {
            Some(ip) => dns_udp_probe(ip, 53, &st.server, Duration::from_millis(1500)),
            // state 未存 https_port,网关 HTTPS 口按 443(与配置默认一致)
            None => direct_tcp_probe(&st.server, 443, Duration::from_millis(1500)),
        };
        return match probed {
            Some(d) => Delay::Value((d.as_millis() as u64).max(1)),
            None => Delay::Timeout,
        };
    }
    if let Some(ip) = vpn_dns {
        let mixed = format!("127.0.0.1:{}", st.port);
        return match socks_probe(&mixed, ip, 53, Duration::from_millis(1500)) {
            Some(d) => Delay::Value((d.as_millis() as u64).max(1)),
            None => Delay::Timeout,
        };
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

/// 直连 TCP 可达性探测(不经任何代理):解析 host 后 connect_timeout,通则返回耗时。
/// TUN 模式的降级探针用它直连网关——绝不能经 zju-connect 代理(会被决策为 VPN 回环)。
pub fn direct_tcp_probe(host: &str, port: u16, timeout: Duration) -> Option<Duration> {
    use std::net::{TcpStream, ToSocketAddrs};
    let start = Instant::now();
    let addrs = (host, port).to_socket_addrs().ok()?;
    for addr in addrs {
        let remain = timeout.checked_sub(start.elapsed())?;
        if TcpStream::connect_timeout(&addr, remain).is_ok() {
            return Some(start.elapsed());
        }
    }
    None
}

/// 构造最小 DNS A 查询报文(RD=1):12 字节头 + QNAME labels + QTYPE=A + QCLASS=IN。
fn build_dns_query(txid: u16, qname: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(12 + qname.len() + 6);
    q.extend_from_slice(&txid.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR=0
    for label in qname.split('.').filter(|l| !l.is_empty()) {
        let bytes = label.as_bytes();
        q.push(bytes.len().min(63) as u8);
        q.extend_from_slice(&bytes[..bytes.len().min(63)]);
    }
    q.push(0); // 根标签
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
    q
}

/// 校验 DNS 应答是否与查询匹配:txid 一致 + QR=1(是应答)。不苛求 RCODE——
/// NXDOMAIN/ServFail 同样证明查询真正穿隧道往返了,数据面是活的。
fn dns_reply_matches(txid: u16, buf: &[u8]) -> bool {
    buf.len() >= 12 && buf[..2] == txid.to_be_bytes() && buf[2] & 0x80 != 0
}

/// TUN 数据面探针:向 VPN DNS 直发 UDP A 查询(内核路由把包送进 utun →
/// zju-connect TUN 栈 → 隧道 → VPN DNS),收到匹配应答即活,返回往返耗时。
///
/// 背景:VPN DNS(如 10.0.104.104)不应答 TCP 53,穿隧道 SOCKS CONNECT 探针在
/// TUN 模式下永远降级;而降级的 curl 网关探测被 zju-connect 决策为 VPN 回环
/// (tunnel.log 实证 `111.207.219.226:443 -> VPN`)必超时——健康隧道被看门狗误杀、
/// 恢复验活必败(2026-07-28 真机事故)。UDP 与 zju-connect 自身 remote DNS 同路,
/// 有真机实证可用。仅适用于 TUN 模式:Proxy 模式没有内网路由,UDP 包出物理口即丢。
pub fn dns_udp_probe(
    dns_ip: std::net::Ipv4Addr,
    port: u16,
    qname: &str,
    timeout: Duration,
) -> Option<Duration> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect((dns_ip, port)).ok()?;
    let txid = (std::process::id() as u16)
        ^ (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u16)
            .unwrap_or(0));
    let start = Instant::now();
    sock.send(&build_dns_query(txid, qname)).ok()?;
    let deadline = start + timeout;
    let mut buf = [0u8; 512];
    loop {
        let remain = deadline.checked_duration_since(Instant::now())?;
        sock.set_read_timeout(Some(remain)).ok()?;
        match sock.recv(&mut buf) {
            Ok(n) if dns_reply_matches(txid, &buf[..n]) => return Some(start.elapsed()),
            Ok(_) => continue, // 串包(txid 不匹配),在预算内继续等
            Err(_) => return None,
        }
    }
}

/// 停止守护并等待其退出（至多 timeout）：SIGTERM（守护会走优雅停隧道路径）→ 轮询 pid 直到退出
/// → 兜底清理 → 清状态。connect 方案 Z 靠「等它真退出再 spawn」避免抢 mixed_port。
/// 兜底按模式分流:Proxy 用 pkill 清用户态 zju-connect;TUN 的隧道是 root 进程,pkill 无效,
/// 必须走 janitor(顺带清 resolver 残留与 pidfile)。
pub fn stop_daemon_and_wait(paths: &Paths, timeout: Duration) {
    let st = paths.read_state();
    let tun_mode = st.as_ref().map(|s| s.mode == crate::config::Mode::Tun).unwrap_or(false);
    if let Some(st) = &st {
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
    if tun_mode {
        let _ = crate::tun::sudo_helper(&["janitor"]).output();
    } else {
        let _ = Command::new("pkill")
            .arg("-f")
            .arg(paths.zju_bin.display().to_string())
            .output();
    }
    paths.clear_state();
}

/// 停止守护,供 disconnect 使用:TUN 模式要等 stop-tunnel → dns-clean 走完,给 3s;
/// Proxy 维持 300ms。
pub fn stop_daemon(paths: &Paths) {
    let tun_mode = paths
        .read_state()
        .map(|s| s.mode == crate::config::Mode::Tun)
        .unwrap_or(false);
    let timeout = if tun_mode { Duration::from_secs(3) } else { Duration::from_millis(300) };
    stop_daemon_and_wait(paths, timeout);
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

    #[test]
    fn dns_query_wire_shape() {
        let q = build_dns_query(0xabcd, "work.yangqianguan.com");
        assert_eq!(&q[..2], &[0xab, 0xcd]); // txid
        assert_eq!(q[2] & 0x80, 0); // QR=0(查询)
        assert_eq!(q[2] & 0x01, 1); // RD=1
        assert_eq!(&q[4..6], &[0x00, 0x01]); // QDCOUNT=1
        // QNAME: 4"work" 12"yangqianguan" 3"com" 0
        let mut expect = vec![4u8];
        expect.extend(b"work");
        expect.push(12);
        expect.extend(b"yangqianguan");
        expect.push(3);
        expect.extend(b"com");
        expect.push(0);
        assert_eq!(&q[12..12 + expect.len()], &expect[..]);
        // 尾部 QTYPE=A QCLASS=IN
        assert_eq!(&q[q.len() - 4..], &[0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn dns_reply_matching_rules() {
        let mut reply = build_dns_query(0x1234, "a.com");
        reply[2] |= 0x80; // QR=1
        assert!(dns_reply_matches(0x1234, &reply));
        assert!(!dns_reply_matches(0x9999, &reply)); // txid 不匹配
        let query = build_dns_query(0x1234, "a.com");
        assert!(!dns_reply_matches(0x1234, &query)); // QR=0 是查询不是应答
        assert!(!dns_reply_matches(0x1234, &reply[..8])); // 报文太短
        // NXDOMAIN(RCODE=3)也算活:查询真正往返了
        let mut nx = reply.clone();
        nx[3] |= 0x03;
        assert!(dns_reply_matches(0x1234, &nx));
    }

    /// 假 DNS server:收到查询,把 QR 置 1 原样回射(txid 天然匹配)。
    fn fake_dns(reply: bool) -> (std::net::Ipv4Addr, u16) {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        thread::spawn(move || {
            let mut buf = [0u8; 512];
            if let Ok((n, peer)) = sock.recv_from(&mut buf) {
                if reply && n >= 12 {
                    buf[2] |= 0x80;
                    let _ = sock.send_to(&buf[..n], peer);
                }
            }
        });
        (std::net::Ipv4Addr::LOCALHOST, port)
    }

    #[test]
    fn dns_udp_probe_reply_is_alive() {
        let (ip, port) = fake_dns(true);
        assert!(dns_udp_probe(ip, port, "work.yangqianguan.com", SHORT).is_some());
    }

    #[test]
    fn dns_udp_probe_silence_times_out_dead() {
        let (ip, port) = fake_dns(false);
        assert!(dns_udp_probe(ip, port, "work.yangqianguan.com", SHORT).is_none());
    }
}
