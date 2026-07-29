//! 后台守护进程（`easy-proxy __serve`）：拉起 zju-connect，并在混合端口上按首字节
//! 嗅探协议（0x05→socks 上游，否则→http 上游，两者都由 zju-connect 提供），透明转发。

use crate::config::{AppConfig, Paths, RuntimeState};
use anyhow::{anyhow, Context, Result};
use regex::Regex;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{copy_bidirectional, AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, ChildStdout, Command};
use tokio::signal::unix::{signal, SignalKind};

type RouteLines = tokio::io::Lines<BufReader<ChildStdout>>;

#[derive(clap::Args, Clone)]
pub struct ServeArgs {
    #[arg(long)]
    twfid: String,
    #[arg(long)]
    server: String,
    #[arg(long = "https-port")]
    https_port: u16,
    #[arg(long = "mixed-port")]
    mixed_port: u16,
    #[arg(long)]
    socks: String,
    #[arg(long)]
    http: String,
    #[arg(long = "last-sms-sent", default_value_t = 0)]
    last_sms_sent: u64,
    /// TUN 透明模式:隧道经 root helper 拉起
    #[arg(long, default_value_t = false)]
    tun: bool,
}

pub fn serve(args: ServeArgs, cfg: AppConfig, paths: &Paths) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run(args, cfg, paths))
}

fn zju_args(a: &ServeArgs) -> Vec<String> {
    vec![
        "-server".into(), a.server.clone(),
        "-port".into(), a.https_port.to_string(),
        "-twf-id".into(), a.twfid.clone(),
        "-disable-zju-config".into(),
        "-skip-domain-resource".into(),
        "-zju-dns-server".into(), "auto".into(),
        "-disable-multi-line".into(),
        "-socks-bind".into(), a.socks.clone(),
        "-http-bind".into(), a.http.clone(),
    ]
}

/// 解析 server 域名的全部 IPv4(启动隧道前调用,此刻无 TUN 路由、解析干净)。
/// zju-connect 运行期会自行重新解析网关域名并 dial,这些 IP 必须在它启动前
/// 全部钉上豁免路由,否则 dial 源地址被绑到 utun 虚拟 IP、SYN 进自己的黑洞。
fn resolve_gateway_ips(server: &str, port: u16) -> Vec<String> {
    use std::net::ToSocketAddrs;
    let mut ips: Vec<String> = (server, port)
        .to_socket_addrs()
        .map(|it| {
            it.filter_map(|a| match a.ip() {
                std::net::IpAddr::V4(v4) => Some(v4.to_string()),
                _ => None,
            })
            .collect()
        })
        .unwrap_or_default();
    ips.sort();
    ips.dedup();
    ips
}

/// 构造隧道启动命令:Proxy 直接跑用户态 zju-connect;TUN 经 sudo -n helper(root)。
/// TUN 分支先做 Rust 侧预校验,坏参数在 spawn 前就报错(helper 内还有最终校验)。
fn tunnel_command(paths: &Paths, args: &ServeArgs, twfid: &str) -> Result<Command> {
    if args.tun {
        crate::tun::validate_serve(&args.server, twfid, &args.socks, &args.http)?;
        let mut cmd = Command::new("/usr/bin/sudo");
        cmd.arg("-n")
            .arg(crate::tun::HELPER_PATH)
            .arg("start-tunnel")
            .arg("--server").arg(&args.server)
            .arg("--https-port").arg(args.https_port.to_string())
            .arg("--twfid").arg(twfid)
            .arg("--socks").arg(&args.socks)
            .arg("--http").arg(&args.http);
        let ips = resolve_gateway_ips(&args.server, args.https_port);
        if ips.is_empty() {
            eprintln!("[daemon] 启动前解析网关 IP 失败,跳过预豁免(隧道可能踩启动竞态)");
        } else {
            eprintln!("[daemon] 启动前预豁免网关 IP: {}", ips.join(","));
            cmd.arg("--exempt-ips").arg(ips.join(","));
        }
        Ok(cmd)
    } else {
        let mut a = args.clone();
        a.twfid = twfid.to_string();
        let mut cmd = Command::new(&paths.zju_bin);
        cmd.args(zju_args(&a));
        Ok(cmd)
    }
}

/// 停掉隧道进程并回收:TUN 模式 daemon 无权 signal root 子进程(EPERM),
/// 一律走 helper stop-tunnel(pidfile);Proxy 维持 start_kill。两者都必须 wait 回收。
async fn kill_tunnel(child: &mut Child, tun: bool) {
    if tun {
        let _ = Command::new("/usr/bin/sudo")
            .args(["-n", crate::tun::HELPER_PATH, "stop-tunnel"])
            .output()
            .await;
    } else {
        let _ = child.start_kill();
    }
    let _ = child.wait().await;
}

/// TUN 启动护栏(spec §7.1 第 7 步):就绪后立即执行,失败绝不假 online。
/// a) 服务端未下发网段(Add route to == 0)→ TUN 无意义;
/// b) 默认路由接口是 utun* → 违反分流不变量(防上游行为变化)。
fn tun_guardrails(paths: &Paths) -> Result<()> {
    let log = crate::config::read_tail_bytes(&paths.tunnel_log, 512 * 1024);
    if crate::tun::count_add_route(&log) == 0 {
        return Err(anyhow!("服务端未下发内网网段(tunnel.log 无 Add route to),TUN 不可用"));
    }
    if let Ok(out) = std::process::Command::new("/sbin/route").args(["-n", "get", "default"]).output() {
        if crate::tun::default_route_is_utun(&String::from_utf8_lossy(&out.stdout)) {
            return Err(anyhow!("默认路由指向 utun,违反分流不变量,回滚"));
        }
    }
    Ok(())
}

/// 隧道就绪后钉网关豁免主机路由(helper route-exempt):到网关自身的流量必须走物理口。
/// 服务端下发的 TUN 路由罩住全公网且不排除网关,zju-connect 每 60s 的 update_session
/// 保活会被吸进隧道回环 → 服务端判 idle 断会话 → 隧道 ~2 分钟必死(2026-07-28 真机事故)。
/// 必须在任何「到网关」的探测之前执行;失败只警告不致命(隧道死了由 TunnelDown 恢复兜底)。
async fn tun_route_exempt(gateway_ip: Option<&str>) {
    let Some(ip) = gateway_ip.filter(|s| crate::tun::valid_ipv4(s)) else {
        eprintln!("[daemon] 未从日志解析到网关 IP,跳过网关豁免路由(隧道保活可能被回环拖死)");
        return;
    };
    match Command::new("/usr/bin/sudo")
        .args(["-n", crate::tun::HELPER_PATH, "route-exempt", ip])
        .output()
        .await
    {
        Ok(out) if out.status.success() => {
            eprintln!("[daemon] 网关豁免路由已钉: {ip} → 物理网关");
        }
        Ok(out) => eprintln!(
            "[daemon] route-exempt 失败: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => eprintln!("[daemon] route-exempt 无法执行: {e}"),
    }
}

/// 隧道就绪后同步 scoped resolver(幂等):dns_suffixes 非空且拿到 vpn_dns 才写;
/// 失败只警告不致命——resolver 缺失时内网域名仍可走 7899 代理路径。
async fn tun_dns_sync(cfg: &AppConfig, state: &RuntimeState) {
    let suffixes: Vec<&str> = cfg
        .tun
        .dns_suffixes
        .iter()
        .map(String::as_str)
        .filter(|s| {
            let ok = crate::tun::valid_suffix(s);
            if !ok {
                eprintln!("[daemon] dns_suffixes 含非法项,跳过: {s}");
            }
            ok
        })
        .collect();
    if suffixes.is_empty() {
        return;
    }
    let Some(dns) = state.vpn_dns.as_deref().filter(|d| crate::tun::valid_ipv4(d)) else {
        eprintln!("[daemon] 未获得可用 VPN DNS,跳过 scoped resolver 配置(域名解析可走 7899 代理)");
        return;
    };
    // 网关域名的解析保护由 hosts-pin 承担(resolver 豁免条目已废——快照 DNS 可能
    // 解析不出网关域名,反成毒源:2026-07-29 真机 lookup no such host → zju panic)
    let pairs = crate::tun::dns_sync_pairs(&suffixes, dns);
    let mut cmd = Command::new("/usr/bin/sudo");
    cmd.arg("-n").arg(crate::tun::HELPER_PATH).arg("dns-sync");
    for p in &pairs {
        cmd.arg(p);
    }
    match cmd.output().await {
        Ok(out) if out.status.success() => {
            eprintln!("[daemon] scoped resolver 已同步: {} 个后缀 → {dns}", suffixes.len());
        }
        Ok(out) => eprintln!(
            "[daemon] dns-sync 失败: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => eprintln!("[daemon] dns-sync 无法执行: {e}"),
    }
}

/// 网关域名 pin 进 /etc/hosts(实连 IP):zju 运行期重建连接/我们的兜底保活都要
/// 解析网关域名,hosts 优先于一切 resolver,保证解析永远指向可达的实连 IP。
/// server 为纯 IP 时无需 pin;失败只警告(解析仍可走系统 DNS,行为同旧)。
async fn tun_hosts_pin(gateway_ip: Option<&str>, server: &str) {
    if crate::tun::valid_ipv4(server) {
        return;
    }
    let Some(ip) = gateway_ip.filter(|s| crate::tun::valid_ipv4(s)) else {
        return; // route-exempt 已对缺失情况告警过,不重复
    };
    match Command::new("/usr/bin/sudo")
        .args(["-n", crate::tun::HELPER_PATH, "hosts-pin", ip, server])
        .output()
        .await
    {
        Ok(out) if out.status.success() => {
            eprintln!("[daemon] 网关域名已 pin: {server} → {ip}(/etc/hosts)");
        }
        Ok(out) => eprintln!(
            "[daemon] hosts-pin 失败: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => eprintln!("[daemon] hosts-pin 无法执行: {e}"),
    }
}

/// 兜底会话保活:替 zju-connect 发 /por/update_session.csp(它内部的该保活因 bug
/// 恒败,服务端 ~4 分钟判会话 idle 掐数据连接——2026-07-29 真机 broken pipe 实锤)。
/// 直连网关(清代理 env;TUN 下有豁免路由+hosts pin 护航),失败仅日志。
async fn send_update_session(server: String, port: u16, twfid: String) {
    let url = format!("https://{server}:{port}/por/update_session.csp?apiversion=1&twfid={twfid}");
    let cookie = format!("Cookie: TWFID={twfid}");
    let mut cmd = Command::new("/usr/bin/curl");
    for v in crate::login::PROXY_ENV {
        cmd.env_remove(v);
    }
    cmd.args([
        "-sk", "-o", "/dev/null", "--max-time", "8", "-w", "%{http_code}",
        "-H", &cookie,
        "-H", "User-Agent: EasyConnect_Linux_Ubuntu",
        &url,
    ]);
    match cmd.output().await {
        Ok(out) => {
            let code = String::from_utf8_lossy(&out.stdout);
            if code.trim() != "200" {
                eprintln!("[daemon] 兜底会话保活失败: http {}", code.trim());
            }
        }
        Err(e) => eprintln!("[daemon] 兜底会话保活无法执行: {e}"),
    }
}

async fn run(args: ServeArgs, cfg: AppConfig, paths: &Paths) -> Result<()> {
    let pid = std::process::id() as i32;
    let mut state = RuntimeState {
        phase: crate::config::Phase::Reconnecting,
        mode: if args.tun { crate::config::Mode::Tun } else { crate::config::Mode::Proxy },
        daemon_pid: pid,
        port: args.mixed_port,
        socks_upstream: args.socks.clone(),
        http_upstream: args.http.clone(),
        server: args.server.clone(),
        tunnel_ip: String::new(),
        vpn_dns: None,
        last_sms_sent: if args.last_sms_sent == 0 { None } else { Some(args.last_sms_sent) },
        error: None,
    };
    paths.write_state(&state)?;

    let log = std::fs::File::create(&paths.tunnel_log)
        .with_context(|| format!("无法创建 {}", paths.tunnel_log.display()))?;
    let mut child = tunnel_command(paths, &args, &args.twfid)?
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()
        .with_context(|| format!("无法启动 {}", paths.zju_bin.display()))?;

    match wait_socks_ready(paths, &mut child, Duration::from_secs(30)).await {
        Ok(info) => {
            state.tunnel_ip = info.ip;
            // TUN:护栏 + 网关豁免路由必须先于任何探测——降级探测直连网关,
            // 豁免没钉时会被新隧道路由吸进回环、必假死
            if args.tun {
                if let Err(e) = tun_guardrails(paths) {
                    kill_tunnel(&mut child, true).await;
                    state.error = Some(e.to_string());
                    let _ = paths.write_state(&state);
                    return Err(e);
                }
                tun_route_exempt(info.gateway_ip.as_deref()).await;
                tun_hosts_pin(info.gateway_ip.as_deref(), &args.server).await;
            }
            state.vpn_dns = pick_probe_target(&args, info.vpn_dns).await;
            // scoped resolver 在探针选型后写:UDP DNS 探针不通说明经隧道 DNS 真不可用,
            // 此时写 resolver 只会造出毒解析
            if args.tun {
                tun_dns_sync(&cfg, &state).await;
            }
        }
        Err(e) => {
            kill_tunnel(&mut child, args.tun).await;
            state.error = Some(e.to_string());
            let _ = paths.write_state(&state);
            return Err(e);
        }
    }

    let listener = match TcpListener::bind(("127.0.0.1", args.mixed_port)).await {
        Ok(l) => l,
        Err(e) => {
            kill_tunnel(&mut child, args.tun).await;
            let msg = format!("绑定混合端口 127.0.0.1:{} 失败: {e}", args.mixed_port);
            state.error = Some(msg.clone());
            let _ = paths.write_state(&state);
            return Err(anyhow!(msg));
        }
    };

    state.phase = crate::config::Phase::Online;
    paths.write_state(&state)?;
    eprintln!("[daemon] ready: mixed 127.0.0.1:{} → socks {}", args.mixed_port, args.socks);

    // 关停标志 + 唤醒:独立信号任务收到 SIGTERM/SIGINT 即置位并唤醒主循环。
    // 关键——恢复流程在 select! 之外 await,若信号只在主 select! 里监听,恢复期间(如 silent_login
    // 等码)信号不会被处理、标志永不置位;放到独立任务里,恢复中的 spawn_blocking 也能凭标志尽快停手。
    let shutdown = Arc::new(AtomicBool::new(false));
    let notify = Arc::new(tokio::sync::Notify::new());
    {
        let sd = shutdown.clone();
        let nf = notify.clone();
        tokio::spawn(async move {
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut sigint = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(_) => return,
            };
            tokio::select! {
                _ = sigterm.recv() => {}
                _ = sigint.recv() => {}
            }
            eprintln!("[daemon] 收到终止信号,准备退出");
            sd.store(true, Ordering::Relaxed);
            nf.notify_one();
        });
    }

    // 健康检查节拍;interval 首个 tick 立即到期,先消费掉,让第一次探测发生在 interval 之后。
    let mut tick = tokio::time::interval(Duration::from_secs(cfg.healthcheck_interval.max(1)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    let mut fails: u32 = 0;
    let mut current_twfid = args.twfid.clone();
    // 兜底会话保活:ready 后立发一次,此后随健康检查节拍(60s)每轮一次
    tokio::spawn(send_update_session(args.server.clone(), args.https_port, current_twfid.clone()));

    // 路由事件订阅:切网/唤醒秒级感知(事件→防抖→立即探测);不可用则只剩定时探测兜底。
    let (mut route_child, mut route_lines) = match spawn_route_monitor() {
        Some((c, l)) => (Some(c), Some(l)),
        None => {
            eprintln!("[daemon] route monitor 不可用,退化为纯定时探测");
            (None, None)
        }
    };

    // select! 只产出「事件」,恢复动作在 select 外执行——避免与 child.wait() 的 &mut child 借用冲突。
    enum Ev {
        Continue,
        Probe,
        NetChange,
        TunnelDown,
        Shutdown,
    }

    // 网络变化防抖截止点:收到首个事件后 1.5s 再统一探测。用「截止点 + select 分支」而非
    // 同步排空事件流——后者会阻塞主循环不 accept,把 mixed_port 上的真实流量卡住
    // (0.4.0 的事故:status 探针 1.5s 超时,每隔几秒闪一次假 reconnecting)。
    let mut net_check_at: Option<tokio::time::Instant> = None;

    loop {
        let ev = tokio::select! {
            accepted = listener.accept() => {
                if let Ok((client, _)) = accepted {
                    let (socks, http) = (args.socks.clone(), args.http.clone());
                    tokio::spawn(async move {
                        let _ = relay(client, socks, http).await;
                    });
                }
                Ev::Continue
            }
            status = child.wait() => {
                eprintln!("[daemon] zju-connect 退出: {status:?}，隧道断开");
                Ev::TunnelDown
            }
            line = next_route_line(&mut route_lines), if route_lines.is_some() => {
                match line {
                    Some(l) if is_route_event(&l) => {
                        if net_check_at.is_none() {
                            net_check_at = Some(tokio::time::Instant::now() + Duration::from_millis(1500));
                        }
                        Ev::Continue
                    }
                    Some(_) => Ev::Continue,
                    None => {
                        route_lines = None;
                        eprintln!("[daemon] route monitor 流结束,退化为纯定时探测");
                        Ev::Continue
                    }
                }
            }
            _ = tokio::time::sleep_until(net_check_at.unwrap_or_else(tokio::time::Instant::now)), if net_check_at.is_some() => {
                net_check_at = None;
                Ev::NetChange
            }
            _ = tick.tick() => Ev::Probe,
            _ = notify.notified() => Ev::Shutdown,
        };

        match ev {
            Ev::Continue => {}
            Ev::Shutdown => break,
            Ev::NetChange => {
                if probe(&args, state.vpn_dns.as_deref()).await {
                    fails = 0; // 网络变化但隧道仍通(次要接口变动等),无事
                } else {
                    eprintln!("[daemon] 检测到网络变化且隧道不通,立即重连");
                    if recover_or_exit(
                        &mut child, &mut state, &cfg, paths, &args, &mut current_twfid, &shutdown,
                    )
                    .await
                    {
                        fails = 0;
                    } else {
                        break;
                    }
                }
            }
            Ev::Probe => {
                tokio::spawn(send_update_session(args.server.clone(), args.https_port, current_twfid.clone()));
                if probe(&args, state.vpn_dns.as_deref()).await {
                    fails = 0; // online:不打日志、不重写 state
                } else {
                    fails += 1;
                    if crate::recover::should_enter_reconnect(fails, cfg.healthcheck_fail_threshold) {
                        eprintln!("[daemon] 探测连续失败 {fails} 次，进入重连");
                        if recover_or_exit(
                            &mut child, &mut state, &cfg, paths, &args, &mut current_twfid, &shutdown,
                        )
                        .await
                        {
                            fails = 0;
                        } else {
                            break;
                        }
                    }
                }
            }
            Ev::TunnelDown => {
                if recover_or_exit(
                    &mut child, &mut state, &cfg, paths, &args, &mut current_twfid, &shutdown,
                )
                .await
                {
                    fails = 0;
                } else {
                    break;
                }
            }
        }
    }

    if let Some(c) = route_child.as_mut() {
        let _ = c.start_kill();
    }
    // shutdown 顺序(spec §7.2):stop-tunnel(优雅,zju 自身 hook 关 utun)→ dns-clean → clear_state
    kill_tunnel(&mut child, args.tun).await;
    if args.tun {
        // 优雅退出才清 resolver;崩溃残留由下次 janitor 兜底
        tun_dns_clean("退出").await;
    }
    paths.clear_state();
    Ok(())
}

/// 用给定 twfid 重启 zju-connect:回收旧进程 → truncate 日志 → 起新进程 → 等 SOCKS 就绪。
/// TUN 模式下停/起都经 helper(root),日志经 fd 继承照写 tunnel.log。
async fn restart_zju(child: &mut Child, paths: &Paths, args: &ServeArgs, twfid: &str) -> Result<ReadyInfo> {
    kill_tunnel(child, args.tun).await; // 回收旧进程,杜绝僵尸
    let log = std::fs::File::create(&paths.tunnel_log)
        .with_context(|| format!("无法创建 {}", paths.tunnel_log.display()))?;
    let new_child = tunnel_command(paths, args, twfid)?
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()
        .with_context(|| format!("无法启动 {}", paths.zju_bin.display()))?;
    *child = new_child;
    wait_socks_ready(paths, child, Duration::from_secs(30)).await
}

/// 探测连通性(true=通)。同步实现,丢 spawn_blocking。
///
/// 按模式分流(2026-07-28 真机事故教训:TUN 下凡是「到网关」的流量都会被吸进隧道
/// 回环——curl 经 1081 到网关被 zju-connect 决策为 VPN,必超时,健康隧道被误杀):
/// - TUN + `vpn_dns=Some`:UDP DNS 查询直发 VPN DNS(内核路由送进 utun,测完整数据面)。
/// - TUN + `vpn_dns=None`:直连网关 TCP(不经代理;豁免路由保证走物理口,对隧道假死不敏感)。
/// - Proxy + `vpn_dns=Some`:SOCKS5 CONNECT 到 VPN DNS:53,**穿隧道**测数据面(网关地址被
///   zju-connect 路由为 DIRECT,curl 网关只能测直连,切网后隧道假死时照样绿——0.3.0 的坑)。
/// - Proxy + `vpn_dns=None`:回退 curl 直连网关(退化行为,对隧道假死不敏感)。
///
/// 关键:绝不走 mixed_port——mixed_port 的转发靠本 daemon 主循环 accept,而探测/恢复期间
/// 主循环正阻塞在这里、不 accept,若探 mixed_port 必然自锁超时、假报断线。
async fn probe(args: &ServeArgs, vpn_dns: Option<&str>) -> bool {
    if args.tun {
        if let Some(ip) = vpn_dns.and_then(|d| d.parse::<std::net::Ipv4Addr>().ok()) {
            let server = args.server.clone();
            return tokio::task::spawn_blocking(move || {
                (0..2).any(|_| {
                    crate::tunnel::dns_udp_probe(ip, 53, &server, Duration::from_secs(3)).is_some()
                })
            })
            .await
            .unwrap_or(false);
        }
        let (server, port) = (args.server.clone(), args.https_port);
        return tokio::task::spawn_blocking(move || {
            (0..2).any(|_| crate::tunnel::direct_tcp_probe(&server, port, Duration::from_secs(3)).is_some())
        })
        .await
        .unwrap_or(false);
    }
    if let Some(ip) = vpn_dns.and_then(|d| d.parse::<std::net::Ipv4Addr>().ok()) {
        let socks = args.socks.clone();
        return tokio::task::spawn_blocking(move || {
            (0..2).any(|_| {
                crate::tunnel::socks_probe(&socks, ip, 53, Duration::from_secs(3)).is_some()
            })
        })
        .await
        .unwrap_or(false);
    }
    let port = http_upstream_port(&args.http);
    let server = args.server.clone();
    tokio::task::spawn_blocking(move || {
        !matches!(crate::tunnel::probe_latency(port, &server), crate::capsule::Delay::Timeout)
    })
    .await
    .unwrap_or(false)
}

/// 在**刚建好的隧道**上选定探针目标:解析到 VPN DNS 且穿隧道探针立即可用 → 用它;
/// 否则降级为网关直连探测(None)。新隧道刚完成 ECAgent 认证+TLS 建链,此刻探针不通
/// 大概率是目标不可用(如 DNS 不答 TCP 53)而非隧道问题——若不降级,探针会永远假死,
/// 看门狗反复重启最后把 daemon 拖下线。降级后行为等同 0.3.0(活着但对隧道假死不敏感)。
async fn pick_probe_target(args: &ServeArgs, parsed_dns: Option<String>) -> Option<String> {
    let kind = if args.tun { "UDP DNS" } else { "SOCKS TCP" };
    match parsed_dns {
        Some(dns) => {
            if probe(args, Some(&dns)).await {
                eprintln!("[daemon] 健康检查:穿隧道 {kind} 探测 VPN DNS {dns}:53");
                Some(dns)
            } else {
                eprintln!("[daemon] 穿隧道 {kind} 探针(VPN DNS {dns}:53)在新隧道上不通,降级为网关直连探测");
                None
            }
        }
        None => {
            eprintln!("[daemon] 未从日志解析到 VPN DNS,健康检查降级为网关直连探测(对隧道假死不敏感)");
            None
        }
    }
}

/// 从 "127.0.0.1:1081" 解析出上游端口(供探针直连,绕过 mixed_port relay);解析失败回退 1081。
fn http_upstream_port(http: &str) -> u16 {
    http.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(1081)
}

enum RecoverOutcome {
    Online,
    GiveUp,
}

/// 摘掉全部 easy-proxy 管理的 resolver 文件(helper dns-clean)。恢复入口与退出两处共用;
/// 失败只警告不致命(sudo 坏掉时恢复照样往下走,行为等同修复前)。
async fn tun_dns_clean(why: &str) {
    match Command::new("/usr/bin/sudo")
        .args(["-n", crate::tun::HELPER_PATH, "dns-clean"])
        .output()
        .await
    {
        Ok(out) if out.status.success() => {}
        Ok(out) => eprintln!(
            "[daemon] dns-clean({why})失败: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => eprintln!("[daemon] dns-clean({why})无法执行: {e}"),
    }
}

/// 分级恢复:①用当前 TWFID 重启 zju-connect(不吃闸门)②闸门通过则静默重登拿新 TWFID 再重启。
/// 任一成功且探测通 → Online;全败 / 闸门拦截 / 被 shutdown 打断 → GiveUp。
async fn attempt_recover(
    child: &mut Child,
    state: &mut RuntimeState,
    cfg: &AppConfig,
    paths: &Paths,
    args: &ServeArgs,
    current_twfid: &mut String,
    shutdown: &Arc<AtomicBool>,
) -> RecoverOutcome {
    // TUN:恢复第一步先摘 scoped resolver——resolver 指向的 VPN DNS 只有隧道活着才可达,
    // 不摘则下面每一步(等网关/重启隧道/静默重登)都要解析网关域名,整条链被毒解析卡死,
    // 各自 ~30s 超时后 GiveUp → 永久 offline(2026-07-28 过夜断线真机事故)。
    // 恢复成功后 tun_dns_sync 会带新的系统 DNS 快照重写,不用单独「装回」。
    if args.tun {
        tun_dns_clean("恢复前").await;
    }

    // 先等新网络就绪(直连网关可达):路由事件触发的恢复往往抢在 DHCP/关联完成之前,
    // 不等就重启必失败,恢复流程会一路 GiveUp 把 daemon 拖下线。
    wait_gateway_reachable(args, Duration::from_secs(30), shutdown).await;

    // step1: 旧 TWFID 重启(不吃闸门)
    if !shutdown.load(Ordering::Relaxed) {
        match restart_zju(child, paths, args, current_twfid).await {
            Ok(info) => {
                state.tunnel_ip = info.ip;
                // TUN:护栏 + 网关豁免路由先于任何探测(降级探测直连网关,豁免没钉必假死)
                if args.tun {
                    if let Err(e) = tun_guardrails(paths) {
                        eprintln!("[daemon] 恢复后护栏失败: {e}");
                        return RecoverOutcome::GiveUp;
                    }
                    tun_route_exempt(info.gateway_ip.as_deref()).await;
                    tun_hosts_pin(info.gateway_ip.as_deref(), &args.server).await;
                }
                // 新隧道上重选探针目标(必要时降级),再按选定目标验活
                state.vpn_dns = pick_probe_target(args, info.vpn_dns).await;
                if probe(args, state.vpn_dns.as_deref()).await {
                    if args.tun {
                        tun_dns_sync(cfg, state).await;
                    }
                    eprintln!("[daemon] 旧 TWFID 重启成功");
                    return RecoverOutcome::Online;
                }
                eprintln!("[daemon] 旧 TWFID 重启后验活探测不通");
            }
            Err(e) => eprintln!("[daemon] 旧 TWFID 重启失败: {e}"),
        }
    }
    if shutdown.load(Ordering::Relaxed) {
        return RecoverOutcome::GiveUp;
    }

    // step2: 闸门 + 静默重登
    let now = crate::config::now_unix();
    if !crate::recover::relogin_allowed(now, state.last_sms_sent, cfg.silent_relogin_interval) {
        eprintln!(
            "[daemon] 距上次发码不足 {}s,不静默重登 → offline",
            cfg.silent_relogin_interval
        );
        return RecoverOutcome::GiveUp;
    }

    let cfg2 = cfg.clone();
    // 静默重登用缓存目录里的一次性 jar，不碰前台 connect 的 cookies
    let _ = std::fs::create_dir_all(&paths.cache_dir);
    let jar = paths.silent_cookies.clone();
    let sd = shutdown.clone();
    let sent = Arc::new(AtomicU64::new(0));
    let sent2 = sent.clone();
    let res = tokio::task::spawn_blocking(move || {
        crate::sms::silent_login(&cfg2, &jar, &sd, &|| {
            sent2.store(crate::config::now_unix(), Ordering::Relaxed);
        })
    })
    .await;

    // 无论重登成败,只要真的发了码就刷新闸门基线(避免失败后立刻又发)。
    let sent_at = sent.load(Ordering::Relaxed);
    if sent_at != 0 {
        state.last_sms_sent = Some(sent_at);
    }

    let new_twfid = match res {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            eprintln!("[daemon] 静默重登失败: {e}");
            return RecoverOutcome::GiveUp;
        }
        Err(e) => {
            eprintln!("[daemon] 静默重登任务异常: {e}");
            return RecoverOutcome::GiveUp;
        }
    };
    *current_twfid = new_twfid.clone();
    match restart_zju(child, paths, args, &new_twfid).await {
        Ok(info) => {
            state.tunnel_ip = info.ip;
            if args.tun {
                if let Err(e) = tun_guardrails(paths) {
                    eprintln!("[daemon] 恢复后护栏失败: {e}");
                    return RecoverOutcome::GiveUp;
                }
                tun_route_exempt(info.gateway_ip.as_deref()).await;
                tun_hosts_pin(info.gateway_ip.as_deref(), &args.server).await;
            }
            state.vpn_dns = pick_probe_target(args, info.vpn_dns).await;
            if probe(args, state.vpn_dns.as_deref()).await {
                if args.tun {
                    tun_dns_sync(cfg, state).await;
                }
                eprintln!("[daemon] 静默重登并重启成功");
                RecoverOutcome::Online
            } else {
                eprintln!("[daemon] 新 TWFID 重启后验活探测不通");
                RecoverOutcome::GiveUp
            }
        }
        Err(e) => {
            eprintln!("[daemon] 新 TWFID 重启失败: {e}");
            RecoverOutcome::GiveUp
        }
    }
}

/// 恢复编排 + 状态落盘:先置 Reconnecting,恢复成功置 Online 返回 true,否则 false(调用方 offline 退出)。
async fn recover_or_exit(
    child: &mut Child,
    state: &mut RuntimeState,
    cfg: &AppConfig,
    paths: &Paths,
    args: &ServeArgs,
    current_twfid: &mut String,
    shutdown: &Arc<AtomicBool>,
) -> bool {
    state.phase = crate::config::Phase::Reconnecting;
    let _ = paths.write_state(state);
    match attempt_recover(child, state, cfg, paths, args, current_twfid, shutdown).await {
        RecoverOutcome::Online => {
            state.phase = crate::config::Phase::Online;
            let _ = paths.write_state(state);
            eprintln!("[daemon] 已恢复 online");
            true
        }
        RecoverOutcome::GiveUp => {
            eprintln!("[daemon] 恢复失败 → offline 退出");
            false
        }
    }
}

/// 首字节嗅探：0x05 → socks 上游；否则 → http 上游。peek 不消费，随后整段透明转发。
async fn relay(client: TcpStream, socks: String, http: String) -> Result<()> {
    let mut first = [0u8; 1];
    let n = client.peek(&mut first).await?;
    if n == 0 {
        return Ok(());
    }
    let upstream = if first[0] == 0x05 { socks } else { http };
    let mut up = TcpStream::connect(&upstream).await?;
    let _ = up.set_nodelay(true);
    let _ = client.set_nodelay(true);
    let mut client = client;
    copy_bidirectional(&mut client, &mut up).await?;
    Ok(())
}

/// 订阅 macOS 路由事件流(`route -n monitor`):切网/插拔网线/唤醒都会立刻吐 RTM 消息,
/// 让 daemon 秒级感知网络变化,不用干等健康检查节拍。普通用户可跑,无需 root。
fn spawn_route_monitor() -> Option<(Child, RouteLines)> {
    let mut child = Command::new("/sbin/route")
        .args(["-n", "monitor"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    Some((child, BufReader::new(stdout).lines()))
}

/// 只认接口/地址级变化(真实切网必伴随):RTM_IFINFO(链路状态)、RTM_NEWADDR/RTM_DELADDR
/// (地址增删)。绝不能匹配所有 RTM_*:空闲机器上 awdl0(AirDrop)每隔几秒就 RTM_ADD 邻居
/// 主机路由(真机实测),普通流量也会产生 RTM_ADD/RTM_GET 噪音——0.4.0 因此每几秒误触发一次。
fn is_route_event(line: &str) -> bool {
    line.starts_with("RTM_IFINFO") || line.starts_with("RTM_NEWADDR") || line.starts_with("RTM_DELADDR")
}

/// 读下一行路由事件;None(流结束/未启用)由调用方处理降级。
async fn next_route_line(lines: &mut Option<RouteLines>) -> Option<String> {
    match lines {
        Some(l) => l.next_line().await.ok().flatten(),
        None => None, // select! 的 if 守卫保证不会走到
    }
}

/// 等新网络就绪:直连 TCP 到网关:443 可达才值得重启隧道——切网后 DHCP/关联要几秒,
/// 立刻重启必失败,恢复流程会一路 GiveUp 把 daemon 拖下线。最多等 budget,等不到照样往下试。
async fn wait_gateway_reachable(args: &ServeArgs, budget: Duration, shutdown: &Arc<AtomicBool>) {
    let deadline = Instant::now() + budget;
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        let ok = tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect((args.server.as_str(), args.https_port)),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
        if ok || Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// zju-connect 就绪信息：隧道虚拟 IP + 服务端下发的 VPN DNS（穿隧道探针的目标)
/// + 实际连接的网关公网 IP(TUN 网关豁免路由的目标)。
struct ReadyInfo {
    ip: String,
    vpn_dns: Option<String>,
    gateway_ip: Option<String>,
}

/// 从 tunnel.log 解析服务端下发/显式配置的 VPN DNS 地址。
fn parse_vpn_dns(text: &str) -> Option<String> {
    let use_re = Regex::new(r"Use DNS server\s+([\d.]+)").unwrap();
    let set_re = Regex::new(r"Set DNS server:\s*([\d.]+)").unwrap();
    use_re
        .captures(text)
        .or_else(|| set_re.captures(text))
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

/// 从 tunnel.log 解析 zju-connect 实际连接的网关公网 IP(`Socket: connected to: IP:port`)。
fn parse_gateway_ip(text: &str) -> Option<String> {
    Regex::new(r"Socket: connected to:\s*([\d.]+):")
        .unwrap()
        .captures(text)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

async fn wait_socks_ready(paths: &Paths, child: &mut Child, timeout: Duration) -> Result<ReadyInfo> {
    let deadline = Instant::now() + timeout;
    let ip_re = Regex::new(r"Client IP:\s*([\d.]+)").unwrap();
    let ip_re2 = Regex::new(r"your IP:\s*([\d.]+)").unwrap();
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(anyhow!(
                "zju-connect 启动即退出 ({status})\n{}",
                tail(paths)
            ));
        }
        // 窗口须罩住整段启动日志:TUN 模式下 Client IP 与 SOCKS5 listening 之间隔着
        // 服务端下发的全部 Add route 行(真机实测 613 条 ≈ 35KB),8KB 窗口会把 IP 冲出去
        // 导致 tunnel_ip 解析为空;512KB 与护栏同窗,几千条网段也罩得住。
        let text = crate::config::read_tail_bytes(&paths.tunnel_log, 512 * 1024);
        if text.contains("SOCKS5 server listening") {
            let ip = ip_re
                .captures(&text)
                .or_else(|| ip_re2.captures(&text))
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            return Ok(ReadyInfo {
                ip,
                vpn_dns: parse_vpn_dns(&text),
                gateway_ip: parse_gateway_ip(&text),
            });
        }
        if Instant::now() >= deadline {
            return Err(anyhow!("等待 zju-connect SOCKS 就绪超时\n{}", tail(paths)));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

fn tail(paths: &Paths) -> String {
    crate::config::read_tail_bytes(&paths.tunnel_log, 1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn route_event_lines_detected() {
        // 接口/地址级变化才算事件(真实切网必伴随)
        assert!(is_route_event("RTM_NEWADDR: address being added to iface: len 176"));
        assert!(is_route_event("RTM_DELADDR: address being removed from iface: len 176"));
        assert!(is_route_event("RTM_IFINFO: iface status change: len 168, if# 12"));
        // 主机路由增删是日常噪音,不算——真机实测 awdl0(AirDrop)每隔几秒就来一条,
        // 0.4.0 把它当切网导致每几秒假 reconnecting 一次
        assert!(!is_route_event(
            "RTM_ADD: Add Route: len 140, pid: 726, seq 155420, errno 0, flags:<HOST,DONE,STATIC>"
        ));
        assert!(!is_route_event("RTM_DELETE: Delete Route: len 172"));
        assert!(!is_route_event("RTM_GET: Report Metrics: len 140"));
        // 消息头与 payload 行忽略
        assert!(!is_route_event("got message of size 176 on Wed Jul 23 15:30:00 2026"));
        assert!(!is_route_event(" locks:  inits: "));
        assert!(!is_route_event("sockaddrs: <DST,GATEWAY,NETMASK>"));
        assert!(!is_route_event(""));
    }

    #[test]
    fn parse_vpn_dns_from_real_log() {
        // 取自真机 tunnel.log
        let log = "2026/07/23 15:30:03 Client IP: 2.0.1.6\n\
                   2026/07/23 15:30:03 Use DNS server 10.0.104.104 provided by server\n\
                   2026/07/23 15:30:03 SOCKS5 server listening on 127.0.0.1:1080\n";
        assert_eq!(parse_vpn_dns(log), Some("10.0.104.104".to_string()));
    }

    #[test]
    fn parse_vpn_dns_set_variant() {
        // 显式配置 DNS 时 zju-connect 的日志格式
        let log = "2026/07/23 15:30:03 Set DNS server: 10.10.0.21\n";
        assert_eq!(parse_vpn_dns(log), Some("10.10.0.21".to_string()));
    }

    #[test]
    fn parse_vpn_dns_absent_is_none() {
        assert_eq!(parse_vpn_dns("SOCKS5 server listening on 127.0.0.1:1080"), None);
    }

    #[test]
    fn parse_gateway_ip_from_real_log() {
        // 取自真机 tunnel.log(2026-07-28):TLS 建链行携带网关公网 IP
        let log = "2026/07/28 23:30:14 Socket: connected to: 111.207.219.226:443\n\
                   2026/07/28 23:30:14 TLS: connected to: 111.207.219.226:443\n\
                   2026/07/28 23:30:14 Client IP: 2.0.1.54\n";
        assert_eq!(parse_gateway_ip(log), Some("111.207.219.226".to_string()));
        assert_eq!(parse_gateway_ip("no socket line here"), None);
    }

    #[test]
    fn ready_window_covers_tun_route_burst() {
        // TUN 模式真机形状:Client IP 与 SOCKS5 listening 之间隔着服务端下发的全部
        // Add route 行(实测 613 条,这里放 2000 条加压)。就绪窗口必须罩住整段,
        // 否则 tunnel_ip 被冲出窗口解析为空——2.0.0 真机踩过的坑。
        let mut log = String::from(
            "2026/07/27 20:02:12 Client IP: 2.0.1.24\n\
             2026/07/27 20:02:12 Use DNS server 10.0.104.104 provided by server\n",
        );
        for i in 0..2000 {
            log.push_str(&format!(
                "2026/07/27 20:02:12 Add route to 10.{}.{}.0/24\n",
                i / 256,
                i % 256
            ));
        }
        log.push_str("2026/07/27 20:02:13 SOCKS5 server listening on 127.0.0.1:1080\n");
        let p = std::env::temp_dir().join(format!("ep_ready_window_{}.log", std::process::id()));
        std::fs::write(&p, &log).unwrap();
        let text = crate::config::read_tail_bytes(&p, 512 * 1024);
        let _ = std::fs::remove_file(&p);
        assert!(text.contains("SOCKS5 server listening"));
        let ip = Regex::new(r"Client IP:\s*([\d.]+)")
            .unwrap()
            .captures(&text)
            .map(|c| c[1].to_string());
        assert_eq!(ip.as_deref(), Some("2.0.1.24"));
        assert_eq!(parse_vpn_dns(&text), Some("10.0.104.104".to_string()));
    }

    #[test]
    fn http_upstream_port_parses_and_falls_back() {
        assert_eq!(http_upstream_port("127.0.0.1:1081"), 1081);
        assert_eq!(http_upstream_port("127.0.0.1:1234"), 1234);
        assert_eq!(http_upstream_port("garbage"), 1081); // 无端口 → 回退
    }

    /// 起一个假上游：接收 1 字节，回一个标记字节表明自己是谁，并返回收到的字节。
    async fn dummy_upstream(tag: u8) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let h = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 1];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(&[tag]).await.unwrap();
            buf[..n].to_vec()
        });
        (addr, h)
    }

    async fn route_first_byte(first: u8) -> (u8, Vec<u8>, Vec<u8>) {
        let (socks_addr, socks_h) = dummy_upstream(b'S').await;
        let (http_addr, http_h) = dummy_upstream(b'H').await;
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        let (s2, h2) = (socks_addr, http_addr);
        tokio::spawn(async move {
            let (client, _) = front.accept().await.unwrap();
            let _ = relay(client, s2, h2).await;
        });
        let mut c = TcpStream::connect(front_addr).await.unwrap();
        c.write_all(&[first]).await.unwrap();
        let mut reply = [0u8; 1];
        c.read_exact(&mut reply).await.unwrap();
        // 只有被选中的上游会收到字节；用超时避免另一个 await 卡死
        let socks_got = tokio::time::timeout(Duration::from_millis(300), socks_h)
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or_default();
        let http_got = tokio::time::timeout(Duration::from_millis(300), http_h)
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or_default();
        (reply[0], socks_got, http_got)
    }

    #[tokio::test]
    async fn socks_first_byte_routes_to_socks_upstream() {
        let (tag, socks_got, http_got) = route_first_byte(0x05).await;
        assert_eq!(tag, b'S', "0x05 应路由到 socks 上游");
        assert_eq!(socks_got, vec![0x05]);
        assert!(http_got.is_empty());
    }

    #[tokio::test]
    async fn http_first_byte_routes_to_http_upstream() {
        let (tag, socks_got, http_got) = route_first_byte(b'G').await; // 'G' as in GET/CONNECT
        assert_eq!(tag, b'H', "非 0x05 应路由到 http 上游");
        assert_eq!(http_got, vec![b'G']);
        assert!(socks_got.is_empty());
    }
}
