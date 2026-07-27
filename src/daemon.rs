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
    let mut cmd = Command::new("/usr/bin/sudo");
    cmd.arg("-n").arg(crate::tun::HELPER_PATH).arg("dns-sync");
    for s in &suffixes {
        cmd.arg(format!("{s}={dns}"));
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
            state.vpn_dns = pick_probe_target(&args, info.vpn_dns).await;
        }
        Err(e) => {
            kill_tunnel(&mut child, args.tun).await;
            state.error = Some(e.to_string());
            let _ = paths.write_state(&state);
            return Err(e);
        }
    }

    // TUN 启动护栏 + scoped resolver:就绪后立即执行,护栏失败绝不假 online
    if args.tun {
        if let Err(e) = tun_guardrails(paths) {
            kill_tunnel(&mut child, true).await;
            state.error = Some(e.to_string());
            let _ = paths.write_state(&state);
            return Err(e);
        }
        tun_dns_sync(&cfg, &state).await;
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
        let _ = Command::new("/usr/bin/sudo")
            .args(["-n", crate::tun::HELPER_PATH, "dns-clean"])
            .output()
            .await;
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
/// 两种模式:
/// - `vpn_dns=Some`:SOCKS5 CONNECT 到 VPN DNS:53,**穿隧道**测数据面(网关地址被
///   zju-connect 路由为 DIRECT,curl 网关只能测直连,切网后隧道假死时照样绿——0.3.0 的坑)。
/// - `vpn_dns=None`:回退 curl 直连网关(退化行为,对隧道假死不敏感)。
///
/// 关键:两种模式都**直连 zju-connect 上游(1080/1081),绝不走 mixed_port**——
/// mixed_port 的转发靠本 daemon 主循环 accept,而探测/恢复期间主循环正阻塞在这里、不 accept,
/// 若探 mixed_port 必然自锁超时、假报断线。直连上游由 zju-connect 独立进程处理,不受影响。
async fn probe(args: &ServeArgs, vpn_dns: Option<&str>) -> bool {
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
    match parsed_dns {
        Some(dns) => {
            if probe(args, Some(&dns)).await {
                eprintln!("[daemon] 健康检查:穿隧道探测 VPN DNS {dns}:53");
                Some(dns)
            } else {
                eprintln!("[daemon] 穿隧道探针(VPN DNS {dns}:53)在新隧道上不通,降级为网关直连探测");
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
    // 先等新网络就绪(直连网关可达):路由事件触发的恢复往往抢在 DHCP/关联完成之前,
    // 不等就重启必失败,恢复流程会一路 GiveUp 把 daemon 拖下线。
    wait_gateway_reachable(args, Duration::from_secs(30), shutdown).await;

    // step1: 旧 TWFID 重启(不吃闸门)
    if !shutdown.load(Ordering::Relaxed) {
        match restart_zju(child, paths, args, current_twfid).await {
            Ok(info) => {
                // 新隧道上重选探针目标(必要时降级),再按选定目标验活
                state.tunnel_ip = info.ip;
                state.vpn_dns = pick_probe_target(args, info.vpn_dns).await;
                if probe(args, state.vpn_dns.as_deref()).await {
                    if args.tun {
                        if let Err(e) = tun_guardrails(paths) {
                            eprintln!("[daemon] 恢复后护栏失败: {e}");
                            return RecoverOutcome::GiveUp;
                        }
                        tun_dns_sync(cfg, state).await;
                    }
                    eprintln!("[daemon] 旧 TWFID 重启成功");
                    return RecoverOutcome::Online;
                }
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
            state.vpn_dns = pick_probe_target(args, info.vpn_dns).await;
            if probe(args, state.vpn_dns.as_deref()).await {
                if args.tun {
                    if let Err(e) = tun_guardrails(paths) {
                        eprintln!("[daemon] 恢复后护栏失败: {e}");
                        return RecoverOutcome::GiveUp;
                    }
                    tun_dns_sync(cfg, state).await;
                }
                eprintln!("[daemon] 静默重登并重启成功");
                RecoverOutcome::Online
            } else {
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

/// zju-connect 就绪信息：隧道虚拟 IP + 服务端下发的 VPN DNS（穿隧道探针的目标）。
struct ReadyInfo {
    ip: String,
    vpn_dns: Option<String>,
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
        let text = crate::config::read_tail_bytes(&paths.tunnel_log, 8192);
        if text.contains("SOCKS5 server listening") {
            let ip = ip_re
                .captures(&text)
                .or_else(|| ip_re2.captures(&text))
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            return Ok(ReadyInfo { ip, vpn_dns: parse_vpn_dns(&text) });
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
