//! 后台守护进程（`easy-proxy __serve`）：拉起 zju-connect，并在混合端口上按首字节
//! 嗅探协议（0x05→socks 上游，否则→http 上游，两者都由 zju-connect 提供），透明转发。

use crate::config::{AppConfig, Paths, RuntimeState};
use anyhow::{anyhow, Context, Result};
use regex::Regex;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::signal::unix::{signal, SignalKind};

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

async fn run(args: ServeArgs, cfg: AppConfig, paths: &Paths) -> Result<()> {
    let pid = std::process::id() as i32;
    let mut state = RuntimeState {
        phase: crate::config::Phase::Reconnecting,
        daemon_pid: pid,
        port: args.mixed_port,
        socks_upstream: args.socks.clone(),
        http_upstream: args.http.clone(),
        server: args.server.clone(),
        tunnel_ip: String::new(),
        last_sms_sent: if args.last_sms_sent == 0 { None } else { Some(args.last_sms_sent) },
        error: None,
    };
    paths.write_state(&state)?;

    let log = std::fs::File::create(&paths.tunnel_log)
        .with_context(|| format!("无法创建 {}", paths.tunnel_log.display()))?;
    let mut child = Command::new(&paths.zju_bin)
        .args(zju_args(&args))
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()
        .with_context(|| format!("无法启动 {}", paths.zju_bin.display()))?;

    match wait_socks_ready(paths, &mut child, Duration::from_secs(30)).await {
        Ok(ip) => state.tunnel_ip = ip,
        Err(e) => {
            let _ = child.start_kill();
            state.error = Some(e.to_string());
            let _ = paths.write_state(&state);
            return Err(e);
        }
    }

    let listener = match TcpListener::bind(("127.0.0.1", args.mixed_port)).await {
        Ok(l) => l,
        Err(e) => {
            let _ = child.start_kill();
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

    // select! 只产出「事件」,恢复动作在 select 外执行——避免与 child.wait() 的 &mut child 借用冲突。
    enum Ev {
        Continue,
        Probe,
        TunnelDown,
        Shutdown,
    }

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
            _ = tick.tick() => Ev::Probe,
            _ = notify.notified() => Ev::Shutdown,
        };

        match ev {
            Ev::Continue => {}
            Ev::Shutdown => break,
            Ev::Probe => {
                if probe(&args).await {
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

    let _ = child.start_kill();
    let _ = child.wait().await;
    paths.clear_state();
    Ok(())
}

/// 用给定 twfid 重启 zju-connect:回收旧进程 → truncate 日志 → 起新进程 → 等 SOCKS 就绪,返回 ip。
async fn restart_zju(child: &mut Child, paths: &Paths, args: &ServeArgs, twfid: &str) -> Result<String> {
    let _ = child.start_kill();
    let _ = child.wait().await; // 回收旧进程,杜绝僵尸
    let log = std::fs::File::create(&paths.tunnel_log)
        .with_context(|| format!("无法创建 {}", paths.tunnel_log.display()))?;
    let mut a = args.clone();
    a.twfid = twfid.to_string();
    let new_child = Command::new(&paths.zju_bin)
        .args(zju_args(&a))
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()
        .with_context(|| format!("无法启动 {}", paths.zju_bin.display()))?;
    *child = new_child;
    wait_socks_ready(paths, child, Duration::from_secs(30)).await
}

/// 通过混合端口探测连通性(true=通)。同步 curl,丢 spawn_blocking。
async fn probe(args: &ServeArgs) -> bool {
    let (port, server) = (args.mixed_port, args.server.clone());
    tokio::task::spawn_blocking(move || {
        !matches!(crate::tunnel::probe_latency(port, &server), crate::capsule::Delay::Timeout)
    })
    .await
    .unwrap_or(false)
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
    // step1: 旧 TWFID 重启(不吃闸门)
    if !shutdown.load(Ordering::Relaxed) {
        match restart_zju(child, paths, args, current_twfid).await {
            Ok(ip) => {
                if probe(args).await {
                    state.tunnel_ip = ip;
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
    let jar = paths.cookies.clone();
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
        Ok(ip) => {
            if probe(args).await {
                state.tunnel_ip = ip;
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

async fn wait_socks_ready(paths: &Paths, child: &mut Child, timeout: Duration) -> Result<String> {
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
            return Ok(ip);
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
