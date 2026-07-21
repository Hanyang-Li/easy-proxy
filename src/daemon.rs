//! 后台守护进程（`easy-proxy __serve`）：拉起 zju-connect，并在混合端口上按首字节
//! 嗅探协议（0x05→socks 上游，否则→http 上游，两者都由 zju-connect 提供），透明转发。

use crate::config::{Paths, RuntimeState};
use anyhow::{anyhow, Context, Result};
use regex::Regex;
use std::process::Stdio;
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
}

pub fn serve(args: ServeArgs, paths: &Paths) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run(args, paths))
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

async fn run(args: ServeArgs, paths: &Paths) -> Result<()> {
    let pid = std::process::id() as i32;
    let mut state = RuntimeState {
        connected: false,
        daemon_pid: pid,
        port: args.mixed_port,
        socks_upstream: args.socks.clone(),
        http_upstream: args.http.clone(),
        server: args.server.clone(),
        tunnel_ip: String::new(),
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

    state.connected = true;
    paths.write_state(&state)?;
    eprintln!("[daemon] ready: mixed 127.0.0.1:{} → socks {}", args.mixed_port, args.socks);

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                if let Ok((client, _)) = accepted {
                    let (socks, http) = (args.socks.clone(), args.http.clone());
                    tokio::spawn(async move {
                        let _ = relay(client, socks, http).await;
                    });
                }
            }
            status = child.wait() => {
                eprintln!("[daemon] zju-connect 退出: {status:?}，隧道断开");
                break;
            }
            _ = sigterm.recv() => { eprintln!("[daemon] SIGTERM"); break; }
            _ = sigint.recv()  => { eprintln!("[daemon] SIGINT"); break; }
        }
    }

    let _ = child.start_kill();
    let _ = child.wait().await;
    paths.clear_state();
    Ok(())
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
        let text = std::fs::read_to_string(&paths.tunnel_log).unwrap_or_default();
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
    let text = std::fs::read_to_string(&paths.tunnel_log).unwrap_or_default();
    let start = text.len().saturating_sub(1000);
    text[start..].to_string()
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
