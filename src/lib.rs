use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::io::{IsTerminal, Write};

mod capsule;
mod config;
mod daemon;
mod install;
mod keychain;
mod login;
mod tunnel;

use capsule::{
    error_line, format_capsule, shell_single_quote, success_line, terminal_width, Delay, ProxyStatus,
};
use config::{AppConfig, Paths};

#[derive(Parser)]
#[command(name = "easy-proxy", version, about = "公司 VPN 一键代理（EasyConnect + zju-connect）")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 登录并启动隧道（跨终端后台守护，交互输入短信验证码）
    Connect {
        /// 忽略钥匙串中已存密码，强制重新输入
        #[arg(long)]
        relogin: bool,
    },
    /// 停止隧道后台守护，并清除当前终端代理环境变量
    Disconnect,
    /// 为当前终端设置代理环境变量
    Start,
    /// 移除当前终端代理环境变量
    Stop,
    /// 重新读取端口并更新当前终端代理环境变量
    Restart,
    /// 显示连接状态胶囊（online/offline · 延迟 · 端口）
    Status,
    /// 只输出当前端口号
    Port {
        /// 仅在已连接时输出端口，否则以非零码退出（供 ep 使用）
        #[arg(long)]
        connected: bool,
    },
    /// 安装 .zshrc wrapper、tab 补全与默认配置
    Install,
    /// 内部：后台守护进程（拉起 zju-connect + 混合端口代理）
    #[command(hide = true, name = "__serve")]
    Serve(daemon::ServeArgs),
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let paths = Paths::new()?;

    // __serve 与 install 不要求已有配置文件
    if let Commands::Serve(args) = &cli.command {
        return daemon::serve(args.clone(), &paths);
    }
    if let Commands::Install = &cli.command {
        return install::cmd_install(&paths);
    }

    let cfg = paths.read_app_config()?;
    match cli.command {
        Commands::Connect { relogin } => cmd_connect(&paths, &cfg, relogin),
        Commands::Disconnect => cmd_disconnect(&paths, &cfg),
        Commands::Start => cmd_start(&paths, &cfg),
        Commands::Stop => cmd_stop(&cfg),
        Commands::Restart => cmd_restart(&paths, &cfg),
        Commands::Status => cmd_status(&paths, &cfg),
        Commands::Port { connected } => cmd_port(&paths, &cfg, connected),
        Commands::Install | Commands::Serve(_) => unreachable!(),
    }
}

/// 自动化：轮询文件读取验证码（最多 180s），供脚本/无 tty 场景。
fn wait_sms_file(path: &str) -> Result<String> {
    use std::time::{Duration, Instant};
    let p = std::path::Path::new(path);
    let _ = std::fs::remove_file(p);
    eprintln!("  [自动化] 等待验证码写入 {path}（180s 超时）");
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if let Ok(s) = std::fs::read_to_string(p) {
            let code = s.trim().to_string();
            let _ = std::fs::remove_file(p);
            if !code.is_empty() && code.chars().all(|c| c.is_ascii_digit()) && (4..=8).contains(&code.len())
            {
                return Ok(code);
            }
        }
        if Instant::now() >= deadline {
            return Err(anyhow!("等待验证码超时"));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn cmd_connect(paths: &Paths, cfg: &AppConfig, relogin: bool) -> Result<()> {
    if cfg.server.trim().is_empty() || cfg.username.trim().is_empty() {
        return Err(anyhow!(
            "请先编辑 {} 填入 server 和 username",
            paths.app_config.display()
        ));
    }
    // 已连接则直接展示状态
    if let Some(st) = paths.read_state() {
        if st.connected && tunnel::pid_alive(st.daemon_pid) {
            let delay = tunnel::probe_latency(st.port, &st.server);
            let status = ProxyStatus { online: true, delay, port: Some(st.port) };
            println!("{}", success_line("已经在连接中", Some(&status), &cfg.prompt));
            return Ok(());
        }
    }

    install::ensure_zju_bin(paths)?;

    let jar = paths.config_dir.join(".cookies");
    let mut password = if relogin {
        None
    } else {
        std::env::var("EASY_PROXY_PASSWORD")
            .ok()
            .or_else(|| keychain::get_password(&cfg.username))
    };

    let twfid = loop {
        let (pwd, from_user) = match password.take() {
            Some(p) => (p, false),
            None => {
                let p = dialoguer::Password::new()
                    .with_prompt(format!("VPN 密码（{}）", cfg.username))
                    .interact()?;
                (p, true)
            }
        };

        let mut sms = |phone: &str| -> Result<String> {
            let msg = if phone.is_empty() {
                "短信验证码已发送".to_string()
            } else {
                format!("短信验证码已发送至 {phone}")
            };
            eprintln!("{}", success_line(&msg, None, &cfg.prompt));
            // 自动化钩子：设置 EASY_PROXY_SMS_FILE 时轮询该文件读取验证码，便于脚本/无 tty 场景
            if let Ok(path) = std::env::var("EASY_PROXY_SMS_FILE") {
                return wait_sms_file(&path);
            }
            let code: String = dialoguer::Input::new()
                .with_prompt("短信验证码")
                .validate_with(|s: &String| -> Result<(), &str> {
                    if s.trim().chars().all(|c| c.is_ascii_digit()) && (4..=8).contains(&s.trim().len()) {
                        Ok(())
                    } else {
                        Err("应为 4-8 位数字")
                    }
                })
                .interact_text()?;
            Ok(code.trim().to_string())
        };

        match login::login(&cfg.server, cfg.port, &cfg.username, &pwd, &jar, &mut sms)? {
            login::LoginOutcome::Ok(twfid) => {
                if from_user {
                    keychain::set_password(&cfg.username, &pwd)?;
                }
                break twfid;
            }
            login::LoginOutcome::PasswordRejected(msg) => {
                eprintln!("{}", error_line(&format!("密码被拒: {msg}，请重新输入", ), None, &cfg.prompt));
                // 下一轮 password 为 None → 交互重输
            }
        }
    };
    let _ = std::fs::remove_file(&jar);

    tunnel::spawn_daemon(paths, cfg, &twfid)?;
    // 中间提示「正在建立隧道…」：在 tty 上用不换行 + 清行，让最终结果替换掉它
    let tty = std::io::stderr().is_terminal();
    if tty {
        eprint!("  正在建立隧道…");
        let _ = std::io::stderr().flush();
    } else {
        eprintln!("  正在建立隧道…");
    }
    let ready = tunnel::wait_ready(paths, std::time::Duration::from_secs(45));
    if tty {
        eprint!("\r\x1b[2K"); // 回行首并清行
        let _ = std::io::stderr().flush();
    }
    let st = ready?;
    let delay = tunnel::probe_latency(st.port, &st.server);
    let status = ProxyStatus { online: true, delay, port: Some(st.port) };
    println!("{}", success_line("已连接", Some(&status), &cfg.prompt));
    Ok(())
}

fn cmd_disconnect(paths: &Paths, cfg: &AppConfig) -> Result<()> {
    tunnel::stop_daemon(paths);
    // 供 zsh wrapper eval：清掉当前终端代理环境变量
    println!("unset http_proxy https_proxy all_proxy no_proxy");
    let status = ProxyStatus { online: false, delay: Delay::Hidden, port: None };
    println!(
        "echo {}",
        shell_single_quote(&success_line("已断开", Some(&status), &cfg.prompt))
    );
    Ok(())
}

fn connected_state(paths: &Paths) -> Option<config::RuntimeState> {
    paths
        .read_state()
        .filter(|s| s.connected && tunnel::pid_alive(s.daemon_pid))
}

fn cmd_start(paths: &Paths, cfg: &AppConfig) -> Result<()> {
    let Some(st) = connected_state(paths) else {
        emit_shell_error("未连接，请先执行 easy-proxy connect", cfg);
        return Ok(());
    };
    let occupied = ["http_proxy", "https_proxy", "all_proxy"]
        .into_iter()
        .any(|k| std::env::var_os(k).is_some());
    if occupied {
        emit_shell_error("环境变量被占用，请先执行 easy-proxy stop", cfg);
        return Ok(());
    }
    emit_exports(st.port, cfg, "命令行代理已开启");
    Ok(())
}

fn cmd_stop(cfg: &AppConfig) -> Result<()> {
    println!("unset http_proxy https_proxy all_proxy no_proxy");
    let status = ProxyStatus { online: false, delay: Delay::Hidden, port: None };
    println!(
        "echo {}",
        shell_single_quote(&success_line("命令行代理已关闭", Some(&status), &cfg.prompt))
    );
    Ok(())
}

fn cmd_restart(paths: &Paths, cfg: &AppConfig) -> Result<()> {
    let Some(st) = connected_state(paths) else {
        emit_shell_error("未连接，请先执行 easy-proxy connect", cfg);
        return Ok(());
    };
    emit_exports(st.port, cfg, "命令行代理已重启");
    Ok(())
}

fn emit_exports(port: u16, cfg: &AppConfig, message: &str) {
    println!("export http_proxy=http://127.0.0.1:{port}");
    println!("export https_proxy=http://127.0.0.1:{port}");
    println!("export all_proxy=socks5://127.0.0.1:{port}");
    println!("export no_proxy=localhost,127.0.0.1");
    let status = ProxyStatus { online: true, delay: Delay::Hidden, port: Some(port) };
    println!(
        "echo {}",
        shell_single_quote(&success_line(message, Some(&status), &cfg.prompt))
    );
}

fn emit_shell_error(message: &str, cfg: &AppConfig) {
    println!(
        "echo {}",
        shell_single_quote(&error_line(message, None, &cfg.prompt))
    );
    println!("return 1 2>/dev/null || exit 1");
}

fn cmd_status(paths: &Paths, cfg: &AppConfig) -> Result<()> {
    let status = match connected_state(paths) {
        Some(st) => {
            let delay = tunnel::probe_latency(st.port, &st.server);
            ProxyStatus { online: true, delay, port: Some(st.port) }
        }
        None => ProxyStatus { online: false, delay: Delay::Hidden, port: None },
    };
    println!("{}", format_capsule(&status, &cfg.prompt, terminal_width(), 0));
    Ok(())
}

fn cmd_port(paths: &Paths, cfg: &AppConfig, connected_only: bool) -> Result<()> {
    match connected_state(paths) {
        Some(st) => {
            println!("{}", st.port);
            Ok(())
        }
        None if connected_only => Err(anyhow!("未连接")),
        None => {
            println!("{}", cfg.mixed_port);
            Ok(())
        }
    }
}
