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

/// 取码命令的安全上限：轮询与「往前看多久」的逻辑都在脚本里（示例脚本自行轮询约 60s），
/// 这里只作防挂死兜底——超过它仍没返回就杀掉子进程、回退手动输入。
const SMS_COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

/// 校验取码输出：去掉首尾空白后，必须是 4–8 位纯数字，否则视作「还没取到」。
fn valid_sms_code(raw: &str) -> Option<String> {
    let s = raw.trim();
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) && (4..=8).contains(&s.len()) {
        Some(s.to_string())
    } else {
        None
    }
}

/// 执行取码命令（`sh -c <command>`），最多等 `timeout`（防挂死兜底）。
/// 分工：脚本负责「轮询等码」和「往前看多久 / 是否过期」；easy-proxy 只负责运行它、取回一段输出。
/// 契约：脚本把 4–8 位验证码打印到 stdout 即视为取到；空输出 / 非数字 / 非零退出 / 超时都视作「没取到」，
/// 返回 None（调用方回退手动）。码是否被接受，交由后续 login_sms1（服务端）判定。
fn run_sms_command(command: &str, timeout: std::time::Duration) -> Option<String> {
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
            Err(_) => return None,
        }
    }
    let mut out = String::new();
    if let Some(mut so) = child.stdout.take() {
        use std::io::Read;
        let _ = so.read_to_string(&mut out);
    }
    valid_sms_code(&out)
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
    std::fs::create_dir_all(&paths.runtime_dir)?; // 登录 cookie / 状态 / 日志的落脚处

    let jar = paths.cookies.clone();
    let mut password = if relogin {
        None
    } else {
        std::env::var("EASY_PROXY_PASSWORD")
            .ok()
            .or_else(|| keychain::get_password(&cfg.username))
    };

    // 自动取码额度与重试节奏（仅在配置了 sms_command 时启用自动）：
    // 总自动提交次数 = 1（首次）+ sms_retries（重试）；login_sms1 总次数再加 3 次手动兜底。
    let auto_enabled = cfg
        .sms_command
        .as_deref()
        .map(str::trim)
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let auto_max: u32 = if auto_enabled { 1 + cfg.sms_retries } else { 0 };
    let retry_wait = std::time::Duration::from_secs(cfg.sms_retry_interval_secs as u64);
    let max_attempts = auto_max + 3;

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

        // 本次登录的自动取码进度；被服务端拒后按 sms_retries 重试（重试前等待、不重发短信），
        // 额度用尽或脚本没取到码则回退手动输入。
        let mut auto_done: u32 = 0;
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
            // 可插拔自动取码：config.sms_command 配了就执行一次；脚本自行轮询/判断有效期，
            // 取到即用，取不到（空/超时）回退手动输入。
            if let Some(cmd) = cfg
                .sms_command
                .as_deref()
                .map(str::trim)
                .filter(|c| !c.is_empty())
            {
                if auto_done < auto_max {
                    if auto_done > 0 {
                        // 重试：上一个自动取的码被服务端拒。等一会儿让「正确的验证码」送达 chat.db
                        // 后再重读——绝不重发短信（重发只会重蹈覆辙）。
                        eprintln!(
                            "  [自动] 上一个验证码被拒，等待 {}s 后重读（不重发短信）…",
                            cfg.sms_retry_interval_secs
                        );
                        std::thread::sleep(retry_wait);
                    }
                    auto_done += 1;
                    // 「取码中…」作为进度行：tty 上不换行，拿到结果后清行替换（同「建立隧道→已连接」）
                    let tty = std::io::stderr().is_terminal();
                    let progress = format!("  [自动] 第 {auto_done}/{auto_max} 次取码（脚本自行轮询）…");
                    if tty {
                        eprint!("{progress}");
                        let _ = std::io::stderr().flush();
                    } else {
                        eprintln!("{progress}");
                    }
                    let got = run_sms_command(cmd, SMS_COMMAND_TIMEOUT);
                    if tty {
                        eprint!("\r\x1b[2K"); // 回行首并清行，让结果替换掉进度行
                        let _ = std::io::stderr().flush();
                    }
                    if let Some(code) = got {
                        eprintln!("{}", success_line("[自动] 已获取验证码", None, &cfg.prompt));
                        return Ok(code);
                    }
                    // 脚本没取到码（空/超时）：再等也多半没有 → 放弃剩余自动额度，回退手动
                    auto_done = auto_max;
                    eprintln!(
                        "{}",
                        error_line("[自动] 未取到验证码，回退手动输入", None, &cfg.prompt)
                    );
                }
                // 自动额度用尽 → 落到下面手动输入
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

        match login::login(&cfg.server, cfg.port, &cfg.username, &pwd, &jar, max_attempts, &mut sms)? {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn valid_code_accepts_4_to_8_digits() {
        assert_eq!(valid_sms_code(" 929869 \n"), Some("929869".to_string()));
        assert_eq!(valid_sms_code("1234"), Some("1234".to_string()));
        assert_eq!(valid_sms_code("12345678"), Some("12345678".to_string()));
    }

    #[test]
    fn valid_code_rejects_junk() {
        assert_eq!(valid_sms_code(""), None);
        assert_eq!(valid_sms_code("   "), None);
        assert_eq!(valid_sms_code("123"), None); // 太短
        assert_eq!(valid_sms_code("123456789"), None); // 太长
        assert_eq!(valid_sms_code("code:123456"), None); // 非纯数字
        assert_eq!(valid_sms_code("abcd"), None);
    }

    #[test]
    fn command_stdout_code_is_returned() {
        assert_eq!(
            run_sms_command("echo 654321", Duration::from_secs(5)),
            Some("654321".to_string())
        );
    }

    #[test]
    fn command_no_valid_output_is_none() {
        assert_eq!(run_sms_command("true", Duration::from_secs(5)), None);
        assert_eq!(run_sms_command("exit 1", Duration::from_secs(5)), None);
        assert_eq!(run_sms_command("echo not-a-code", Duration::from_secs(5)), None);
    }

    #[test]
    fn command_timeout_kills_and_returns_none() {
        let start = Instant::now();
        let code = run_sms_command("sleep 5; echo 123456", Duration::from_millis(300));
        assert_eq!(code, None);
        assert!(start.elapsed() < Duration::from_secs(3), "应在超时后立即返回，不等满 5s");
    }
}
