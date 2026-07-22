use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::io::{IsTerminal, Write};
use std::path::Path;

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

/// 取码结果：取到码 / 没取到（空 · 超时 · 非法输出）/ 用户按 esc 取消。
#[derive(Debug, PartialEq)]
enum SmsFetch {
    Code(String),
    Empty,
    Cancelled,
}

/// 让终端进入「非规范 + 无回显」模式，以便在取码/等待期间非阻塞探测 esc；drop 时恢复原状。
/// 保留 ISIG，Ctrl-C 依旧能中断。非 tty 时 `new` 返回 None（即无 esc 取消能力）。
struct EscGuard {
    orig: libc::termios,
}

impl EscGuard {
    fn new() -> Option<EscGuard> {
        let fd = libc::STDIN_FILENO;
        if unsafe { libc::isatty(fd) } != 1 {
            return None;
        }
        unsafe {
            let mut orig: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut orig) != 0 {
                return None;
            }
            let mut raw = orig;
            raw.c_lflag &= !(libc::ICANON | libc::ECHO); // 关行缓冲与回显，保留 ISIG
            raw.c_cc[libc::VMIN] = 0; // read 立即返回可用字节数（可能为 0）
            raw.c_cc[libc::VTIME] = 0;
            if libc::tcsetattr(fd, libc::TCSANOW, &raw) != 0 {
                return None;
            }
            Some(EscGuard { orig })
        }
    }

    /// 读走当前输入缓冲；出现「单独的 ESC 字节」判为取消（方向键等 ESC 序列忽略）。
    fn esc_pressed(&self) -> bool {
        let mut buf = [0u8; 32];
        let n = unsafe {
            libc::read(
                libc::STDIN_FILENO,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n <= 0 {
            return false;
        }
        let bytes = &buf[..n as usize];
        let is_seq = bytes.len() >= 2 && bytes[0] == 0x1b && (bytes[1] == b'[' || bytes[1] == b'O');
        !is_seq && bytes.contains(&0x1b)
    }
}

impl Drop for EscGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.orig);
        }
    }
}

/// 可被 esc 打断的等待：返回 true 表示中途按了 esc，false 表示睡满 `dur`。
fn sleep_cancelable(dur: std::time::Duration, esc: Option<&EscGuard>) -> bool {
    use std::time::Instant;
    let start = Instant::now();
    loop {
        if let Some(e) = esc {
            if e.esc_pressed() {
                return true;
            }
        }
        if start.elapsed() >= dur {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(120));
    }
}

/// 执行取码命令（`sh -c <command>`），最多等 `timeout`（防挂死兜底）。
/// 分工：脚本负责「轮询等码」和「往前看多久 / 是否过期」；easy-proxy 只负责运行它、取回一段输出。
/// 契约：脚本把 4–8 位验证码打印到 stdout 即视为取到；空输出 / 非数字 / 非零退出 / 超时都视作「没取到」（Empty）。
/// 期间若 `esc` 探测到 esc 键，杀掉子进程并返回 `Cancelled`。码是否被接受，交由后续 login_sms1（服务端）判定。
fn run_sms_command(command: &str, timeout: std::time::Duration, esc: Option<&EscGuard>) -> SmsFetch {
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let mut child = match Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return SmsFetch::Empty,
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if let Some(e) = esc {
                    if e.esc_pressed() {
                        let _ = child.kill();
                        let _ = child.wait();
                        return SmsFetch::Cancelled;
                    }
                }
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return SmsFetch::Empty;
                }
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
            Err(_) => return SmsFetch::Empty,
        }
    }
    let mut out = String::new();
    if let Some(mut so) = child.stdout.take() {
        use std::io::Read;
        let _ = so.read_to_string(&mut out);
    }
    match valid_sms_code(&out) {
        Some(code) => SmsFetch::Code(code),
        None => SmsFetch::Empty,
    }
}

/// 单行原地刷新器：tty 上用 `\r\x1b[2K` 覆盖上一次内容（进度行不换行、结果行换行定格）；
/// 非 tty 退化为逐行打印（每个状态各占一行，便于日志留痕）。
struct StatusLine {
    tty: bool,
}

impl StatusLine {
    fn new() -> Self {
        StatusLine { tty: std::io::stderr().is_terminal() }
    }

    /// 刷成一条「进行中」的行：tty 上覆盖并停在行尾（等待被后续内容替换）。
    fn progress(&self, text: &str) {
        if self.tty {
            eprint!("\r\x1b[2K{text}");
            let _ = std::io::stderr().flush();
        } else {
            eprintln!("{text}");
        }
    }

    /// 定格一条最终结果行：覆盖掉进行中的行并换行。
    fn finish(&self, text: &str) {
        if self.tty {
            eprintln!("\r\x1b[2K{text}");
        } else {
            eprintln!("{text}");
        }
    }
}

/// 短信已下发后，拿到 TWFID：先自动取码（单行原地刷新的「第 N/max 次取码」），
/// 成功即返回；没取到 / 被拒到上限 / esc 取消 → 回退手动输入。彻底失败向上抛错。
fn obtain_twfid(cfg: &AppConfig, jar: &Path, phone: &str) -> Result<String> {
    // 表头：短信已下发（一次性持久行，位于取码进度行之上）
    let sent = if phone.is_empty() {
        "短信验证码已发送".to_string()
    } else {
        format!("短信验证码已发送至 {phone}")
    };
    eprintln!("{}", success_line(&sent, None, &cfg.prompt));

    // 自动化钩子：设置 EASY_PROXY_SMS_FILE 时从文件读码，便于脚本/无 tty 场景
    if let Ok(path) = std::env::var("EASY_PROXY_SMS_FILE") {
        return automation_via_file(cfg, jar, &path);
    }

    // 自动取码阶段（配了 sms_command 才启用）
    if let Some(cmd) = cfg
        .sms_command
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        if let Some(twfid) = auto_fetch_phase(cfg, jar, cmd)? {
            return Ok(twfid);
        }
        // 落空（没取到 / 被拒到上限 / esc 取消）→ 手动
    }

    manual_phase(cfg, jar)
}

/// 自动取码主循环：第 1..=auto_max 轮（auto_max = 1 + sms_retries），整段只占屏幕一行、原地刷新。
/// 每一轮：进下一轮前**统一**等待 sms_retry_interval_secs（首轮不等）——两条失败路径共用等待，
/// 唯一区别是「上一轮没取到」会先补发一次短信（被拒则不补发）。取到码就提交：
/// 通过→返回 Some(twfid)；被拒→进下一轮（不补发）；没取到→进下一轮（补发）。
/// 轮数耗尽 / esc 取消 → 定格失败行并返回 None（调用方回退手动）。
fn auto_fetch_phase(cfg: &AppConfig, jar: &Path, cmd: &str) -> Result<Option<String>> {
    let auto_max = 1 + cfg.sms_retries;
    let retry_wait = std::time::Duration::from_secs(cfg.sms_retry_interval_secs as u64);
    let esc = EscGuard::new(); // None = 非 tty，无 esc 取消能力
    let line = StatusLine::new();
    let hint = if esc.is_some() { " (esc 键取消)" } else { "" };

    // 上一轮的失败原因：None = 首轮；Some(true) = 没取到（下一轮前补发）；Some(false) = 被拒（不补发）。
    let mut prev_empty: Option<bool> = None;
    let mut cancelled = false;

    let mut round = 0u32;
    while round < auto_max {
        round += 1;
        line.progress(&format!("  [自动] 第 {round}/{auto_max} 次取码…{hint}"));

        // 非首轮：先（按需）补发一条新码，再统一等待；等待让码送达 chat.db（不因是否补发而不同）。
        if let Some(was_empty) = prev_empty {
            if was_empty {
                if let Err(e) = login::resend_sms(&cfg.server, cfg.port, jar) {
                    line.finish(&error_line(
                        &format!("[自动] 补发短信失败：{e}，回退手动输入"),
                        None,
                        &cfg.prompt,
                    ));
                    return Ok(None);
                }
            }
            if sleep_cancelable(retry_wait, esc.as_ref()) {
                cancelled = true;
                break;
            }
        }

        match run_sms_command(cmd, SMS_COMMAND_TIMEOUT, esc.as_ref()) {
            SmsFetch::Cancelled => {
                cancelled = true;
                break;
            }
            SmsFetch::Empty => prev_empty = Some(true),
            SmsFetch::Code(code) => match login::submit_sms(&cfg.server, cfg.port, jar, &code)? {
                login::SmsOutcome::Accepted(twfid) => {
                    line.finish(&success_line("[自动] 验证码已通过", None, &cfg.prompt));
                    return Ok(Some(twfid));
                }
                login::SmsOutcome::Rejected(_why) => prev_empty = Some(false),
            },
        }
    }

    if cancelled {
        line.finish(&error_line("[自动] 已取消自动取码，转手动输入", None, &cfg.prompt));
    } else {
        line.finish(&error_line("[自动] 未取到验证码，回退手动输入", None, &cfg.prompt));
    }
    Ok(None)
    // esc 在此 drop，终端恢复规范模式，交给手动阶段的 dialoguer
}

/// 手动输入验证码并提交，最多 3 次（格式错误由 dialoguer 当场拦下、不计入）。全错则抛错。
fn manual_phase(cfg: &AppConfig, jar: &Path) -> Result<String> {
    const MANUAL_ATTEMPTS: u32 = 3;
    for attempt in 1..=MANUAL_ATTEMPTS {
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
        match login::submit_sms(&cfg.server, cfg.port, jar, code.trim())? {
            login::SmsOutcome::Accepted(twfid) => return Ok(twfid),
            login::SmsOutcome::Rejected(why) => eprintln!(
                "{}",
                error_line(
                    &format!("验证码错误（{why}），剩余 {} 次", MANUAL_ATTEMPTS - attempt),
                    None,
                    &cfg.prompt
                )
            ),
        }
    }
    Err(anyhow!("验证码连续 {MANUAL_ATTEMPTS} 次错误"))
}

/// 无 tty / 脚本场景：从 EASY_PROXY_SMS_FILE 轮询读码并提交，被拒则重读，最多 3 次。
fn automation_via_file(cfg: &AppConfig, jar: &Path, path: &str) -> Result<String> {
    const FILE_ATTEMPTS: u32 = 3;
    for attempt in 1..=FILE_ATTEMPTS {
        let code = wait_sms_file(path)?;
        match login::submit_sms(&cfg.server, cfg.port, jar, &code)? {
            login::SmsOutcome::Accepted(twfid) => return Ok(twfid),
            login::SmsOutcome::Rejected(why) => {
                eprintln!("  [自动化] 验证码被拒（{why}），剩余 {} 次", FILE_ATTEMPTS - attempt)
            }
        }
    }
    Err(anyhow!("[自动化] 验证码连续 {FILE_ATTEMPTS} 次被拒"))
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

        match login::login_password(&cfg.server, cfg.port, &cfg.username, &pwd, &jar)? {
            login::PwOutcome::PasswordRejected(msg) => {
                eprintln!("{}", error_line(&format!("密码被拒: {msg}，请重新输入"), None, &cfg.prompt));
                // 下一轮 password 为 None → 交互重输
            }
            login::PwOutcome::SmsSent { phone } => {
                // 短信已发（密码正确）→ 取码 + 提交，拿到 TWFID。取码彻底失败会向上抛错。
                let twfid = obtain_twfid(cfg, &jar, &phone)?;
                if from_user {
                    keychain::set_password(&cfg.username, &pwd)?;
                }
                break twfid;
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
            run_sms_command("echo 654321", Duration::from_secs(5), None),
            SmsFetch::Code("654321".to_string())
        );
    }

    #[test]
    fn command_no_valid_output_is_empty() {
        assert_eq!(run_sms_command("true", Duration::from_secs(5), None), SmsFetch::Empty);
        assert_eq!(run_sms_command("exit 1", Duration::from_secs(5), None), SmsFetch::Empty);
        assert_eq!(
            run_sms_command("echo not-a-code", Duration::from_secs(5), None),
            SmsFetch::Empty
        );
    }

    #[test]
    fn command_timeout_kills_and_returns_empty() {
        let start = Instant::now();
        let code = run_sms_command("sleep 5; echo 123456", Duration::from_millis(300), None);
        assert_eq!(code, SmsFetch::Empty);
        assert!(start.elapsed() < Duration::from_secs(3), "应在超时后立即返回，不等满 5s");
    }
}
