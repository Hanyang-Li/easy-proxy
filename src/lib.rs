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
mod recover;
mod sms;
mod tunnel;

use capsule::{
    error_line, format_capsule, info_line, shell_single_quote, success_line, terminal_width, Delay,
    ProxyStatus,
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
        let cfg = paths.read_app_config()?;
        return daemon::serve(args.clone(), cfg, &paths);
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

/// 顶层错误输出(供 main 使用):红叉 + 消息,无胶囊,不依赖具体配置。
pub fn top_error(message: &str) -> String {
    capsule::error_line(message, None, &config::PromptConfig::default())
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

    /// 只清掉进行中的行、不打印新内容（tty）；非 tty 无操作。
    /// 用于「结果行走 stdout」的场景：先清 stderr 进度行，再由调用方 println 结果。
    fn clear(&self) {
        if self.tty {
            eprint!("\r\x1b[2K");
            let _ = std::io::stderr().flush();
        }
    }
}

/// 短信已下发后，拿到 TWFID：先自动取码（单行原地刷新的「第 N/max 次取码」），
/// 成功即返回；没取到 / 被拒到上限 / esc 取消 → 回退手动输入。彻底失败向上抛错。
fn obtain_twfid(cfg: &AppConfig, jar: &Path, phone: &str, on_sms_sent: &dyn Fn()) -> Result<String> {
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
        if let Some(twfid) = auto_fetch_phase(cfg, jar, cmd, on_sms_sent)? {
            return Ok(twfid);
        }
        // 落空（没取到 / 被拒到上限 / esc 取消）→ 手动
    }

    manual_phase(cfg, jar)
}

/// 前台自动取码:构造 tty UI(原地刷新 + esc 取消)调用 sms 核心;落空返回 None 交由调用方回退手动。
fn auto_fetch_phase(
    cfg: &AppConfig,
    jar: &Path,
    cmd: &str,
    on_sms_sent: &dyn Fn(),
) -> Result<Option<String>> {
    let ui = TtyUi {
        line: StatusLine::new(),
        esc: EscGuard::new(),
    };
    sms::fetch_and_submit_loop(cfg, jar, cmd, &ui, on_sms_sent)
}

/// 前台取码 UI:原地刷新进度行,esc 键取消(保留 ISIG,Ctrl-C 仍可中断)。
struct TtyUi {
    line: StatusLine,
    esc: Option<EscGuard>,
}

impl sms::SmsUi for TtyUi {
    fn progress(&self, t: &str) {
        self.line.progress(t);
    }
    fn finish_ok(&self, t: &str) {
        self.line.finish(t);
    }
    fn finish_err(&self, t: &str) {
        self.line.finish(t);
    }
    fn is_cancelled(&self) -> bool {
        self.esc.as_ref().map(|e| e.esc_pressed()).unwrap_or(false)
    }
    fn sleep_cancelable(&self, dur: std::time::Duration) -> bool {
        sleep_cancelable(dur, self.esc.as_ref())
    }
    fn cancel_hint(&self) -> &str {
        if self.esc.is_some() {
            " (esc 键取消)"
        } else {
            ""
        }
    }
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
                eprintln!(
                    "{}",
                    error_line(
                        &format!("[自动化] 验证码被拒（{why}），剩余 {} 次", FILE_ATTEMPTS - attempt),
                        None,
                        &cfg.prompt
                    )
                )
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
    // 已有守护:online 直接展示;reconnecting(方案 Z)则停掉它、由本次登录接管重连(daemon 无 tty,
    // 手动输码这条路只能前台走)。停旧 + 等其退出后,后续照常登录 + spawn 新 daemon,与全新 connect 同路径。
    if let Some(st) = paths.read_state() {
        if tunnel::pid_alive(st.daemon_pid) {
            if st.phase == config::Phase::Online {
                let delay = tunnel::probe_latency(st.port, &st.server);
                let status = ProxyStatus { online: true, delay, port: Some(st.port) };
                println!("{}", success_line("已经在连接中", Some(&status), &cfg.prompt));
                return Ok(());
            }
            eprintln!(
                "{}",
                info_line("检测到后台正在重连,改由本次登录接管", None, &cfg.prompt)
            );
            tunnel::stop_daemon_and_wait(paths, std::time::Duration::from_secs(5));
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

    // 记录本次登录「最后一次发码」的时刻(初次下发 + 补发都刷新),连接后传给 daemon 作静默重登限流基线。
    let last_sms = std::cell::Cell::new(0u64);
    let on_sms_sent = || last_sms.set(config::now_unix());

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
                // 短信已发（密码正确）→ 记发码时刻 → 取码 + 提交，拿到 TWFID。取码彻底失败会向上抛错。
                on_sms_sent();
                let twfid = obtain_twfid(cfg, &jar, &phone, &on_sms_sent)?;
                if from_user {
                    keychain::set_password(&cfg.username, &pwd)?;
                }
                break twfid;
            }
        }
    };
    let _ = std::fs::remove_file(&jar);

    tunnel::spawn_daemon(paths, cfg, &twfid, last_sms.get())?;
    // 「连接中…」进度行：覆盖「建隧道就绪」+「延迟探测」整段（否则探测那几秒静默像假死），
    // 到最后一刻才清行、让 stdout 的「已连接」胶囊接上。
    let line = StatusLine::new();
    line.progress("  连接中…");
    let ready = tunnel::wait_ready(paths, std::time::Duration::from_secs(45))
        .map(|st| {
            let delay = tunnel::probe_latency(st.port, &st.server);
            (st, delay)
        });
    line.clear(); // 无论成功失败，先清掉进度行，别让后续输出黏在「连接中…」后面
    let (st, delay) = ready?;
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
        .filter(|s| s.phase == config::Phase::Online && tunnel::pid_alive(s.daemon_pid))
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

