use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::io::{IsTerminal, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

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
    error_line, format_capsule, info_line, shell_single_quote, success_line, terminal_width,
    ConnState, Delay, ProxyStatus,
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

/// 进度 spinner 帧(与参考项目 fintopia-jump 同款盲文动画,单字宽,与 ✔/✘ 对齐)。
const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn spinner_frame(i: usize) -> &'static str {
    SPINNER_FRAMES[i % SPINNER_FRAMES.len()]
}

/// SIGINT 前快照到的「干净(cooked)终端属性」。任何 raw 阶段(EscGuard / dialoguer)被 Ctrl-C
/// 打断时,由信号线程据此把终端恢复原状,避免残留无回显 / 无行编辑。
static ORIG_TERMIOS: Mutex<Option<libc::termios>> = Mutex::new(None);

/// 安装 Ctrl-C 处理:先快照当前(此刻仍是 cooked)终端属性,再起一条独立线程等待 SIGINT——
/// 收到即恢复终端、换行、以 130 退出。放在独立线程(而非信号上下文)里做,故可安全 tcsetattr / 加锁,
/// spinner 后台线程与之互不阻塞,Ctrl-C 全程可即时干净退出。
fn install_sigint_handler() {
    unsafe {
        let fd = libc::STDIN_FILENO;
        if libc::isatty(fd) == 1 {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut t) == 0 {
                if let Ok(mut g) = ORIG_TERMIOS.lock() {
                    *g = Some(t);
                }
            }
        }
    }
    if let Ok(mut signals) = signal_hook::iterator::Signals::new([signal_hook::consts::SIGINT]) {
        thread::spawn(move || {
            // 等第一个 SIGINT 即恢复终端并退出;后续无需理会(进程随即终止)。
            if signals.forever().next().is_some() {
                if let Ok(g) = ORIG_TERMIOS.lock() {
                    if let Some(t) = g.as_ref() {
                        unsafe {
                            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, t);
                        }
                    }
                }
                let _ = writeln!(std::io::stderr()); // 从 spinner / 提示行挪到新行
                std::process::exit(130);
            }
        });
    }
}

/// 交互输入主题:把左侧 logo 换成本项目的加粗蓝 `›`(与 spinner 同蓝、与 ✔/✘ 同宽同风格),
/// 冒号后缀承接参考项目 `› 标签: ` 的观感;成功/错误前缀沿用 dialoguer 的绿 ✔ / 红 ✘。
fn ep_theme() -> dialoguer::theme::ColorfulTheme {
    use dialoguer::console::style;
    dialoguer::theme::ColorfulTheme {
        prompt_prefix: style("›".to_string())
            .for_stderr()
            .true_color(137, 180, 250)
            .bold(),
        prompt_suffix: style(":".to_string()).for_stderr().black().bright(),
        ..dialoguer::theme::ColorfulTheme::default()
    }
}

/// Ctrl-C 落在 dialoguer 输入上时(其读取期间 ISIG 关闭,不产生信号)会返回 Interrupted;
/// 这里统一映射成「干净退出 130」,与 raw / spinner 阶段的 Ctrl-C 行为一致。
fn prompt_or_exit<T>(r: dialoguer::Result<T>) -> Result<T> {
    match r {
        Ok(v) => Ok(v),
        Err(dialoguer::Error::IO(e)) if e.kind() == std::io::ErrorKind::Interrupted => {
            eprintln!();
            std::process::exit(130);
        }
        Err(e) => Err(e.into()),
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

/// 单行原地刷新器 + 后台蓝色 spinner:
/// tty 上 `progress` 会拉起一条独立动画线程(固定 ~80ms 一帧),即便主线程正卡在取码 / 等待里,
/// spinner 也照转不误、绝不冻结;`finish` 停转并定格结果行,`clear` 停转并擦除。
/// 非 tty 退化为逐行打印(每个状态各占一行、便于日志留痕,且不含控制字节 / spinner 刷屏)。
struct StatusLine {
    tty: bool,
    state: Arc<Mutex<SpinnerState>>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

struct SpinnerState {
    msg: String,
    done: bool,
}

impl StatusLine {
    fn new() -> Self {
        StatusLine {
            tty: std::io::stderr().is_terminal(),
            state: Arc::new(Mutex::new(SpinnerState { msg: String::new(), done: false })),
            handle: Mutex::new(None),
        }
    }

    /// 刷成一条「进行中」的行:tty 上首次调用拉起后台 spinner 线程、其后仅更新文案(线程自转);
    /// 非 tty 逐行打印。spinner 字形取加粗蓝、文案留默认色,前缀与 ✔/✘ 同宽对齐。
    fn progress(&self, text: &str) {
        if !self.tty {
            eprintln!("{text}");
            return;
        }
        {
            let mut s = self.state.lock().unwrap();
            s.msg = text.trim_start().to_string(); // 去掉旧的两空格 logo 位,交给 spinner 字形占位
            s.done = false;
        }
        let mut h = self.handle.lock().unwrap();
        if h.is_none() {
            let shared = self.state.clone();
            *h = Some(thread::spawn(move || {
                let mut frame = 0usize;
                loop {
                    {
                        let s = shared.lock().unwrap();
                        if s.done {
                            break;
                        }
                        let mut e = std::io::stderr();
                        let _ = write!(
                            e,
                            "\r\x1b[2K{}{}{} {}",
                            capsule::ANSI_BOLD_BLUE,
                            spinner_frame(frame),
                            capsule::ANSI_RESET,
                            s.msg
                        );
                        let _ = e.flush();
                    }
                    frame += 1;
                    thread::sleep(std::time::Duration::from_millis(80));
                }
            }));
        }
    }

    /// 停转后台 spinner 并等它退出(未启动则无操作)。
    fn stop(&self) {
        {
            let mut s = self.state.lock().unwrap();
            s.done = true;
        }
        if let Some(h) = self.handle.lock().unwrap().take() {
            let _ = h.join();
        }
    }

    /// 定格一条最终结果行:停转 spinner,覆盖掉进行中的行并换行。
    fn finish(&self, text: &str) {
        self.stop();
        if self.tty {
            eprintln!("\r\x1b[2K{text}");
        } else {
            eprintln!("{text}");
        }
    }

    /// 只擦掉进行中的行、不打印新内容(tty):先停转 spinner 再清行,供「结果行走 stdout」场景。
    fn clear(&self) {
        self.stop();
        if self.tty {
            eprint!("\r\x1b[2K");
            let _ = std::io::stderr().flush();
        }
    }
}

impl Drop for StatusLine {
    fn drop(&mut self) {
        // 漏调 finish/clear(如错误向上传播)时,确保后台线程停下,别在后续输出上继续刷屏。
        self.stop();
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
    let theme = ep_theme();
    for attempt in 1..=MANUAL_ATTEMPTS {
        let code: String = prompt_or_exit(
            dialoguer::Input::with_theme(&theme)
                .with_prompt("短信验证码")
                .validate_with(|s: &String| -> Result<(), &str> {
                    if s.trim().chars().all(|c| c.is_ascii_digit())
                        && (4..=8).contains(&s.trim().len())
                    {
                        Ok(())
                    } else {
                        Err("应为 4-8 位数字")
                    }
                })
                .interact_text(),
        )?;
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
    // 进入交互(密码 / 取码含 raw 模式)前装好 Ctrl-C 处理:全程可即时干净退出、不残留终端状态。
    install_sigint_handler();
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
                let status = runtime_capsule(&st);
                if status.state == ConnState::Online {
                    println!("{}", success_line("已经在连接中", Some(&status), &cfg.prompt));
                } else {
                    // phase=Online 但实测隧道不通:看门狗将自动恢复,不由本次 connect 接管(省一次短信)
                    println!(
                        "{}",
                        info_line("隧道恢复中(看门狗将自动重连)", Some(&status), &cfg.prompt)
                    );
                }
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
                let p = prompt_or_exit(
                    dialoguer::Password::with_theme(&ep_theme())
                        .with_prompt(format!("VPN 密码（{}）", cfg.username))
                        .interact(),
                )?;
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
        .map(|st| runtime_capsule(&st));
    line.clear(); // 无论成功失败，先清掉进度行，别让后续输出黏在「连接中…」后面
    let status = ready?;
    println!("{}", success_line("已连接", Some(&status), &cfg.prompt));
    Ok(())
}

fn cmd_disconnect(paths: &Paths, cfg: &AppConfig) -> Result<()> {
    tunnel::stop_daemon(paths);
    // 供 zsh wrapper eval：清掉当前终端代理环境变量
    println!("unset http_proxy https_proxy all_proxy no_proxy");
    let status = ProxyStatus { state: ConnState::Offline, delay: Delay::Hidden, port: None };
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

/// proxy_name 被设为非 easy 的其他非空值时,说明当前终端已被别的代理工具接管,
/// easy-proxy 不应干预,返回该占用值。不存在、为空、或等于 easy 时返回 None(允许操作)。
fn foreign_proxy_name() -> Option<String> {
    let val = std::env::var_os("proxy_name")?;
    match val.to_str() {
        Some("") | Some("easy") => None,
        Some(other) => Some(other.to_string()),
        None => Some("<非文本值>".to_string()),
    }
}

fn cmd_start(paths: &Paths, cfg: &AppConfig) -> Result<()> {
    if let Some(name) = foreign_proxy_name() {
        emit_shell_error(&format!("proxy_name 当前为 {name}，非 easy，拒绝操作"), cfg);
        return Ok(());
    }
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
    if let Some(name) = foreign_proxy_name() {
        emit_shell_error(&format!("proxy_name 当前为 {name}，非 easy，拒绝操作"), cfg);
        return Ok(());
    }
    println!("unset http_proxy https_proxy all_proxy no_proxy CORP_PROXY proxy_name");
    // 不带状态胶囊:stop 只清当前终端的环境变量,daemon 仍在运行,显示 offline 会误导
    println!(
        "echo {}",
        shell_single_quote(&success_line("命令行代理已关闭", None, &cfg.prompt))
    );
    Ok(())
}

fn cmd_restart(paths: &Paths, cfg: &AppConfig) -> Result<()> {
    if let Some(name) = foreign_proxy_name() {
        emit_shell_error(&format!("proxy_name 当前为 {name}，非 easy，拒绝操作"), cfg);
        return Ok(());
    }
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
    println!("export CORP_PROXY=http://127.0.0.1:{port}");
    println!("export proxy_name=easy");
    let status = ProxyStatus { state: ConnState::Online, delay: Delay::Hidden, port: Some(port) };
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
    // 三态:online(探针通,带延迟) / reconnecting(phase 已是重连、或 phase=Online 但实测不通) / offline
    let status = match paths.read_state().filter(|s| tunnel::pid_alive(s.daemon_pid)) {
        Some(st) => runtime_capsule(&st),
        None => ProxyStatus { state: ConnState::Offline, delay: Delay::Hidden, port: None },
    };
    println!("{}", format_capsule(&status, &cfg.prompt, terminal_width(), 0));
    Ok(())
}

/// 胶囊显示决策(纯函数):phase=Online 且探针通 → online+延迟;phase=Online 但探针不通 →
/// reconnecting(看门狗还没攒够失败阈值,抢先如实反映「不可用但会自愈」,不显示延迟段);
/// phase=Reconnecting → reconnecting。reconnecting 一律隐藏延迟段、保留端口段。
fn capsule_from(phase: config::Phase, probe: Delay, port: u16) -> ProxyStatus {
    match (phase, probe) {
        (config::Phase::Online, Delay::Timeout) | (config::Phase::Reconnecting, _) => ProxyStatus {
            state: ConnState::Reconnecting,
            delay: Delay::Hidden,
            port: Some(port),
        },
        (config::Phase::Online, delay) => ProxyStatus {
            state: ConnState::Online,
            delay,
            port: Some(port),
        },
    }
}

/// 依据运行时状态合成胶囊:Online 才实测探针(单次快速),Reconnecting 直接出黄胶囊、零等待。
fn runtime_capsule(st: &config::RuntimeState) -> ProxyStatus {
    let probe = if st.phase == config::Phase::Online {
        tunnel::probe_state_latency(st)
    } else {
        Delay::Hidden
    };
    capsule_from(st.phase, probe, st.port)
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

    #[test]
    fn spinner_frame_cycles() {
        assert_eq!(spinner_frame(0), SPINNER_FRAMES[0]);
        assert_eq!(spinner_frame(10), SPINNER_FRAMES[0]);
        assert_eq!(spinner_frame(11), SPINNER_FRAMES[1]);
    }

    #[test]
    fn progress_logo_aligns_with_result_markers() {
        // spinner 字形与输入 logo `›` 必须与 ✔/✘ 同宽(单字宽 + 空格 = 2 列),保证左边缘对齐。
        for f in SPINNER_FRAMES {
            assert_eq!(capsule::display_width(&format!("{f} ")), 2, "帧 {f} 不是单字宽");
        }
        assert_eq!(capsule::display_width("› "), 2);
        assert_eq!(capsule::display_width("✔ "), 2);
        assert_eq!(capsule::display_width("✘ "), 2);
    }

    #[test]
    fn capsule_online_with_probe_alive_shows_delay() {
        let c = capsule_from(config::Phase::Online, Delay::Value(42), 7899);
        assert_eq!(c.state, ConnState::Online);
        assert_eq!(c.delay, Delay::Value(42));
        assert_eq!(c.port, Some(7899));
    }

    #[test]
    fn capsule_online_but_probe_dead_shows_reconnecting_without_delay() {
        // 切网后、看门狗未达阈值:phase 仍 Online 但探针 timeout → 黄胶囊,无延迟段
        let c = capsule_from(config::Phase::Online, Delay::Timeout, 7899);
        assert_eq!(c.state, ConnState::Reconnecting);
        assert_eq!(c.delay, Delay::Hidden);
        assert_eq!(c.port, Some(7899));
    }

    #[test]
    fn capsule_reconnecting_phase_never_shows_delay() {
        let c = capsule_from(config::Phase::Reconnecting, Delay::Value(10), 7899);
        assert_eq!(c.state, ConnState::Reconnecting);
        assert_eq!(c.delay, Delay::Hidden);
    }
}

