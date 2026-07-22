//! 取码核心:自动取码主循环与「取码 UI」抽象。前台(tty:原地刷新+esc 取消+手动回退)
//! 与 daemon(无 tty:打日志+shutdown flag 取消)共用同一份循环逻辑,差异由 `SmsUi` 注入。

use crate::capsule::{error_line, success_line};
use crate::config::AppConfig;
use crate::login;
use anyhow::{anyhow, Result};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// 取码命令的安全上限:轮询与「往前看多久」的逻辑都在脚本里(示例脚本自行轮询约 60s),
/// 这里只作防挂死兜底——超过它仍没返回就杀掉子进程、回退。
pub const SMS_COMMAND_TIMEOUT: Duration = Duration::from_secs(90);

/// 取码结果:取到码 / 没取到(空 · 超时 · 非法输出)/ 被取消(esc 或 shutdown)。
#[derive(Debug, PartialEq)]
pub enum SmsFetch {
    Code(String),
    Empty,
    Cancelled,
}

/// 取码过程的 UI/取消注入点。前台实现走 tty(原地刷新、esc);daemon 实现走日志、shutdown flag。
pub trait SmsUi {
    /// 刷一条「进行中」的行。
    fn progress(&self, text: &str);
    /// 定格一条成功结果行。
    fn finish_ok(&self, text: &str);
    /// 定格一条失败结果行。
    fn finish_err(&self, text: &str);
    /// 是否已请求取消(前台=esc 键;daemon=shutdown flag)。
    fn is_cancelled(&self) -> bool;
    /// 可被取消打断的等待:返回 true 表示中途被取消,false 表示睡满。
    fn sleep_cancelable(&self, dur: Duration) -> bool;
    /// 进度行末尾的取消提示(前台 tty 为 " (esc 键取消)",daemon 为空)。
    fn cancel_hint(&self) -> &str {
        ""
    }
}

/// 校验取码输出:去掉首尾空白后,必须是 4–8 位纯数字,否则视作「还没取到」。
pub fn valid_sms_code(raw: &str) -> Option<String> {
    let s = raw.trim();
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) && (4..=8).contains(&s.len()) {
        Some(s.to_string())
    } else {
        None
    }
}

/// 上一轮结果决定下一轮是否补发短信:Some(true)=没取到→补发;Some(false)=被拒→不补发;None=首轮→不补发。
pub fn should_resend(prev_empty: Option<bool>) -> bool {
    matches!(prev_empty, Some(true))
}

/// 执行取码命令(`sh -c <command>`),最多等 `timeout`(防挂死兜底)。
/// 契约:脚本把 4–8 位验证码打印到 stdout 即视为取到;空 / 非数字 / 非零退出 / 超时都视作「没取到」(Empty)。
/// 期间若 `ui` 报告取消,杀掉子进程并返回 `Cancelled`。
pub fn run_sms_command(command: &str, timeout: Duration, ui: &dyn SmsUi) -> SmsFetch {
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
                if ui.is_cancelled() {
                    let _ = child.kill();
                    let _ = child.wait();
                    return SmsFetch::Cancelled;
                }
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return SmsFetch::Empty;
                }
                std::thread::sleep(Duration::from_millis(150));
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

/// 自动取码主循环:第 1..=auto_max 轮(auto_max = 1 + sms_retries),整段占屏一行原地刷新(前台)。
/// 每一轮:进下一轮前统一等待 sms_retry_interval_secs(首轮不等)——两条失败路径共用等待,
/// 唯一区别是「上一轮没取到」会先补发一次短信(被拒则不补发)。取到码就提交:
/// 通过→返回 Some(twfid);被拒→进下一轮(不补发);没取到→进下一轮(补发)。
/// 轮数耗尽 / 取消 → 定格失败行并返回 None(调用方决定回退/失败)。每次成功发码后调 on_sms_sent。
pub fn fetch_and_submit_loop(
    cfg: &AppConfig,
    jar: &Path,
    cmd: &str,
    ui: &dyn SmsUi,
    on_sms_sent: &dyn Fn(),
) -> Result<Option<String>> {
    let auto_max = 1 + cfg.sms_retries;
    let retry_wait = Duration::from_secs(cfg.sms_retry_interval_secs as u64);
    let hint = ui.cancel_hint();

    // 上一轮失败原因:None=首轮;Some(true)=没取到(下一轮前补发);Some(false)=被拒(不补发)。
    let mut prev_empty: Option<bool> = None;
    let mut cancelled = false;

    let mut round = 0u32;
    while round < auto_max {
        round += 1;
        ui.progress(&format!("  [自动] 第 {round}/{auto_max} 次取码…{hint}"));

        // 非首轮:先(按需)补发一条新码,再统一等待;等待让码送达(不因是否补发而不同)。
        if prev_empty.is_some() {
            if should_resend(prev_empty) {
                if let Err(e) = login::resend_sms(&cfg.server, cfg.port, jar) {
                    ui.finish_err(&error_line(
                        &format!("[自动] 补发短信失败：{e}，回退手动输入"),
                        None,
                        &cfg.prompt,
                    ));
                    return Ok(None);
                }
                on_sms_sent();
            }
            if ui.sleep_cancelable(retry_wait) {
                cancelled = true;
                break;
            }
        }

        match run_sms_command(cmd, SMS_COMMAND_TIMEOUT, ui) {
            SmsFetch::Cancelled => {
                cancelled = true;
                break;
            }
            SmsFetch::Empty => prev_empty = Some(true),
            SmsFetch::Code(code) => match login::submit_sms(&cfg.server, cfg.port, jar, &code)? {
                login::SmsOutcome::Accepted(twfid) => {
                    ui.finish_ok(&success_line("[自动] 验证码已通过", None, &cfg.prompt));
                    return Ok(Some(twfid));
                }
                login::SmsOutcome::Rejected(_why) => prev_empty = Some(false),
            },
        }
    }

    if cancelled {
        ui.finish_err(&error_line("[自动] 已取消自动取码，转手动输入", None, &cfg.prompt));
    } else {
        ui.finish_err(&error_line("[自动] 未取到验证码，回退手动输入", None, &cfg.prompt));
    }
    Ok(None)
}

/// daemon 侧取码 UI:进度打日志(daemon.log),取消 = shutdown flag。无 esc 提示、无手动回退。
struct DaemonUi<'a> {
    shutdown: &'a AtomicBool,
}

impl<'a> SmsUi for DaemonUi<'a> {
    fn progress(&self, t: &str) {
        eprintln!("[daemon] {t}");
    }
    fn finish_ok(&self, t: &str) {
        eprintln!("[daemon] {t}");
    }
    fn finish_err(&self, t: &str) {
        eprintln!("[daemon] {t}");
    }
    fn is_cancelled(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
    fn sleep_cancelable(&self, dur: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < dur {
            if self.shutdown.load(Ordering::Relaxed) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(120));
        }
        false
    }
}

/// daemon 无 tty 静默登录:钥匙串取密码 → login_password(发码 → 调 on_sms_sent)
/// → fetch_and_submit_loop(自动取码,取消走 shutdown flag) → twfid。
/// 无 sms_command / 无密码 / 密码被拒 / 取不到码 / 被拒到上限 → Err(调用方据此判 offline)。
pub fn silent_login(
    cfg: &AppConfig,
    jar: &Path,
    shutdown: &AtomicBool,
    on_sms_sent: &dyn Fn(),
) -> Result<String> {
    let cmd = cfg
        .sms_command
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .ok_or_else(|| anyhow!("未配置 sms_command, 无法静默重登"))?;
    let pwd = std::env::var("EASY_PROXY_PASSWORD")
        .ok()
        .or_else(|| crate::keychain::get_password(&cfg.username))
        .ok_or_else(|| anyhow!("钥匙串无密码, 无法静默重登"))?;
    match login::login_password(&cfg.server, cfg.port, &cfg.username, &pwd, jar)? {
        login::PwOutcome::PasswordRejected(m) => return Err(anyhow!("密码被拒: {m}")),
        login::PwOutcome::SmsSent { .. } => on_sms_sent(),
    }
    if shutdown.load(Ordering::Relaxed) {
        return Err(anyhow!("shutdown"));
    }
    let ui = DaemonUi { shutdown };
    match fetch_and_submit_loop(cfg, jar, cmd, &ui, on_sms_sent)? {
        Some(twfid) => Ok(twfid),
        None => Err(anyhow!("静默取码失败")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用:不取消、不打印的静默 UI。
    struct SilentUi;
    impl SmsUi for SilentUi {
        fn progress(&self, _t: &str) {}
        fn finish_ok(&self, _t: &str) {}
        fn finish_err(&self, _t: &str) {}
        fn is_cancelled(&self) -> bool {
            false
        }
        fn sleep_cancelable(&self, dur: Duration) -> bool {
            std::thread::sleep(dur);
            false
        }
    }

    #[test]
    fn should_resend_only_on_prev_empty() {
        assert_eq!(should_resend(None), false);
        assert_eq!(should_resend(Some(true)), true);
        assert_eq!(should_resend(Some(false)), false);
    }

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
        assert_eq!(valid_sms_code("123"), None);
        assert_eq!(valid_sms_code("123456789"), None);
        assert_eq!(valid_sms_code("code:123456"), None);
        assert_eq!(valid_sms_code("abcd"), None);
    }

    #[test]
    fn command_stdout_code_is_returned() {
        assert_eq!(
            run_sms_command("echo 654321", Duration::from_secs(5), &SilentUi),
            SmsFetch::Code("654321".to_string())
        );
    }

    #[test]
    fn command_no_valid_output_is_empty() {
        assert_eq!(run_sms_command("true", Duration::from_secs(5), &SilentUi), SmsFetch::Empty);
        assert_eq!(run_sms_command("exit 1", Duration::from_secs(5), &SilentUi), SmsFetch::Empty);
        assert_eq!(
            run_sms_command("echo not-a-code", Duration::from_secs(5), &SilentUi),
            SmsFetch::Empty
        );
    }

    #[test]
    fn command_timeout_kills_and_returns_empty() {
        let start = Instant::now();
        let code = run_sms_command("sleep 5; echo 123456", Duration::from_millis(300), &SilentUi);
        assert_eq!(code, SmsFetch::Empty);
        assert!(start.elapsed() < Duration::from_secs(3), "应在超时后立即返回,不等满 5s");
    }

    #[test]
    fn silent_login_without_sms_command_errs_fast() {
        let mut cfg = AppConfig::default();
        cfg.server = "127.0.0.1".into();
        cfg.username = "u".into();
        cfg.sms_command = None; // 无取码命令 → 应在碰网络前就失败
        std::env::remove_var("EASY_PROXY_PASSWORD");
        let jar = std::env::temp_dir().join(format!("ep_silent_{}.cookies", std::process::id()));
        let sd = std::sync::atomic::AtomicBool::new(false);
        let noop = || {};
        let r = silent_login(&cfg, &jar, &sd, &noop);
        assert!(r.is_err());
    }
}
