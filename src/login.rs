//! 深信服 EasyConnect 门户纯 HTTP 登录（无浏览器）。
//! 流程: login_auth → psw_config(拿 RSA/CSRF) → RSA(password_csrf) → login_psw
//!       → login_sms(触发短信) → 交互输入 → login_sms1 → 认证后的 TWFID。
//! 用 curl 维持会话 cookie，RSA 本地做。

use anyhow::{anyhow, Context, Result};
use regex::Regex;
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};
use std::path::Path;
use std::process::Command;

const UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36";

/// 登录必须直连网关，绝不能走用户已有的 clash 代理，否则受 http_proxy/no_proxy 干扰。
pub const PROXY_ENV: [&str; 10] = [
    "http_proxy", "https_proxy", "all_proxy", "no_proxy", "ftp_proxy",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY",
];

pub enum LoginOutcome {
    /// 认证成功，携带可直接喂给 zju-connect 的 TWFID。
    Ok(String),
    /// 密码被拒（发生在短信之前，未消耗验证码），调用方应重新索取密码后重试。
    PasswordRejected(String),
}

/// login_psw 的结果。Ready 表示密码/RSA 通过、服务端已下发短信；Rejected 表示凭据被拒。
enum PreSms {
    Ready,
    Rejected(String),
}

/// steps 1-4：login_auth → psw_config → RSA → login_psw。
/// 注意：本网关在 login_psw 密码通过时**就会下发短信**（不是等到 login_sms），因此这一步已消耗短信额度。
fn pre_sms(base: &str, username: &str, password: &str, jar: &Path) -> Result<PreSms> {
    let _ = std::fs::remove_file(jar);

    // 1. login_auth：建立会话，拿 TWFID cookie
    curl_get(base, "/por/login_auth.csp?apiversion=1", jar)
        .context("login_auth 请求失败（网络/证书问题？）")?;

    // 2. psw_config：RSA 公钥 + CSRF（门户实际用这里的值）
    let cfg = curl_get(base, "/public/psw_config?apiversion=1", jar)?;
    let rsa_key = find(&cfg, r"<RSA_ENCRYPT_KEY>([0-9A-Fa-f]+)</RSA_ENCRYPT_KEY>")
        .ok_or_else(|| anyhow!("psw_config 缺少 RSA_ENCRYPT_KEY"))?;
    let rsa_exp: u64 = find(&cfg, r"<RSA_ENCRYPT_EXP>(\d+)</RSA_ENCRYPT_EXP>")
        .and_then(|v| v.parse().ok())
        .unwrap_or(65537);
    let csrf = find(&cfg, r"<CSRF_RAND_CODE>(\d+)</CSRF_RAND_CODE>")
        .ok_or_else(|| anyhow!("psw_config 缺少 CSRF_RAND_CODE"))?;

    // 3. RSA 加密 password_csrf
    let enc = rsa_encrypt(&rsa_key, rsa_exp, &format!("{password}_{csrf}")).context("RSA 加密失败")?;

    // 4. login_psw
    let psw = curl_post(
        base,
        "/por/login_psw.csp?anti_replay=1&encrypt=1&apiversion=1",
        &[
            ("svpn_rand_code", ""),
            ("mitm", ""),
            ("svpn_req_randcode", &csrf),
            ("svpn_name", username),
            ("svpn_password", &enc),
        ],
        jar,
    )?;
    if psw.contains("auth/sms") || psw.contains("<Result>2</Result>") {
        Ok(PreSms::Ready)
    } else {
        let msg = find(&psw, r"<Message><!\[CDATA\[(.*?)\]\]></Message>")
            .or_else(|| find(&psw, r"<Message>(.*?)</Message>"))
            .unwrap_or_else(|| "登录被拒".to_string());
        Ok(PreSms::Rejected(msg))
    }
}

/// sms 回调入参是服务端的短信提示文案（T_SMSINFOR），返回用户输入的验证码。
pub fn login(
    server: &str,
    port: u16,
    username: &str,
    password: &str,
    jar: &Path,
    sms: &mut dyn FnMut(&str) -> Result<String>,
) -> Result<LoginOutcome> {
    let base = format!("https://{server}:{port}");
    match pre_sms(&base, username, password, jar)? {
        PreSms::Rejected(msg) => return Ok(LoginOutcome::PasswordRejected(msg)),
        PreSms::Ready => {}
    }

    // 5. login_sms：触发/确认短信下发
    let sms_resp = curl_post(&base, "/por/login_sms.csp?apiversion=1", &[], jar)?;
    let infor = find(&sms_resp, r"<T_SMSINFOR>(.*?)</T_SMSINFOR>")
        .unwrap_or_else(|| "验证码已发送".to_string());

    // 6. login_sms1：交互输入，最多 3 次
    for attempt in 1..=3 {
        let code = sms(&infor)?;
        let resp = curl_post(
            &base,
            "/por/login_sms1.csp?apiversion=1",
            &[("svpn_inputsms", code.trim())],
            jar,
        )?;
        if resp.contains("<Result>1</Result>") || resp.contains("Auth sms suc") {
            let twfid = find(&resp, r"<TwfID>([0-9a-fA-F]{16})</TwfID>")
                .or_else(|| twfid_from_jar(jar))
                .ok_or_else(|| anyhow!("认证成功但未解析到 TWFID"))?;
            return Ok(LoginOutcome::Ok(twfid.to_lowercase()));
        }
        let why = find(&resp, r"<Message><!\[CDATA\[(.*?)\]\]></Message>")
            .unwrap_or_else(|| "验证码校验失败".to_string());
        eprintln!("  验证码错误（{why}），剩余 {} 次", 3 - attempt);
    }
    Err(anyhow!("验证码连续 3 次错误"))
}

fn rsa_encrypt(key_hex: &str, exp: u64, plaintext: &str) -> Result<String> {
    let n = BigUint::from_bytes_be(&hex::decode(key_hex)?);
    let e = BigUint::from(exp);
    let key = RsaPublicKey::new(n, e)?;
    let mut rng = rand::thread_rng();
    let ct = key.encrypt(&mut rng, Pkcs1v15Encrypt, plaintext.as_bytes())?;
    Ok(hex::encode(ct))
}

fn find(haystack: &str, pattern: &str) -> Option<String> {
    Regex::new(pattern)
        .ok()?
        .captures(haystack)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

fn twfid_from_jar(jar: &Path) -> Option<String> {
    let text = std::fs::read_to_string(jar).ok()?;
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() == 7 && fields[5] == "TWFID" {
            return Some(fields[6].to_string());
        }
    }
    None
}

fn curl_base(jar: &Path) -> Command {
    let mut c = Command::new("/usr/bin/curl");
    for v in PROXY_ENV {
        c.env_remove(v);
    }
    c.args(["-sS", "--max-time", "20", "-A", UA, "-c"])
        .arg(jar)
        .arg("-b")
        .arg(jar);
    c
}

fn run_curl(mut c: Command) -> Result<String> {
    let out = c.output().context("无法执行 curl")?;
    if !out.status.success() {
        return Err(anyhow!("curl 失败: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn curl_get(base: &str, path: &str, jar: &Path) -> Result<String> {
    let mut c = curl_base(jar);
    c.arg(format!("{base}{path}"));
    run_curl(c)
}

fn curl_post(base: &str, path: &str, fields: &[(&str, &str)], jar: &Path) -> Result<String> {
    let mut c = curl_base(jar);
    if fields.is_empty() {
        c.arg("-d").arg("");
    } else {
        for (k, v) in fields {
            c.arg("--data-urlencode").arg(format!("{k}={v}"));
        }
    }
    c.arg(format!("{base}{path}"));
    run_curl(c)
}
