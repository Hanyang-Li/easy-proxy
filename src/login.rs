//! 深信服 EasyConnect 门户纯 HTTP 登录（无浏览器）。
//! 流程: login_auth → psw_config(拿 RSA/CSRF) → RSA(password_csrf) → login_psw
//!       → login_sms(触发短信) → login_sms1(提交验证码) → 认证后的 TWFID。
//! 对外拆成三步：login_password / resend_sms / submit_sms，重试主循环交由调用方编排。
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

/// login_password 的结果。SmsSent：密码/RSA 通过、网关已下发短信（附掩码手机号，可能为空）；
/// PasswordRejected：凭据被拒（发生在短信之前、未消耗验证码），调用方应重新索取密码后重试。
pub enum PwOutcome {
    SmsSent { phone: String },
    PasswordRejected(String),
}

/// submit_sms 的结果。Accepted：验证码通过，携带可直接喂给 zju-connect 的 TWFID；
/// Rejected：验证码被服务端拒，携带原因（调用方决定重取还是回退手动）。
pub enum SmsOutcome {
    Accepted(String),
    Rejected(String),
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

/// 步骤 1-5：login_auth → psw_config → RSA → login_psw → login_sms。
/// 密码/RSA 通过时网关**即下发短信**；返回掩码手机号（可能为空）。密码被拒则未消耗短信。
pub fn login_password(
    server: &str,
    port: u16,
    username: &str,
    password: &str,
    jar: &Path,
) -> Result<PwOutcome> {
    let base = format!("https://{server}:{port}");
    match pre_sms(&base, username, password, jar)? {
        PreSms::Rejected(msg) => return Ok(PwOutcome::PasswordRejected(msg)),
        PreSms::Ready => {}
    }
    // 5. login_sms：触发/确认短信下发；顺便解析掩码手机号（供中文提示）
    let phone = parse_phone(&curl_post(&base, "/por/login_sms.csp?apiversion=1", &[], jar)?);
    Ok(PwOutcome::SmsSent { phone })
}

/// 重发短信：再触发一次 login_sms.csp 下发（用于「取码没取到、需要一条新码」）。
pub fn resend_sms(server: &str, port: u16, jar: &Path) -> Result<()> {
    let base = format!("https://{server}:{port}");
    curl_post(&base, "/por/login_sms.csp?apiversion=1", &[], jar).map(|_| ())
}

/// 提交一个验证码（login_sms1）。只提交、**绝不触发短信下发**。
/// Accepted 携带 TWFID；Rejected 携带服务端给的原因。
pub fn submit_sms(server: &str, port: u16, jar: &Path, code: &str) -> Result<SmsOutcome> {
    let base = format!("https://{server}:{port}");
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
        Ok(SmsOutcome::Accepted(twfid.to_lowercase()))
    } else {
        let why = find(&resp, r"<Message><!\[CDATA\[(.*?)\]\]></Message>")
            .unwrap_or_else(|| "验证码校验失败".to_string());
        Ok(SmsOutcome::Rejected(why))
    }
}

/// 从 login_sms 响应里抓掩码手机号：T_SMSINFOR 通常已掩码，兜底看 USER_PHONE。
fn parse_phone(sms_resp: &str) -> String {
    find(sms_resp, r"<T_SMSINFOR>(.*?)</T_SMSINFOR>")
        .and_then(|s| extract_phone(&s))
        .or_else(|| find(sms_resp, r"<USER_PHONE><!\[CDATA\[(.*?)\]\]></USER_PHONE>"))
        .or_else(|| find(sms_resp, r"<USER_PHONE>(.*?)</USER_PHONE>"))
        .map(|p| mask_phone(&p))
        .unwrap_or_default()
}

fn rsa_encrypt(key_hex: &str, exp: u64, plaintext: &str) -> Result<String> {
    let n = BigUint::from_bytes_be(&hex::decode(key_hex)?);
    let e = BigUint::from(exp);
    let key = RsaPublicKey::new(n, e)?;
    let mut rng = rand::thread_rng();
    let ct = key.encrypt(&mut rng, Pkcs1v15Encrypt, plaintext.as_bytes())?;
    Ok(hex::encode(ct))
}

/// 从文本里抓取手机号片段（连续的数字或含掩码星号，长度≥7）。
fn extract_phone(s: &str) -> Option<String> {
    find(s, r"([0-9][0-9*]{6,})")
}

/// 完整 11 位手机号(1[0-9]{10})掩去中间四位；已含掩码或其他格式原样返回。
fn mask_phone(s: &str) -> String {
    let s = s.trim();
    if s.contains('*') {
        return s.to_string();
    }
    if Regex::new(r"^1[0-9]{10}$").unwrap().is_match(s) {
        format!("{}****{}", &s[0..3], &s[7..11])
    } else {
        s.to_string()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_full_cn_mobile() {
        assert_eq!(mask_phone("13800138000"), "138****8000");
        assert_eq!(mask_phone("13912345678"), "139****5678");
    }

    #[test]
    fn mask_leaves_already_masked_and_non_phone() {
        assert_eq!(mask_phone("176****2966"), "176****2966");
        assert_eq!(mask_phone("12345"), "12345");
        assert_eq!(mask_phone("not-a-phone"), "not-a-phone");
    }

    #[test]
    fn extract_phone_from_server_text() {
        assert_eq!(
            extract_phone("The passcode has been sent to 176****2966."),
            Some("176****2966".to_string())
        );
        assert_eq!(
            extract_phone("已发送至 13912345678"),
            Some("13912345678".to_string())
        );
        assert_eq!(extract_phone("no digits here"), None);
    }
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
