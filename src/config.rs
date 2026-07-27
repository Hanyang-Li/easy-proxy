use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// 状态胶囊里各段的图标（Nerd Font 私有区字形）。
#[derive(Debug, Clone, Deserialize)]
pub struct PromptConfig {
    pub online_icon: Option<String>,
    pub offline_icon: Option<String>,
    pub reconnecting_icon: Option<String>,
    pub delay_icon: Option<String>,
    pub port_icon: Option<String>,
}

impl Default for PromptConfig {
    fn default() -> Self {
        Self {
            online_icon: Some("󰌘".to_string()),   // link
            offline_icon: Some("󰌙".to_string()),  // link-off
            reconnecting_icon: Some("󰑐".to_string()), // refresh
            delay_icon: Some("󱎫".to_string()),    // 与 verge-proxy 对齐
            port_icon: Some("󰤨".to_string()),     // 与 verge-proxy 对齐
        }
    }
}

impl PromptConfig {
    pub fn online(&self) -> &str {
        self.online_icon.as_deref().unwrap_or("󰌘")
    }
    pub fn offline(&self) -> &str {
        self.offline_icon.as_deref().unwrap_or("󰌙")
    }
    pub fn reconnecting(&self) -> &str {
        self.reconnecting_icon.as_deref().unwrap_or("󰑐")
    }
    pub fn delay(&self) -> &str {
        self.delay_icon.as_deref().unwrap_or("󱎫")
    }
    pub fn port(&self) -> &str {
        self.port_icon.as_deref().unwrap_or("󰤨")
    }
}

/// TUN 透明模式配置(config.yaml `tun:` 段,整段可缺省)。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TunConfig {
    /// 内网专用域名后缀:隧道就绪后写成 /etc/resolver/<suffix> scoped resolver,
    /// nameserver 指服务端下发的 VPN DNS。默认空 = 不写任何 resolver 文件。
    #[serde(default)]
    pub dns_suffixes: Vec<String>,
}

/// 连接模式:Proxy=现有纯代理;Tun=分流透明模式(root 隧道 + scoped resolver)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    Proxy,
    Tun,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Proxy
    }
}

/// ~/.config/easy-proxy/config.yaml
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: String,
    #[serde(default = "default_https_port")]
    pub port: u16,
    pub username: String,
    #[serde(default = "default_mixed_port")]
    pub mixed_port: u16,
    #[serde(default)]
    pub prompt: PromptConfig,
    /// 可选、可插拔的自动取码命令（`sh -c` 执行）。为空/缺省则 connect 时手动输入验证码。
    /// 分工：脚本负责轮询等码、往前看多久、本地是否过期，并把 4–8 位码打到 stdout；
    /// easy-proxy 负责运行它、取回码交服务端校验，取不到/被拒到上限就回退手动输入。
    #[serde(default)]
    pub sms_command: Option<String>,
    /// 自动取码额度（仅当配置了 sms_command 时生效）。总自动取码轮数 = 1 + sms_retries，默认 1 → 共 2 轮。
    /// 两种「重取」触发：① 被服务端拒 → 等 sms_retry_interval_secs 后重读，**绝不重发短信**；
    /// ② 脚本没取到码 → **补发一次短信**（整轮登录仅一次）后立即重取（多半是短信还没到）。
    /// 额度用尽 / 按 esc 取消则回退手动输入。设 0 = 只自动取一次、不重试。
    #[serde(default = "default_sms_retries")]
    pub sms_retries: u32,
    /// 「被服务端拒后重读」前的等待秒数：给正确的验证码送达 chat.db 的时间（不会重发短信）。默认 30。
    #[serde(default = "default_sms_retry_interval_secs")]
    pub sms_retry_interval_secs: u32,
    /// 隧道健康检查周期(秒)。切网/唤醒由路由事件秒级触发探测,此节拍只是兜底心跳。
    #[serde(default = "default_healthcheck_interval")]
    pub healthcheck_interval: u64,
    /// 连续探测失败几次判定断线(躲开单次抖动)。
    #[serde(default = "default_healthcheck_fail_threshold")]
    pub healthcheck_fail_threshold: u32,
    /// 静默重登最小间隔(秒)。按上次发码时刻算,限流下一次「自动」重登;手动 connect 不受限。
    #[serde(default = "default_silent_relogin_interval")]
    pub silent_relogin_interval: u64,
    /// TUN 透明模式配置(仅 connect --tun 时使用)。
    #[serde(default)]
    pub tun: TunConfig,
}

fn default_https_port() -> u16 {
    443
}
fn default_mixed_port() -> u16 {
    7899
}
fn default_sms_retries() -> u32 {
    1
}
fn default_sms_retry_interval_secs() -> u32 {
    30
}
fn default_healthcheck_interval() -> u64 {
    60
}
fn default_healthcheck_fail_threshold() -> u32 {
    2
}
fn default_silent_relogin_interval() -> u64 {
    3600
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 443,
            username: String::new(),
            mixed_port: 7899,
            prompt: PromptConfig::default(),
            sms_command: None,
            sms_retries: 1,
            sms_retry_interval_secs: 30,
            healthcheck_interval: 60,
            healthcheck_fail_threshold: 2,
            silent_relogin_interval: 3600,
            tun: TunConfig::default(),
        }
    }
}

/// daemon 运行阶段。offline 不在此枚举内——它等价于「没有 state 文件」。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Online,
    Reconnecting,
}

impl Default for Phase {
    fn default() -> Self {
        Phase::Reconnecting
    }
}

/// SystemTime → unix 秒(用于 last_sms_sent 等时间戳)。
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 只读文件末尾 ≤max 字节(UTF-8 lossy),避免日志变大后 read_to_string 全文的内存/IO 开销。
pub fn read_tail_bytes(path: &std::path::Path, max: usize) -> String {
    let mut f = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return String::new(),
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(max as u64);
    if f.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_err() {
        return String::new();
    }
    String::from_utf8_lossy(&buf).to_string()
}

/// 后台守护进程写、其余命令读的运行时状态。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeState {
    #[serde(default)]
    pub phase: Phase,
    /// 本次连接的模式;旧 state.json 无此字段,默认 Proxy。
    #[serde(default)]
    pub mode: Mode,
    pub daemon_pid: i32,
    pub port: u16,
    pub socks_upstream: String,
    pub http_upstream: String,
    pub server: String,
    pub tunnel_ip: String,
    /// 服务端下发的 VPN DNS(穿隧道健康探针的目标);None = 探针降级为网关直连模式。
    #[serde(default)]
    pub vpn_dns: Option<String>,
    #[serde(default)]
    pub last_sms_sent: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
}

/// XDG 风味的四段布局（1.0.0）：配置 / 数据 / 运行时状态 / 缓存各归其位，都在 $HOME 下、无需 sudo。
#[derive(Debug, Clone)]
pub struct Paths {
    /// 配置目录 ~/.config/easy-proxy（只放 config.yaml）
    pub config_dir: PathBuf,
    /// 数据目录 ~/.local/share/easy-proxy（zju-connect、补全源文件、你自备的取码脚本）
    pub data_dir: PathBuf,
    /// 补全软链目录 ~/.local/share/zsh/site-functions（需在 zsh fpath 上）
    pub zsh_functions_dir: PathBuf,
    /// 运行时状态目录 ~/.local/state/easy-proxy（状态 / 日志 / 登录 cookie）
    pub state_dir: PathBuf,
    /// 缓存目录 ~/.cache/easy-proxy（可随时删的临时产物）
    pub cache_dir: PathBuf,
    pub app_config: PathBuf,
    pub zju_bin: PathBuf,
    pub completion_file: PathBuf,
    pub completion_link: PathBuf,
    pub state: PathBuf,
    pub cookies: PathBuf,
    /// 守护进程静默重登的临时 cookie jar：可丢弃，不与前台 connect 抢同一个 jar
    pub silent_cookies: PathBuf,
    pub daemon_log: PathBuf,
    pub tunnel_log: PathBuf,
    pub zshrc: PathBuf,
}

impl Paths {
    pub fn new() -> Result<Self> {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("无法定位 HOME"))?;
        let config_dir = home.join(".config/easy-proxy");
        let data_dir = home.join(".local/share/easy-proxy");
        let zsh_functions_dir = home.join(".local/share/zsh/site-functions");
        let state_dir = home.join(".local/state/easy-proxy");
        let cache_dir = home.join(".cache/easy-proxy");
        Ok(Self {
            app_config: config_dir.join("config.yaml"),
            // 程序自带资源放数据目录
            zju_bin: data_dir.join("zju-connect"),
            completion_file: data_dir.join("_easy-proxy"),
            completion_link: zsh_functions_dir.join("_easy-proxy"),
            // 运行时产物集中到 ~/.local/state/easy-proxy，不塞进配置目录
            state: state_dir.join("state.json"),
            cookies: state_dir.join(".cookies"),
            daemon_log: state_dir.join("daemon.log"),
            tunnel_log: state_dir.join("tunnel.log"),
            silent_cookies: cache_dir.join("silent.cookies"),
            zshrc: home.join(".zshrc"),
            config_dir,
            data_dir,
            zsh_functions_dir,
            state_dir,
            cache_dir,
        })
    }

    pub fn read_app_config(&self) -> Result<AppConfig> {
        let input = fs::read_to_string(&self.app_config)
            .with_context(|| format!("无法读取 {}（请先运行 easy-proxy install）", self.app_config.display()))?;
        serde_yaml::from_str(&input)
            .with_context(|| format!("无法解析 {}", self.app_config.display()))
    }

    pub fn read_state(&self) -> Option<RuntimeState> {
        let input = fs::read_to_string(&self.state).ok()?;
        serde_json::from_str(&input).ok()
    }

    pub fn write_state(&self, state: &RuntimeState) -> Result<()> {
        fs::create_dir_all(&self.state_dir)?;
        let tmp = self.state.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(state)?)?;
        fs::rename(&tmp, &self.state)?;
        Ok(())
    }

    pub fn clear_state(&self) {
        let _ = fs::remove_file(&self.state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_default_is_reconnecting() {
        assert_eq!(Phase::default(), Phase::Reconnecting);
    }

    #[test]
    fn runtime_state_roundtrip_and_legacy_compat() {
        let st = RuntimeState {
            phase: Phase::Online,
            mode: Mode::Proxy,
            daemon_pid: 42,
            port: 7899,
            socks_upstream: "127.0.0.1:1080".into(),
            http_upstream: "127.0.0.1:1081".into(),
            server: "vpn.example.com".into(),
            tunnel_ip: "10.0.0.1".into(),
            vpn_dns: Some("10.0.104.104".into()),
            last_sms_sent: Some(1000),
            error: None,
        };
        let json = serde_json::to_string(&st).unwrap();
        let back: RuntimeState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.phase, Phase::Online);
        assert_eq!(back.last_sms_sent, Some(1000));
        assert_eq!(back.vpn_dns.as_deref(), Some("10.0.104.104"));
        // 旧 0.2.x json(有 connected、无 phase/last_sms_sent/vpn_dns)应能解析,新字段落默认
        let legacy = r#"{"connected":true,"daemon_pid":1,"port":7899,"socks_upstream":"a","http_upstream":"b","server":"s","tunnel_ip":"","error":null}"#;
        let parsed: RuntimeState = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.phase, Phase::Reconnecting);
        assert_eq!(parsed.last_sms_sent, None);
        assert_eq!(parsed.vpn_dns, None);
    }

    #[test]
    fn tun_config_defaults_empty_and_parses() {
        // 整段缺省
        let c: AppConfig = serde_yaml::from_str("server: s\nusername: u\n").unwrap();
        assert!(c.tun.dns_suffixes.is_empty());
        // 显式配置
        let c: AppConfig =
            serde_yaml::from_str("server: s\nusername: u\ntun:\n  dns_suffixes: [\"a.b\"]\n").unwrap();
        assert_eq!(c.tun.dns_suffixes, vec!["a.b".to_string()]);
    }

    #[test]
    fn mode_default_is_proxy_and_legacy_state_compat() {
        assert_eq!(Mode::default(), Mode::Proxy);
        // 旧 state.json(无 mode 字段)解析后 mode 落 Proxy
        let legacy = r#"{"phase":"Online","daemon_pid":1,"port":7899,"socks_upstream":"a","http_upstream":"b","server":"s","tunnel_ip":"","error":null}"#;
        let st: RuntimeState = serde_json::from_str(legacy).unwrap();
        assert_eq!(st.mode, Mode::Proxy);
        // round-trip
        let mut st2 = st.clone();
        st2.mode = Mode::Tun;
        let back: RuntimeState = serde_json::from_str(&serde_json::to_string(&st2).unwrap()).unwrap();
        assert_eq!(back.mode, Mode::Tun);
    }

    #[test]
    fn appconfig_defaults_present() {
        let c = AppConfig::default();
        assert_eq!(c.healthcheck_interval, 60);
        assert_eq!(c.healthcheck_fail_threshold, 2);
        assert_eq!(c.silent_relogin_interval, 3600);
    }

    #[test]
    fn read_tail_bytes_returns_only_suffix() {
        let p = std::env::temp_dir().join(format!("ep_tail_test_{}.log", std::process::id()));
        std::fs::write(&p, "0123456789ABCDEF").unwrap();
        let tail = read_tail_bytes(&p, 4);
        let _ = std::fs::remove_file(&p);
        assert_eq!(tail, "CDEF");
    }

    #[test]
    fn read_tail_bytes_shorter_than_max_ok() {
        let p = std::env::temp_dir().join(format!("ep_tail_test2_{}.log", std::process::id()));
        std::fs::write(&p, "abc").unwrap();
        let tail = read_tail_bytes(&p, 100);
        let _ = std::fs::remove_file(&p);
        assert_eq!(tail, "abc");
    }

    #[test]
    fn paths_layout_config_data_state_cache() {
        let p = Paths::new().unwrap();
        // 配置只留 config.yaml
        assert!(p.app_config.ends_with(".config/easy-proxy/config.yaml"));
        // 程序资源在数据目录，补全软链在 zsh fpath 目录
        assert!(p.zju_bin.ends_with(".local/share/easy-proxy/zju-connect"));
        assert!(p.completion_file.ends_with(".local/share/easy-proxy/_easy-proxy"));
        assert!(p.completion_link.ends_with(".local/share/zsh/site-functions/_easy-proxy"));
        // 运行时产物集中到 ~/.local/state/easy-proxy
        assert!(p.state.ends_with(".local/state/easy-proxy/state.json"));
        assert!(p.cookies.ends_with(".local/state/easy-proxy/.cookies"));
        assert!(p.daemon_log.ends_with(".local/state/easy-proxy/daemon.log"));
        assert!(p.tunnel_log.ends_with(".local/state/easy-proxy/tunnel.log"));
        // 可丢弃的临时产物在缓存目录
        assert!(p.silent_cookies.ends_with(".cache/easy-proxy/silent.cookies"));
    }
}
