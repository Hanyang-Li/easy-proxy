use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// 状态胶囊里各段的图标（Nerd Font 私有区字形）。
#[derive(Debug, Clone, Deserialize)]
pub struct PromptConfig {
    pub online_icon: Option<String>,
    pub offline_icon: Option<String>,
    pub delay_icon: Option<String>,
    pub port_icon: Option<String>,
}

impl Default for PromptConfig {
    fn default() -> Self {
        Self {
            online_icon: Some("󰌘".to_string()),   // link
            offline_icon: Some("󰌙".to_string()),  // link-off
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
    pub fn delay(&self) -> &str {
        self.delay_icon.as_deref().unwrap_or("󱎫")
    }
    pub fn port(&self) -> &str {
        self.port_icon.as_deref().unwrap_or("󰤨")
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
    /// 自动取码重试次数（仅当配置了 sms_command 时生效）。默认 1：先自动取一次，
    /// 若被服务端拒，再重试 1 次（重试前等待 sms_retry_interval_secs，**不重发短信**，
    /// 只是等正确的码送达后重读），仍失败则回退手动输入。设 0 = 只自动取一次、不重试。
    #[serde(default = "default_sms_retries")]
    pub sms_retries: u32,
    /// 自动取码「重试前」的等待秒数：给正确的验证码送达 chat.db 的时间（不会重发短信）。默认 30。
    #[serde(default = "default_sms_retry_interval_secs")]
    pub sms_retry_interval_secs: u32,
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
        }
    }
}

/// 后台守护进程写、其余命令读的运行时状态。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeState {
    pub connected: bool,
    pub daemon_pid: i32,
    pub port: u16,
    pub socks_upstream: String,
    pub http_upstream: String,
    pub server: String,
    pub tunnel_ip: String,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub app_config: PathBuf,
    pub state: PathBuf,
    pub zju_bin: PathBuf,
    pub daemon_log: PathBuf,
    pub tunnel_log: PathBuf,
    pub completions_dir: PathBuf,
    pub completion_file: PathBuf,
    pub zshrc: PathBuf,
}

impl Paths {
    pub fn new() -> Result<Self> {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("无法定位 HOME"))?;
        let config_dir = home.join(".config/easy-proxy");
        Ok(Self {
            app_config: config_dir.join("config.yaml"),
            state: config_dir.join("state.json"),
            zju_bin: config_dir.join("zju-connect"),
            daemon_log: config_dir.join("daemon.log"),
            tunnel_log: config_dir.join("tunnel.log"),
            completions_dir: config_dir.join("completions"),
            completion_file: config_dir.join("completions/_easy-proxy"),
            zshrc: home.join(".zshrc"),
            config_dir,
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
        fs::create_dir_all(&self.config_dir)?;
        let tmp = self.state.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(state)?)?;
        fs::rename(&tmp, &self.state)?;
        Ok(())
    }

    pub fn clear_state(&self) {
        let _ = fs::remove_file(&self.state);
    }
}
