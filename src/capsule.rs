//! 状态胶囊渲染（powerline 风格圆角段），移植自 verge-proxy 并裁剪为 easy-proxy 的
//! online/offline · delay · port 三段。

use crate::config::PromptConfig;
use std::env;
use std::process::Command;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub const ANSI_RESET: &str = "\x1b[0m";
pub const ANSI_BOLD_GREEN: &str = "\x1b[1;38;2;166;227;161m";
pub const ANSI_BOLD_RED: &str = "\x1b[1;38;2;243;139;168m";
/// 进行中 spinner 字形 / 输入提示 logo 用的加粗蓝(#89b4fa),与 ✔/✘ 同风格同宽。
pub const ANSI_BOLD_BLUE: &str = "\x1b[1;38;2;137;180;250m";

const COLOR_ONLINE: &str = "#a6e3a1";
const COLOR_RECONNECTING: &str = "#f8dea6";
const COLOR_OFFLINE: &str = "#6c7086";
const COLOR_DELAY: &str = "#74c7ec";
const COLOR_PORT: &str = "#b4befe";
const COLOR_TEXT: &str = "#11111b";

/// 延时段显示状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delay {
    Hidden,
    Value(u64),
    Timeout,
}

/// 连接状态(胶囊第一段):online / reconnecting(daemon 活着、后台重连中) / offline。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    Online,
    Reconnecting,
    Offline,
}

/// 胶囊 port 段内容:Proxy 模式显示端口号,TUN 模式显示「tun」表明透明模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortSeg {
    Num(u16),
    Tun,
}

#[derive(Debug, Clone)]
pub struct ProxyStatus {
    pub state: ConnState,
    pub delay: Delay,
    pub port: Option<PortSeg>,
}

#[derive(Clone)]
struct Segment {
    icon: String,
    value: String,
    color: &'static str,
    width: usize,
}

impl Segment {
    fn new(icon: &str, value: String, color: &'static str) -> Self {
        let icon = normalize(icon);
        let value = normalize(&value);
        let plain = format!(" {icon} {value} ");
        Self {
            icon,
            value,
            color,
            width: prompt_width(&plain),
        }
    }

    fn fit(&self, max_width: usize) -> Self {
        if self.width <= max_width {
            return self.clone();
        }
        let empty = prompt_width("   ");
        let icon_budget = max_width.saturating_sub(empty);
        let icon = truncate(&self.icon, icon_budget);
        let fixed = prompt_width(&format!(" {icon}  "));
        let value_budget = max_width.saturating_sub(fixed);
        Self::new(&icon, truncate(&self.value, value_budget), self.color)
    }
}

fn segments(status: &ProxyStatus, prompt: &PromptConfig) -> Vec<Segment> {
    let mut out = Vec::with_capacity(3);
    match status.state {
        ConnState::Offline => {
            out.push(Segment::new(prompt.offline(), "offline".to_string(), COLOR_OFFLINE));
            return out;
        }
        ConnState::Online => {
            out.push(Segment::new(prompt.online(), "online".to_string(), COLOR_ONLINE));
        }
        ConnState::Reconnecting => {
            out.push(Segment::new(
                prompt.reconnecting(),
                "reconnecting".to_string(),
                COLOR_RECONNECTING,
            ));
        }
    }
    match status.delay {
        Delay::Hidden => {}
        Delay::Value(ms) => out.push(Segment::new(prompt.delay(), format!("{ms}ms"), COLOR_DELAY)),
        Delay::Timeout => out.push(Segment::new(prompt.delay(), "timeout".to_string(), COLOR_DELAY)),
    }
    if let Some(port) = status.port {
        let value = match port {
            PortSeg::Num(n) => n.to_string(),
            PortSeg::Tun => "tun".to_string(),
        };
        out.push(Segment::new(prompt.port(), value, COLOR_PORT));
    }
    out
}

/// 按终端宽度把段分行渲染。initial_width 是同一行已占用的宽度（例如前缀 "✔ 消息 "）。
pub fn format_capsule(
    status: &ProxyStatus,
    prompt: &PromptConfig,
    terminal_width: usize,
    initial_width: usize,
) -> String {
    let terminal_width = terminal_width.max(20);
    let mut lines: Vec<Vec<Segment>> = Vec::new();
    let mut current: Vec<Segment> = Vec::new();
    let mut current_width = initial_width;
    for segment in segments(status, prompt) {
        let segment = segment.fit(terminal_width);
        let add = if current.is_empty() {
            segment.width
        } else {
            segment.width.saturating_sub(1)
        };
        if current_width > 0 && current_width + add >= terminal_width {
            lines.push(std::mem::take(&mut current));
            current_width = 0;
        }
        let add = if current.is_empty() {
            segment.width
        } else {
            segment.width.saturating_sub(1)
        };
        current_width += add;
        current.push(segment);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
        .iter()
        .map(|line| render_line(line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_line(segments: &[Segment]) -> String {
    let mut out = String::new();
    for (i, seg) in segments.iter().enumerate() {
        if i == 0 {
            out.push_str(&ansi_fg(seg.color));
            out.push('\u{e0b6}');
        }
        out.push_str(&ansi_bg_fg(seg.color, COLOR_TEXT));
        out.push(' ');
        out.push_str(&seg.icon);
        out.push(' ');
        out.push_str(&seg.value);
        out.push(' ');
        if let Some(next) = segments.get(i + 1) {
            out.push_str(&ansi_bg_fg(next.color, seg.color));
            out.push('\u{e0b4}');
        } else {
            out.push_str(ANSI_RESET);
            out.push_str(&ansi_fg(seg.color));
            out.push('\u{e0b4}');
            out.push_str(ANSI_RESET);
        }
    }
    out
}

pub fn success_line(message: &str, status: Option<&ProxyStatus>, prompt: &PromptConfig) -> String {
    let mut out = format!("{ANSI_BOLD_GREEN}✔{ANSI_RESET} {message}");
    if let Some(status) = status {
        out.push(' ');
        out.push_str(&format_capsule(status, prompt, terminal_width(), display_width(message) + 3));
    }
    out
}

pub fn error_line(message: &str, status: Option<&ProxyStatus>, prompt: &PromptConfig) -> String {
    let mut out = format!("{ANSI_BOLD_RED}✘{ANSI_RESET} {message}");
    if let Some(status) = status {
        out.push(' ');
        out.push_str(&format_capsule(status, prompt, terminal_width(), display_width(message) + 3));
    }
    out
}

/// 中性 / 进行中 / 无对错的提示:logo 位放加粗蓝小圆点 `•`(与 `›` 同色、与 `✔ `/`✘ ` 等宽),
/// 使文案左边缘与成功 / 错误行对齐。
pub fn info_line(message: &str, status: Option<&ProxyStatus>, prompt: &PromptConfig) -> String {
    let mut out = format!("{ANSI_BOLD_BLUE}•{ANSI_RESET} {message}");
    if let Some(status) = status {
        out.push(' ');
        out.push_str(&format_capsule(status, prompt, terminal_width(), display_width(message) + 3));
    }
    out
}

fn normalize(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn prompt_width(input: &str) -> usize {
    input.chars().map(prompt_char_width).sum()
}

fn prompt_char_width(ch: char) -> usize {
    if is_private_use(ch) {
        return 2;
    }
    UnicodeWidthChar::width(ch).unwrap_or(0)
}

fn is_private_use(ch: char) -> bool {
    matches!(
        ch as u32,
        0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x100000..=0x10FFFD
    )
}

fn truncate(input: &str, max_width: usize) -> String {
    if prompt_width(input) <= max_width {
        return input.to_string();
    }
    if max_width == 0 {
        return String::new();
    }
    let marker = "…";
    let marker_width = display_width(marker);
    if max_width <= marker_width {
        return marker.to_string();
    }
    let content_width = max_width - marker_width;
    let mut out = String::new();
    let mut width = 0;
    for ch in input.chars() {
        let w = prompt_char_width(ch);
        if width + w > content_width {
            break;
        }
        out.push(ch);
        width += w;
    }
    out.push_str(marker);
    out
}

fn ansi_bg_fg(bg: &str, fg: &str) -> String {
    let (br, bg2, bb) = hex_to_rgb(bg).unwrap_or((49, 50, 68));
    let (fr, fg2, fb) = hex_to_rgb(fg).unwrap_or((17, 17, 27));
    format!("\x1b[48;2;{br};{bg2};{bb}m\x1b[38;2;{fr};{fg2};{fb}m")
}

fn ansi_fg(fg: &str) -> String {
    let (r, g, b) = hex_to_rgb(fg).unwrap_or((205, 214, 244));
    format!("\x1b[38;2;{r};{g};{b}m")
}

fn hex_to_rgb(input: &str) -> Option<(u8, u8, u8)> {
    let input = input.strip_prefix('#').unwrap_or(input);
    if input.len() != 6 {
        return None;
    }
    Some((
        u8::from_str_radix(&input[0..2], 16).ok()?,
        u8::from_str_radix(&input[2..4], 16).ok()?,
        u8::from_str_radix(&input[4..6], 16).ok()?,
    ))
}

pub fn display_width(input: &str) -> usize {
    UnicodeWidthStr::width(input)
}

pub fn terminal_width() -> usize {
    env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .or_else(|| {
            Command::new("tput")
                .arg("cols")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<usize>().ok())
        })
        .unwrap_or(80)
}

pub fn shell_single_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logo_slot_widths_align() {
        // ✔/✘ 前缀与中性圆点前缀显示宽度一致,保证三类提示文案左边缘对齐
        assert_eq!(display_width("✔ "), 2);
        assert_eq!(display_width("✘ "), 2);
        assert_eq!(display_width("• "), 2);
    }

    #[test]
    fn info_line_uses_blue_dot_logo() {
        let p = PromptConfig::default();
        assert_eq!(info_line("连接中…", None, &p), format!("{ANSI_BOLD_BLUE}•{ANSI_RESET} 连接中…"));
    }

    #[test]
    fn tun_port_segment_renders_tun() {
        let p = PromptConfig::default();
        let st = ProxyStatus {
            state: ConnState::Online,
            delay: Delay::Value(12),
            port: Some(PortSeg::Tun),
        };
        let segs = segments(&st, &p);
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[2].value, "tun");
    }

    #[test]
    fn reconnecting_state_renders_yellow_first_segment() {
        let p = PromptConfig::default();
        let st = ProxyStatus {
            state: ConnState::Reconnecting,
            delay: Delay::Hidden,
            port: Some(PortSeg::Num(7899)),
        };
        let segs = segments(&st, &p);
        assert_eq!(segs[0].value, "reconnecting");
        assert_eq!(segs[0].color, "#f8dea6");
        // 端口段保留(daemon 还活着),延迟段隐藏
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[1].value, "7899");
    }

    #[test]
    fn online_and_offline_states_unchanged() {
        let p = PromptConfig::default();
        let on = segments(
            &ProxyStatus { state: ConnState::Online, delay: Delay::Value(42), port: Some(PortSeg::Num(7899)) },
            &p,
        );
        assert_eq!(on[0].value, "online");
        assert_eq!(on.len(), 3);
        let off = segments(
            &ProxyStatus { state: ConnState::Offline, delay: Delay::Hidden, port: None },
            &p,
        );
        assert_eq!(off[0].value, "offline");
        assert_eq!(off.len(), 1);
    }
}
