//! TUN 透明模式:root helper 的常量/脚本内容/调用封装,与护栏解析纯函数。
//!
//! 安全模型见 spec §5:sudoers 只 NOPASSWD 授权固定路径的 ep-tun-helper,
//! helper 只认白名单子命令、参数正则校验,zju-connect 命令行由 helper 自己拼。
//! 路径全部编译期固定——可配置即提权洞。

use crate::config::Paths;
use anyhow::{anyhow, Result};

pub const HELPER_DIR: &str = "/usr/local/libexec/easy-proxy";
pub const HELPER_PATH: &str = "/usr/local/libexec/easy-proxy/ep-tun-helper";
pub const ROOT_ZJU_PATH: &str = "/usr/local/libexec/easy-proxy/zju-connect";
pub const SUDOERS_PATH: &str = "/etc/sudoers.d/easy-proxy";

/// root helper 脚本全文(install --tun 释放到 HELPER_PATH,root:wheel 0755)。
pub const HELPER_SCRIPT: &str = r##"#!/bin/sh
# ep-tun-helper — easy-proxy TUN 模式 root helper(由 easy-proxy install --tun 安装)
# sudoers NOPASSWD 的唯一授权入口:子命令白名单 + 参数正则校验;
# zju-connect 命令行由本脚本固定拼装,外部只能填值、不能注入 flag。
set -eu

DIR="/usr/local/libexec/easy-proxy"
ZJU="$DIR/zju-connect"
PIDFILE="/var/run/easy-proxy-tun.pid"
RESOLVER_DIR="/etc/resolver"
MARKER="# managed by easy-proxy"

die() { echo "ep-tun-helper: $*" >&2; exit 1; }
match() { printf '%s' "$1" | grep -Eq "$2"; }

[ "$(id -u)" = "0" ] || die "需要 root(应经 sudo 调用)"

# 按 pidfile 停隧道:校验 pid 的可执行路径确为 root copy,防 pid 复用误杀
stop_tunnel() {
  [ -f "$PIDFILE" ] || return 0
  pid=$(cat "$PIDFILE" 2>/dev/null || true)
  if match "${pid:-}" '^[0-9]+$'; then
    comm=$(ps -p "$pid" -o comm= 2>/dev/null || true)
    if [ "$comm" = "$ZJU" ]; then
      kill "$pid" 2>/dev/null || true
      i=0
      while [ "$i" -lt 50 ] && kill -0 "$pid" 2>/dev/null; do sleep 0.1; i=$((i+1)); done
      if kill -0 "$pid" 2>/dev/null; then kill -9 "$pid" 2>/dev/null || true; fi
    fi
  fi
  rm -f "$PIDFILE"
}

dns_clean() {
  [ -d "$RESOLVER_DIR" ] || return 0
  for f in "$RESOLVER_DIR"/*; do
    [ -f "$f" ] || continue
    if [ "$(head -n 1 "$f" 2>/dev/null)" = "$MARKER" ]; then rm -f "$f"; fi
  done
  return 0
}

cmd="${1:-}"
if [ $# -gt 0 ]; then shift; fi

case "$cmd" in
  start-tunnel)
    server=""; https_port=""; twfid=""; socks=""; http=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --server)     server="$2";     shift 2 ;;
        --https-port) https_port="$2"; shift 2 ;;
        --twfid)      twfid="$2";      shift 2 ;;
        --socks)      socks="$2";      shift 2 ;;
        --http)       http="$2";       shift 2 ;;
        *) die "未知参数: $1" ;;
      esac
    done
    match "$server" '^[A-Za-z0-9.-]+$'        || die "server 非法"
    match "$https_port" '^[0-9]+$'            || die "https-port 非法"
    match "$twfid" '^[A-Za-z0-9]+$'           || die "twfid 非法"
    match "$socks" '^127\.0\.0\.1:[0-9]+$'    || die "socks 非法"
    match "$http" '^127\.0\.0\.1:[0-9]+$'     || die "http 非法"
    stop_tunnel
    echo "$$" > "$PIDFILE"
    # exec 不换 pid,pidfile 即隧道进程;stdout/stderr 继承调用方 fd(tunnel.log)
    exec "$ZJU" -server "$server" -port "$https_port" -twf-id "$twfid" \
      -tun-mode -add-route \
      -disable-zju-config -skip-domain-resource -zju-dns-server auto -disable-multi-line \
      -socks-bind "$socks" -http-bind "$http"
    ;;
  stop-tunnel)
    stop_tunnel
    ;;
  dns-sync)
    [ $# -gt 0 ] || die "dns-sync 需要至少一个 suffix=ip"
    mkdir -p "$RESOLVER_DIR"
    keep=" "
    for pair in "$@"; do
      suffix="${pair%%=*}"; ip="${pair#*=}"
      match "$suffix" '^[a-z0-9.-]+$' || die "suffix 非法: $suffix"
      case "$suffix" in *..*|.*) die "suffix 非法: $suffix" ;; esac
      match "$ip" '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || die "ip 非法: $ip"
      printf '%s\nnameserver %s\n' "$MARKER" "$ip" > "$RESOLVER_DIR/$suffix"
      keep="$keep$suffix "
    done
    # 同步语义:删掉带标记但不在本次列表中的旧文件
    for f in "$RESOLVER_DIR"/*; do
      [ -f "$f" ] || continue
      [ "$(head -n 1 "$f" 2>/dev/null)" = "$MARKER" ] || continue
      name=$(basename "$f")
      case "$keep" in *" $name "*) ;; *) rm -f "$f" ;; esac
    done
    ;;
  dns-clean)
    dns_clean
    ;;
  janitor)
    dns_clean
    # 只杀可执行路径 == root copy 的孤儿隧道,绝不误伤用户态 zju-connect
    pids=$(ps -axo pid=,comm= | awk -v z="$ZJU" '$2==z {print $1}' || true)
    for p in $pids; do kill "$p" 2>/dev/null || true; done
    rm -f "$PIDFILE"
    ;;
  *)
    die "未知子命令: ${cmd:-<空>}"
    ;;
esac
"##;

/// server 白名单:域名/IP 字符集(与 helper 内正则一致)。
pub fn valid_server(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// twfid 白名单:纯字母数字(与 helper 内正则一致)。
pub fn valid_twfid(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// resolver 后缀白名单:小写字母数字点横线,禁 `..` 与前导点(防路径穿越)。
pub fn valid_suffix(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !s.contains("..")
        && !s.starts_with('.')
}

pub fn valid_ipv4(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok()
}

/// socks/http 监听地址白名单:必须 127.0.0.1:端口。
pub fn valid_bind(s: &str) -> bool {
    match s.strip_prefix("127.0.0.1:") {
        Some(port) => !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// daemon 调 helper start-tunnel 前的整体预校验(helper 内还有同规则的最终校验)。
pub fn validate_serve(server: &str, twfid: &str, socks: &str, http: &str) -> Result<()> {
    if !valid_server(server) {
        return Err(anyhow!("server 含非法字符: {server}"));
    }
    if !valid_twfid(twfid) {
        return Err(anyhow!("twfid 含非法字符"));
    }
    if !valid_bind(socks) || !valid_bind(http) {
        return Err(anyhow!("socks/http 监听地址非法(须为 127.0.0.1:端口)"));
    }
    Ok(())
}

/// 启动护栏 a:tunnel.log 中服务端下发路由条数(0 = 服务端未下发 ipSet,TUN 不可用)。
pub fn count_add_route(log: &str) -> usize {
    log.lines().filter(|l| l.contains("Add route to")).count()
}

/// 启动护栏 b:`route -n get default` 输出的 interface 是否 utun*(是则违反分流不变量)。
pub fn default_route_is_utun(route_get_output: &str) -> bool {
    route_get_output
        .lines()
        .filter_map(|l| l.trim().strip_prefix("interface:"))
        .any(|v| v.trim().starts_with("utun"))
}

/// 组一条 `sudo -n <helper> <args...>` 命令(-n:免密不可用立即失败,绝不挂在密码提示上)。
pub fn sudo_helper(args: &[&str]) -> std::process::Command {
    let mut cmd = std::process::Command::new("/usr/bin/sudo");
    cmd.arg("-n").arg(HELPER_PATH);
    cmd.args(args);
    cmd
}

/// 同步跑一次 janitor(清残留 resolver/孤儿 root 隧道/pidfile)。
pub fn janitor() -> Result<()> {
    let out = sudo_helper(&["janitor"]).output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "janitor 失败: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// TUN 组件就绪状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// helper 内容一致 + sudoers 存在 + root copy 与用户态 zju-connect 大小一致
    Ready,
    /// helper 与 sudoers 均不存在(全新机器)
    NotInstalled,
    /// 装过但内容/版本不一致(easy-proxy 升级后未重跑 install --tun 等)
    Stale,
}

/// 检查 TUN 组件是否就绪(不动系统,只读)。
pub fn check_ready(paths: &Paths) -> Readiness {
    let helper_exists = std::path::Path::new(HELPER_PATH).exists();
    let sudoers_exists = std::path::Path::new(SUDOERS_PATH).exists();
    if !helper_exists && !sudoers_exists {
        return Readiness::NotInstalled;
    }
    let helper_ok = std::fs::read_to_string(HELPER_PATH)
        .map(|s| s == HELPER_SCRIPT)
        .unwrap_or(false);
    let zju_ok = match (std::fs::metadata(ROOT_ZJU_PATH), std::fs::metadata(&paths.zju_bin)) {
        (Ok(root), Ok(user)) => root.len() == user.len(),
        _ => false,
    };
    if helper_ok && sudoers_exists && zju_ok {
        Readiness::Ready
    } else {
        Readiness::Stale
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_twfid_bind_whitelists() {
        assert!(valid_server("vpn.example.com"));
        assert!(!valid_server("v;rm -rf /"));
        assert!(!valid_server(""));
        assert!(valid_twfid("abcDEF123"));
        assert!(!valid_twfid("a b"));
        assert!(!valid_twfid("-tun-mode")); // flag 注入样本
        assert!(valid_bind("127.0.0.1:1080"));
        assert!(!valid_bind("0.0.0.0:1080"));
        assert!(!valid_bind("127.0.0.1:1080 -x"));
    }

    #[test]
    fn suffix_and_ip_whitelists() {
        assert!(valid_suffix("corp.example.com"));
        assert!(!valid_suffix("Corp.Example.com")); // 大写不收
        assert!(!valid_suffix("a/b"));
        assert!(!valid_suffix("..")); // 路径穿越样本
        assert!(!valid_suffix(".hidden"));
        assert!(!valid_suffix("a..b"));
        assert!(valid_ipv4("10.0.104.104"));
        assert!(!valid_ipv4("10.0.104"));
        assert!(!valid_ipv4("evil"));
    }

    #[test]
    fn validate_serve_rejects_injection() {
        assert!(validate_serve("vpn.example.com", "abc123", "127.0.0.1:1080", "127.0.0.1:1081").is_ok());
        assert!(validate_serve("vpn.example.com", "x; reboot", "127.0.0.1:1080", "127.0.0.1:1081").is_err());
    }

    #[test]
    fn count_add_route_from_real_log_shape() {
        let log = "2026/07/27 10:00:01 Add route to 10.0.0.0/8\n\
                   2026/07/27 10:00:01 Add route to 172.16.0.0/12\n\
                   2026/07/27 10:00:02 SOCKS5 server listening on 127.0.0.1:1080\n";
        assert_eq!(count_add_route(log), 2);
        assert_eq!(count_add_route("no routes here"), 0);
    }

    #[test]
    fn default_route_utun_detection() {
        let utun = "   route to: default\ndestination: default\n  interface: utun6\n";
        let wifi = "   route to: default\ndestination: default\n  interface: en0\n";
        assert!(default_route_is_utun(utun));
        assert!(!default_route_is_utun(wifi));
        assert!(!default_route_is_utun("")); // 拿不到输出不误报
    }

    #[test]
    fn helper_script_invariants() {
        // 安全不变量静态自检:绝不启用 dns-hijack;标记/pidfile/root copy 路径一致;白名单存在
        assert!(!HELPER_SCRIPT.contains("dns-hijack"));
        assert!(HELPER_SCRIPT.contains("-tun-mode"));
        assert!(HELPER_SCRIPT.contains("-add-route"));
        assert!(HELPER_SCRIPT.contains("# managed by easy-proxy"));
        assert!(HELPER_SCRIPT.contains("/var/run/easy-proxy-tun.pid"));
        // root copy 路径由 DIR + 文件名拼成,两个组成部分都必须与常量一致
        assert!(HELPER_SCRIPT.contains(&format!("DIR=\"{HELPER_DIR}\"")));
        assert!(HELPER_SCRIPT.contains("ZJU=\"$DIR/zju-connect\""));
        assert!(ROOT_ZJU_PATH.starts_with(HELPER_DIR));
        assert!(HELPER_SCRIPT.starts_with("#!/bin/sh"));
        assert!(HELPER_SCRIPT.contains("set -eu"));
    }
}
