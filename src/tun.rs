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
EXEMPT_FILE="/var/run/easy-proxy-route-exempt"
RESOLVER_DIR="/etc/resolver"
MARKER="# managed by easy-proxy"
HOSTS_FILE="/etc/hosts"
HOSTS_MARKER="# easy-proxy-pin"

die() { echo "ep-tun-helper: $*" >&2; exit 1; }
match() { printf '%s' "$1" | grep -Eq "$2"; }

[ "$(id -u)" = "0" ] || die "需要 root(应经 sudo 调用)"

# 摘全部网关豁免主机路由(记录文件每行一个 IP),隧道停/清残留时调用
route_unexempt() {
  [ -f "$EXEMPT_FILE" ] || return 0
  while IFS= read -r ip; do
    if match "${ip:-}" '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
      /sbin/route -n delete -host "$ip" >/dev/null 2>&1 || true
    fi
  done < "$EXEMPT_FILE"
  rm -f "$EXEMPT_FILE"
}

# 钉一个网关豁免主机路由(幂等追加):到网关自身的流量必须走物理口。
# 失败只警告不致命——没有豁免时隧道仍能连上(~78s 后死,由看门狗自愈),比连不上强。
route_exempt_one() {
  ip="$1"
  gw=$(/sbin/route -n get default 2>/dev/null | awk '/gateway:/{print $2}')
  if ! match "${gw:-}" '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "ep-tun-helper: 取不到物理默认网关,跳过豁免 $ip" >&2
    return 0
  fi
  /sbin/route -n delete -host "$ip" >/dev/null 2>&1 || true
  if /sbin/route -n add -host "$ip" "$gw" >/dev/null 2>&1; then
    grep -qx "$ip" "$EXEMPT_FILE" 2>/dev/null || echo "$ip" >> "$EXEMPT_FILE"
  else
    echo "ep-tun-helper: 豁免路由添加失败: $ip -> $gw" >&2
  fi
  return 0
}

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

# 摘 /etc/hosts 里的网关域名 pin(带行尾标记的行)。cat 重定向保 inode/权限。
hosts_unpin() {
  grep -q "$HOSTS_MARKER" "$HOSTS_FILE" 2>/dev/null || return 0
  tmp="/var/run/easy-proxy-hosts.$$"
  grep -v "$HOSTS_MARKER" "$HOSTS_FILE" > "$tmp" 2>/dev/null || true
  cat "$tmp" > "$HOSTS_FILE"
  rm -f "$tmp"
  return 0
}

# dns_clean 语义 = 清掉 easy-proxy 注入的一切域名解析改动(resolver 文件 + hosts pin),
# 恢复前与退出时共用:保证网关域名解析回到系统原生路径。
dns_clean() {
  hosts_unpin
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
    server=""; https_port=""; twfid=""; socks=""; http=""; exempt_ips=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --server)     server="$2";     shift 2 ;;
        --https-port) https_port="$2"; shift 2 ;;
        --twfid)      twfid="$2";      shift 2 ;;
        --socks)      socks="$2";      shift 2 ;;
        --http)       http="$2";       shift 2 ;;
        --exempt-ips) exempt_ips="$2"; shift 2 ;;
        *) die "未知参数: $1" ;;
      esac
    done
    match "$server" '^[A-Za-z0-9.-]+$'        || die "server 非法"
    match "$https_port" '^[0-9]+$'            || die "https-port 非法"
    match "$twfid" '^[A-Za-z0-9]+$'           || die "twfid 非法"
    match "$socks" '^127\.0\.0\.1:[0-9]+$'    || die "socks 非法"
    match "$http" '^127\.0\.0\.1:[0-9]+$'     || die "http 非法"
    if [ -n "$exempt_ips" ]; then
      match "$exempt_ips" '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(,[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)*$' || die "exempt-ips 非法"
    fi
    stop_tunnel
    # 网关豁免必须在 zju-connect 启动**之前**钉好:zju 的 L3 数据连接 dial 与
    # -add-route 批量加路由是并发竞速,路由先生效时 dial 源地址被绑到 utun 虚拟 IP,
    # SYN 进自己的 TUN 黑洞,~75s 超时 panic → 隧道 78s 必死(2026-07-29 真机抓包实锤:
    # SYN_SENT 源 2.0.1.44)。先钉豁免则 dial 恒走物理口,竞态消失。
    for eip in $(printf '%s' "$exempt_ips" | tr ',' ' '); do
      route_exempt_one "$eip"
    done
    echo "$$" > "$PIDFILE"
    # exec 不换 pid,pidfile 即隧道进程;stdout/stderr 继承调用方 fd(tunnel.log)
    exec "$ZJU" -server "$server" -port "$https_port" -twf-id "$twfid" \
      -tun-mode -add-route \
      -disable-zju-config -skip-domain-resource -zju-dns-server auto -disable-multi-line \
      -socks-bind "$socks" -http-bind "$http"
    ;;
  stop-tunnel)
    stop_tunnel
    route_unexempt
    ;;
  route-exempt)
    # 就绪后按实连 IP 补钉豁免(幂等追加,不清启动前已钉的解析 IP——update_session
    # 会重新解析域名,解析出的 IP 与实连 IP 都必须保持豁免)。
    [ $# -gt 0 ] || die "route-exempt 需要至少一个 ip"
    for ip in "$@"; do
      match "$ip" '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || die "ip 非法: $ip"
      route_exempt_one "$ip"
    done
    ;;
  hosts-pin)
    # 网关域名 pin 进 /etc/hosts(实连 IP):运行期 zju 重建连接/会话保活都要重新
    # 解析网关域名,而 scoped resolver 的快照 DNS 可能解析不出它(2026-07-29 真机:
    # 豁免条目指向 114 → lookup no such host → panic)。hosts 优先于一切 DNS,连根解决。
    ip="${1:-}"; domain="${2:-}"
    match "$ip" '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || die "ip 非法"
    match "$domain" '^[A-Za-z0-9.-]+$'             || die "domain 非法"
    hosts_unpin
    printf '%s %s %s\n' "$ip" "$domain" "$HOSTS_MARKER" >> "$HOSTS_FILE"
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
    route_unexempt
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

/// 组装 dns-sync 的 `name=ip` 参数列表:各 suffix → vpn_dns。
///
/// 网关域名的解析保护不再走 resolver 豁免条目(2026-07-29 真机事故:快照 DNS
/// 114.114.114.114 解析不出网关域名,zju 运行期重建连接 lookup 失败直接 panic),
/// 改由 helper hosts-pin 把网关域名 pin 到实连 IP——hosts 优先于一切 resolver。
pub fn dns_sync_pairs(suffixes: &[&str], vpn_dns: &str) -> Vec<String> {
    suffixes.iter().map(|s| format!("{s}={vpn_dns}")).collect()
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
    fn dns_sync_pairs_maps_suffixes_to_vpn_dns() {
        // 网关域名豁免条目已废(hosts-pin 取代):pairs 只含 suffix 映射,
        // 绝不能再出现指向快照 DNS 的网关域名条目(2026-07-29 毒解析事故)
        let pairs = dns_sync_pairs(&["yangqianguan.com", "fintopia.tech"], "10.0.104.104");
        assert_eq!(
            pairs,
            vec![
                "yangqianguan.com=10.0.104.104".to_string(),
                "fintopia.tech=10.0.104.104".to_string(),
            ]
        );
    }

    #[test]
    fn dns_sync_pairs_empty_suffixes_empty() {
        assert!(dns_sync_pairs(&[], "10.0.104.104").is_empty());
    }

    #[test]
    fn helper_script_invariants() {
        // 安全不变量静态自检:绝不启用 dns-hijack;标记/pidfile/root copy 路径一致;白名单存在
        assert!(!HELPER_SCRIPT.contains("dns-hijack"));
        assert!(HELPER_SCRIPT.contains("-tun-mode"));
        assert!(HELPER_SCRIPT.contains("-add-route"));
        assert!(HELPER_SCRIPT.contains("# managed by easy-proxy"));
        assert!(HELPER_SCRIPT.contains("/var/run/easy-proxy-tun.pid"));
        // 网关豁免:route-exempt 子命令存在;stop-tunnel 与 janitor 都必须清豁免路由,
        // 否则断开后残留主机路由指向旧物理网关,切网后网关域名解析仍会走错口
        assert!(HELPER_SCRIPT.contains("route-exempt)"));
        assert!(HELPER_SCRIPT.contains("/var/run/easy-proxy-route-exempt"));
        assert!(HELPER_SCRIPT.matches("    route_unexempt").count() >= 2, "stop-tunnel/janitor 两处都应清豁免");
        // hosts pin:子命令存在;dns_clean 必须顺带清 hosts pin(恢复前/退出共用)
        assert!(HELPER_SCRIPT.contains("hosts-pin)"));
        assert!(HELPER_SCRIPT.contains("# easy-proxy-pin"));
        let dns_clean_fn = HELPER_SCRIPT.split("dns_clean() {").nth(1).and_then(|s| s.split('}').next()).expect("dns_clean 函数存在");
        assert!(dns_clean_fn.contains("hosts_unpin"), "dns_clean 必须清 hosts pin");
        // 竞态修复核心不变量:start-tunnel 必须在 exec zju 之前钉预豁免
        // (--exempt-ips 参数 + route_exempt_one 调用先于 exec 出现)
        assert!(HELPER_SCRIPT.contains("--exempt-ips"));
        // start-tunnel 分支之后,首个 route_exempt_one 调用必须先于唯一的 exec
        let after_start = HELPER_SCRIPT.split("start-tunnel)").nth(1).expect("start-tunnel 块存在");
        let exempt_pos = after_start.find("route_exempt_one").expect("start-tunnel 内有预豁免");
        let exec_pos = after_start.find("exec \"$ZJU\"").expect("start-tunnel 内有 exec");
        assert!(exempt_pos < exec_pos, "预豁免必须先于 exec zju-connect");
        // root copy 路径由 DIR + 文件名拼成,两个组成部分都必须与常量一致
        assert!(HELPER_SCRIPT.contains(&format!("DIR=\"{HELPER_DIR}\"")));
        assert!(HELPER_SCRIPT.contains("ZJU=\"$DIR/zju-connect\""));
        assert!(ROOT_ZJU_PATH.starts_with(HELPER_DIR));
        assert!(HELPER_SCRIPT.starts_with("#!/bin/sh"));
        assert!(HELPER_SCRIPT.contains("set -eu"));
    }
}
