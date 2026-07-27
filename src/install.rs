//! install：释放内嵌 zju-connect、写默认配置 / zsh 补全 / .zshrc 托管块。
//!
//! 落盘位置见 [`crate::config::Paths`]：配置 ~/.config/easy-proxy、数据 ~/.local/share/easy-proxy、
//! 补全软链 ~/.local/share/zsh/site-functions，全在 $HOME 下，不需要 sudo。

use crate::capsule::{success_line, ANSI_BOLD_BLUE, ANSI_RESET};
use crate::config::{Paths, PromptConfig};
use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// 编译期内嵌的 zju-connect 二进制（darwin-arm64, v1.2.0）。
const ZJU_BIN: &[u8] = include_bytes!("../vendor/zju-connect");

const BLOCK_BEGIN: &str = "# >>> easy-proxy >>>";
const BLOCK_END: &str = "# <<< easy-proxy <<<";

#[derive(Clone, Copy)]
enum Action {
    Set,
    Updated,
    Kept,
}

impl Action {
    fn label(self) -> &'static str {
        match self {
            Action::Set => "已设置",
            Action::Updated => "已更新",
            Action::Kept => "已存在",
        }
    }
}

pub fn cmd_install(paths: &Paths, tun: bool) -> Result<()> {
    // --tun 只装 TUN 权限组件,不重跑常规安装(zshrc/补全/配置早已就位)
    if tun {
        return install_tun(paths);
    }
    fs::create_dir_all(&paths.config_dir)
        .with_context(|| format!("无法创建 {}", paths.config_dir.display()))?;
    fs::create_dir_all(&paths.data_dir)
        .with_context(|| format!("无法创建 {}", paths.data_dir.display()))?;
    fs::create_dir_all(&paths.state_dir)?;

    let cfg_action = ensure_config(paths)?;
    ensure_zju_bin(paths)?;
    let (comp_action, comp_path) = write_completion(paths)?;
    let zshrc_action = update_zshrc(paths)?;

    let prompt = PromptConfig::default();
    println!("{}", install_line(zshrc_action, "环境配置(.zshrc)", &paths.zshrc, &prompt));
    println!("{}", install_line(comp_action, "补全配置", &comp_path, &prompt));
    println!("{}", install_line(cfg_action, "默认配置", &paths.app_config, &prompt));
    println!(
        "{}",
        success_line(&format!("zju-connect 已就绪: {}", paths.zju_bin.display()), None, &prompt)
    );
    println!(
        "{}",
        success_line("完成。执行 source ~/.zshrc 或打开新终端后生效", None, &prompt)
    );
    Ok(())
}

/// sudoers 单行内容:只 NOPASSWD 授权固定路径的 helper 这一个入口。
fn sudoers_content(user: &str) -> String {
    format!("{user} ALL=(root) NOPASSWD: {}\n", crate::tun::HELPER_PATH)
}

/// sudo 密码提示(`sudo -p`,替换默认的 Password:):与 dialoguer 的 `› 标签: ` 输入行
/// 同风格,自带用途说明——不另打预告行(凭证有缓存时 sudo 根本不会问,预告反而成噪音)。
fn sudo_password_prompt(action: &str) -> String {
    format!("{ANSI_BOLD_BLUE}›{ANSI_RESET} {action}需要 root, 请输入 sudo 密码: ")
}

/// 失败细节:优先取捕获的 stderr(visudo/install 的具体报错),空则退回退出码。
fn sudo_failure_detail(out: &std::process::Output) -> String {
    let detail = String::from_utf8_lossy(&out.stderr);
    let detail = detail.trim();
    if detail.is_empty() {
        format!("(sudo 退出码 {})", out.status.code().unwrap_or(-1))
    } else {
        format!(": {detail}")
    }
}

fn current_username() -> Result<String> {
    std::env::var("USER")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            Command::new("/usr/bin/id")
                .arg("-un")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("无法确定当前用户名"))
}

/// TUN 权限组件安装(spec §5.1):单次交互 sudo 完成目录/两个文件/sudoers,末尾免密自检。
pub fn install_tun(paths: &Paths) -> Result<()> {
    ensure_zju_bin(paths)?; // root copy 的来源必须先就位
    let cache = &paths.cache_dir;
    fs::create_dir_all(cache)?;
    let helper_tmp = cache.join("ep-tun-helper.staged");
    fs::write(&helper_tmp, crate::tun::HELPER_SCRIPT)?;
    let sudoers_tmp = cache.join("sudoers.staged");
    fs::write(&sudoers_tmp, sudoers_content(&current_username()?))?;

    // 一段 root shell 完成全部落盘;路径经位置参数传入,不做字符串拼接
    let script = r#"set -e
install -d -o root -g wheel -m 0755 "$1"
install -o root -g wheel -m 0755 "$2" "$1/ep-tun-helper"
install -o root -g wheel -m 0755 "$3" "$1/zju-connect"
visudo -cf "$4" >/dev/null
install -o root -g wheel -m 0440 "$4" /etc/sudoers.d/easy-proxy
"#;
    // output() 捕获 stdout/stderr:失败细节(visudo/install 的报错)并进红叉行统一呈现,
    // 不让原始 stderr 裸奔;sudo 的密码对话走 /dev/tty,不受捕获影响。
    let out = Command::new("/usr/bin/sudo")
        .arg("-p").arg(sudo_password_prompt("安装 TUN 权限组件"))
        .arg("/bin/sh").arg("-c").arg(script).arg("sh")
        .arg(crate::tun::HELPER_DIR)
        .arg(&helper_tmp)
        .arg(&paths.zju_bin)
        .arg(&sudoers_tmp)
        .output()
        .context("无法执行 sudo")?;
    let _ = fs::remove_file(&helper_tmp);
    let _ = fs::remove_file(&sudoers_tmp);
    if !out.status.success() {
        return Err(anyhow::anyhow!("TUN 组件安装失败{}", sudo_failure_detail(&out)));
    }
    // 自检:免密路径立即可用(顺带完成一次 janitor 清场)
    crate::tun::janitor().context("安装自检失败:sudo -n 免密调用 helper 不可用")?;

    let prompt = PromptConfig::default();
    println!("{}", success_line(&format!("已安装 root helper: {}", crate::tun::HELPER_PATH), None, &prompt));
    println!("{}", success_line(&format!("已安装 sudoers 免密规则: {}", crate::tun::SUDOERS_PATH), None, &prompt));
    println!("{}", success_line("TUN 组件就绪", None, &prompt));
    Ok(())
}

/// 卸载 TUN 权限组件(spec §5.3):对称移除,幂等,不依赖 helper 完好。
pub fn cmd_uninstall(paths: &Paths, tun: bool) -> Result<()> {
    if !tun {
        return Err(anyhow::anyhow!("目前仅支持 uninstall --tun"));
    }
    let prompt = PromptConfig::default();
    // 先停 TUN 模式 daemon(优雅路径会自己 stop-tunnel + dns-clean)
    if let Some(st) = paths.read_state() {
        if st.mode == crate::config::Mode::Tun && crate::tunnel::pid_alive(st.daemon_pid) {
            eprintln!("  检测到 TUN 连接,先断开…");
            crate::tunnel::stop_daemon_and_wait(paths, std::time::Duration::from_secs(3));
        }
    }
    let helper_installed = Path::new(crate::tun::HELPER_DIR).exists();
    let sudoers_installed = Path::new(crate::tun::SUDOERS_PATH).exists();
    if !helper_installed && !sudoers_installed {
        println!("{}", success_line("TUN 组件未安装,无需卸载", None, &prompt));
        return Ok(());
    }
    // root 内联清理:等价 janitor 但不依赖 helper 完好(半残安装也能卸干净)
    let script = r##"set -u
if [ -d /etc/resolver ]; then
  for f in /etc/resolver/*; do
    [ -f "$f" ] || continue
    if [ "$(head -n 1 "$f" 2>/dev/null)" = "# managed by easy-proxy" ]; then rm -f "$f"; fi
  done
fi
pids=$(ps -axo pid=,comm= | awk '$2=="/usr/local/libexec/easy-proxy/zju-connect" {print $1}')
for p in $pids; do kill "$p" 2>/dev/null || true; done
rm -f /var/run/easy-proxy-tun.pid
rm -f /etc/sudoers.d/easy-proxy
rm -rf /usr/local/libexec/easy-proxy
exit 0
"##;
    let out = Command::new("/usr/bin/sudo")
        .arg("-p").arg(sudo_password_prompt("卸载 TUN 权限组件"))
        .arg("/bin/sh").arg("-c").arg(script)
        .output()
        .context("无法执行 sudo")?;
    if !out.status.success() {
        return Err(anyhow::anyhow!("卸载失败{}", sudo_failure_detail(&out)));
    }
    println!(
        "{}",
        success_line("TUN 组件已卸载: helper、sudoers、resolver 残留、孤儿隧道均已清理", None, &prompt)
    );
    Ok(())
}

/// 释放内嵌 zju-connect 到 ~/.local/share/easy-proxy/zju-connect（缺失或大小不符才重写），赋可执行权限并去隔离属性。
pub fn ensure_zju_bin(paths: &Paths) -> Result<()> {
    fs::create_dir_all(&paths.data_dir)?;
    let need = match fs::metadata(&paths.zju_bin) {
        Ok(m) => m.len() != ZJU_BIN.len() as u64,
        Err(_) => true,
    };
    if need {
        fs::write(&paths.zju_bin, ZJU_BIN)
            .with_context(|| format!("无法写入 {}", paths.zju_bin.display()))?;
        let mut perm = fs::metadata(&paths.zju_bin)?.permissions();
        perm.set_mode(0o755);
        fs::set_permissions(&paths.zju_bin, perm)?;
        let _ = Command::new("xattr")
            .args(["-d", "com.apple.quarantine"])
            .arg(&paths.zju_bin)
            .output();
    }
    Ok(())
}

fn ensure_config(paths: &Paths) -> Result<Action> {
    if paths.app_config.exists() {
        return Ok(Action::Kept);
    }
    fs::write(&paths.app_config, default_config())
        .with_context(|| format!("无法写入 {}", paths.app_config.display()))?;
    Ok(Action::Set)
}

fn default_config() -> String {
    r#"# easy-proxy 配置：首次安装后请填写 server 与 username
server: ""            # 深信服 EasyConnect 门户地址，例: vpn.example.com
port: 443
username: ""          # 门户登录用户名/邮箱，例: your-name@example.com
# 本机对外暴露的混合代理端口（http+socks 同一个端口）
mixed_port: 7899
# 自动获取短信验证码（可选、可插拔，默认关闭）：配一条命令，connect 时执行它取码，
# 取不到就回退手动输入（自动期间可随时按 esc 取消，直接转手动）。命令经 `sh -c` 执行；
# 脚本自己负责轮询等码、往前看多久、是否过期，只需把 4–8 位数字打到 stdout（是否有效由服务端最终校验）。
# 示例脚本见 README（不随程序内置）。
# sms_command: "python3 ~/.local/share/easy-proxy/scripts/get_sms.py"
# sms_retries: 1              # 自动取码额度：总轮数=1+该值。没取到会补发一次短信重取；被拒则不重发只重读。默认 1
# sms_retry_interval_secs: 30 # 「被拒后重读」前的等待秒数（给正确验证码送达的时间）。默认 30
# TUN 透明模式（connect --tun)专用：内网专用域名后缀，隧道在线时写成 /etc/resolver/<suffix>
# 分流解析（nameserver 指服务端下发的 VPN DNS）；只放内网 zone，别把纯公网域名圈进来。
# tun:
#   dns_suffixes: ["corp.example.com"]
prompt:
  online_icon: "󰌘"
  offline_icon: "󰌙"
  reconnecting_icon: "󰑐"
  delay_icon: "󱎫"
  port_icon: "󰤨"
"#
    .to_string()
}

/// 补全源文件写数据目录，再软链到 ~/.local/share/zsh/site-functions（与 verge-proxy 一致，
/// 不再依赖 brew --prefix：该目录归用户所有，install.sh 负责把它挂到 fpath 上）。
fn write_completion(paths: &Paths) -> Result<(Action, PathBuf)> {
    fs::create_dir_all(&paths.data_dir)?;
    fs::write(&paths.completion_file, completion_script())
        .with_context(|| format!("无法写入 {}", paths.completion_file.display()))?;

    let link = &paths.completion_link;
    let existed = fs::symlink_metadata(link).is_ok();
    fs::create_dir_all(&paths.zsh_functions_dir)?;
    if existed {
        fs::remove_file(link)
            .with_context(|| format!("无法移除旧补全配置 {}", link.display()))?;
    }
    std::os::unix::fs::symlink(&paths.completion_file, link).with_context(|| {
        format!(
            "无法创建补全软链接 {} -> {}",
            link.display(),
            paths.completion_file.display()
        )
    })?;
    Ok((if existed { Action::Updated } else { Action::Set }, link.clone()))
}

fn completion_script() -> &'static str {
    r#"#compdef easy-proxy

_easy-proxy() {
  local -a commands
  commands=(
    'connect:登录并启动隧道后台守护'
    'disconnect:停止隧道并清除当前终端代理'
    'start:为当前终端设置代理环境变量'
    'stop:移除当前终端代理环境变量'
    'restart:重新读取端口并更新代理环境变量'
    'status:显示连接状态胶囊'
    'port:输出当前端口号'
    'install:安装 .zshrc、补全与默认配置(--tun 加装 TUN 权限组件)'
    'uninstall:卸载 TUN 权限组件'
  )
  _arguments -s \
    '(-h --help)'{-h,--help}'[显示帮助信息]' \
    '1:command:->cmds' \
    '*::arg:->args'
  case "$state" in
    cmds) _describe 'command' commands ;;
    args)
      case "$words[1]" in
        connect) _arguments '--relogin[忽略钥匙串密码，强制重新输入]' '(-t --tun)'{-t,--tun}'[以 TUN 透明模式连接]' ;;
        stop|restart) _arguments '(-f --force)'{-f,--force}'[proxy_name 非 easy 时也强制执行]' ;;
        install) _arguments '--tun[安装 TUN 权限组件(需一次 sudo)]' ;;
        uninstall) _arguments '--tun[卸载 TUN 权限组件(需一次 sudo)]' ;;
      esac
      ;;
  esac
}

_easy-proxy "$@"
"#
}

fn update_zshrc(paths: &Paths) -> Result<Action> {
    let exe = current_exe_path();
    let block = zsh_block(&exe);
    let original = fs::read_to_string(&paths.zshrc).unwrap_or_default();
    let action = if original.contains(BLOCK_BEGIN) && original.contains(BLOCK_END) {
        Action::Updated
    } else {
        Action::Set
    };
    let updated = replace_managed_block(&original, &block);
    fs::write(&paths.zshrc, updated)?;
    Ok(action)
}

fn current_exe_path() -> String {
    env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .unwrap_or_else(|| PathBuf::from("easy-proxy"))
        .display()
        .to_string()
}

fn zsh_block(exe: &str) -> String {
    format!(
        r#"{BLOCK_BEGIN}
# easy-proxy wrapper (added by easy-proxy install)
easy-proxy() {{
  case "$1" in
    start|stop|restart|disconnect) eval "$(COLUMNS=${{COLUMNS:-80}} "{exe}" "$@")" ;;
    *) COLUMNS=${{COLUMNS:-80}} "{exe}" "$@" ;;
  esac
}}
ep() {{
  emulate -L zsh
  if ! COLUMNS=${{COLUMNS:-80}} "{exe}" port --connected >/dev/null 2>&1; then
    COLUMNS=${{COLUMNS:-80}} "{exe}" status >&2
    return 1
  fi
  (
    eval "$(COLUMNS=${{COLUMNS:-80}} "{exe}" restart -f)" >&2 || exit
    if [[ -n ${{aliases[$1]}} ]]; then
      eval "${{aliases[$1]}} ${{(j: :)${{(@q)@[2,-1]}}}}"
    else
      "$@"
    fi
  )
}}
{BLOCK_END}
"#
    )
}

fn replace_managed_block(original: &str, block: &str) -> String {
    let Some(begin) = original.find(BLOCK_BEGIN) else {
        let mut out = original.to_string();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
        out.push_str(block);
        return out;
    };
    let Some(rel_end) = original[begin..].find(BLOCK_END) else {
        let mut out = original.to_string();
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
        out.push_str(block);
        return out;
    };
    let mut end = begin + rel_end + BLOCK_END.len();
    if original[end..].starts_with('\n') {
        end += 1;
    }
    format!("{}{}{}", &original[..begin], block, &original[end..])
}

fn install_line(action: Action, name: &str, path: &Path, prompt: &PromptConfig) -> String {
    success_line(&format!("{}{}: {}", action.label(), name, path.display()), None, prompt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sudoers_line_shape() {
        let line = sudoers_content("alice");
        assert_eq!(line, "alice ALL=(root) NOPASSWD: /usr/local/libexec/easy-proxy/ep-tun-helper\n");
    }

    #[test]
    fn completion_covers_tun_surface() {
        let s = completion_script();
        assert!(s.contains("uninstall:"));
        assert!(s.contains("--tun"));
    }

    #[test]
    fn managed_block_replaces_only_marked_region() {
        let original = "before\n# >>> easy-proxy >>>\nold\n# <<< easy-proxy <<<\nafter\n";
        let block = "# >>> easy-proxy >>>\nnew\n# <<< easy-proxy <<<\n";
        assert_eq!(
            replace_managed_block(original, block),
            "before\n# >>> easy-proxy >>>\nnew\n# <<< easy-proxy <<<\nafter\n"
        );
    }

    #[test]
    fn managed_block_appended_when_absent() {
        let original = "export PATH=/x\n";
        let block = "# >>> easy-proxy >>>\nx\n# <<< easy-proxy <<<\n";
        let out = replace_managed_block(original, block);
        assert!(out.starts_with("export PATH=/x\n"));
        assert!(out.contains(BLOCK_BEGIN));
    }

    #[test]
    fn zsh_block_uses_absolute_exe_and_eval_for_env_commands() {
        let block = zsh_block("/usr/local/bin/easy-proxy");
        assert!(block.contains(r#"start|stop|restart|disconnect) eval "$(COLUMNS=${COLUMNS:-80} "/usr/local/bin/easy-proxy" "$@")" ;;"#));
        assert!(block.contains("ep() {"));
        assert!(block.contains(r#""/usr/local/bin/easy-proxy" port --connected >/dev/null 2>&1"#));
        assert!(block.contains(r#""/usr/local/bin/easy-proxy" status >&2"#));
        // ep 在子 shell 里拿代理变量,不影响外层环境,故被其他代理接管时也强制执行
        assert!(block.contains(r#"eval "$(COLUMNS=${COLUMNS:-80} "/usr/local/bin/easy-proxy" restart -f)" >&2 || exit"#));
    }
}
