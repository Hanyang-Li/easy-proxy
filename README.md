# easy-proxy

公司 VPN 一键本地代理。纯 HTTP 模拟深信服 EasyConnect 门户登录（密码 + 短信二次认证，无需浏览器），
用内嵌的 [zju-connect](https://github.com/Mythologyli/zju-connect) 建隧道，并在本机暴露**一个混合端口**
（http + socks5 同一个端口，像 clash verge 的 mixed-port）。不装内核驱动、不要 root、不用 TUN 模式。

CLI 约定参照姊妹项目 `verge-proxy`：eval 式 `start/stop`、powerline 状态胶囊、`install` 三件套、`ep` 单命令代理。

## 安装

```sh
curl -fsSL https://raw.githubusercontent.com/Hanyang-Li/easy-proxy/main/install.sh | sh
```

脚本从 GitHub Releases 下载 Apple Silicon（M 系列）二进制、校验 sha256，装到 `~/.local/bin`，再执行 `easy-proxy install`。
**全程在 `$HOME` 下，不需要 sudo**；`~/.local/bin` 不在 `PATH`、`~/.local/share/zsh/site-functions` 不在 zsh `fpath` 时，会分别往 shell rc 里补一行。

环境变量：`VERSION=v1.0.0` 装指定版本、`INSTALL_DIR=/path` 换安装目录（不可写时才回退 sudo）、`NO_MODIFY_PATH=1` 不改 rc 只打印手动提示。

装完后编辑 `~/.config/easy-proxy/config.yaml` 填入 `server` 与 `username`，再 `source ~/.zshrc`。

### 从源码构建

> 本仓库不含 `zju-connect` 二进制（GPL，见「注意」）。构建前先从
> [zju-connect releases](https://github.com/Mythologyli/zju-connect/releases) 下载对应平台二进制，
> 放到 `vendor/zju-connect` 并 `chmod +x`——编译期 `include_bytes!` 会把它内嵌进 easy-proxy。

```sh
cargo build --release
install -m 0755 target/release/easy-proxy ~/.local/bin/easy-proxy
easy-proxy install
source ~/.zshrc
```

`install` 会：
- 写默认配置 `~/.config/easy-proxy/config.yaml`
- 释放内嵌的 `zju-connect` 到 `~/.local/share/easy-proxy/zju-connect`
- 生成 zsh 补全 `~/.local/share/easy-proxy/_easy-proxy`，并软链到 `~/.local/share/zsh/site-functions/_easy-proxy`
- 在 `~/.zshrc` 的托管块（`# >>> easy-proxy >>>` … `# <<< easy-proxy <<<`）里写入 `easy-proxy()` wrapper 与 `ep()` 函数

二进制**自包含**（`zju-connect` 编译期内嵌），拷走单个文件即可用。

## 目录结构

1.0.0 起按 XDG 风味分四段，全在 `$HOME` 下、不需要 sudo：

```
~/.local/bin/easy-proxy        # 二进制（自包含）

~/.config/easy-proxy/          # 配置：只有一个文件
└── config.yaml

~/.local/share/easy-proxy/     # 数据：程序自带资源 + 你自备的脚本
├── zju-connect                #   释放出的隧道后端
├── _easy-proxy                #   zsh 补全源文件
└── scripts/get_sms.py         #   （可选）你自备的自动取码脚本
~/.local/share/zsh/site-functions/_easy-proxy   # → 软链到上面的补全源文件

~/.local/state/easy-proxy/     # 运行时状态（不与配置混放）
├── state.json                 #   连接状态（status/port 读它）
├── daemon.log / tunnel.log    #   守护进程 / zju-connect 日志
└── .cookies                   #   前台 connect 的临时 cookie

~/.cache/easy-proxy/           # 可随时删
└── silent.cookies             #   守护进程静默重登的一次性 jar
```

从 0.4.x 及更早版本升级是**一次性断裂**，`install` 不做自动迁移（旧布局散在 `/usr/local/bin`、
`~/.config/easy-proxy/{bin,completions}`、`~/.easy-proxy`、`$(brew --prefix)/share/zsh/site-functions`）。
先 `easy-proxy disconnect`（用旧二进制停掉守护），装完新版后手动清理：

```sh
sudo rm -f /usr/local/bin/easy-proxy
rm -rf ~/.config/easy-proxy/bin ~/.config/easy-proxy/completions ~/.easy-proxy
rm -f "$(brew --prefix)/share/zsh/site-functions/_easy-proxy"
mv ~/.config/easy-proxy/scripts ~/.local/share/easy-proxy/scripts   # 如果配了取码脚本
```

取码脚本挪位后记得同步改 `config.yaml` 里的 `sms_command` 路径。

## 命令

```sh
easy-proxy connect       # 登录并启动隧道后台守护（跨终端）。交互输入短信验证码；成功后显示延迟+端口胶囊
easy-proxy disconnect    # 停止后台守护 + 保活，并清除当前终端的代理环境变量
easy-proxy start         # 为当前终端设置代理环境变量（http_proxy/https_proxy/all_proxy）
easy-proxy stop          # 移除当前终端代理环境变量
easy-proxy restart       # 重新读取端口并更新当前终端代理环境变量
easy-proxy status        # 状态胶囊：online/offline · 延迟 · 端口
easy-proxy port          # 只输出端口号
easy-proxy install       # 配置 .zshrc / 补全 / 默认配置 / 释放 zju-connect
```

- `connect`/`disconnect` 控制的是**跨终端**的后台守护进程（连接服务本身）。
- `start`/`stop`/`restart` 只影响**当前终端**的环境变量，通过 `install` 写入的 zsh wrapper `eval` 生效
  （子进程无法直接改父 shell 环境变量，这点同 verge-proxy）。
- `disconnect` 既停守护，也顺带清掉当前终端的代理环境变量。

## ep：只给单条命令走代理

```sh
ep curl https://内网地址
ep git pull
```

`ep <cmd>` 在子 shell 里临时设置代理环境变量执行该命令，不影响当前 shell。未连接时会打印 status 并返回非零。

## 配置 `~/.config/easy-proxy/config.yaml`

```yaml
server: "vpn.example.com"       # 你的深信服 EasyConnect 门户地址
port: 443
username: "your-name@example.com"
mixed_port: 7899          # 本机对外暴露的混合端口（避开 clash verge 的 7897 等）
# sms_command: "python3 ~/.local/share/easy-proxy/scripts/get_sms.py"   # 可选：自动取码命令（见「自动获取短信验证码」）
healthcheck_interval: 60         # 兜底心跳（秒）：切网、唤醒由路由事件秒级触发探测，此周期只是兜底
healthcheck_fail_threshold: 2    # 连续探测失败几次判定断线（躲开单次抖动）
silent_relogin_interval: 3600    # 静默重登最小间隔（秒），按上次发码时刻限流下一次自动重登
prompt:
  online_icon: "󰌘"
  offline_icon: "󰌙"
  delay_icon: "󱦺"
  port_icon: "󰈀"
```

**密码存 macOS 钥匙串**（service=`easy-proxy`, account=用户名），config 里不存密码：
- 首次 `connect` 交互输入密码 → 存入钥匙串；之后自动读取，只需输短信码。
- 密码变更后被拒会自动重新索取并更新钥匙串；也可 `easy-proxy connect --relogin` 强制重输。

## 架构

```
connect ──login(纯HTTP: login_auth→psw_config→RSA(PKCS1v15)→login_psw[发短信]→login_sms1[提交码]；重发走 post_sms)──▶ TWFID
        └─▶ 后台守护 easy-proxy __serve
               ├─ 拉起 zju-connect  (socks 127.0.0.1:1080 / http 127.0.0.1:1081，内部)
               └─ 混合端口 127.0.0.1:<mixed_port>：按首字节嗅探
                     0x05 → 转发 socks 上游；否则 → 转发 http 上游
```

- 隧道后端 zju-connect 自带 UDP 保活，隧道可长时间稳定（原版 EasierConnect 无保活，几分钟必掉）。
- 单混合端口由 easy-proxy 自己实现（zju-connect 只有 socks/http 两个独立端口，无 mixed-port）。
- 首条短信在 `login_psw`（密码通过）那一刻由服务端下发。需要新码时走 `post_sms.csp`（门户「重新发送验证码」同款接口，约 30s 重发间隔，新旧码各 5 分钟有效）；`login_sms.csp` 只查手机号配置、**不发短信**。
- daemon 还会每 `healthcheck_interval` 探测一次连通性（详见下节）。

## 断线自动恢复（0.3.0，探针 0.3.1 修正，路由事件 0.4.0）

**切网秒级感知（0.4.0）**：daemon 订阅 macOS 路由事件流（`route -n monitor`），切 Wi-Fi / 插拔网线 / 唤醒时立即触发探测（1.5s 防抖），不通马上置 reconnecting 并重连——重连前先等新网络就绪（直连网关可达，最多 30s），避开 DHCP/关联窗口。定时探测退为兜底心跳：每 `healthcheck_interval`（默认 60s）探一次，连续 `healthcheck_fail_threshold`（默认 2）次失败进入**分级恢复**。

探针**穿隧道探测**：SOCKS5 CONNECT 到服务端下发的 VPN DNS（如 `10.0.104.104:53`），TCP 握手必须穿过隧道往返，能测出「隧道假死」。0.3.0 曾探 `https://{server}/`，但网关地址被 zju-connect 路由为 DIRECT（直连不进隧道），切网后隧道已死探针仍绿、ssh 却超时。若日志里解析不到 VPN DNS、或新隧道上探不通 DNS:53（如 DNS 不答 TCP），自动降级回网关直连探测（行为同 0.3.0，只对「彻底断网」敏感）。`status` 的延迟数字同样穿隧道测（经混合端口），不再显示假延迟。

1. **先用当前 TWFID 重启 zju-connect**（不发短信、不受频率限制）——切网 / 出地铁 / 短暂断连多半这一步就恢复，零短信。
2. 仍不通且**配了 `sms_command`** 时，才**静默重新登录**（钥匙串密码 + 自动取码）。此步受 `silent_relogin_interval`（默认 3600s）限流：按**上次发码时刻**算（手动 connect、补发、静默重登的发码都算），距上次发码不足该间隔就不再自动重登，直接转 offline。
3. 恢复彻底失败（旧 TWFID 失效 + 被限流 / 取不到码 / 未配 `sms_command`）→ daemon 退出、`status` 显示 offline，等你手动 `connect`。

**状态**：`online`（探测通） / `reconnecting`（daemon 活着、后台重连中，胶囊黄色） / `offline`（无守护）。合盖休眠时进程被系统挂起、不占资源，唤醒后立即补探一次。

**手动 `connect` 不受限流**；若后台正在重连，手动 `connect` 会**接管**——停掉后台守护，由前台（有 tty）完整走登录（向手机发码、自动 / 手动取码），与平常 connect 完全一致。

## 自动化（无 tty / 脚本）

- `EASY_PROXY_PASSWORD`：非交互提供密码（跳过钥匙串/提示）。
- `EASY_PROXY_SMS_FILE`：`connect` 会轮询该文件读取短信验证码（写入 4–8 位数字即可），便于脚本驱动。

## 自动获取短信验证码（可选、可插拔）

`connect` 默认需要手动输入短信验证码。如果你的短信能被某处程序读到（例如 macOS 开了 iPhone
「短信转发」，验证码会进「信息」App 的 `~/Library/Messages/chat.db`），可以在 config 里配一条
**取码命令**让它自动完成：

```yaml
sms_command: "python3 ~/.local/share/easy-proxy/scripts/get_sms.py"
sms_retries: 1               # 自动取码额度：总轮数=1+该值。没取到会补发新码，被拒则复用不重发。默认 1
sms_retry_interval_secs: 30  # 每轮进下一轮前统一等待秒数，默认 30
```

- 配了就用：`connect` 发出验证码后执行该命令；脚本取到就自动填入，取不到则**回退手动输入**，不会卡死。
- 优先级：`EASY_PROXY_SMS_FILE`（若设置）> `sms_command` > 手动输入。
- easy-proxy 本身**不含任何读码逻辑、也不内置脚本**——取码逻辑完全由你的命令决定，仓库不收录该脚本。
- **重试节奏**：总自动取码轮数 = 1 + `sms_retries`（默认 2；屏幕上「第 N/总数 次取码」原地刷新**一行**显示，中途不打失败结果，只有成功/耗尽/取消才定格）。每轮进下一轮前统一等 `sms_retry_interval_secs`（默认 30s，首轮不等）；两条失败路径**唯一区别**是——上一轮「没取到码」会先经 `post_sms.csp` 补发一条**新码**再取，「被服务端拒」则复用现有码、不重发。轮数用尽 / 自动期间按 `esc` 取消 → 回退手动（手动最多 3 次）。

**分工**（谁负责什么）：

| 负责方 | 职责 |
|---|---|
| **你的脚本** | 轮询等码、决定「往前看多久」、本地是否过期。取到就把 4–8 位码打到 stdout（`exit 0`）；暂时没有就 `exit 1` 或空输出。轮询与超时都在脚本里（示例约 60s）。 |
| **easy-proxy** | 只 `sh -c` 跑一次命令、取回一段输出（safety cap 90s，防脚本挂死）。拿到码交 `login_sms1` 让**服务端**判真假；被拒 → 下一轮复用重读（不重发）；没取到 → 下一轮经 `post_sms.csp` 补发新码后重读；轮数用尽 / `esc` 取消才回退手动。 |

> **为什么判据是「有效期」而不是「本次登录后才收到」**：被服务端拒时 easy-proxy 不重发、要你复用现有码（5 分钟内仍有效）；仅当「没取到」才 `post_sms.csp` 补发新码（约 30s 间隔）。所以脚本该找「仍在有效期内的最新一条码」（刚发的或仍有效的旧的都行），而不是死等一条"本次登录后"的新短信。

**示例：从 macOS「信息」`chat.db` 轮询读取**（自行放到 `~/.local/share/easy-proxy/scripts/get_sms.py`，按你的短信文案调整关键词/正则）。用 `LOOKBACK_SECS` 往前看、再用短信自带的「有效期截止 HH:MM」精确校验未过期：

```python
#!/usr/bin/env python3
import os, re, sqlite3, sys, time
from datetime import datetime, timedelta

LOOKBACK_SECS, POLL_TIMEOUT, POLL_INTERVAL = 300, 60, 2   # 往前看 / 轮询上限 / 间隔
DB = os.path.expanduser("~/Library/Messages/chat.db")

def find_valid_code():
    try:
        con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    except sqlite3.Error:
        return None
    # chat.db 的 date 是「2001-01-01 起的纳秒」，+978307200 换成 Unix 秒
    rows = con.execute("""
        SELECT text, date/1000000000 + 978307200 AS ts
        FROM message WHERE text LIKE '%VPN登录验证码%'
        ORDER BY date DESC LIMIT 8
    """).fetchall()
    con.close()
    now, floor = datetime.now(), time.time() - LOOKBACK_SECS
    for text, ts in rows:
        text = text or ""
        if ts is None or ts < floor:            # 超出「往前看」窗口
            continue
        m = re.search(r'验证码[:：]?\s*(\d{4,8})', text)
        if not m:
            continue
        exp = re.search(r'截止\s*(\d{1,2}):(\d{2})', text)   # 精确校验未过期（含跨零点）
        if exp:
            recv = datetime.fromtimestamp(ts)
            deadline = recv.replace(hour=int(exp.group(1)), minute=int(exp.group(2)),
                                    second=0, microsecond=0)
            if deadline < recv:
                deadline += timedelta(days=1)
            if now >= deadline - timedelta(seconds=5):
                continue
        return m.group(1)
    return None

end = time.time() + POLL_TIMEOUT
while True:
    code = find_valid_code()
    if code:
        print(code); sys.exit(0)
    if time.time() >= end:
        sys.exit(1)                             # 放弃 → easy-proxy 回退手动输入
    time.sleep(POLL_INTERVAL)
```

> 前提：终端（或 easy-proxy 所在进程）对 `~/Library/Messages/chat.db` 有读权限（macOS「完全磁盘访问权限」），
> 且 iPhone 已开启「设置 → 信息 → 短信转发」把这台 Mac 勾上。转发经 Apple 服务器中转，不要求同一 Wi-Fi/近距离；
> 但手机关机 / 无网络、或转发被关时会取不到——此时自动回退手动输入。

## 注意

- 非官方客户端：公司 IT 在服务端可见你的登录；是否合规（是否绕过了要求的终端安全检查）由你判断。
- 供应链：`zju-connect` 由其 GitHub Actions 从公开源码构建；要绝对放心可自行从源码交叉编译后替换 `vendor/zju-connect` 再 build。
- 许可证：`zju-connect` 为 GPL 系开源（以其仓库 LICENSE 为准）。本仓库通过 `.gitignore` 不纳入该二进制，仅在本地构建时内嵌；如需再分发内嵌了它的二进制，请遵守其许可证。
