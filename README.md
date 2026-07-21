# easy-proxy

公司 VPN 一键本地代理。纯 HTTP 模拟深信服 EasyConnect 门户登录（密码 + 短信二次认证，无需浏览器），
用内嵌的 [zju-connect](https://github.com/Mythologyli/zju-connect) 建隧道，并在本机暴露**一个混合端口**
（http + socks5 同一个端口，像 clash verge 的 mixed-port）。不装内核驱动、不要 root、不用 TUN 模式。

CLI 约定参照姊妹项目 `verge-proxy`：eval 式 `start/stop`、powerline 状态胶囊、`install` 三件套、`ep` 单命令代理。

## 安装

```sh
curl -fsSL https://raw.githubusercontent.com/Hanyang-Li/easy-proxy/main/install.sh | sh
```

脚本从 GitHub Releases 下载 Apple Silicon（M 系列）二进制到 `/usr/local/bin`，并执行 `easy-proxy install`。
可设置 `VERSION=v0.2.0` 安装指定版本。装完后编辑 `~/.config/easy-proxy/config.yaml` 填入 `server` 与 `username`，再 `source ~/.zshrc`。

### 从源码构建

> 本仓库不含 `zju-connect` 二进制（GPL，见「注意」）。构建前先从
> [zju-connect releases](https://github.com/Mythologyli/zju-connect/releases) 下载对应平台二进制，
> 放到 `vendor/zju-connect` 并 `chmod +x`——编译期 `include_bytes!` 会把它内嵌进 easy-proxy。

```sh
cargo build --release
sudo cp target/release/easy-proxy /usr/local/bin/easy-proxy
easy-proxy install
source ~/.zshrc
```

`install` 会：
- 写默认配置 `~/.config/easy-proxy/config.yaml`
- 释放内嵌的 `zju-connect` 到 `~/.config/easy-proxy/zju-connect`
- 生成 zsh 补全 `~/.config/easy-proxy/completions/_easy-proxy`
- 在 `~/.zshrc` 的托管块（`# >>> easy-proxy >>>` … `# <<< easy-proxy <<<`）里写入 `easy-proxy()` wrapper 与 `ep()` 函数

二进制**自包含**（`zju-connect` 编译期内嵌），拷走单个文件即可用。

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
# sms_command: "python3 ~/.config/easy-proxy/get_sms.py"   # 可选：自动取码命令（见「自动获取短信验证码」）
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
connect ──login(纯HTTP: login_auth→psw_config→RSA(PKCS1v15)→login_psw→[短信]→login_sms1)──▶ TWFID
        └─▶ 后台守护 easy-proxy __serve
               ├─ 拉起 zju-connect  (socks 127.0.0.1:1080 / http 127.0.0.1:1081，内部)
               └─ 混合端口 127.0.0.1:<mixed_port>：按首字节嗅探
                     0x05 → 转发 socks 上游；否则 → 转发 http 上游
```

- 隧道后端 zju-connect 自带 UDP 保活，隧道可长时间稳定（原版 EasierConnect 无保活，几分钟必掉）。
- 单混合端口由 easy-proxy 自己实现（zju-connect 只有 socks/http 两个独立端口，无 mixed-port）。
- 登录时的短信在 `login_psw`（密码通过）那一刻由服务端下发，`login_sms` 在冷却期内不会重复发；每次 `connect` 只发一条。

## 自动化（无 tty / 脚本）

- `EASY_PROXY_PASSWORD`：非交互提供密码（跳过钥匙串/提示）。
- `EASY_PROXY_SMS_FILE`：`connect` 会轮询该文件读取短信验证码（写入 4–8 位数字即可），便于脚本驱动。

## 自动获取短信验证码（可选、可插拔）

`connect` 默认需要手动输入短信验证码。如果你的短信能被某处程序读到（例如 macOS 开了 iPhone
「短信转发」，验证码会进「信息」App 的 `~/Library/Messages/chat.db`），可以在 config 里配一条
**取码命令**让它自动完成：

```yaml
sms_command: "python3 ~/.config/easy-proxy/get_sms.py"
sms_retries: 1               # 自动码被拒后重读几次（不重发短信），默认 1
sms_retry_interval_secs: 30  # 每次重试前等待秒数，默认 30
```

- 配了就用：`connect` 发出验证码后执行该命令；脚本取到就自动填入，取不到则**回退手动输入**，不会卡死。
- 优先级：`EASY_PROXY_SMS_FILE`（若设置）> `sms_command` > 手动输入。
- easy-proxy 本身**不含任何读码逻辑、也不内置脚本**——取码逻辑完全由你的命令决定，仓库不收录该脚本。
- **重试不重发**：自动码被服务端拒时按 `sms_retries`（默认 1）重试；每次重试前先等 `sms_retry_interval_secs`（默认 30s）让**正确的**码送达后再重读，**绝不重发新短信**（第一次常读到还没到货的旧码，等一下重读就对了；重发反而重蹈覆辙）。重试用尽仍失败才回退手动。总的 `login_sms1` 提交次数 = (1 + `sms_retries`) 次自动 + 3 次手动兜底。

**分工**（谁负责什么）：

| 负责方 | 职责 |
|---|---|
| **你的脚本** | 轮询等码、决定「往前看多久」、本地是否过期。取到就把 4–8 位码打到 stdout（`exit 0`）；暂时没有就 `exit 1` 或空输出。轮询与超时都在脚本里（示例约 60s）。 |
| **easy-proxy** | 只 `sh -c` 跑一次命令、取回一段输出（safety cap 90s，防脚本挂死）。拿到码交 `login_sms1` 让**服务端**判真假；被拒时本次登录**自动只试一次、之后转手动**；没取到（空/非零/超时）直接回退手动输入。 |

> **为什么判据是「有效期」而不是「本次登录后才收到」**：深信服门户在约 5 分钟内不会重发短信，而是要你复用上一条码。所以脚本该找「仍在有效期内的最新一条码」（无论是刚发的还是被复用的旧的），而不是死等一条新短信。

**示例：从 macOS「信息」`chat.db` 轮询读取**（自行放到 `~/.config/easy-proxy/get_sms.py`，按你的短信文案调整关键词/正则）。用 `LOOKBACK_SECS` 往前看、再用短信自带的「有效期截止 HH:MM」精确校验未过期：

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
