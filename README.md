# easy-proxy

公司 VPN 一键本地代理。纯 HTTP 模拟深信服 EasyConnect 门户登录（密码 + 短信二次认证，无需浏览器），
用内嵌的 [zju-connect](https://github.com/Mythologyli/zju-connect) 建隧道，并在本机暴露**一个混合端口**
（http + socks5 同一个端口，像 clash verge 的 mixed-port）。不装内核驱动、不要 root、不用 TUN 模式。

CLI 约定参照姊妹项目 `verge-proxy`：eval 式 `start/stop`、powerline 状态胶囊、`install` 三件套、`ep` 单命令代理。

## 安装

> **构建前置**：本仓库不含 `zju-connect` 二进制（GPL 开源，见「注意」）。构建前请从
> [zju-connect releases](https://github.com/Mythologyli/zju-connect/releases) 下载对应平台二进制，
> 放到 `vendor/zju-connect` 并 `chmod +x`——它会被编译期 `include_bytes!` 内嵌进 easy-proxy。

```sh
cargo build --release
cp target/release/easy-proxy ~/.local/bin/easy-proxy   # 或 /usr/local/bin（需 sudo）
easy-proxy install
# 编辑 ~/.config/easy-proxy/config.yaml 填入 server 与 username
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

## 注意

- 非官方客户端：公司 IT 在服务端可见你的登录；是否合规（是否绕过了要求的终端安全检查）由你判断。
- 供应链：`zju-connect` 由其 GitHub Actions 从公开源码构建；要绝对放心可自行从源码交叉编译后替换 `vendor/zju-connect` 再 build。
- 许可证：`zju-connect` 为 GPL 系开源（以其仓库 LICENSE 为准）。本仓库通过 `.gitignore` 不纳入该二进制，仅在本地构建时内嵌；如需再分发内嵌了它的二进制，请遵守其许可证。
