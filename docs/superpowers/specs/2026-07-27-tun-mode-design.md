# 设计:TUN 透明代理模式(macOS)

日期:2026-07-27
分支:`feat/tun-mode`(暂定)
前置调研:zju-connect upstream main 源码(TUN 实现)+ 真机事件流经验(0.4.x)

## 1. 背景与调研结论

现状:easy-proxy 全用户态,`connect` 起 daemon 管一个 zju-connect 子进程,对外只暴露 mixed 7899 代理端口。不方便配代理的场景(浏览器直访内网站点、ssh 直连内网域名、任意不认代理环境变量的工具)覆盖不到。

TUN 模式(`zju-connect -tun-mode -add-route`,需 root)能做透明接管,但一直有"进程被 kill 后整机断网"的担忧。对 zju-connect TUN 源码的调研结论把这个担忧精确定性:

1. **建卡**:sing-tun 建 utun,`AutoRoute: false`,只配隧道虚拟 IP/32,MTU 固定 1400(`stack/tun/stack_darwin.go`)。
2. **路由是分流的,从不碰默认路由**:`-add-route` 对服务端下发的每个网段执行 `route -n add -net <网段> -interface utunX`。只有公司内网网段走 utun。
3. **TUN 栈只转发匹配服务端 ipResources 的包**,不匹配的直接 drop——路由与资源集合一致,无流量黑洞。
4. **TUN 模式下 `-socks-bind`/`-http-bind` 照常监听**,还会在「隧道IP:53」起本地 DNS server。
5. **真正的断网元凶是 `-dns-hijack`**:它用 `networksetup -setdnsservers <所有网络服务> <隧道IP>` 改系统**全局** DNS,清理只注册在优雅退出的 terminal hook 里。kill -9/崩溃/断电后全局 DNS 指向已死的隧道 IP → 整机 DNS 全挂。这是"TUN 危险"的唯一真实来源。
6. **路由残留在 macOS 上不存在**:utun 绑定进程 fd,进程死亡(含 kill -9)内核立刻销毁 utun,接口路由随之自动清空。上游源码没有路由清理代码——因为不需要。

**设计原则一句话:只做分流路由 + 只做域名级 DNS(scoped resolver),全局网络配置一个字节都不改;禁用 `-dns-hijack`,剩下的交给内核自清 + janitor 自愈。**

## 2. 目标与非目标

**目标**
- `connect --tun/-t` 一键启用 TUN 透明模式:内网网段免代理直达,内网域名免配置解析。
- 无人值守自愈不打折:现有看门狗(穿隧道 SOCKS 探针、路由事件秒级检测、分级恢复)在 TUN 模式下原样生效,重启隧道免密。
- 任何异常退出(kill -9、崩溃、断电)不破坏本机网络;残留下次使用时自动归零。
- 权限一次性授予(`install --tun` 单次 sudo),此后全程免密;可随时 `uninstall --tun` 对称移除全部系统级安装物。

**非目标**
- 不用 `-dns-hijack`,不改全局 DNS,不改默认路由,不做全局透明代理(只分流服务端下发网段)。
- 不替代代理模式:mixed 7899 与 `start/stop/restart` 语义完全不变,TUN 是"额外"的透明层。
- 不做 Linux/Windows 支持(utun 自清依赖 macOS 内核行为)。
- 不引入 launchd/system daemon;root 权限只存在于 zju-connect 隧道进程本身。

## 3. 设计不变量(安全边界)

以下两条是整个设计的安全边界,实现与评审时作为硬性检查项:

1. **全程不改默认路由、不改全局 DNS。** utun 及其分流路由由内核随进程消亡自动清理;DNS 只通过 `/etc/resolver/<suffix>` 按后缀分流,挂了只影响配置内的内网后缀。
2. **TUN 模式下 mixed 7899 与 `start/stop/restart` 语义完全不变。** zju-connect 的 socks/http 监听照常,mixed relay 照跑,`ep` 包装器、ssh 的 ep-proxy.sh、探针在两种模式下行为统一;胶囊 port 段显示「tun」以表明模式。

## 4. 架构与进程关系

```
connect --tun (用户,前台,登录拿 TWFID)
  └─ spawn easy-proxy __serve --tun (用户,setsid daemon,mixed relay + 看门狗)
       └─ tokio spawn: sudo -n ep-tun-helper start-tunnel ... (root)
            └─ exec zju-connect -tun-mode -add-route ... (root,pid 不变)
```

- daemon 对 root 子进程 `kill()` 必然 EPERM:**所有停止/重启动作一律走 `helper stop-tunnel`(按 pidfile SIGTERM)**;`child.start_kill()` 在 tun 分支弃用。
- `child.wait()` 是父进程权利、无需权限,照常工作 → zju-connect 死亡秒级感知不变。
- 日志布局不变:`~/.local/state/easy-proxy/daemon.log`(daemon)、`~/.local/state/easy-proxy/tunnel.log`(zju-connect 输出经 sudo/helper 继承 fd 直写)。

## 5. 权限模型:install --tun + ep-tun-helper + sudoers

**速览:easy-proxy 本体保持全用户态零变化;只为「隧道进程需 root + 看门狗需免密重启它」,额外向系统安装 3 个文件,一次 `install --tun`(输一次 sudo 密码)装完,此后全程免密:**

| 安装物 | 位置 | 作用 |
|---|---|---|
| `ep-tun-helper`(sh 脚本,root:wheel) | `/usr/local/libexec/easy-proxy/` | 免密授权的唯一入口 |
| zju-connect root 副本(root:wheel) | `/usr/local/libexec/easy-proxy/` | root 进程只能信 root 属主、用户不可写的二进制 |
| sudoers 单行规则(0440) | `/etc/sudoers.d/easy-proxy` | 授权当前用户免密执行 helper(且只有 helper) |

推导链条:① TUN 必须 root(zju-connect 显式检查 uid=0);② 看门狗要在无人值守时(半夜切网、睡眠唤醒)重启 root 隧道,而 macOS sudo 默认 `tty_tickets`,daemon 无 tty,前台缓存的凭证用不上——**凭证缓存方案不可行,NOPASSWD 是硬前提**;③ NOPASSWD 不能直接给 zju-connect,否则用户态任意进程可 root 执行它并注入任意参数 → 只授权死板的 helper 单入口;④ helper 与二进制必须在用户不可写的 root 目录,否则换掉文件内容即等于拿到 root——所以复制 zju-connect 而非直接用 `~/.local/share` 里那份。

卸载走 `uninstall --tun`(§5.3),与安装对称。不带 `--tun` 时这些文件完全闲置,代理模式行为不受影响。

### 5.1 `install --tun`(单次 sudo,幂等)

1. `mkdir -p /usr/local/libexec/easy-proxy`(root:wheel 0755,用户不可写——NOPASSWD 不被提权利用的前提)。
2. 拷 `~/.local/share/easy-proxy/zju-connect` → 同目录 root copy,chown root:wheel,chmod 0755。内嵌二进制升级后需重跑(按大小/哈希不一致检测并提示)。
3. 释放内嵌 helper 脚本 → `/usr/local/libexec/easy-proxy/ep-tun-helper`,root:wheel 0755。
4. sudoers:先写临时文件 → `visudo -cf` 校验通过 → `install -m 0440` 到 `/etc/sudoers.d/easy-proxy`,内容一行:
   `<username> ALL=(root) NOPASSWD: /usr/local/libexec/easy-proxy/ep-tun-helper`
   **只授权 helper 这一个入口**,不直接授权 zju-connect(避免任意参数被滥用为 root 执行/写文件)。
5. 自检:`sudo -n /usr/local/libexec/easy-proxy/ep-tun-helper janitor` 跑通即就绪。
6. zsh 补全的 connect 分支加 `--tun/-t`。

helper 与安装路径**不可配置**(sudoers 必须匹配固定绝对路径,可配置即提权洞)。

### 5.2 ep-tun-helper 命令面

形态:easy-proxy 内嵌的 POSIX sh 脚本(编译期常量,`install --tun` 释放)。pidfile:`/var/run/easy-proxy-tun.pid`(root 写)。所有参数白名单校验,不合法即退出非零:

| 子命令 | 行为 |
|---|---|
| `start-tunnel --server <host> --https-port <n> --twfid <id> --socks 127.0.0.1:1080 --http 127.0.0.1:1081` | 校验:server 匹配 `^[A-Za-z0-9.-]+$`、端口纯数字、twfid `^[A-Za-z0-9]+$`、socks/http 匹配 `^127\.0\.0\.1:[0-9]+$`。pidfile 指向的进程还活着先杀。zju-connect 命令行由 helper 自己拼,固定追加 `-tun-mode -add-route -disable-zju-config -skip-domain-resource -zju-dns-server auto -disable-multi-line`,用户输入只能填充值、不能注入 flag。写 `$$` 进 pidfile 后 `exec` root copy 的 zju-connect(exec 不换 pid),stdout/stderr 继承调用方 fd(即 tunnel.log)。 |
| `stop-tunnel` | 读 pidfile → 校验该 pid 的可执行路径确为 root copy(防 pid 复用误杀)→ SIGTERM → 等 5s → 兜底 SIGKILL → 删 pidfile。 |
| `dns-sync <suffix>=<ip> ...` | suffix 匹配 `^[a-z0-9.-]+$`、ip 必须 IPv4;写 `/etc/resolver/<suffix>`(首行标记 `# managed by easy-proxy` + `nameserver <ip>`);同时删除带标记但不在本次列表中的旧文件(幂等同步语义)。 |
| `dns-clean` | 只删 `/etc/resolver/` 下带 easy-proxy 标记的文件。 |
| `janitor` | dns-clean + 杀所有可执行路径 == root copy zju-connect 的孤儿进程 + 删 pidfile。 |

### 5.3 `uninstall --tun`(与 install 对称,交互 sudo 一次)

1. 若 TUN 模式 daemon 在跑,先走 disconnect 流程(优雅停隧道 + 清 resolver)。
2. 以 root 内联执行等价 janitor 的清理(删带标记 resolver 文件、杀孤儿 root zju-connect、删 pidfile)——**不依赖 helper 完好**,半残安装也能卸干净。
3. 删 `/etc/sudoers.d/easy-proxy` 与整个 `/usr/local/libexec/easy-proxy/`。
4. 幂等:未安装时逐项提示「不存在,跳过」,不报错。
5. 不给 helper 加 uninstall 子命令:保持 NOPASSWD 命令面最小;卸载是人在场的稀有操作,交互输一次 sudo 密码可接受(与 install 对称)。

## 6. DNS:scoped resolver,不劫持全局

config.yaml 新增(整段可缺省,`serde(default)`):

```yaml
tun:
  dns_suffixes: []   # 内网专用域名后缀(zone);默认空 = 不写任何 /etc/resolver 文件
```

- 隧道**就绪后**(首连 + 每次看门狗恢复成功后)daemon 调 `helper dns-sync`,写 `/etc/resolver/<suffix>`,幂等。
- nameserver 用 `state.vpn_dns`(服务端下发 DNS,经 TUN 路由可达,**重登换隧道 IP 后地址不变**,文件一次写好重连不用刷);不用 tunIP。`vpn_dns` 为 None 则跳过 dns-sync 并日志警告(此时内网域名仍可走 7899 代理路径,由 zju-connect 内部解析)。
- 匹配按整个后缀分流,由 mDNSResponder 完成(Tailscale/Docker 同机制);`dig/nslookup` 不走系统解析器,验证需用 `dscacheutil -q host -a name xxx` 或 ping。
- 清理:disconnect 优雅路径 `dns-clean`;每次 connect 前 janitor;崩溃残留最坏只影响 suffixes 内域名,下次任一入口自愈。
- `dns_suffixes` 只配内网专用 zone,别把纯公网域名圈进来(VPN 离线期间该后缀全部解析不了,直到清理)。

## 7. CLI 流程

### 7.1 `connect --tun/-t`

1. 既有前置检查照旧(foreign_proxy_name、已在线判断、config 校验)。
2. TUN 就绪检查:helper 与 sudoers 已安装且 `sudo -n` 可用、root copy 与内嵌二进制版本一致。不满足则**交互询问**「TUN 组件未安装(或版本过旧),是否现在安装?需输入一次 sudo 密码」——确认即当场执行 `install --tun` 流程后继续 connect;拒绝则中止并提示可手动执行 `easy-proxy install --tun`;无 tty(自动化)场景不询问,直接报错退出。
3. **janitor**(`sudo -n helper janitor`):清上次残留(resolver 文件、孤儿 root 隧道、pidfile)。
4. 登录流程完全复用(密码 → 短信 → TWFID)。
5. spawn 用户态 daemon(setsid),`ServeArgs` 加 `--tun`。
6. daemon 起隧道:`sudo -n helper start-tunnel ...`,stdout/stderr 重定向到 tunnel.log;`wait_socks_ready` 逻辑照旧(日志格式不变)。
7. **启动护栏**(就绪后立即执行,失败则 stop-tunnel + error 落 state + 退出,绝不假 online):
   a. tunnel.log 中 `Add route to` 条数 == 0 → 报错「服务端未下发网段,TUN 不可用」;
   b. `route -n get default` 的 interface 是 utun* → 违反分流原则,回滚报错。
   另:检测到其他大网段 TUN(clash verge TUN 模式、Tailscale 默认路由)时给出共存警告(仅警告不阻断)。
8. `dns_suffixes` 非空且 `state.vpn_dns` 有值 → `sudo -n helper dns-sync <suffix>=<vpn_dns> ...`。
9. state 写 `mode: Tun`、phase=Online;胶囊 port 段显示「tun」。

### 7.2 `disconnect`

1. daemon 收 SIGTERM,shutdown 路径按序:`helper stop-tunnel`(优雅,zju-connect 自身 hook 关 utun、内核清路由)→ `helper dns-clean` → `clear_state` → 退出。
2. CLI 侧等待超时从 300ms 提到 3s(tun 模式);daemon 没退干净则 CLI 兜底 `sudo -n helper janitor`。现有 `pkill -f zju_bin` 兜底对 root 进程无效,tun 分支必须换成 janitor。
3. unset 环境变量输出、offline 胶囊照旧。

### 7.3 `start/stop/restart/port/status`

语义零变化(不变量 2)。status 在 TUN 模式下延迟探测照旧走穿隧道 SOCKS 探针(1080 照常监听);胶囊 port 段渲染「tun」。

## 8. 看门狗与恢复(复用,差异仅在启停动作)

- 探针(穿隧道 SOCKS probe)、路由事件秒级检测、防抖、恢复分级(旧 TWFID 重启 → 闸门 → 静默重登)**全部零改动复用**。
- 重启动作从"spawn zju-connect"换成 `helper stop-tunnel` → `sudo -n helper start-tunnel`(新/旧 TWFID);NOPASSWD 保证无人值守可用。
- 每次恢复成功后重跑启动护栏 + dns-sync(幂等;utun 名字变了没关系,路由由 zju-connect 重加,resolver 指向的 vpn_dns 不变)。
- `child.wait()` 感知 root 隧道死亡照常;`start_kill` 分支在 tun 模式改走 stop-tunnel。

## 9. 数据结构与代码改动

```rust
// config.rs
pub struct TunConfig { pub dns_suffixes: Vec<String> }   // AppConfig.tun: TunConfig, serde(default)
pub enum Mode { Proxy, Tun }                              // RuntimeState.mode, serde default = Proxy(兼容旧 state.json)

// capsule.rs
// ProxyStatus.port: Option<u16> → Option<PortSeg>
pub enum PortSeg { Num(u16), Tun }                        // 渲染「tun」
```

| 文件 | 改动 |
|---|---|
| `src/lib.rs` | Connect 加 `--tun/-t`;新增 Uninstall 子命令(`--tun`);connect/disconnect 的 tun 分支;胶囊调用适配 PortSeg |
| `src/config.rs` | `TunConfig`、`RuntimeState.mode`(default Proxy) |
| `src/capsule.rs` | `PortSeg` 枚举与「tun」渲染 |
| `src/tunnel.rs` | spawn_daemon 透传 `--tun`;stop 路径 tun 分支(janitor 兜底替代 pkill);sudo/helper 调用封装 |
| `src/daemon.rs` | `ServeArgs.tun`;启停走 helper;启动护栏;shutdown 序列(stop-tunnel → dns-clean);恢复路径适配 |
| `src/install.rs` | `install --tun` / `uninstall --tun`;sudoers 写入 + visudo 校验;补全更新(含 uninstall) |
| `src/tun.rs`(新增) | helper 脚本内容常量、调用封装、janitor、参数校验、护栏解析 |
| README / docs | TUN 模式说明、dns_suffixes 配置示例、验证方法(dscacheutil 而非 dig) |

## 10. 失效矩阵(设计目标)

| 场景 | 结果 |
|---|---|
| kill -9 zju-connect(root) | utun+路由内核自清;daemon `child.wait` 秒级感知 → 免密自动重启 → 恢复 |
| kill -9 daemon | root 隧道成孤儿仍在跑(网络不坏),下次 connect 的 janitor 杀掉重来;或 disconnect 清理 |
| 两个都 kill -9 | 路由/utun 自清,公网正常;仅 resolver 残留(只影响内网后缀)→ janitor |
| 切网/睡眠唤醒 | 现有路由事件+看门狗恢复链路原样生效 |
| 断电重启 | utun/路由本来就不跨重启;resolver 残留 → janitor |

## 11. 错误处理与边界

1. **服务端不下发网段**:启动护栏 a 直接 fail fast,不假 online(这是 TUN 可行性先决条件,见 §13 验证项 1)。
2. **sudoers/helper 未装或版本不符**:connect --tun 前置检查引导 `install --tun`,不进入半残状态。
3. **vpn_dns 缺失**:跳过 dns-sync,警告降级——透明路由仍可用(按 IP),域名解析走 7899 代理路径兜底。
4. **helper 参数注入**:所有值白名单正则校验;flag 由 helper 固定拼装;sudoers 只授权 helper 单入口;安装目录 root 属主用户不可写。
5. **pid 复用误杀**:stop-tunnel/janitor 杀进程前校验可执行路径 == root copy。
6. **旧 state.json / 旧 config 兼容**:`mode`、`tun` 段均 serde default;Proxy 模式行为与现状 bit 级一致。
7. **`dig` 验证误判**:文档明确用 `dscacheutil`/ping 验证 scoped resolver;Firefox DoH、容器内解析等绕过系统解析器的场景不受控,写入 README 已知边界。

## 12. 测试策略

**单元测(不碰网络/root)**
- helper 参数校验正则(server/port/twfid/suffix/ip 的合法与注入样本)。
- `Add route to` 计数解析、`route -n get default` 输出解析(护栏纯函数,喂真机样本)。
- `PortSeg` 渲染(Num→数字、Tun→「tun」)、胶囊三态组合。
- `TunConfig`/`Mode` serde default 与旧 json round-trip 兼容。
- helper 脚本常量的 shellcheck 级静态检查(有条件则加)。

**真机验证(沿用"先验证再上"规矩,上线前逐项过)**
1. 公司 EasyConnect 服务端是否给这个账号下发 ipSet(看 `Add route to` 条数)——**先决条件,先手动 `sudo zju-connect -tun-mode -add-route ...` 跑一次确认**;
2. kill -9 后 `netstat -rn` 确认路由自清、公网无感;
3. TUN 模式下 SOCKS 探针是否仍测的是隧道数据面;
4. MTU 1400 下大流量场景(内网 git clone);
5. 与 clash verge(系统代理模式)共存无冲突;
6. scoped resolver 用 `dscacheutil -q host` 验证内网/公网域名分流;Docker 容器内解析转发行为;
7. 看门狗无人值守免密重启(sudo -n 无 tty 场景)端到端;
8. 钥匙串在 daemon 静默重登路径无新增弹框(与 0.3.0 验证项合并);
9. `uninstall --tun` 后三件套确实移除、resolver 干净,随后 `connect --tun` 能重新交互引导安装。

## 13. 风险与开放问题

- **先决条件未证实**:服务端可能不下发 ipSet(护栏会拦住,但功能就无意义了)——真机验证项 1 先行。
- **上游 experimental**:zju-connect TUN 标记为实验性;`-zju-dns-server auto` 与 `-tun-mode` 组合的行为以真机为准。
- **/var/run 语义**:重启后 pidfile 自动消失(tmpfs),与"utun 不跨重启"一致,无残留风险。

## 14. 版本

本特性作为 **1.1.0** 发布(新增 CLI flag、config 段、state 字段、root helper 与安装流程)。
