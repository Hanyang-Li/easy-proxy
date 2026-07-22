# 设计:daemon 健康检查看门狗与自动重连(0.3.0)

日期:2026-07-22
分支:`feat/healthcheck-watchdog`

## 1. 背景与问题

`connect` 后会 `setsid` 拉起一个常驻后台 daemon(`__serve`),daemon 再管一个 zju-connect 子进程建立隧道,并在混合端口上按首字节嗅探转发(`src/daemon.rs`)。

当前的状态判定只看两件事(`src/lib.rs` `connected_state`):`state.json` 里 `connected==true` 且 `pid_alive(daemon_pid)`。因此**断网(尤其带 MBP 在路上:合盖休眠、WiFi 切蜂窝、隧道口反复断连)时**:

- 若 zju-connect 进程未退出(常见),`state.json` 仍是 `connected:true`、pid 仍活,status **一直显示 online**,不会自动 offline;仅延迟探测 `probe_latency` 失败会让胶囊显示 `online + timeout`。
- 只有 zju-connect 进程真正退出,daemon 才会 break 主循环、`clear_state` 并退出,status 才变 offline。

daemon 目前**没有健康检查、没有重连**:主循环(`src/daemon.rs` `run`)只被动 `select!` 三件事(accept、`child.wait()`、SIGTERM/SIGINT),无周期性探测。

## 2. 目标与非目标

**目标**
- daemon 周期性用延迟探针检测连通性;断线自动尝试恢复,恢复失败进入 offline 终态。
- 恢复分级、短信节流,避免频繁断连导致短信轰炸。
- 状态对用户可见语义清晰:online / (对外仍显示 offline 的)重连中 / offline。
- 用户手动 `connect` 与后台自动重连并发时不打架。

**非目标**
- 不改隧道底层协议、不改 zju-connect 调用参数。
- 不做"重连中"的独立视觉胶囊(重连期间对外显示 offline)。
- 不引入除 `state.json` 之外的任何新持久化文件。
- 不订阅本机网络/唤醒事件;连通性检测采用**固定周期纯轮询**(事件触发+长兜底留作未来 0.3.x 增强)。

## 3. daemon 状态机

`state.json` 的 `phase` 字段表达常驻态。**offline 不是常驻态,而是 daemon 退出、无 state 文件**(与现状一致)。

```
[启动] 用 connect 传入的 TWFID 起 zju-connect → 就绪 → ONLINE

ONLINE  (phase=Online, 探测通)
  每 healthcheck_interval(默认 15s) 探测一次
  ├─ 通            → 保持 ONLINE
  └─ 连续 healthcheck_fail_threshold(默认 2) 次失败 → RECONNECTING

RECONNECTING  (phase=Reconnecting, daemon 活着, status 对外显示 offline)
  step1  用【当前 TWFID】重启 zju-connect(不吃重登额度)
         ├─ 就绪且探测通 → ONLINE
         └─ 失败        → step2
  step2  闸门: now - last_sms_sent >= silent_relogin_interval(默认 3600s)?
         ├─ 否(距上次发码不足间隔) → OFFLINE 终态, 不发码
         └─ 是 → 静默重登(钥匙串密码 + sms_command 取码 + submit_sms; 发码刷新 last_sms_sent)
                 ├─ 成功 → 用新 TWFID 重启 zju-connect → ONLINE
                 └─ 失败(取不到码/被拒到上限/没配 sms_command) → OFFLINE 终态

OFFLINE  终态
  kill zju-connect + clear_state + daemon 进程退出(不残留)
  → 之后 status 读不到 state = offline, 等用户手动 connect
```

## 4. 限流语义(核心)

闸门时间戳是 **`last_sms_sent`(上次实际发送验证码的 unix 秒)**,**不是**"上次静默重登"。

- **任何发码都刷新它**:手动 connect 登录时初次下发的、补发的(`resend_sms`)、静默重登时下发的,全部刷新。
- 它**只 gate 下一次"静默重登"**;**用户手动 connect 永不受限**(用户主动要连就立即发),但手动发码也会刷新时间戳,从而顺延之后静默重登的可发时机。
- 静默重登开始前检查 `now - last_sms_sent >= silent_relogin_interval`;不满足直接 offline 终态。

**场景自检**
- 手动 connect 于 t0 发码连上(`last_sms_sent=t0`)→ t0+20min 断连、旧 TWFID 无效 → 静默重登检查 `20min < 1h` → 不发码 → offline 终态退出。✓
- 若 t0+90min 才断,旧 TWFID 无效 → `90min > 1h` → 允许静默重登发码,成功则记 `last_sms_sent=t0+90min`。✓

**存储与生命周期**:`last_sms_sent` 只活在 `state.json` 里。connect 是自己发的码、知道时刻,`spawn_daemon` 时作为参数传给 daemon 写入初值;daemon 静默重登读/写的都是 `state.json` 该字段。daemon 退出后该字段随 state 清掉无妨——下次一定是手动 connect 起新 daemon,会带上新的发码时刻。

## 5. connect 命令的接管(方案 Z)

前台 connect 有 tty,daemon 无 tty。"接管" = **停掉旧 daemon + 完整走一遍现有 connect 流程**,复用现有交互与文案,daemon 永不碰 tty。

```
connect 读 state:
  ├─ 有活 daemon 且 phase=Online        → "已经在连接中"(现有行为, 不额外探测)
  ├─ 有活 daemon 且 phase=Reconnecting  → 【Z】SIGTERM 杀它, 轮询 pid 直到退出(带超时),
  │                                        再走现有完整 connect → spawn 新 daemon
  └─ 无活 daemon(offline/无 state)      → 走现有完整 connect → spawn 新 daemon(现有行为)
```

- `mixed_port` 在杀旧起新之间有毫秒级空窗;reconnecting 时隧道本已断,基本无感。
- Z 依赖"恢复可被打断"(见 §8),否则 SIGTERM 无法及时终止正在跑登录的 daemon。

## 6. 数据结构(单一 state.json)

`src/config.rs` `RuntimeState` 扩展;新字段全部 `#[serde(default)]` 保证向后兼容:

```rust
pub enum Phase { Online, Reconnecting }   // Serialize/Deserialize; offline = 无 state 文件

pub struct RuntimeState {
    pub phase: Phase,                 // 新增(替代 connected: bool)
    pub daemon_pid: i32,
    pub port: u16,
    pub socks_upstream: String,
    pub http_upstream: String,
    pub server: String,
    pub tunnel_ip: String,
    pub last_sms_sent: Option<u64>,   // 新增: 上次发码 unix 秒, 静默重登闸门用
    pub error: Option<String>,
}
```

- `connected_state()` 改为 `phase==Online && pid_alive(daemon_pid)`。
- `read_state` 保持"解析失败即 None"(旧 state 残留被安全当作未连接)。
- 需要一个"活着的 daemon(不论 Online/Reconnecting)"判定,供 connect 的 Z 分支识别 reconnecting daemon。

## 7. config 新增字段(带默认)

`src/config.rs` `AppConfig`:

```
healthcheck_interval: u64        = 15      // 秒, 健康检查周期
healthcheck_fail_threshold: u32  = 2       // 连续失败几次判断线
silent_relogin_interval: u64     = 3600    // 秒, 静默重登最小间隔(闸门)
```

均 `#[serde(default = ...)]`,缺省用默认。README 的 config 示例同步补充。

## 8. 组件拆分与重构点

### 8.1 登录/取码核心逻辑抽出共用(部分重构)
现在"自动取码循环"埋在 `src/lib.rs` `auto_fetch_phase`,和前台 UI(`StatusLine`/`EscGuard`/手动回退)缠在一起。抽出一个参数化核心:

```
fetch_and_submit_loop(cfg, jar, {
    progress:        进度上报,        // 前台=StatusLine 原地刷新; daemon=写 daemon.log
    cancel:          取消探测,        // 前台=EscGuard(esc); daemon=shutdown flag
    manual_fallback: bool,           // 前台=true; daemon=false
    on_sms_sent:     刷新 last_sms_sent 回调,
}) -> Result<Option<twfid>>
```

- 前台 `auto_fetch_phase` 变成套壳调用,保持现有文案/行为不变。
- daemon 侧 `silent_login()` 也调它,`manual_fallback=false`、无 esc、进度打日志;取不到/被拒到上限 → `Err`。
- `login_password` 返回 `SmsSent`、`resend_sms` 成功两处,通过 `on_sms_sent` 刷新 `state.last_sms_sent`。

### 8.2 恢复编排(放 daemon.rs 内或新 recover.rs)
- `probe_ok()`:复用 `tunnel::probe_latency`,连续 `healthcheck_fail_threshold` 次失败才算断。
- `restart_with_old_twfid()`:kill 旧 zju-connect → 用当前 TWFID 重启 → `wait_socks_ready` → 探测确认。不吃闸门。
- `silent_relogin()`:闸门检查通过 → `silent_login()` 拿新 TWFID → 重启 zju-connect。
- `recover()`:编排 step1→step2,任一成功回 `Online`,全败 → `Offline` 终态(break 主循环 → 现有 cleanup 退出)。**决策部分抽成注入式纯函数**(见 §10)。

### 8.3 daemon 主循环集成(并发关键点)
zju-connect 的 `child` 句柄持有/重启收敛到一个 "supervisor";`relay` 只依赖固定上游地址(1080/1081,不变)。主 `select!` 增加 `interval.tick()` 分支:到点用 `tokio::task::spawn_blocking` 跑同步的探测/恢复(登录/探测都是同步 curl 子进程,不能阻塞 accept 循环)。恢复期间 `phase=Reconnecting`;成功回 `Online`,失败退出。

### 8.4 daemon 改为也读 config
现在 `serve` 分支在 `read_app_config` 之前返回,daemon 只靠 `ServeArgs`。静默重登需要 `username`/`sms_command`/`sms_retries`/`sms_retry_interval_secs`/新增间隔等。改为 **daemon `serve` 启动时也 `read_app_config`**;`ServeArgs` 只留运行时必需(twfid/server/port/mixed/socks/http + `last_sms_sent` 初值)。

### 8.5 tunnel.rs
- `spawn_daemon` 增加 `last_sms_sent` 参数,透传给 `__serve`。
- connect 撞 Reconnecting:复用 `stop_daemon` 杀旧 + 轮询退出 + 正常流程(Z)。

## 9. 错误处理与边界

1. **恢复必须可被打断(最重要)**:`spawn_blocking` 里的同步登录不会被 tokio 自动取消。用共享 `AtomicBool` shutdown flag——主循环收到 SIGTERM/SIGINT 时置位并 `start_kill` zju-connect;`silent_login` 每轮迭代、`sleep` 前后检查该 flag,置位则杀掉当前 `sms_command` 子进程并尽快返回。保证 daemon 及时干净退出(Z 依赖此)。
2. **Z 释放竞态**:connect 走 Z 时 SIGTERM 旧 daemon 后**轮询 `pid_alive` 直到退出(带超时)再 spawn**,避免新 daemon `bind(mixed_port)` 撞旧端口(`daemon.rs` bind 失败已有兜底,但主动避免)。
3. **旧 TWFID 失效**:`restart_with_old_twfid` 中 zju-connect 启动即退出,`wait_socks_ready` 已能检测 → Err → 升级 step2。
4. **没配 sms_command**:step2 直接失败 → offline 终态。即"断线→旧TWFID重启,成功 online / 失败直接 offline 退出"。
5. **向后兼容**:新字段全 `#[serde(default)]`;`read_state` 解析失败即 None(旧 state 安全当未连接)。
6. **恢复期间 relay**:只依赖固定上游,zju-connect 重启后自动恢复;窗口内新连接失败为预期。

## 10. 测试策略

核心思路:**把 `recover()` 的决策抽成注入式纯函数重点单测,副作用(curl/kill/keychain)靠手动验证**。

**单元测(不碰网络)**
- 闸门 `now - last_sms_sent >= interval` 边界(小于/等于/大于/`None`)。
- 连续失败阈值计数(给一串探测结果,判定何时进 reconnecting)。
- 状态机决策纯函数:注入(探测结果、旧TWFID重启结果、闸门、重登结果)→ 断言下一步(回 Online / 升级 / offline 退出),覆盖所有分支。
- config 缺字段用默认值;`RuntimeState`/`Phase` serde round-trip + 旧 json 兼容。
- 现有 `relay` 首字节路由测试保持通过。

**手动/集成验证(碰真实网关/钥匙串/tty)**
- 钥匙串后台访问是否弹框(风险 §11)。
- 真实断网 → 旧 TWFID 重启表现。
- 静默重登端到端(`sms_command` 真能取码)。
- Z 接管:reconnecting 时手动 connect 的完整文案体验。
- SIGTERM 能否及时打断正在 sleep/curl 的恢复。

## 11. 风险点

- **macOS 钥匙串后台访问**:daemon 无 tty 调 `keychain::get_password` 时首次可能弹授权框。同签名 binary 访问同一 item 通常不弹或可"始终允许",但必须实测;否则静默重登会卡在授权框上。若确认会弹,退路:静默重登失败即 offline(用户手动 connect 时前台仍可正常访问钥匙串)。

## 12. 资源与稳定性约束(长命 daemon)

daemon 可能连续运行数天,健康检查每 `healthcheck_interval` 触发一次,必须杜绝累积增长。以下为实现硬约束:

1. **子进程必回收**:每次 probe 的 curl(`probe_latency` 用 `Command::output()` 已内部 wait)、`sms_command`(`run_sms_command` 已 try_wait+wait)、以及重启 zju-connect 时对**旧 child** 必须 `start_kill` 后 `wait().await` 回收,严禁僵尸累积。
2. **不泄漏 tokio 任务**:relay 每连接 spawn 的任务随连接结束而结束;健康检查用 `spawn_blocking`,任务返回即回收;不在循环里 spawn 永不结束的任务。
3. **定长状态**:连续失败计数(u32)、`last_sms_sent`(u64)等为定长,不随时间累积。
4. **日志不因健康检查膨胀**:online 态探测通时**不打日志**;只在状态迁移(online↔reconnecting、恢复成功/失败、offline 退出)时各打一行。
5. **state.json 只在 phase 变化时写**:正常 online 轮询探通不重写 state,避免每 15s 写盘。
6. **tail 读日志改为只读末尾 N 字节**:`tail()`/`wait_socks_ready` 现在 `read_to_string` 整个 tunnel_log;改为 seek 到末尾读固定字节,避免日志变大后每次恢复读全文件。
7. **休眠**:合盖休眠时进程挂起不跑;唤醒后 tokio timer 立即到期补探一次,无需特殊处理。

**预期占用**:每 15s 一次 curl 探测(毫秒级 CPU、几十 KB 网络、子进程秒级回收),平均 CPU 占用可忽略(<0.1%);daemon 常驻内存固定、无累积;daemon.log 常态不增长。

## 13. 版本

本特性作为 **0.3.0** 发布(含状态结构、config、daemon 行为的较大变更)。
