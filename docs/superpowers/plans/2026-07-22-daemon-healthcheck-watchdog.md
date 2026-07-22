# daemon 健康检查看门狗与自动重连 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让后台 daemon 周期性探测隧道连通性,断线时分级自动恢复(旧 TWFID 重启 → 静默重登),恢复失败进入 offline 终态并干净退出;用户手动 connect 与自动重连并发时不打架。

**Architecture:** daemon(tokio)主循环新增一个 `interval.tick()` 分支,每 15s 用同步 `probe_latency`(curl,`spawn_blocking`)探测;连续失败进 Reconnecting。恢复编排在 daemon async 上下文里管 zju-connect 子进程,把同步登录(curl)丢 `spawn_blocking`。所有新运行时状态并入单一 `state.json`。connect 撞上 Reconnecting 走"杀旧 daemon + 完整重连"(方案 Z)。

**Tech Stack:** Rust 2021,tokio(rt-multi-thread/net/process/time/signal),serde,同步 `/usr/bin/curl` 子进程做登录与探测。

## Global Constraints

- Rust edition 2021;不新增第三方 crate(纯轮询,不引入网络事件监听依赖)。
- 登录/探测复用现有同步 curl 函数(`login::*`、`tunnel::probe_latency`),daemon 里用 `tokio::task::spawn_blocking` 调用。
- 只有一个持久化文件 `state.json`;新字段全部 `#[serde(default)]`。
- 默认值:`healthcheck_interval=15`(秒)、`healthcheck_fail_threshold=2`、`silent_relogin_interval=3600`(秒)。
- 资源红线(长命 daemon):子进程必 `wait` 回收;不泄漏 tokio 任务;online 探通时**不打日志、不重写 state**;日志 tail 只读末尾固定字节。
- 中文文案,与现有 connect 保持一致;offline = daemon 退出、无 state 文件(不残留)。
- commit message 中文,结尾附 `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`。

---

### Task 1: 状态结构与 config 字段(Phase / RuntimeState / AppConfig)

**Files:**
- Modify: `src/config.rs`(RuntimeState、AppConfig、新增 Phase、now_unix helper)
- Modify: `src/daemon.rs:53-62`、`src/daemon.rs:96`(state 构造与就绪迁移)
- Modify: `src/tunnel.rs:51`(wait_ready 判定)
- Modify: `src/lib.rs:439`、`src/lib.rs:516-520`(connect 已连接判定、connected_state)

**Interfaces:**
- Produces:
  - `config::Phase { Online, Reconnecting }`(`Serialize/Deserialize/Clone/Copy/PartialEq/Eq/Debug`,`Default=Reconnecting`)
  - `config::RuntimeState.phase: Phase`(取代 `connected: bool`)、`config::RuntimeState.last_sms_sent: Option<u64>`
  - `config::AppConfig.healthcheck_interval: u64`、`healthcheck_fail_threshold: u32`、`silent_relogin_interval: u64`
  - `config::now_unix() -> u64`(SystemTime → unix 秒)

- [ ] **Step 1: 写失败测试**(`src/config.rs` `#[cfg(test)] mod tests` 内追加)

```rust
#[test]
fn phase_default_is_reconnecting() {
    assert_eq!(Phase::default(), Phase::Reconnecting);
}

#[test]
fn runtime_state_roundtrip_and_legacy_compat() {
    // 新结构 round-trip
    let st = RuntimeState { phase: Phase::Online, daemon_pid: 42, port: 7899,
        socks_upstream: "127.0.0.1:1080".into(), http_upstream: "127.0.0.1:1081".into(),
        server: "vpn.example.com".into(), tunnel_ip: "10.0.0.1".into(),
        last_sms_sent: Some(1000), error: None };
    let json = serde_json::to_string(&st).unwrap();
    let back: RuntimeState = serde_json::from_str(&json).unwrap();
    assert_eq!(back.phase, Phase::Online);
    assert_eq!(back.last_sms_sent, Some(1000));
    // 旧 0.2.x json(有 connected、无 phase/last_sms_sent)应能解析,phase 落默认
    let legacy = r#"{"connected":true,"daemon_pid":1,"port":7899,"socks_upstream":"a","http_upstream":"b","server":"s","tunnel_ip":"","error":null}"#;
    let parsed: RuntimeState = serde_json::from_str(legacy).unwrap();
    assert_eq!(parsed.phase, Phase::Reconnecting); // default
    assert_eq!(parsed.last_sms_sent, None);
}

#[test]
fn appconfig_defaults_present() {
    let c = AppConfig::default();
    assert_eq!(c.healthcheck_interval, 15);
    assert_eq!(c.healthcheck_fail_threshold, 2);
    assert_eq!(c.silent_relogin_interval, 3600);
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test --lib config::tests 2>&1 | tail -20`
Expected: 编译失败(`Phase` 未定义 / 字段不存在)。

- [ ] **Step 3: 实现**

`src/config.rs`:
- 顶部 `use std::time::{SystemTime, UNIX_EPOCH};`
- 新增:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase { Online, Reconnecting }
impl Default for Phase { fn default() -> Self { Phase::Reconnecting } }

pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
```
- `RuntimeState`:删除 `pub connected: bool`,新增
```rust
    #[serde(default)]
    pub phase: Phase,
    // ...其余不变...
    #[serde(default)]
    pub last_sms_sent: Option<u64>,
```
  (保留 `#[derive(..., Default)]`;`error` 保持 `#[serde(default)]`。)
- `AppConfig` 追加字段与默认函数:
```rust
    #[serde(default = "default_healthcheck_interval")]
    pub healthcheck_interval: u64,
    #[serde(default = "default_healthcheck_fail_threshold")]
    pub healthcheck_fail_threshold: u32,
    #[serde(default = "default_silent_relogin_interval")]
    pub silent_relogin_interval: u64,
```
```rust
fn default_healthcheck_interval() -> u64 { 15 }
fn default_healthcheck_fail_threshold() -> u32 { 2 }
fn default_silent_relogin_interval() -> u64 { 3600 }
```
  并在 `impl Default for AppConfig` 里补 `healthcheck_interval: 15, healthcheck_fail_threshold: 2, silent_relogin_interval: 3600`。

引用点改造(使项目编译通过):
- `src/daemon.rs:53-62`:`connected: false,` → `phase: crate::config::Phase::Reconnecting,`;并加 `last_sms_sent: None,`(初值,Task 5 再从 args 填)。
- `src/daemon.rs:96`:`state.connected = true;` → `state.phase = crate::config::Phase::Online;`
- `src/tunnel.rs:51`:`if st.connected {` → `if st.phase == crate::config::Phase::Online {`
- `src/lib.rs:439`:`if st.connected && tunnel::pid_alive(st.daemon_pid) {` → `if st.phase == config::Phase::Online && tunnel::pid_alive(st.daemon_pid) {`
- `src/lib.rs:519`:`.filter(|s| s.connected && tunnel::pid_alive(s.daemon_pid))` → `.filter(|s| s.phase == config::Phase::Online && tunnel::pid_alive(s.daemon_pid))`

- [ ] **Step 4: 运行确认通过**

Run: `cargo test --lib 2>&1 | tail -20`
Expected: 全绿(含既有 relay/mask 测试)。

- [ ] **Step 5: commit**

```bash
git add src/config.rs src/daemon.rs src/tunnel.rs src/lib.rs
git commit -m "$(printf 'feat: RuntimeState 引入 Phase(online/reconnecting) 与 last_sms_sent, config 加健康检查字段\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 2: 日志 tail 改为只读末尾固定字节

**Files:**
- Modify: `src/config.rs`(新增 `Paths::read_tail(&self, path, max) ` 或独立 helper)
- Modify: `src/tunnel.rs:71-75`(`read_tail`)
- Modify: `src/daemon.rs:172-176`(`tail`)、`daemon.rs:155`(`wait_socks_ready` 内读取)

**Interfaces:**
- Produces: `config::read_tail_bytes(path: &std::path::Path, max: usize) -> String`(seek 到末尾读 ≤max 字节,UTF-8 lossy)

- [ ] **Step 1: 写失败测试**(`src/config.rs` tests 内)

```rust
#[test]
fn read_tail_bytes_returns_only_suffix() {
    let dir = std::env::temp_dir();
    let p = dir.join(format!("ep_tail_test_{}.log", std::process::id()));
    std::fs::write(&p, "0123456789ABCDEF").unwrap();
    let tail = read_tail_bytes(&p, 4);
    let _ = std::fs::remove_file(&p);
    assert_eq!(tail, "CDEF");
}

#[test]
fn read_tail_bytes_shorter_than_max_ok() {
    let dir = std::env::temp_dir();
    let p = dir.join(format!("ep_tail_test2_{}.log", std::process::id()));
    std::fs::write(&p, "abc").unwrap();
    let tail = read_tail_bytes(&p, 100);
    let _ = std::fs::remove_file(&p);
    assert_eq!(tail, "abc");
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test --lib config::tests::read_tail 2>&1 | tail -20`
Expected: 编译失败(`read_tail_bytes` 未定义)。

- [ ] **Step 3: 实现**

`src/config.rs`(模块级 `pub fn`):
```rust
use std::io::{Read, Seek, SeekFrom};

pub fn read_tail_bytes(path: &std::path::Path, max: usize) -> String {
    let mut f = match std::fs::File::open(path) { Ok(f) => f, Err(_) => return String::new() };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(max as u64);
    if f.seek(SeekFrom::Start(start)).is_err() { return String::new(); }
    let mut buf = Vec::with_capacity(max.min(len as usize));
    if f.read_to_end(&mut buf).is_err() { return String::new(); }
    String::from_utf8_lossy(&buf).to_string()
}
```
改造调用点:
- `src/tunnel.rs` `read_tail`:改为 `crate::config::read_tail_bytes(&paths.tunnel_log, bytes)`。
- `src/daemon.rs` `tail`:改为 `crate::config::read_tail_bytes(&paths.tunnel_log, 1000)`。
- `src/daemon.rs` `wait_socks_ready`(155 行 `read_to_string` 用于匹配 `SOCKS5 server listening`):仍需读足够内容做匹配——改为 `read_tail_bytes(&paths.tunnel_log, 8192)` 后做 `contains`/正则(就绪标志一定在近尾部,8KB 足够)。

- [ ] **Step 4: 运行确认通过**

Run: `cargo test --lib 2>&1 | tail -20`
Expected: 全绿。

- [ ] **Step 5: commit**

```bash
git add src/config.rs src/tunnel.rs src/daemon.rs
git commit -m "$(printf 'perf: 日志 tail 改为 seek 末尾读固定字节, 避免日志变大后读全文\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 3: 抽取取码核心到 `src/sms.rs`(SmsUi + fetch_and_submit_loop + should_resend)

**Files:**
- Create: `src/sms.rs`
- Modify: `src/lib.rs`(`mod sms;`;`auto_fetch_phase` 改为构造 TtyUi 调核心;迁出 `run_sms_command`/`SmsFetch`/`valid_sms_code`)

**Interfaces:**
- Consumes: `login::submit_sms`、`login::resend_sms`(现有,同步);`config::AppConfig`;`config::now_unix`
- Produces:
```rust
pub enum SmsFetch { Code(String), Empty, Cancelled }
pub trait SmsUi {
    fn progress(&self, text: &str);
    fn finish_ok(&self, text: &str);
    fn finish_err(&self, text: &str);
    fn is_cancelled(&self) -> bool;                 // esc / shutdown flag
    fn sleep_cancelable(&self, dur: std::time::Duration) -> bool; // true=中途取消
    fn allow_manual_fallback(&self) -> bool;        // 前台=true, daemon=false
}
pub fn valid_sms_code(raw: &str) -> Option<String>;
pub fn run_sms_command(command: &str, timeout: std::time::Duration, ui: &dyn SmsUi) -> SmsFetch;
pub fn should_resend(prev_empty: Option<bool>) -> bool; // Some(true)=没取到→补发
/// 自动取码主循环;成功 Some(twfid);落空 None(调用方决定回退/失败)。每次发码后调 on_sms_sent。
pub fn fetch_and_submit_loop(
    cfg: &config::AppConfig, jar: &std::path::Path, cmd: &str,
    ui: &dyn SmsUi, on_sms_sent: &dyn Fn(),
) -> anyhow::Result<Option<String>>;
```

- [ ] **Step 1: 写失败测试**(`src/sms.rs` tests)

```rust
#[test]
fn should_resend_only_on_prev_empty() {
    assert_eq!(should_resend(None), false);        // 首轮不补发
    assert_eq!(should_resend(Some(true)), true);   // 上轮没取到→补发
    assert_eq!(should_resend(Some(false)), false); // 上轮被拒→不补发
}

#[test]
fn valid_sms_code_rules() {
    assert_eq!(valid_sms_code(" 123456 ").as_deref(), Some("123456"));
    assert_eq!(valid_sms_code("12"), None);       // 太短
    assert_eq!(valid_sms_code("12ab56"), None);   // 非数字
    assert_eq!(valid_sms_code(""), None);
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test --lib sms:: 2>&1 | tail -20`
Expected: 编译失败(`sms` 模块不存在)。

- [ ] **Step 3: 实现**

1. `src/lib.rs` 顶部加 `mod sms;`。
2. 迁移 `SmsFetch`、`valid_sms_code`、`run_sms_command` 到 `sms.rs`;`run_sms_command` 的 `esc: Option<&EscGuard>` 参数改为 `ui: &dyn SmsUi`,内部 `esc.esc_pressed()` 改 `ui.is_cancelled()`。
3. `sms.rs` 新增:
```rust
pub fn should_resend(prev_empty: Option<bool>) -> bool { matches!(prev_empty, Some(true)) }
```
4. `fetch_and_submit_loop`:把 `lib.rs::auto_fetch_phase` 循环骨架搬来,替换:
   - `line.progress(...)` → `ui.progress(...)`;`line.finish(err/ok)` → `ui.finish_err/finish_ok`
   - `login::resend_sms(...)` 成功后调 `on_sms_sent()`
   - `sleep_cancelable(retry_wait, esc)` → `ui.sleep_cancelable(retry_wait)`
   - `run_sms_command(cmd, TIMEOUT, esc)` → `run_sms_command(cmd, TIMEOUT, ui)`
   - 是否补发用 `should_resend(prev_empty)`
   - `SMS_COMMAND_TIMEOUT` 常量迁到 `sms.rs`
   返回 `Some(twfid)` / `None`。
5. `src/lib.rs` 新增前台 UI:
```rust
struct TtyUi { line: StatusLine, esc: Option<EscGuard> }
impl sms::SmsUi for TtyUi {
    fn progress(&self, t: &str) { self.line.progress(t); }
    fn finish_ok(&self, t: &str) { self.line.finish(t); }
    fn finish_err(&self, t: &str) { self.line.finish(t); }
    fn is_cancelled(&self) -> bool { self.esc.as_ref().map(|e| e.esc_pressed()).unwrap_or(false) }
    fn sleep_cancelable(&self, dur: std::time::Duration) -> bool { sleep_cancelable(dur, self.esc.as_ref()) }
    fn allow_manual_fallback(&self) -> bool { true }
}
```
   注意:`progress`/`finish_ok`/`finish_err` 需要 `success_line`/`error_line` 包装的文案——沿用原 `auto_fetch_phase` 里对 `success_line("[自动] 验证码已通过", ...)` 等的调用,即在 `fetch_and_submit_loop` 内构造好带前缀的文案字符串再传给 `ui`(保持现有中文文案逐字不变)。为此 `fetch_and_submit_loop` 需要 `cfg`(拿 `prompt`)。
6. 重写 `auto_fetch_phase`:
```rust
fn auto_fetch_phase(cfg: &AppConfig, jar: &Path, cmd: &str) -> Result<Option<String>> {
    let ui = TtyUi { line: StatusLine::new(), esc: EscGuard::new() };
    let noop = || {};
    sms::fetch_and_submit_loop(cfg, jar, cmd, &ui, &noop)
}
```
   `manual_phase` 保持不变;`obtain_twfid` 调 `auto_fetch_phase` 落空后回退 `manual_phase` 的结构不变。
7. `on_sms_sent` 前台此处先用 no-op(Task 5 换成刷新发码时刻)。

- [ ] **Step 4: 运行确认通过 + 手动核对文案**

Run: `cargo test --lib 2>&1 | tail -20`
Expected: 全绿。
核对:`git diff` 确认 `[自动] 第 N/max 次取码…`、`[自动] 验证码已通过`、`[自动] 未取到验证码,回退手动输入`、`[自动] 已取消自动取码,转手动输入`、补发失败文案逐字未变。

- [ ] **Step 5: commit**

```bash
git add src/sms.rs src/lib.rs
git commit -m "$(printf 'refactor: 取码主循环抽到 sms 模块, 用 SmsUi trait 注入 UI, 前台行为不变\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 4: daemon 无-tty 静默登录 `silent_login`

**Files:**
- Modify: `src/sms.rs`(新增 `DaemonUi` 与 `silent_login`)
- Modify: `src/login.rs`(无需改;复用 `login_password`/`submit_sms`/`resend_sms`)

**Interfaces:**
- Consumes: `login::login_password`、`keychain::get_password`、`Task 3` 的 `fetch_and_submit_loop`
- Produces:
```rust
/// daemon 侧无 tty 静默登录:钥匙串取密码 → login_password(发码,调 on_sms_sent)
/// → fetch_and_submit_loop(自动取码,无手动回退,cancel 走 shutdown flag) → twfid。
/// 取不到/被拒到上限/没配 sms_command/密码被拒/无密码 → Err。
pub fn silent_login(
    cfg: &config::AppConfig, jar: &std::path::Path,
    shutdown: &std::sync::atomic::AtomicBool, on_sms_sent: &dyn Fn(),
) -> anyhow::Result<String>;
```

- [ ] **Step 1: 写失败测试**(`src/sms.rs` tests;仅测"没配 sms_command 即刻 Err",不碰网络)

```rust
#[test]
fn silent_login_without_sms_command_errs_fast() {
    use std::sync::atomic::AtomicBool;
    let mut cfg = config::AppConfig::default();
    cfg.server = "127.0.0.1".into();       // 不会真连通;应在取码阶段前就因无 sms_command 失败
    cfg.username = "u".into();
    cfg.sms_command = None;
    // 无密码(钥匙串空 + 无环境变量)→ 应直接 Err,不阻塞
    std::env::remove_var("EASY_PROXY_PASSWORD");
    let jar = std::env::temp_dir().join(format!("ep_silent_{}.cookies", std::process::id()));
    let sd = AtomicBool::new(false);
    let noop = || {};
    let r = silent_login(&cfg, &jar, &sd, &noop);
    assert!(r.is_err());
}
```
   (说明:该用例覆盖"无凭据/无 sms_command 快速失败"路径,不依赖真实网关。)

- [ ] **Step 2: 运行确认失败**

Run: `cargo test --lib sms::tests::silent_login 2>&1 | tail -20`
Expected: 编译失败(`silent_login` 未定义)。

- [ ] **Step 3: 实现**

`src/sms.rs`:
```rust
use std::sync::atomic::{AtomicBool, Ordering};

struct DaemonUi<'a> { shutdown: &'a AtomicBool }
impl<'a> SmsUi for DaemonUi<'a> {
    fn progress(&self, t: &str) { eprintln!("[daemon] {t}"); }   // 进 daemon.log
    fn finish_ok(&self, t: &str) { eprintln!("[daemon] {t}"); }
    fn finish_err(&self, t: &str) { eprintln!("[daemon] {t}"); }
    fn is_cancelled(&self) -> bool { self.shutdown.load(Ordering::Relaxed) }
    fn sleep_cancelable(&self, dur: std::time::Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < dur {
            if self.shutdown.load(Ordering::Relaxed) { return true; }
            std::thread::sleep(std::time::Duration::from_millis(120));
        }
        false
    }
    fn allow_manual_fallback(&self) -> bool { false }
}

pub fn silent_login(
    cfg: &config::AppConfig, jar: &std::path::Path,
    shutdown: &AtomicBool, on_sms_sent: &dyn Fn(),
) -> anyhow::Result<String> {
    let cmd = cfg.sms_command.as_deref().map(str::trim).filter(|c| !c.is_empty())
        .ok_or_else(|| anyhow::anyhow!("未配置 sms_command, 无法静默重登"))?;
    let pwd = std::env::var("EASY_PROXY_PASSWORD").ok()
        .or_else(|| crate::keychain::get_password(&cfg.username))
        .ok_or_else(|| anyhow::anyhow!("钥匙串无密码, 无法静默重登"))?;
    match crate::login::login_password(&cfg.server, cfg.port, &cfg.username, &pwd, jar)? {
        crate::login::PwOutcome::PasswordRejected(m) => return Err(anyhow::anyhow!("密码被拒: {m}")),
        crate::login::PwOutcome::SmsSent { .. } => { on_sms_sent(); }   // 已发码
    }
    if shutdown.load(Ordering::Relaxed) { return Err(anyhow::anyhow!("shutdown")); }
    let ui = DaemonUi { shutdown };
    match fetch_and_submit_loop(cfg, jar, cmd, &ui, on_sms_sent)? {
        Some(twfid) => Ok(twfid),
        None => Err(anyhow::anyhow!("静默取码失败")),
    }
}
```

- [ ] **Step 4: 运行确认通过**

Run: `cargo test --lib 2>&1 | tail -20`
Expected: 全绿(新用例快速返回 Err)。

- [ ] **Step 5: commit**

```bash
git add src/sms.rs
git commit -m "$(printf 'feat: sms::silent_login, daemon 无 tty 静默登录(钥匙串密码+自动取码), 可被 shutdown 打断\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 5: `last_sms_sent` 端到端贯通

**Files:**
- Modify: `src/tunnel.rs`(`spawn_daemon` 加参数)
- Modify: `src/daemon.rs`(`ServeArgs` 加字段;写入初值)
- Modify: `src/lib.rs`(`cmd_connect` 记录发码时刻并传参;前台 `on_sms_sent` 改为刷新)

**Interfaces:**
- Consumes: `config::now_unix`
- Produces:
  - `tunnel::spawn_daemon(paths, cfg, twfid, last_sms_sent: u64)`(签名新增末位参数)
  - `daemon::ServeArgs.last_sms_sent: u64`(`--last-sms-sent`)

- [ ] **Step 1: 实现(此任务以编译 + 手动验证为主,无独立单测)**

1. `src/daemon.rs` `ServeArgs` 加:
```rust
    #[arg(long = "last-sms-sent", default_value_t = 0)]
    last_sms_sent: u64,
```
   `run()` 里 state 初值:`last_sms_sent: if args.last_sms_sent == 0 { None } else { Some(args.last_sms_sent) },`
2. `src/tunnel.rs` `spawn_daemon` 签名加 `last_sms_sent: u64`,并在命令里 `.arg("--last-sms-sent").arg(last_sms_sent.to_string())`。
3. `src/lib.rs` `cmd_connect`:
   - 在 `twfid` 循环外声明 `let last_sms = std::cell::Cell::new(0u64);`
   - `login::PwOutcome::SmsSent { phone }` 分支里,进入 `obtain_twfid` 前 `last_sms.set(config::now_unix());`(初次发码时刻)
   - `obtain_twfid`/`auto_fetch_phase` 传入 `on_sms_sent = || last_sms.set(config::now_unix())`(补发时刷新)。为此把 `on_sms_sent` 从 `auto_fetch_phase` 一路传入 `sms::fetch_and_submit_loop`(替换 Task 3 的 no-op)。
   - `tunnel::spawn_daemon(paths, cfg, &twfid, last_sms.get())`

- [ ] **Step 2: 运行确认编译 + 既有测试通过**

Run: `cargo test --lib 2>&1 | tail -20 && cargo build 2>&1 | tail -5`
Expected: 全绿 + build 成功。

- [ ] **Step 3: commit**

```bash
git add src/tunnel.rs src/daemon.rs src/lib.rs
git commit -m "$(printf 'feat: last_sms_sent 从 connect 发码时刻贯通到 daemon state(spawn 参数)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 6: 恢复决策纯函数 `src/recover.rs`

**Files:**
- Create: `src/recover.rs`
- Modify: `src/lib.rs`(`mod recover;`)

**Interfaces:**
- Produces:
```rust
pub fn should_enter_reconnect(consecutive_fails: u32, threshold: u32) -> bool;
pub fn relogin_allowed(now: u64, last_sms_sent: Option<u64>, interval: u64) -> bool;
```

- [ ] **Step 1: 写失败测试**(`src/recover.rs` tests)

```rust
#[test]
fn enter_reconnect_at_threshold() {
    assert!(!should_enter_reconnect(1, 2));
    assert!(should_enter_reconnect(2, 2));
    assert!(should_enter_reconnect(3, 2));
}

#[test]
fn relogin_gate_semantics() {
    // 从未发码 → 允许
    assert!(relogin_allowed(1000, None, 3600));
    // 距上次发码不足 interval → 拒绝
    assert!(!relogin_allowed(1000, Some(900), 3600));  // 100s < 3600
    // 恰好达到 interval → 允许
    assert!(relogin_allowed(4600, Some(1000), 3600));  // 3600 >= 3600
    // 时钟回拨(now < last)→ saturating, 不允许
    assert!(!relogin_allowed(500, Some(1000), 3600));
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test --lib recover:: 2>&1 | tail -20`
Expected: 编译失败(模块不存在)。

- [ ] **Step 3: 实现**

`src/recover.rs`:
```rust
//! 恢复决策纯函数(可单测);副作用编排在 daemon.rs。
pub fn should_enter_reconnect(consecutive_fails: u32, threshold: u32) -> bool {
    consecutive_fails >= threshold
}
pub fn relogin_allowed(now: u64, last_sms_sent: Option<u64>, interval: u64) -> bool {
    match last_sms_sent {
        Some(t) => now.saturating_sub(t) >= interval,
        None => true,
    }
}
```
`src/lib.rs` 顶部加 `mod recover;`。

- [ ] **Step 4: 运行确认通过**

Run: `cargo test --lib recover:: 2>&1 | tail -20`
Expected: 全绿。

- [ ] **Step 5: commit**

```bash
git add src/recover.rs src/lib.rs
git commit -m "$(printf 'feat: recover 恢复决策纯函数(断线阈值/静默重登闸门)+单测\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 7: daemon 骨架 —— 读 config + 健康检查轮询 + 状态迁移 + shutdown flag

**Files:**
- Modify: `src/lib.rs:62-64`(`serve` 分支改为也读 config 后调用)
- Modify: `src/daemon.rs`(`serve`/`run` 签名带 cfg;主循环加 interval + 失败计数 + shutdown flag;状态迁移日志/写策略)

**Interfaces:**
- Consumes: `tunnel::probe_latency`、`recover::should_enter_reconnect`、`config::{AppConfig, Phase}`
- Produces: `daemon::serve(args, cfg, paths)`(签名新增 `cfg: AppConfig`)
- 说明:本任务恢复动作先做**最小实现**——探测判定断线后**直接进 OFFLINE 终态退出**(kill+clear+break)。Task 8 再接入真正的分级恢复。

- [ ] **Step 1: 实现(集成任务,单测在 Task 6 已覆盖决策;此处编译 + 手动验证)**

1. `src/lib.rs`:
```rust
    if let Commands::Serve(args) = &cli.command {
        let cfg = paths.read_app_config()?;
        return daemon::serve(args.clone(), cfg, &paths);
    }
```
2. `src/daemon.rs`:
   - `pub fn serve(args: ServeArgs, cfg: AppConfig, paths: &Paths) -> Result<()>`,`run(args, cfg, paths)`。
   - `run` 内 ready 之后,建 `let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));`
   - 建探测计时器:`let mut tick = tokio::time::interval(Duration::from_secs(cfg.healthcheck_interval.max(1)));` 并 `tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);`
   - `let mut fails: u32 = 0;`
   - 主 `select!` 增加分支:
```rust
            _ = tick.tick() => {
                let (port, server) = (args.mixed_port, args.server.clone());
                let ok = tokio::task::spawn_blocking(move || {
                    !matches!(crate::tunnel::probe_latency(port, &server), crate::capsule::Delay::Timeout)
                }).await.unwrap_or(false);
                if ok {
                    fails = 0;   // online: 不打日志、不重写 state
                } else {
                    fails += 1;
                    if crate::recover::should_enter_reconnect(fails, cfg.healthcheck_fail_threshold) {
                        eprintln!("[daemon] 探测连续失败 {fails} 次, 进入重连");
                        state.phase = crate::config::Phase::Reconnecting;
                        let _ = paths.write_state(&state);
                        // Task 8 将在此调用分级恢复; 骨架阶段: 直接放弃 → offline 终态
                        break;
                    }
                }
            }
```
   - SIGTERM/SIGINT 分支里置 `shutdown.store(true, Ordering::Relaxed);` 后 `break`(为 Task 8 的可打断恢复预留;骨架阶段仅 break)。
   - 循环退出后的清理沿用现有(`child.start_kill` + `wait` + `clear_state`)。

- [ ] **Step 2: 运行确认通过**

Run: `cargo test --lib 2>&1 | tail -10 && cargo build 2>&1 | tail -5`
Expected: 全绿 + build 成功。

- [ ] **Step 3: 手动验证(骨架:断线即退出)**

在能连的环境 `easy-proxy connect`;`easy-proxy status` 显示 online;断网 → 约 2×15s 后 daemon 退出、`status` 显示 offline;`~/.easy-proxy/daemon.log` 有"探测连续失败"一行。恢复网络需手动 connect(Task 8 前的预期行为)。

- [ ] **Step 4: commit**

```bash
git add src/lib.rs src/daemon.rs
git commit -m "$(printf 'feat: daemon 健康检查轮询骨架(读 config + interval 探测 + 断线阈值 + shutdown flag)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 8: 分级恢复接线(旧 TWFID 重启 → 闸门 → 静默重登)

**Files:**
- Modify: `src/daemon.rs`(`restart_zju` 辅助;`attempt_recover`;主循环调用)

**Interfaces:**
- Consumes: `recover::relogin_allowed`、`sms::silent_login`、`login`(重启用当前/新 twfid)、`config::now_unix`
- Produces(daemon 内部,不 pub):
```rust
async fn restart_zju(child: &mut Child, paths: &Paths, args: &ServeArgs, twfid: &str) -> Result<String>; // 返回 tunnel_ip
async fn attempt_recover(child, state, cfg, paths, args, twfid, shutdown) -> Phase; // Online=已恢复; Reconnecting 不返回; 放弃返回一个"应退出"信号
```

- [ ] **Step 1: 实现**

1. `restart_zju`:`child.start_kill(); let _ = child.wait().await;`(回收旧进程)→ 用给定 `twfid` 以 `zju_args` 重新 `Command::spawn`(复用现有 spawn 代码,写 tunnel_log)→ `wait_socks_ready(paths, child, 30s)` → 返回 ip。失败 Err。
2. `attempt_recover`(async):
```
// step1: 当前 twfid 重启
if let Ok(ip) = restart_zju(child, paths, args, current_twfid).await {
    let ok = spawn_blocking(probe).await;
    if ok { state.tunnel_ip = ip; return Online; }
}
if shutdown { return 放弃; }
// step2: 闸门
let now = now_unix();
if !relogin_allowed(now, state.last_sms_sent, cfg.silent_relogin_interval) {
    eprintln!("[daemon] 距上次发码不足 {}s, 不静默重登 → offline", cfg.silent_relogin_interval);
    return 放弃;
}
// 静默重登(sync → spawn_blocking); on_sms_sent 刷新 state.last_sms_sent(经由回传)
let (cfg2, jar) = ...;
let sd = shutdown.clone();
let sent = Arc::new(AtomicU64::new(0));
let sent2 = sent.clone();
let res = spawn_blocking(move || sms::silent_login(&cfg2, &jar, &sd, &|| { sent2.store(now_unix(), Relaxed); })).await;
if sent.load(Relaxed) != 0 { state.last_sms_sent = Some(sent.load(Relaxed)); }
match res {
    Ok(Ok(new_twfid)) => {
        *current_twfid = new_twfid.clone();
        if let Ok(ip) = restart_zju(child, paths, args, &new_twfid).await {
            if spawn_blocking(probe).await { state.tunnel_ip = ip; return Online; }
        }
        return 放弃;
    }
    _ => return 放弃,
}
```
   ("放弃"用返回值或 enum 表示,主循环据此 `break` → 现有 cleanup → offline 终态退出。)
3. 主循环 Task 7 里 `break` 处替换为:
```rust
match attempt_recover(&mut child, &mut state, &cfg, paths, &args, &mut current_twfid, &shutdown).await {
    Outcome::Online => {
        state.phase = crate::config::Phase::Online;
        let _ = paths.write_state(&state);
        fails = 0;
        eprintln!("[daemon] 已恢复 online");
    }
    Outcome::GiveUp => { eprintln!("[daemon] 恢复失败 → offline 退出"); break; }
}
```
   `current_twfid` 用 `let mut current_twfid = args.twfid.clone();` 在 run 开头声明。
4. 可打断:`restart_zju` 与 `spawn_blocking(silent_login)` 之间检查 `shutdown`;`silent_login` 内已按 flag 打断。SIGTERM 分支置 flag 后,若恢复正在 `spawn_blocking` 中,flag 使其尽快返回;主循环 break 清理退出。

- [ ] **Step 2: 运行确认通过**

Run: `cargo test --lib 2>&1 | tail -10 && cargo build 2>&1 | tail -5`
Expected: 全绿 + build 成功。

- [ ] **Step 3: 手动验证**

见 Task 10 手动清单的"断网自愈""旧 TWFID 失效→静默重登""闸门内二次断连→offline"三项。

- [ ] **Step 4: commit**

```bash
git add src/daemon.rs
git commit -m "$(printf 'feat: daemon 分级恢复(旧 TWFID 重启→闸门→静默重登), 可被 SIGTERM 打断\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 9: connect 方案 Z 接管(撞 Reconnecting → 杀旧起新)

**Files:**
- Modify: `src/lib.rs`(`cmd_connect` 开头判定)
- Modify: `src/tunnel.rs`(`stop_daemon` 后确保退出;或新增 `stop_daemon_and_wait`)

**Interfaces:**
- Consumes: `tunnel::pid_alive`、`tunnel::stop_daemon`、`config::Phase`
- Produces: `tunnel::stop_daemon_and_wait(paths, timeout) -> ()`(SIGTERM 后轮询 pid 直到退出或超时,再兜底 pkill + clear_state)

- [ ] **Step 1: 实现**

1. `src/tunnel.rs` 新增:
```rust
pub fn stop_daemon_and_wait(paths: &Paths, timeout: Duration) {
    if let Some(st) = paths.read_state() {
        if st.daemon_pid > 0 && pid_alive(st.daemon_pid) {
            unsafe { libc::kill(st.daemon_pid, libc::SIGTERM); }
            let deadline = Instant::now() + timeout;
            while pid_alive(st.daemon_pid) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    let _ = Command::new("pkill").arg("-f").arg(paths.zju_bin.display().to_string()).output();
    paths.clear_state();
}
```
2. `src/lib.rs` `cmd_connect` 开头(替换 438-445 的"已连接则直接展示状态"块):
```rust
    if let Some(st) = paths.read_state() {
        if tunnel::pid_alive(st.daemon_pid) {
            if st.phase == config::Phase::Online {
                let delay = tunnel::probe_latency(st.port, &st.server);
                let status = ProxyStatus { online: true, delay, port: Some(st.port) };
                println!("{}", success_line("已经在连接中", Some(&status), &cfg.prompt));
                return Ok(());
            }
            // phase=Reconnecting:方案 Z——停掉正在重连的 daemon,前台接管完整重连
            eprintln!("{}", success_line("检测到后台正在重连,改由本次登录接管", None, &cfg.prompt));
            tunnel::stop_daemon_and_wait(paths, std::time::Duration::from_secs(5));
        }
    }
```
   其后照旧走 `install::ensure_zju_bin` → 登录 → `spawn_daemon`。

- [ ] **Step 2: 运行确认通过**

Run: `cargo test --lib 2>&1 | tail -10 && cargo build 2>&1 | tail -5`
Expected: 全绿 + build 成功。

- [ ] **Step 3: 手动验证**

断网使 daemon 进 reconnecting(用一个会失败的场景),期间 `easy-proxy connect` → 前台打印"改由本次登录接管" → 正常走密码/短信流程 → 连上;确认没有出现两个 daemon(`pgrep -fl __serve` 只剩 1 个)。

- [ ] **Step 4: commit**

```bash
git add src/lib.rs src/tunnel.rs
git commit -m "$(printf 'feat: connect 撞上 reconnecting 走方案 Z 接管(停旧 daemon 并等待退出后重连)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 10: 收尾 —— README、config 示例、版本号、手动验证清单

**Files:**
- Modify: `Cargo.toml`(version → 0.3.0)
- Modify: `README.md`(config 示例补三个字段 + 自动重连说明)

- [ ] **Step 1: 版本与文档**

1. `Cargo.toml` `version = "0.3.0"`。
2. `README.md` config 示例补:
```yaml
healthcheck_interval: 15         # 隧道健康检查周期(秒)
healthcheck_fail_threshold: 2    # 连续探测失败几次判定断线
silent_relogin_interval: 3600    # 静默重登最小间隔(秒), 限流下一次自动重登
```
   并加一段"断线自动恢复"说明:旧 TWFID 重启不限次;静默重登受 `silent_relogin_interval` 限流(按上次发码时刻算);恢复彻底失败则 daemon 退出、status 显示 offline,需手动 `connect`;手动 connect 不受限流,并会接管正在重连的后台。

- [ ] **Step 2: 全量测试 + 构建**

Run: `cargo test 2>&1 | tail -15 && cargo build --release 2>&1 | tail -5`
Expected: 全绿 + release 构建成功。

- [ ] **Step 3: 手动验证清单(逐项打勾)**

- [ ] `connect` 正常连上,`status` = online + 延迟
- [ ] 断网 → daemon 用旧 TWFID 重启;网络很快恢复 → 自动回 online(零短信)
- [ ] 断网且旧 TWFID 失效、距上次发码 > interval → 静默重登发码 → 回 online
- [ ] 距上次发码 < interval 的二次断连 + 旧 TWFID 无效 → daemon 退出、`status` offline、无残留(`pgrep -fl __serve` 为空)
- [ ] 未配 `sms_command` 时断网 → 旧 TWFID 重启失败即 offline 退出
- [ ] reconnecting 期间 `easy-proxy connect` → 接管成功、只剩一个 daemon
- [ ] daemon 连续运行观察:online 态 `daemon.log` 不增长、`pgrep -c zju-connect` 稳定为 1(无僵尸)
- [ ] **钥匙串**:daemon 静默重登调 `keychain::get_password` 是否弹授权框(风险点);若弹,记录并决定是否改为"静默重登失败即 offline"

- [ ] **Step 4: commit**

```bash
git add Cargo.toml README.md
git commit -m "$(printf 'chore: 0.3.0 版本号 + README 自动重连与健康检查配置说明\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

## Self-Review

**Spec 覆盖**:§3 状态机→Task 7/8;§4 限流→Task 5/6(`relogin_allowed`)/8;§5 connect Z→Task 9;§6 数据结构→Task 1;§7 config→Task 1/10;§8.1 取码抽取→Task 3;§8.2 恢复→Task 6/8;§8.3 主循环→Task 7/8;§8.4 读 config→Task 7;§8.5 tunnel→Task 5/9;§9 边界(可打断/释放竞态/兼容)→Task 8/9/1;§10 测试→Task 1/2/3/6;§12 资源(子进程回收/日志/state 写策略/tail)→Task 2/7/8。全部有对应任务。

**类型一致**:`Phase`、`RuntimeState.phase/last_sms_sent`、`spawn_daemon(...,last_sms_sent)`、`ServeArgs.last_sms_sent`、`daemon::serve(args,cfg,paths)`、`sms::{SmsUi,fetch_and_submit_loop,silent_login,should_resend,valid_sms_code,run_sms_command}`、`recover::{should_enter_reconnect,relogin_allowed}`、`tunnel::stop_daemon_and_wait`、`config::{now_unix,read_tail_bytes}` 全程一致。

**风险提示**:钥匙串后台弹框(Task 10 验证);daemon async 管 child 与 sync 登录经 `spawn_blocking` 的边界(Task 8 需仔细处理所有权与打断)。
