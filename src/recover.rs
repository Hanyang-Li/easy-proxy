//! 恢复决策纯函数(可单测);副作用编排在 daemon.rs。

/// 连续探测失败次数达到阈值即判定断线,进入重连。
pub fn should_enter_reconnect(consecutive_fails: u32, threshold: u32) -> bool {
    consecutive_fails >= threshold
}

/// 静默重登闸门:距上次发码 >= interval 才允许(从未发码→允许;时钟回拨 now<last→不允许)。
pub fn relogin_allowed(now: u64, last_sms_sent: Option<u64>, interval: u64) -> bool {
    match last_sms_sent {
        Some(t) => now.saturating_sub(t) >= interval,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(!relogin_allowed(1000, Some(900), 3600));
        // 恰好达到 interval → 允许
        assert!(relogin_allowed(4600, Some(1000), 3600));
        // 时钟回拨(now < last)→ saturating, 不允许
        assert!(!relogin_allowed(500, Some(1000), 3600));
    }
}
