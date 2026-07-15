//! Stall detection: pure logic for the stats poller.
//!
//! Compares byte counters across poll cycles. A connected session with zero
//! byte delta for longer than the configured threshold is flagged idle; the
//! tray menu label and icon reflect the warning state.

/// Update byte counters and detect stall condition.
///
/// Pure logic — extracted for testability. Compares current byte counts to
/// the previous poll cycle. If the delta is zero and the session has been
/// idle for longer than `threshold_secs`, sets `idle_since`. If traffic
/// resumes, clears `idle_since`.
///
/// `threshold_secs == 0` disables stall detection.
pub fn apply_stall_detection(
    session: &mut crate::tray::SessionInfo,
    bytes_in: u64,
    bytes_out: u64,
    threshold_secs: u32,
) {
    let delta_in = bytes_in.saturating_sub(session.last_bytes_in);
    let delta_out = bytes_out.saturating_sub(session.last_bytes_out);

    session.bytes_in = bytes_in;
    session.bytes_out = bytes_out;
    session.last_bytes_in = bytes_in;
    session.last_bytes_out = bytes_out;

    if threshold_secs == 0 {
        session.idle_started_at = None;
        session.idle_since = None;
        return;
    }

    if delta_in > 0 || delta_out > 0 {
        // Traffic resumed — reset both the start-clock and the warning flag.
        session.idle_started_at = None;
        session.idle_since = None;
        return;
    }

    // The idle clock/warning are only meaningful while Connected. The stats
    // poll loop captures `connected` then `await`s `statistics()`; a
    // StatusChange (e.g. tunnel errors) can fire during that await, and
    // `status_handler` clears the flags. Without this gate the poller resumes
    // and re-arms `idle_since` on the now-Error session, and `current_icon`'s
    // `idle_since.is_some()` branch masks the error icon with the idle one —
    // the exact regression the status-handler clearing exists to prevent.
    if !session.status.is_connected() {
        session.idle_started_at = None;
        session.idle_since = None;
        return;
    }

    // Zero delta: start the idle clock on the first such poll and let it
    // accumulate across subsequent polls (`idle_started_at` persists).
    let started = *session
        .idle_started_at
        .get_or_insert_with(std::time::Instant::now);

    // Only surface the idle/stall warning once the threshold is actually
    // crossed. `idle_since.is_some()` is the warning flag read by the menu,
    // icon, and `should_auto_reconnect_on_stall`; keep it `None` while below
    // threshold so a single zero-delta poll never flips the icon prematurely.
    session.idle_since = if started.elapsed().as_secs() >= threshold_secs as u64 {
        Some(started)
    } else {
        None
    };
}

/// Decide whether a stalled session should trigger an auto-reconnect.
///
/// Returns true when:
/// - `auto_reconnect` setting is enabled
/// - stall detection is on (`threshold_secs > 0`)
/// - session is idle past the stall threshold
/// - cooldown window has elapsed since the last attempt for this session
///   (prevents loops against persistently dead servers)
///
/// Marks `auto_reconnect_attempted_at` on the session when returning true so
/// the caller doesn't need to remember to set it. The caller is responsible
/// for issuing the disconnect — SessDestroyed then drives T1's reconnect path.
pub fn should_auto_reconnect_on_stall(
    session: &mut crate::tray::SessionInfo,
    auto_reconnect: bool,
    threshold_secs: u32,
    cooldown_secs: u64,
) -> bool {
    if !auto_reconnect || threshold_secs == 0 {
        return false;
    }
    let Some(since) = session.idle_since else {
        return false;
    };
    if since.elapsed().as_secs() < threshold_secs as u64 {
        return false;
    }
    if let Some(last) = session.auto_reconnect_attempted_at
        && last.elapsed().as_secs() < cooldown_secs
    {
        return false;
    }
    session.auto_reconnect_attempted_at = Some(std::time::Instant::now());
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbus::types::{SessionStatus, StatusMajor, StatusMinor};
    use crate::tray::SessionInfo;

    fn make_connected_session() -> SessionInfo {
        SessionInfo {
            session_path: "/test/sess".into(),
            config_path: "/test/cfg".into(),
            config_name: "TestVPN".into(),
            status: SessionStatus {
                major: StatusMajor::Connection,
                minor: StatusMinor::ConnConnected,
            },
            connected_at: None,
            bytes_in: 1000,
            bytes_out: 500,
            last_bytes_in: 1000,
            last_bytes_out: 500,
            idle_started_at: None,
            idle_since: None,
            auto_reconnect_attempted_at: None,
            kill_switch_active: false,
        }
    }

    #[test]
    fn test_traffic_clears_idle() {
        let mut s = make_connected_session();
        s.idle_since = Some(std::time::Instant::now());
        apply_stall_detection(&mut s, 2000, 1000, 60);
        assert!(s.idle_since.is_none());
        assert_eq!(s.bytes_in, 2000);
        assert_eq!(s.bytes_out, 1000);
    }

    #[test]
    fn test_zero_delta_below_threshold_not_idle() {
        let mut s = make_connected_session();
        // Same bytes as last poll = zero delta, but no time has elapsed so
        // we are still below threshold — idle_since must read None so the
        // icon/menu don't show a premature warning.
        apply_stall_detection(&mut s, 1000, 500, 60);
        assert!(s.idle_since.is_none());
    }

    #[test]
    fn test_zero_delta_past_threshold_marks_idle() {
        let mut s = make_connected_session();
        // Seed the start-clock older than the threshold, then send zero delta.
        s.idle_started_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(120));
        apply_stall_detection(&mut s, 1000, 500, 60);
        assert!(s.idle_since.is_some());
    }

    #[test]
    fn test_idle_clock_accumulates_across_polls() {
        // Regression: the start-clock must persist across consecutive
        // zero-delta polls so elapsed idle time accumulates. A poll that
        // re-stamps the clock every cycle would never cross the threshold.
        let mut s = make_connected_session();
        apply_stall_detection(&mut s, 1000, 500, 60); // first zero-delta poll
        let started = s.idle_started_at.expect("start-clock set on first poll");
        apply_stall_detection(&mut s, 1000, 500, 60); // second zero-delta poll
        assert_eq!(
            s.idle_started_at,
            Some(started),
            "start-clock must not be reset on subsequent polls"
        );
    }

    #[test]
    fn test_disabled_threshold_never_idles() {
        let mut s = make_connected_session();
        apply_stall_detection(&mut s, 1000, 500, 0);
        assert!(s.idle_since.is_none());
    }

    #[test]
    fn test_disabled_clears_existing_idle() {
        let mut s = make_connected_session();
        s.idle_since = Some(std::time::Instant::now());
        apply_stall_detection(&mut s, 1000, 500, 0);
        assert!(s.idle_since.is_none());
    }

    #[test]
    fn test_non_connected_session_never_marked_idle() {
        // Regression: the stats poller captures `connected` then awaits
        // statistics(); a StatusChange to Error during that await clears the
        // flags via status_handler, but the poller resumes and must NOT
        // re-arm idle_since on the now-non-Connected session — otherwise
        // current_icon's idle branch masks the error icon.
        let mut s = make_connected_session();
        // Transition to Error (status_handler would have cleared flags; here
        // we leave a stale idle_started_at to prove the gate clears it too).
        s.status.minor = StatusMinor::ConnFailed;
        s.idle_started_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(120));
        s.idle_since = Some(std::time::Instant::now() - std::time::Duration::from_secs(120));
        apply_stall_detection(&mut s, 1000, 500, 60);
        assert!(s.idle_since.is_none(), "idle flag cleared on non-Connected");
        assert!(
            s.idle_started_at.is_none(),
            "idle clock cleared on non-Connected"
        );
        // Counters still update regardless of status.
        assert_eq!(s.bytes_in, 1000);
        assert_eq!(s.bytes_out, 500);
    }

    #[test]
    fn test_should_reconnect_disabled_setting() {
        let mut s = make_connected_session();
        s.idle_since = Some(std::time::Instant::now() - std::time::Duration::from_secs(120));
        assert!(!should_auto_reconnect_on_stall(&mut s, false, 60, 60));
        assert!(s.auto_reconnect_attempted_at.is_none());
    }

    #[test]
    fn test_should_reconnect_threshold_zero() {
        let mut s = make_connected_session();
        s.idle_since = Some(std::time::Instant::now() - std::time::Duration::from_secs(120));
        assert!(!should_auto_reconnect_on_stall(&mut s, true, 0, 60));
    }

    #[test]
    fn test_should_reconnect_not_idle() {
        let mut s = make_connected_session();
        s.idle_since = None;
        assert!(!should_auto_reconnect_on_stall(&mut s, true, 60, 60));
    }

    #[test]
    fn test_should_reconnect_below_threshold() {
        let mut s = make_connected_session();
        s.idle_since = Some(std::time::Instant::now());
        assert!(!should_auto_reconnect_on_stall(&mut s, true, 60, 60));
    }

    #[test]
    fn test_should_reconnect_fires_past_threshold() {
        let mut s = make_connected_session();
        s.idle_since = Some(std::time::Instant::now() - std::time::Duration::from_secs(120));
        assert!(should_auto_reconnect_on_stall(&mut s, true, 60, 60));
        assert!(s.auto_reconnect_attempted_at.is_some());
    }

    #[test]
    fn test_should_reconnect_cooldown_blocks_loop() {
        let mut s = make_connected_session();
        s.idle_since = Some(std::time::Instant::now() - std::time::Duration::from_secs(120));
        s.auto_reconnect_attempted_at = Some(std::time::Instant::now());
        assert!(!should_auto_reconnect_on_stall(&mut s, true, 60, 60));
    }

    #[test]
    fn test_should_reconnect_after_cooldown_expires() {
        let mut s = make_connected_session();
        s.idle_since = Some(std::time::Instant::now() - std::time::Duration::from_secs(120));
        s.auto_reconnect_attempted_at =
            Some(std::time::Instant::now() - std::time::Duration::from_secs(120));
        assert!(should_auto_reconnect_on_stall(&mut s, true, 60, 60));
    }
}
