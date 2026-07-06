//! Periodic session statistics poller.
//!
//! Polls `BYTES_IN/OUT` from each connected session's D-Bus `statistics`
//! property and updates the tray menu labels and icon state.
//!
//! Also runs stall detection: if a connected session shows zero byte delta
//! for longer than the configured threshold, it is flagged as idle and the
//! tray menu label and icon reflect the warning state.

use crate::settings::Settings;
use crate::tray::VpnTray;

/// Spawn the stats polling loop on the GTK main loop.
///
/// Interval is re-read from settings each tick so preference changes take
/// effect on the next iteration.
pub(super) fn setup_stats_poller(dbus: &zbus::Connection, tray: &ksni::blocking::Handle<VpnTray>) {
    let tray_for_timer = tray.clone();
    let dbus_for_stats = dbus.clone();
    glib::spawn_future_local(async move {
        loop {
            let settings = Settings::new();
            let secs = settings.stats_refresh_interval();
            let stall_threshold = settings.health_check_stall_seconds();
            glib::timeout_future_seconds(secs).await;

            let session_paths: Vec<(String, bool)> = tray_for_timer
                .update(|t| {
                    t.sessions
                        .iter()
                        .map(|(path, s)| (path.clone(), s.status.is_connected()))
                        .collect()
                })
                .unwrap_or_default();

            let any_connected = session_paths.iter().any(|(_, c)| *c);

            let auto_reconnect = settings.auto_reconnect();
            let cooldown_secs = (settings.auto_reconnect_delay_seconds() as u64) * 2;

            for (path, connected) in session_paths {
                if !connected {
                    continue;
                }
                if let Ok(obj_path) = zbus::zvariant::OwnedObjectPath::try_from(path.as_str())
                    && let Ok(builder) =
                        crate::dbus::session::SessionProxy::builder(&dbus_for_stats).path(obj_path)
                    && let Ok(session) = builder.build().await
                    && let Ok(stats) = session.statistics().await
                {
                    let bi = stats.get("BYTES_IN").copied().unwrap_or(0) as u64;
                    let bo = stats.get("BYTES_OUT").copied().unwrap_or(0) as u64;
                    let p = path.clone();
                    let threshold = stall_threshold;
                    let trigger_reconnect = tray_for_timer
                        .update(move |t| {
                            if let Some(s) = t.sessions.get_mut(&p) {
                                apply_stall_detection(s, bi, bo, threshold);
                                should_auto_reconnect_on_stall(
                                    s,
                                    auto_reconnect,
                                    threshold,
                                    cooldown_secs,
                                )
                            } else {
                                false
                            }
                        })
                        .unwrap_or(false);

                    if trigger_reconnect {
                        tracing::info!(
                            "Stall threshold exceeded for session {}, triggering auto-reconnect via disconnect+SessDestroyed path",
                            path
                        );
                        if let Err(e) =
                            super::session_ops::session_action(&dbus_for_stats, &path, "disconnect")
                                .await
                        {
                            tracing::warn!("Stall-driven disconnect failed for {}: {}", path, e);
                        }
                    }
                }
            }

            tray_for_timer.update(|_| {});

            // Drift detection (S38 T2): once per stats cycle, while at least
            // one session is connected AND bypass is currently Active, verify
            // the live nft sets still hold the desired CIDR list. Cheap D-Bus
            // round-trip that runs at the user-configured stats interval (30s
            // default). On detected drift → tray `Drifted` + persistent notify.
            // Skipped when bypass is Off/Failed/Drifted (no point re-checking a
            // non-active state) or no session is connected (kill-switch not
            // enforcing anyway). A helper that lacks the method (pre-0.3.14)
            // errors the call → we no-op and stop polling for the session.
            let bypass_active = tray_for_timer
                .update(|t| matches!(t.bypass_state, crate::tray::BypassState::Active { .. }))
                .unwrap_or(false);
            if bypass_active && any_connected {
                let all = settings.bypass_cidrs();
                let disabled = settings.bypass_cidrs_disabled();
                let enabled = crate::settings::enabled_cidrs(&all, &disabled);
                let (desired_v4, desired_v6) = crate::settings::split_v4_v6(&enabled);
                if let Some(report) =
                    crate::dbus::killswitch::verify_bypass_set(desired_v4, desired_v6).await
                {
                    if report.is_clean() {
                        tray_for_timer.update(|t| {
                            // Clear a prior drift state once sets match again.
                            if matches!(t.bypass_state, crate::tray::BypassState::Drifted { .. }) {
                                t.bypass_state = crate::tray::BypassState::Active {
                                    applied: enabled.len(),
                                    failed: 0,
                                };
                            }
                        });
                    } else {
                        let missing: Vec<String> = report
                            .v4_missing
                            .iter()
                            .chain(&report.v6_missing)
                            .cloned()
                            .collect();
                        let missing_count = missing.len();
                        tracing::warn!(
                            missing_count,
                            extra = report.extra.len(),
                            "bypass drift detected by periodic verify"
                        );
                        tray_for_timer.update(|t| {
                            t.bypass_state = crate::tray::BypassState::Drifted {
                                missing: missing_count,
                            };
                        });
                        crate::dialogs::show_bypass_drift_notification(&missing);
                    }
                }
            }
        }
    });
}

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
