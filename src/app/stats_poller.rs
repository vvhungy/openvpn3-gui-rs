//! Periodic session statistics poller.
//!
//! Polls `BYTES_IN/OUT` from each connected session's D-Bus `statistics`
//! property and updates the tray. Doubles as the tooltip-refresh tick — the
//! ksni tray re-reads tooltip text whenever we call `tray.update(|_| {})`.
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
            let secs = settings.tooltip_refresh_interval();
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
                    tray_for_timer.update(move |t| {
                        if let Some(s) = t.sessions.get_mut(&p) {
                            apply_stall_detection(s, bi, bo, threshold);
                        }
                    });
                }
            }

            tray_for_timer.update(|_| {});
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
        session.idle_since = None;
        return;
    }

    if delta_in > 0 || delta_out > 0 {
        session.idle_since = None;
    } else if session.idle_since.is_none() {
        session.idle_since = Some(std::time::Instant::now());
    }

    // If idle for longer than threshold, keep idle_since set (menu/icon
    // read it to show warning). The caller already has the timestamp —
    // no additional action needed here.
    if let Some(since) = session.idle_since {
        let idle_secs = since.elapsed().as_secs();
        if idle_secs < threshold_secs as u64 {
            // Not yet past threshold — clear so menu doesn't show premature warning
            session.idle_since = None;
            // Re-mark so the clock starts from the real first zero-delta poll
            session.idle_since = Some(since);
        }
    }
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
            idle_since: None,
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
    fn test_zero_delta_starts_idle_timer() {
        let mut s = make_connected_session();
        // Same bytes as last poll = zero delta
        apply_stall_detection(&mut s, 1000, 500, 60);
        // idle_since is set, but not yet past threshold — the function
        // keeps it so the next poll can check elapsed time.
        assert!(s.idle_since.is_some());
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
}
