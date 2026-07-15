//! Periodic session statistics poller.
//!
//! Polls `BYTES_IN/OUT` from each connected session's D-Bus `statistics`
//! property and updates the tray menu labels and icon state.
//!
//! Also runs stall detection: if a connected session shows zero byte delta
//! for longer than the configured threshold, it is flagged as idle and the
//! tray menu label and icon reflect the warning state.
//!
//! Split into:
//! - [`stall`]: pure stall-detection / auto-reconnect logic.
//! - [`drift`]: pure bypass-drift state machine.
//!
//! This module owns the async poll loop that drives both.

mod drift;
mod stall;

use crate::settings::Settings;
use crate::tray::VpnTray;

use drift::{bypass_is_live, drift_transition, recover_from_drift};
pub use stall::{apply_stall_detection, should_auto_reconnect_on_stall};

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
            // one session is connected AND bypass is Active or Drifted, verify
            // the live nft sets still hold the desired CIDR list. Cheap D-Bus
            // round-trip that runs at the user-configured stats interval (30s
            // default). On detected drift → tray `Drifted` + persistent notify.
            // Must keep verifying while Drifted, not just Active, so the
            // `is_clean()` recovery path stays reachable once the missing
            // element is restored (otherwise Drifted is a one-way trap).
            // Skipped when bypass is Off/Failed (no live set to reconcile) or
            // no session is connected (kill-switch not enforcing anyway). A
            // helper that lacks the method (pre-0.3.14) errors the call → we
            // no-op and stop polling for the session.
            let bypass_live = tray_for_timer
                .update(|t| bypass_is_live(&t.bypass_state))
                .unwrap_or(false);
            if bypass_live && any_connected {
                let all = settings.bypass_cidrs();
                let disabled = settings.bypass_cidrs_disabled();
                let enabled = crate::settings::enabled_cidrs(&all, &disabled);
                let (desired_v4, desired_v6) = crate::settings::split_v4_v6(&enabled);
                if let Some(report) =
                    crate::dbus::killswitch::verify_bypass_set(desired_v4, desired_v6).await
                {
                    if report.is_clean() {
                        // Recovery: restore the apply-outcome counts captured
                        // when we entered Drifted, not a fabricated full-success
                        // Active. Drift verifies set *membership*, a different
                        // measurement than route apply-outcome — a partial apply
                        // that then matched the (enabled) desired set must not be
                        // silently upgraded to failed=0.
                        let was_drifted = tray_for_timer
                            .update(|t| {
                                if let Some(restored) = recover_from_drift(&t.bypass_state) {
                                    t.bypass_state = restored;
                                    true
                                } else {
                                    false
                                }
                            })
                            .unwrap_or(false);
                        if was_drifted {
                            tracing::info!("bypass drift cleared — live sets match desired again");
                            crate::dialogs::show_bypass_recovered_notification();
                        }
                    } else {
                        let missing: Vec<String> = report
                            .v4_missing
                            .iter()
                            .chain(&report.v6_missing)
                            .cloned()
                            .collect();
                        let missing_count = missing.len();
                        let extra_count = report.extra.len();
                        tracing::warn!(
                            missing_count,
                            extra = extra_count,
                            "bypass drift detected by periodic verify"
                        );
                        // Re-arm guard: the gate was captured before the verify
                        // await. A disconnect / split-tunnel toggle during that
                        // window can have moved bypass_state to Off/Failed on the
                        // single-threaded main loop; only transition into Drifted
                        // from a still-live (Active/Drifted) state so we never
                        // resurrect a torn-down kill-switch as Drifted. Preserve
                        // the pre-drift apply counts for faithful recovery.
                        let transitioned = tray_for_timer
                            .update(|t| {
                                if let Some((new_state, notify)) =
                                    drift_transition(&t.bypass_state, missing_count, extra_count)
                                {
                                    t.bypass_state = new_state;
                                    notify
                                } else {
                                    false
                                }
                            })
                            .unwrap_or(false);
                        if transitioned {
                            crate::dialogs::show_bypass_drift_notification(&missing, extra_count);
                        }
                    }
                }
            }
        }
    });
}
