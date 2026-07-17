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
//! This module owns the async poll loop that drives both. The per-tick body is
//! decomposed into [`poll_connected_sessions`] (per-session stall check) and
//! [`check_bypass_drift`] (periodic bypass-set reconciliation), each under the
//! complexity gate; the pure transition logic they lean on lives in the
//! submodules and is unit-tested there.

mod drift;
mod stall;

use crate::settings::Settings;
use crate::tray::VpnTray;

use drift::{bypass_is_live, drift_transition, recover_from_drift};
pub use stall::{apply_stall_detection, should_auto_reconnect_on_stall};

/// Spawn the stats polling loop on the GTK main loop.
///
/// Interval is re-read from settings each tick so preference changes take
/// effect on the next iteration. The per-tick work is delegated to
/// [`poll_connected_sessions`] (stall detection) and [`check_bypass_drift`]
/// (bypass-set reconciliation).
pub(super) fn setup_stats_poller(dbus: &zbus::Connection, tray: &ksni::blocking::Handle<VpnTray>) {
    let tray_for_timer = tray.clone();
    let dbus_for_stats = dbus.clone();
    glib::spawn_future_local(async move {
        loop {
            let settings = Settings::new();
            let secs = settings.stats_refresh_interval();
            glib::timeout_future_seconds(secs).await;

            let stall_threshold = settings.health_check_stall_seconds();
            let auto_reconnect = settings.auto_reconnect();
            let cooldown_secs = (settings.auto_reconnect_delay_seconds() as u64) * 2;

            poll_connected_sessions(
                &dbus_for_stats,
                &tray_for_timer,
                stall_threshold,
                auto_reconnect,
                cooldown_secs,
            )
            .await;

            // Force a menu/icon refresh after the poll cycle even when no
            // session stats changed (idle/stall flags may have flipped).
            tray_for_timer.update(|_| {});

            check_bypass_drift(&tray_for_timer, &settings).await;
        }
    });
}

/// Poll every connected session for fresh byte counters and run stall
/// detection, triggering an auto-reconnect (via disconnect + SessDestroyed)
/// for any session stalled past the threshold.
///
/// Impure async glue — the pure stall/reconnect decision logic lives in
/// [`stall`] (`apply_stall_detection`, `should_auto_reconnect_on_stall`) and is
/// unit-tested there. No unit surface here.
async fn poll_connected_sessions(
    dbus: &zbus::Connection,
    tray: &ksni::blocking::Handle<VpnTray>,
    stall_threshold: u32,
    auto_reconnect: bool,
    cooldown_secs: u64,
) {
    let session_paths: Vec<(String, bool)> = tray
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
            && let Ok(builder) = crate::dbus::session::SessionProxy::builder(dbus).path(obj_path)
            && let Ok(session) = builder.build().await
            && let Ok(stats) = session.statistics().await
        {
            let bi = stats.get("BYTES_IN").copied().unwrap_or(0) as u64;
            let bo = stats.get("BYTES_OUT").copied().unwrap_or(0) as u64;
            let p = path.clone();
            // apply_stall_detection mutates the session's idle state; read back
            // idle_since + config_path so the cooldown decision below can run
            // against the config-keyed map OUTSIDE the tray lock (H5: the
            // cooldown must outlive this session — see session_ops).
            let (idle_since, config_path) = tray
                .update(move |t| {
                    let s = t.sessions.get_mut(&p)?;
                    apply_stall_detection(s, bi, bo, stall_threshold);
                    Some((s.idle_since, s.config_path.clone()))
                })
                .flatten()
                .unwrap_or((None, String::new()));

            let trigger_reconnect = !config_path.is_empty()
                && should_auto_reconnect_on_stall(
                    idle_since,
                    super::session_ops::last_auto_reconnect_attempt(&config_path),
                    auto_reconnect,
                    stall_threshold,
                    cooldown_secs,
                );

            if trigger_reconnect {
                // Stamp the attempt keyed by config_path BEFORE the disconnect —
                // the SessDestroyed/recreate cycle would lose a per-session
                // stamp (H5). Best-effort; poison-tolerant inside the helper.
                super::session_ops::record_auto_reconnect_attempt(&config_path);
                tracing::info!(
                    "Stall threshold exceeded for session {}, triggering auto-reconnect via disconnect+SessDestroyed path",
                    path
                );
                if let Err(e) = super::session_ops::session_action(dbus, &path, "disconnect").await
                {
                    tracing::warn!("Stall-driven disconnect failed for {}: {}", path, e);
                }
            }
        }
    }
}

/// Periodic bypass-set reconciliation (S38 T2).
///
/// While at least one session is connected AND bypass is `Active` or
/// `Drifted`, verify the live nft sets still hold the desired CIDR list. Cheap
/// D-Bus round-trip at the user-configured stats interval (30s default). On
/// detected drift → tray `Drifted` + persistent notify; on recovery →
/// restored `Active` + notify.
///
/// Impure async glue — the pure transition logic lives in [`drift`]
/// (`bypass_is_live`, `recover_from_drift`, `drift_transition`) and is
/// unit-tested there. No unit surface here.
async fn check_bypass_drift(tray: &ksni::blocking::Handle<VpnTray>, settings: &Settings) {
    // One lock for both gates — the poll loop is single-threaded but a second
    // acquisition here would contend with the StatusChange mutator for nothing.
    let (any_connected, bypass_live) = tray
        .update(|t| {
            (
                t.sessions.values().any(|s| s.status.is_connected()),
                bypass_is_live(&t.bypass_state),
            )
        })
        .unwrap_or((false, false));

    // Skipped when bypass is Off/Failed (no live set to reconcile) or no
    // session is connected (kill-switch not enforcing anyway). A helper that
    // lacks the method (pre-0.3.14) errors the call → we no-op.
    if !(bypass_live && any_connected) {
        return;
    }

    // Must keep verifying while Drifted, not just Active, so the `is_clean()`
    // recovery path stays reachable once the missing element is restored
    // (otherwise Drifted is a one-way trap).
    let all = settings.bypass_cidrs();
    let disabled = settings.bypass_cidrs_disabled();
    let enabled = crate::settings::enabled_cidrs(&all, &disabled);
    let (desired_v4, desired_v6) = crate::settings::split_v4_v6(&enabled);
    let Some(report) = crate::dbus::killswitch::verify_bypass_set(desired_v4, desired_v6).await
    else {
        return;
    };

    if report.is_clean() {
        // Recovery: restore the apply-outcome counts captured when we entered
        // Drifted, not a fabricated full-success Active. Drift verifies set
        // *membership*, a different measurement than route apply-outcome — a
        // partial apply that then matched the (enabled) desired set must not
        // be silently upgraded to failed=0.
        let was_drifted = tray
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
        return;
    }

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
    // Re-arm guard: the gate was captured before the verify await. A disconnect
    // / split-tunnel toggle during that window can have moved bypass_state to
    // Off/Failed on the single-threaded main loop; only transition into Drifted
    // from a still-live (Active/Drifted) state so we never resurrect a
    // torn-down kill-switch as Drifted. Preserve the pre-drift apply counts for
    // faithful recovery.
    let transitioned = tray
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
