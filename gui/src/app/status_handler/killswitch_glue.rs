//! Kill-switch glue invoked from the StatusChange loop.
//!
//! All knowledge about *when* to apply or remove firewall rules in response
//! to per-session connection-state transitions lives here, so the main loop
//! stays focused on connection-lifecycle dispatch + auth fan-out.
//!
//! Most of this module is async D-Bus glue + side effects (notifications,
//! firewall calls) with no testable pure surface; the pause-teardown gate is
//! the exception and is extracted as [`should_teardown_on_pause`] so it is
//! unit-testable in isolation. Whether a *survivor* keeps the firewall up on
//! pause is not decided here — [`on_paused`] delegates to
//! [`crate::app::signal_handlers::decide_kill_switch_teardown`], the same pure
//! decision the destroy path uses, so both lifecycles hold one invariant.
//! One-shot semantics are covered indirectly by the status_handler integration
//! smoke test.

use std::sync::atomic::{AtomicBool, Ordering};
use tracing::warn;

use crate::tray::VpnTray;

/// One-shot flag — fire the "helper missing" notification at most once per
/// app session. The Preferences hint label persists as the visual reminder.
static HELPER_MISSING_NOTIFIED: AtomicBool = AtomicBool::new(false);

/// Build a SessionProxy for `path`, read the tun interface name and the
/// currently connected server IP, and ask the kill-switch helper to install
/// rules that block all non-tunnel traffic.
///
/// Returns `Ok(true)` if rules were attempted. Returns `Ok(false)` if the
/// helper package is not installed (caller may surface a notification).
/// Returns `Err` on real D-Bus or proxy failures.
pub(crate) async fn apply_kill_switch(
    conn: &zbus::Connection,
    session_path: &str,
    allow_lan: bool,
) -> anyhow::Result<bool> {
    let proxy = crate::dbus::session::SessionProxy::builder(conn)
        .path(session_path)?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await?;
    let device_name = proxy.device_name().await?;
    if device_name.is_empty() {
        warn!("kill-switch: device_name empty on connected session — rules NOT applied");
        return Ok(false);
    }
    let (_proto, server_ip, _port) = proxy.connected_to().await?;
    if server_ip.is_empty() {
        warn!("kill-switch: connected_to address empty — rules NOT applied");
        return Ok(false);
    }
    let helper_installed =
        crate::dbus::killswitch::add_rules(&device_name, vec![server_ip], allow_lan).await;
    Ok(helper_installed)
}

pub(super) fn on_connected(
    conn: &zbus::Connection,
    session_path: &str,
    tray: &ksni::blocking::Handle<VpnTray>,
) {
    let settings = crate::settings::Settings::new();
    let path = session_path.to_string();
    let conn = conn.clone();
    let tray = tray.clone();

    // Bypass routing is independent of kill-switch (D4). Apply whenever
    // the user has configured bypass CIDRs — no KS gate.
    let bypass_cidrs =
        crate::settings::enabled_cidrs(&settings.bypass_cidrs(), &settings.bypass_cidrs_disabled());
    let ks_enabled = settings.enable_kill_switch();
    let allow_lan = settings.kill_switch_allow_lan();

    let tray_for_bypass = tray.clone();
    glib::spawn_future_local(async move {
        // Push bypass CIDRs and install routing (replaces any prior state). The
        // SetBypassCidrs→ApplyBypassRoutes gate lives inside apply_bypass.
        crate::app::bypass_apply::apply_bypass(&tray_for_bypass, bypass_cidrs, "session connect")
            .await;

        // Kill-switch firewall — gated by user preference.
        if ks_enabled {
            match apply_kill_switch(&conn, &path, allow_lan).await {
                Ok(true) => {
                    let p = path.clone();
                    tray.update(move |t| {
                        if let Some(s) = t.sessions.get_mut(&p) {
                            s.kill_switch_active = true;
                        }
                    });
                    crate::dialogs::show_killswitch_active_notification();
                }
                Ok(false) if !HELPER_MISSING_NOTIFIED.swap(true, Ordering::Relaxed) => {
                    crate::dialogs::show_helper_missing_notification();
                }
                Err(e) => {
                    warn!("kill-switch: apply failed: {}", e);
                    crate::dialogs::show_error_notification(
                        "Kill-Switch Failed",
                        &format!("Firewall rules could not be applied: {}", e),
                    );
                }
                _ => {}
            }
        }
    });
}

/// Pure decision: whether the kill-switch firewall should be torn down when a
/// session pauses. Returns `true` only when the kill-switch is enabled AND the
/// user has not set block-during-pause (which keeps rules up to stay protected
/// while paused). Separated from [`on_paused`] so the gate is unit-testable
/// without a D-Bus connection or live firewall (I6 pure/impure split).
///
/// This gate answers "does pausing release the firewall at all?" — it does not
/// answer "is anyone else still protected?". That second question is
/// [`decide_kill_switch_teardown`], shared with the destroy path.
fn should_teardown_on_pause(enable_kill_switch: bool, block_during_pause: bool) -> bool {
    enable_kill_switch && !block_during_pause
}

/// Release the kill-switch on pause — but only as far as the *other* sessions
/// allow. The helper's kill-switch is a single global nft table, so the old
/// blanket `remove_rules()` + clear-every-flag stripped protection from a
/// still-connected, still-protected survivor whenever any one session paused.
/// Reuses the destroy path's survivor decision so both lifecycles enforce the
/// same invariant.
///
/// Bypass routes are deliberately left alone: they are independent of the
/// kill-switch (D4) and `on_connected` re-applies them on resume.
pub(super) fn on_paused(
    conn: &zbus::Connection,
    paused_path: &str,
    tray: &ksni::blocking::Handle<VpnTray>,
) {
    let settings = crate::settings::Settings::new();
    if !should_teardown_on_pause(
        settings.enable_kill_switch(),
        settings.kill_switch_block_during_pause(),
    ) {
        return;
    }
    let allow_lan = settings.kill_switch_allow_lan();
    let tray = tray.clone();
    let conn = conn.clone();
    let paused = paused_path.to_string();
    glib::spawn_future_local(async move {
        // Snapshot survivors *inside* the future: the pause decision must run
        // against tray state as it is at teardown time, not as it was when the
        // StatusChange arrived (I7 — captured state has a TTL).
        let survivors = tray
            .update(|t| {
                t.sessions
                    .iter()
                    .map(|(p, s)| (p.clone(), s.status.is_connected(), s.kill_switch_active))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        match crate::app::signal_handlers::decide_kill_switch_teardown(&paused, false, survivors) {
            crate::app::signal_handlers::KillSwitchTeardown::Full => {
                pause_full_teardown(&tray).await;
            }
            crate::app::signal_handlers::KillSwitchTeardown::RebindTo { session_path } => {
                // Another tunnel is still connected and protected. Rebind the
                // global table to it and clear only the paused session's flag.
                // A rebind that can't anchor a live rule (Ok(false)/Err) would
                // leave the table bound to the paused tunnel's interface, so
                // fall back to a full teardown exactly as the destroy path does.
                let rebound = match apply_kill_switch(&conn, &session_path, allow_lan).await {
                    Ok(true) => true,
                    Ok(false) => {
                        warn!(
                            "kill-switch: pause rebind to {} skipped (not ready / helper absent); falling back to full teardown",
                            session_path
                        );
                        false
                    }
                    Err(e) => {
                        warn!(
                            "kill-switch: pause rebind to {} failed: {}; falling back to full teardown",
                            session_path, e
                        );
                        false
                    }
                };
                if rebound {
                    let paused = paused.clone();
                    tray.update(move |t| {
                        if let Some(s) = t.sessions.get_mut(&paused) {
                            s.kill_switch_active = false;
                        }
                    });
                } else {
                    pause_full_teardown(&tray).await;
                }
            }
            // Unreachable for a pause (is_auth_retry is always false here), but
            // matched explicitly so a future variant can't fall through silently.
            crate::app::signal_handlers::KillSwitchTeardown::Skip => {}
        }
    });
}

/// No protected survivor remains after a pause: drop the firewall and clear
/// every session's flag. Impure (D-Bus + tray + notification), no test surface.
async fn pause_full_teardown(tray: &ksni::blocking::Handle<VpnTray>) {
    crate::dbus::killswitch::remove_rules().await;
    tray.update(|t| {
        for s in t.sessions.values_mut() {
            s.kill_switch_active = false;
        }
    });
    crate::dialogs::show_killswitch_inactive_notification();
}

#[cfg(test)]
mod tests {
    use super::should_teardown_on_pause;
    use crate::app::signal_handlers::{KillSwitchTeardown, decide_kill_switch_teardown};

    const PAUSED: &str = "/net/openvpn/v3/sessions/paused";
    const OTHER: &str = "/net/openvpn/v3/sessions/other";

    fn sess(path: &str, connected: bool, ks: bool) -> (String, bool, bool) {
        (path.to_string(), connected, ks)
    }

    #[test]
    fn teardown_on_pause_only_when_enabled_and_not_blocking() {
        // Kill-switch disabled → no teardown regardless of the block flag.
        assert!(!should_teardown_on_pause(false, false));
        assert!(!should_teardown_on_pause(false, true));
        // Enabled + block-during-pause → keep rules (stay protected while paused).
        assert!(!should_teardown_on_pause(true, true));
        // Enabled + not blocking → tear the firewall down on pause.
        assert!(should_teardown_on_pause(true, false));
    }

    // The pause path reuses the destroy path's survivor decision, so these
    // assert the *pause* wiring holds the same invariant: a connected+protected
    // survivor must never be stripped by another session pausing (#5).

    #[test]
    fn pause_with_protected_survivor_rebinds_instead_of_wiping() {
        let d = decide_kill_switch_teardown(
            PAUSED,
            false,
            vec![sess(PAUSED, false, true), sess(OTHER, true, true)],
        );
        assert_eq!(
            d,
            KillSwitchTeardown::RebindTo {
                session_path: OTHER.to_string()
            },
            "pausing one session must not tear down a still-protected survivor"
        );
    }

    #[test]
    fn pause_of_only_protected_session_tears_down_fully() {
        let d = decide_kill_switch_teardown(PAUSED, false, vec![sess(PAUSED, false, true)]);
        assert_eq!(d, KillSwitchTeardown::Full);
    }

    #[test]
    fn pause_with_unprotected_survivor_tears_down_fully() {
        // A connected but never-kill-switch-protected session has nothing to
        // preserve, so releasing the firewall on pause is correct.
        let d = decide_kill_switch_teardown(PAUSED, false, vec![sess(OTHER, true, false)]);
        assert_eq!(d, KillSwitchTeardown::Full);
    }

    #[test]
    fn pause_never_skips_teardown() {
        // Skip exists only for auth-retry session swaps; a pause always passes
        // is_auth_retry = false, so the pause path can never reach Skip and
        // silently leave the firewall bound to the paused tunnel.
        for survivors in [
            vec![],
            vec![sess(PAUSED, false, true)],
            vec![sess(OTHER, true, true)],
        ] {
            assert_ne!(
                decide_kill_switch_teardown(PAUSED, false, survivors),
                KillSwitchTeardown::Skip
            );
        }
    }
}
