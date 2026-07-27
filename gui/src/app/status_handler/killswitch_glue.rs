//! Kill-switch glue invoked from the StatusChange loop.
//!
//! All knowledge about *when* to apply or remove firewall rules in response
//! to per-session connection-state transitions lives here, so the main loop
//! stays focused on connection-lifecycle dispatch + auth fan-out.
//!
//! Most of this module is async D-Bus glue + side effects (notifications,
//! firewall calls) with no testable pure surface; the pause-teardown gate is
//! the exception and is extracted as [`should_teardown_on_pause`] so it is
//! unit-testable in isolation. One-shot semantics are covered indirectly by
//! the status_handler integration smoke test.

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
fn should_teardown_on_pause(enable_kill_switch: bool, block_during_pause: bool) -> bool {
    enable_kill_switch && !block_during_pause
}

pub(super) fn on_paused(tray: &ksni::blocking::Handle<VpnTray>) {
    let settings = crate::settings::Settings::new();
    if !should_teardown_on_pause(
        settings.enable_kill_switch(),
        settings.kill_switch_block_during_pause(),
    ) {
        return;
    }
    let tray = tray.clone();
    glib::spawn_future_local(async move {
        crate::dbus::killswitch::remove_rules().await;
        tray.update(|t| {
            for s in t.sessions.values_mut() {
                s.kill_switch_active = false;
            }
        });
        crate::dialogs::show_killswitch_inactive_notification();
    });
}

#[cfg(test)]
mod tests {
    use super::should_teardown_on_pause;

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
}
