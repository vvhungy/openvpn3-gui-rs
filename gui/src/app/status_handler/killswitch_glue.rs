//! Kill-switch glue invoked from the StatusChange loop.
//!
//! All knowledge about *when* to apply or remove firewall rules in response
//! to per-session connection-state transitions lives here, so the main loop
//! stays focused on connection-lifecycle dispatch + auth fan-out.
//!
//! No testable pure surface — async D-Bus glue + side effects (notifications,
//! firewall calls). One-shot semantics covered indirectly by the status_handler
//! integration smoke test.

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
        // Push bypass CIDRs and install routing (replaces any prior state).
        // Gate ApplyBypassRoutes on SetBypassCidrs success — if validation
        // rejects the list, the helper retains its prior state and applying
        // would install routes for the wrong CIDRs.
        if !bypass_cidrs.is_empty() {
            let count = bypass_cidrs.len();
            let set_ok = crate::dbus::killswitch::set_bypass_cidrs(bypass_cidrs).await;
            let apply_ok = set_ok && crate::dbus::killswitch::apply_bypass_routes().await;
            if apply_ok {
                tray_for_bypass
                    .update(move |t| t.bypass_state = crate::tray::BypassState::Active(count));
                crate::dialogs::show_bypass_active_notification(count);
            } else {
                tray_for_bypass.update(|t| t.bypass_state = crate::tray::BypassState::Failed);
                crate::dialogs::show_bypass_failed_notification();
            }
        }

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

pub(super) fn on_paused(tray: &ksni::blocking::Handle<VpnTray>) {
    let settings = crate::settings::Settings::new();
    if !settings.enable_kill_switch() || settings.kill_switch_block_during_pause() {
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
