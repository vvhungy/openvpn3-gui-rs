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
        return Ok(true);
    }
    let (_proto, server_ip, _port) = proxy.connected_to().await?;
    if server_ip.is_empty() {
        warn!("kill-switch: connected_to address empty — rules NOT applied");
        return Ok(true);
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
    if !settings.enable_kill_switch() {
        return;
    }
    let allow_lan = settings.kill_switch_allow_lan();
    let path = session_path.to_string();
    let conn = conn.clone();
    let tray = tray.clone();
    glib::spawn_future_local(async move {
        match apply_kill_switch(&conn, &path, allow_lan).await {
            Ok(true) => {
                let p = path.clone();
                tray.update(move |t| {
                    if let Some(s) = t.sessions.get_mut(&p) {
                        s.kill_switch_active = true;
                    }
                });
            }
            Ok(false) if !HELPER_MISSING_NOTIFIED.swap(true, Ordering::Relaxed) => {
                crate::dialogs::show_helper_missing_notification();
            }
            Err(e) => warn!("kill-switch: apply failed: {}", e),
            _ => {}
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
    });
}
