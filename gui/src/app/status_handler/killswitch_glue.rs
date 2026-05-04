//! Kill-switch glue invoked from the StatusChange loop.
//!
//! All knowledge about *when* to apply or remove firewall rules in response
//! to per-session connection-state transitions lives here, so the main loop
//! stays focused on connection-lifecycle dispatch + auth fan-out.

use tracing::warn;

/// Build a SessionProxy for `path`, read the tun interface name and the
/// currently connected server IP, and ask the kill-switch helper to install
/// rules that block all non-tunnel traffic. Returns `Err` only on real
/// D-Bus or proxy failures; missing helper / empty fields are warned about
/// inside and reported as `Ok(())`.
pub(crate) async fn apply_kill_switch(
    conn: &zbus::Connection,
    session_path: &str,
    allow_lan: bool,
) -> anyhow::Result<()> {
    let proxy = crate::dbus::session::SessionProxy::builder(conn)
        .path(session_path)?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await?;
    let device_name = proxy.device_name().await?;
    if device_name.is_empty() {
        warn!("kill-switch: device_name empty on connected session — rules NOT applied");
        return Ok(());
    }
    let (_proto, server_ip, _port) = proxy.connected_to().await?;
    if server_ip.is_empty() {
        warn!("kill-switch: connected_to address empty — rules NOT applied");
        return Ok(());
    }
    crate::dbus::killswitch::add_rules(&device_name, vec![server_ip], allow_lan).await;
    Ok(())
}

pub(super) fn on_connected(conn: &zbus::Connection, session_path: &str) {
    let settings = crate::settings::Settings::new();
    if !settings.enable_kill_switch() {
        return;
    }
    let allow_lan = settings.kill_switch_allow_lan();
    let path = session_path.to_string();
    let conn = conn.clone();
    glib::spawn_future_local(async move {
        if let Err(e) = apply_kill_switch(&conn, &path, allow_lan).await {
            warn!("kill-switch: apply failed: {}", e);
        }
    });
}

pub(super) fn on_paused() {
    let settings = crate::settings::Settings::new();
    if !settings.enable_kill_switch() || settings.kill_switch_block_during_pause() {
        return;
    }
    glib::spawn_future_local(async {
        crate::dbus::killswitch::remove_rules().await;
    });
}
