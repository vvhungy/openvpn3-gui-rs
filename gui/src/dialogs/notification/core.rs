//! Core transport + simple fire-and-forget notifications.
//!
//! `send_dbus_notification` is the low-level shim around
//! `org.freedesktop.Notifications.Notify`; it transparently retries with a
//! fresh id when `replaces_id` is stale.

use std::collections::HashMap;

use tracing::warn;

use super::dedup::NOTIFICATION_IDS;
use crate::settings::Settings;

/// Send a notification, optionally replacing an existing one.
/// Returns the notification ID assigned by the daemon.
/// If `replaces_id` is stale (notification already reaped), falls back to
/// a fresh notification silently.
/// Send one `org.freedesktop.Notifications.Notify` call and return the
/// daemon-assigned id. Shared transport primitive — every notification path
/// routes through here (the fire-and-forget retry wrapper below, the kill-switch
/// state toasts, and the interactive action-button loop), so the Notify
/// tuple construction lives in exactly one place. `actions` is empty for
/// non-interactive toasts; `replaces_id`/`expire_timeout` are caller-controlled.
// 8 args mirror the org.freedesktop.Notifications.Notify signature 1:1;
// grouping into a struct would just re-spread these fields at every call site.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_notify(
    conn: &zbus::Connection,
    icon: &str,
    summary: &str,
    body: &str,
    actions: &[&str],
    urgency: u8,
    replaces_id: u32,
    expire_timeout: i32,
) -> anyhow::Result<u32> {
    let hints: HashMap<&str, zbus::zvariant::Value<'_>> =
        HashMap::from([("urgency", zbus::zvariant::Value::U8(urgency))]);
    let reply = conn
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &(
                "openvpn3-gui-rs",
                replaces_id,
                icon,
                summary,
                body,
                actions,
                &hints,
                expire_timeout,
            ),
        )
        .await?;
    Ok(reply.body().deserialize()?)
}

/// Send a notification, optionally replacing an existing one.
/// Returns the notification ID assigned by the daemon.
/// If `replaces_id` is stale (notification already reaped), falls back to
/// a fresh notification silently. Fire-and-forget toasts use the fixed
/// `network-vpn` icon, no actions, and the daemon-default expiry (-1).
pub(super) async fn send_dbus_notification(
    summary: &str,
    body: &str,
    urgency: u8,
    replaces_id: u32,
) -> anyhow::Result<u32> {
    let conn = zbus::Connection::session().await?;
    let mut rid = replaces_id;
    loop {
        match send_notify(&conn, "network-vpn", summary, body, &[], urgency, rid, -1).await {
            Ok(id) => return Ok(id),
            Err(_) if rid != 0 => {
                // Stale replaces_id — retry as a fresh notification.
                rid = 0;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Fire-and-forget notification, deduped on `summary`. A second call with the
/// same summary replaces the prior toast instead of stacking. The dedup key is
/// the summary (the title) because info/error toasts are categorized by title
/// (e.g. "Import Failed", "Clear Credentials Failed"); repeated failures of the
/// same kind should coalesce, not pile up. Per CLAUDE.md every notification
/// must route through the `NOTIFICATION_IDS` dedup map — these generic toasts
/// previously bypassed it.
pub(super) fn send_notification(summary: &str, body: &str, urgency: u8) {
    let summary = summary.to_string();
    let body = body.to_string();
    let key = summary.clone();
    let replaces_id = NOTIFICATION_IDS
        .lock()
        .map(|m| *m.get(&key).unwrap_or(&0))
        .unwrap_or(0);
    glib::spawn_future_local(async move {
        match send_dbus_notification(&summary, &body, urgency, replaces_id).await {
            Ok(new_id) => {
                if let Ok(mut map) = NOTIFICATION_IDS.lock() {
                    map.insert(key, new_id);
                }
            }
            Err(e) => warn!("Failed to send notification: {}", e),
        }
    });
}

/// Show an info notification (suppressed when show_notifications is off)
pub fn show_info_notification(title: &str, message: &str) {
    if !Settings::new().show_notifications() {
        return;
    }
    send_notification(title, message, 1);
}

/// Show an error notification (always shown regardless of show_notifications)
pub fn show_error_notification(title: &str, message: &str) {
    send_notification(title, message, 2);
}

/// Show a connection status notification, replacing any previous toast for this
/// config so rapid status transitions don't stack separate notifications.
/// Suppressed when show_notifications is off.
pub fn show_connection_notification(config_name: &str, status: &str) {
    if !Settings::new().show_notifications() {
        return;
    }
    let title = format!("VPN: {}", config_name);
    let status = status.to_string();
    let key = config_name.to_string();
    let replaces_id = NOTIFICATION_IDS
        .lock()
        .map(|m| *m.get(&key).unwrap_or(&0))
        .unwrap_or(0);
    glib::spawn_future_local(async move {
        match send_dbus_notification(&title, &status, 1, replaces_id).await {
            Ok(new_id) => {
                if let Ok(mut map) = NOTIFICATION_IDS.lock() {
                    map.insert(key, new_id);
                }
            }
            Err(e) => warn!("Failed to send notification: {}", e),
        }
    });
}
