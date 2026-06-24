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
pub(super) async fn send_dbus_notification(
    summary: &str,
    body: &str,
    urgency: u8,
    replaces_id: u32,
) -> anyhow::Result<u32> {
    let conn = zbus::Connection::session().await?;
    let hints: HashMap<&str, zbus::zvariant::Value<'_>> =
        HashMap::from([("urgency", zbus::zvariant::Value::U8(urgency))]);
    let mut rid = replaces_id;
    loop {
        let reply = conn
            .call_method(
                Some("org.freedesktop.Notifications"),
                "/org/freedesktop/Notifications",
                Some("org.freedesktop.Notifications"),
                "Notify",
                &(
                    "openvpn3-gui-rs",
                    rid,
                    "network-vpn",
                    summary,
                    body,
                    &[] as &[&str],
                    &hints,
                    -1i32,
                ),
            )
            .await;
        match reply {
            Ok(r) => return Ok(r.body().deserialize()?),
            Err(_) if rid != 0 => {
                // Stale replaces_id — retry as a fresh notification.
                rid = 0;
                continue;
            }
            Err(e) => return Err(e.into()),
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
