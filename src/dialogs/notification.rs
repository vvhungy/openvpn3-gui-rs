//! Desktop notifications
//!
//! Sends notifications via org.freedesktop.Notifications D-Bus interface,
//! which works without a .desktop file installed.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use futures::StreamExt;
use tracing::warn;
use zbus::message::Type as MessageType;

use crate::settings::Settings;

/// Tracks the last notification ID per config name so status updates replace
/// the previous toast instead of stacking new ones.
static NOTIFICATION_IDS: LazyLock<Mutex<HashMap<String, u32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Send a notification, optionally replacing an existing one.
/// Returns the notification ID assigned by the daemon.
async fn send_dbus_notification(
    summary: &str,
    body: &str,
    urgency: u8,
    replaces_id: u32,
) -> anyhow::Result<u32> {
    let conn = zbus::Connection::session().await?;
    let hints: HashMap<&str, zbus::zvariant::Value<'_>> =
        HashMap::from([("urgency", zbus::zvariant::Value::U8(urgency))]);
    let reply = conn
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &(
                "openvpn3-gui-rs", // app_name
                replaces_id,       // replaces_id (0 = new notification)
                "network-vpn",     // app_icon
                summary,           // summary
                body,              // body
                &[] as &[&str],    // actions
                hints,             // hints
                -1i32,             // expire_timeout (-1 = default)
            ),
        )
        .await?;
    let id: u32 = reply.body().deserialize()?;
    Ok(id)
}

/// Fire-and-forget notification with replaces_id=0 (always a fresh toast).
fn send_notification(summary: &str, body: &str, urgency: u8) {
    let summary = summary.to_string();
    let body = body.to_string();
    glib::spawn_future_local(async move {
        if let Err(e) = send_dbus_notification(&summary, &body, urgency, 0).await {
            warn!("Failed to send notification: {}", e);
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

/// Show a notification with a "Reconnect" action button for unexpected disconnects.
/// When the user clicks Reconnect, dispatches `TrayAction::Connect(config_path)`.
/// Gated behind `warn-on-unexpected-disconnect` setting.
/// Uses `replaces_id` to prevent stacking on rapid crash/restart cycles.
pub fn show_reconnect_notification(
    config_path: String,
    config_name: String,
    action_tx: crate::tray::ActionSender,
) {
    if !Settings::new().warn_on_unexpected_disconnect() {
        return;
    }
    glib::spawn_future_local(async move {
        if let Err(e) = do_reconnect_notification(config_path, config_name, action_tx).await {
            warn!("Reconnect notification error: {}", e);
        }
    });
}

async fn do_reconnect_notification(
    config_path: String,
    config_name: String,
    action_tx: crate::tray::ActionSender,
) -> anyhow::Result<()> {
    let conn = zbus::Connection::session().await?;

    // Subscribe to the signals we need from the notification daemon
    for member in &["ActionInvoked", "NotificationClosed"] {
        conn.call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "AddMatch",
            &format!(
                "type='signal',interface='org.freedesktop.Notifications',member='{}'",
                member
            ),
        )
        .await?;
    }

    let hints: HashMap<&str, zbus::zvariant::Value<'_>> =
        HashMap::from([("urgency", zbus::zvariant::Value::U8(2u8))]);
    let body = format!("'{}' disconnected unexpectedly.", config_name);

    let key = config_name.clone();
    let replaces_id = NOTIFICATION_IDS
        .lock()
        .map(|m| *m.get(&key).unwrap_or(&0))
        .unwrap_or(0);

    let reply = conn
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &(
                "openvpn3-gui-rs",
                replaces_id,
                "network-vpn",
                "VPN Disconnected",
                body.as_str(),
                &["reconnect", "Reconnect"] as &[&str],
                hints,
                0i32, // never auto-dismiss — user must acknowledge
            ),
        )
        .await?;

    let notification_id: u32 = reply.body().deserialize()?;
    if let Ok(mut map) = NOTIFICATION_IDS.lock() {
        map.insert(key, notification_id);
    }

    let mut stream = zbus::MessageStream::from(&conn);
    while let Some(Ok(msg)) = stream.next().await {
        if msg.message_type() != MessageType::Signal {
            continue;
        }
        let header = msg.header();
        if header.interface().map(|i| i.as_str()) != Some("org.freedesktop.Notifications") {
            continue;
        }
        match header.member().map(|m| m.as_str()) {
            Some("ActionInvoked") => {
                if let Ok((id, key)) = msg.body().deserialize::<(u32, &str)>()
                    && id == notification_id
                    && key == "reconnect"
                {
                    let _ = action_tx.unbounded_send(crate::tray::TrayAction::Connect(config_path));
                    break;
                }
            }
            Some("NotificationClosed") => {
                if let Ok((id, _reason)) = msg.body().deserialize::<(u32, u32)>()
                    && id == notification_id
                {
                    break;
                }
            }
            _ => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique key prefix to avoid collisions with other test runs in the
    /// shared static map.
    const TEST_PREFIX: &str = "__notif_test__";

    fn test_key(suffix: &str) -> String {
        format!("{}{}", TEST_PREFIX, suffix)
    }

    fn cleanup(key: &str) {
        if let Ok(mut m) = NOTIFICATION_IDS.lock() {
            m.remove(key);
        }
    }

    #[test]
    fn test_notification_ids_lock_is_accessible() {
        // Verify the static mutex can be locked without deadlock
        let _guard = NOTIFICATION_IDS.lock().unwrap();
    }

    #[test]
    fn test_notification_ids_insert_and_retrieve() {
        let key = test_key("insert");
        {
            let mut m = NOTIFICATION_IDS.lock().unwrap();
            m.insert(key.clone(), 99u32);
        }
        let stored = NOTIFICATION_IDS
            .lock()
            .map(|m| *m.get(&key).unwrap_or(&0))
            .unwrap_or(0);
        assert_eq!(stored, 99);
        cleanup(&key);
    }

    #[test]
    fn test_notification_ids_missing_key_returns_zero() {
        let key = test_key("missing");
        // Ensure it's not in the map
        cleanup(&key);
        let stored = NOTIFICATION_IDS
            .lock()
            .map(|m| *m.get(&key).unwrap_or(&0))
            .unwrap_or(0);
        assert_eq!(stored, 0);
    }

    #[test]
    fn test_notification_ids_overwrite() {
        let key = test_key("overwrite");
        {
            let mut m = NOTIFICATION_IDS.lock().unwrap();
            m.insert(key.clone(), 1u32);
            m.insert(key.clone(), 2u32);
        }
        let stored = NOTIFICATION_IDS
            .lock()
            .map(|m| *m.get(&key).unwrap_or(&0))
            .unwrap_or(0);
        assert_eq!(stored, 2);
        cleanup(&key);
    }

    #[test]
    fn test_notification_ids_remove() {
        let key = test_key("remove");
        {
            let mut m = NOTIFICATION_IDS.lock().unwrap();
            m.insert(key.clone(), 5u32);
        }
        cleanup(&key);
        let stored = NOTIFICATION_IDS
            .lock()
            .map(|m| *m.get(&key).unwrap_or(&0))
            .unwrap_or(0);
        assert_eq!(stored, 0);
    }
}
