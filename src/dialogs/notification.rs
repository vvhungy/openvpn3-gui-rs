//! Desktop notifications
//!
//! Sends notifications via org.freedesktop.Notifications D-Bus interface,
//! which works without a .desktop file installed.

use std::collections::HashMap;

use futures::StreamExt;
use tracing::warn;
use zbus::message::Type as MessageType;

use crate::settings::Settings;

/// Send a notification via org.freedesktop.Notifications D-Bus interface
fn send_notification(summary: &str, body: &str, urgency: u8) {
    let summary = summary.to_string();
    let body = body.to_string();
    glib::spawn_future_local(async move {
        if let Err(e) = send_dbus_notification(&summary, &body, urgency).await {
            warn!("Failed to send notification: {}", e);
        }
    });
}

async fn send_dbus_notification(summary: &str, body: &str, urgency: u8) -> anyhow::Result<()> {
    let conn = zbus::Connection::session().await?;
    let hints: HashMap<&str, zbus::zvariant::Value<'_>> =
        HashMap::from([("urgency", zbus::zvariant::Value::U8(urgency))]);
    conn.call_method(
        Some("org.freedesktop.Notifications"),
        "/org/freedesktop/Notifications",
        Some("org.freedesktop.Notifications"),
        "Notify",
        &(
            "openvpn3-gui-rs", // app_name
            0u32,              // replaces_id
            "network-vpn",     // app_icon
            summary,           // summary
            body,              // body
            &[] as &[&str],    // actions
            hints,             // hints
            -1i32,             // expire_timeout (-1 = default)
        ),
    )
    .await?;
    Ok(())
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

/// Show a connection status notification (suppressed when show_notifications is off)
pub fn show_connection_notification(config_name: &str, status: &str) {
    if !Settings::new().show_notifications() {
        return;
    }
    let title = format!("VPN: {}", config_name);
    send_notification(&title, status, 1);
}

/// Show a notification with a "Reconnect" action button for unexpected disconnects.
/// When the user clicks Reconnect, dispatches `TrayAction::Connect(config_path)`.
pub fn show_reconnect_notification(
    config_path: String,
    config_name: String,
    action_tx: crate::tray::ActionSender,
) {
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

    let reply = conn
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &(
                "openvpn3-gui-rs",
                0u32,
                "network-vpn",
                "VPN Disconnected",
                body.as_str(),
                &["reconnect", "Reconnect"] as &[&str],
                hints,
                30_000i32, // dismiss after 30 s if no action taken
            ),
        )
        .await?;

    let notification_id: u32 = reply.body().deserialize()?;

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
