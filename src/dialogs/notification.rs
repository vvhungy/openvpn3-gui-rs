//! Desktop notifications
//!
//! Sends notifications via org.freedesktop.Notifications D-Bus interface,
//! which works without a .desktop file installed.

use std::collections::HashMap;
use tracing::warn;

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

/// Show an info notification
pub fn show_info_notification(title: &str, message: &str) {
    send_notification(title, message, 1);
}

/// Show an error notification
pub fn show_error_notification(title: &str, message: &str) {
    send_notification(title, message, 2);
}

/// Show a connection status notification
pub fn show_connection_notification(config_name: &str, status: &str) {
    let title = format!("VPN: {}", config_name);
    send_notification(&title, status, 1);
}
