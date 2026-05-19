//! Bypass (split-tunneling) state notifications.
//!
//! Success and failure share a dedup key so they replace each other on retry.

use std::collections::HashMap;

use tracing::warn;

use super::dedup::NOTIFICATION_IDS;
use crate::settings::Settings;

/// Shared dedup key for bypass apply notifications — success and failure share
/// the slot so they replace each other rather than stacking on retry.
const BYPASS_STATE_KEY: &str = "__bypass_state__";

async fn send_bypass_state(
    summary: &str,
    body: &str,
    urgency: u8,
    expire_timeout: i32,
) -> anyhow::Result<u32> {
    let conn = zbus::Connection::session().await?;
    let hints: HashMap<&str, zbus::zvariant::Value<'_>> =
        HashMap::from([("urgency", zbus::zvariant::Value::U8(urgency))]);
    let replaces_id = NOTIFICATION_IDS
        .lock()
        .map(|m| *m.get(BYPASS_STATE_KEY).unwrap_or(&0))
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
                summary,
                body,
                &[] as &[&str],
                &hints,
                expire_timeout,
            ),
        )
        .await?;
    let new_id: u32 = reply.body().deserialize()?;
    if let Ok(mut map) = NOTIFICATION_IDS.lock() {
        map.insert(BYPASS_STATE_KEY.to_string(), new_id);
    }
    Ok(new_id)
}

/// Fired when bypass routes are successfully installed. One-shot
/// (`expire_timeout=-1`) per approved T5a spec: routing is informational,
/// not security-critical (KS handles that).
pub fn show_bypass_active_notification(count: usize) {
    if !Settings::new().show_notifications() {
        return;
    }
    let body = if count == 1 {
        "1 bypass network routed outside the VPN tunnel.".to_string()
    } else {
        format!("{} bypass networks routed outside the VPN tunnel.", count)
    };
    glib::spawn_future_local(async move {
        if let Err(e) = send_bypass_state("Split Tunneling Active", &body, 1, -1).await {
            warn!("Failed to send bypass active notification: {}", e);
        }
    });
}

/// Fired when bypass apply fails (helper reject, network capture failed, etc.).
/// Persistent (`urgency=critical`, `expire_timeout=0`) per approved T5a spec:
/// silent failure would leave the user thinking split tunneling worked.
pub fn show_bypass_failed_notification() {
    if !Settings::new().show_notifications() {
        return;
    }
    glib::spawn_future_local(async move {
        if let Err(e) = send_bypass_state(
            "Split Tunneling Apply Failed",
            "Bypass routes could not be installed. Reconnect or check helper logs.",
            2,
            0,
        )
        .await
        {
            warn!("Failed to send bypass failure notification: {}", e);
        }
    });
}
