//! Kill-switch state notifications (apply/remove) and the helper-missing toast.
//!
//! Apply and remove share a dedup key so they replace each other rather than
//! stacking when the user toggles state quickly.

use tracing::warn;

use super::core::send_notification;
use super::dedup::NOTIFICATION_IDS;
use crate::settings::Settings;

/// Show a one-shot info notification when the kill-switch helper package is
/// not installed. Gated by `show-notifications` (same gate as connection events).
pub fn show_helper_missing_notification() {
    if !Settings::new().show_notifications() {
        return;
    }
    send_notification(
        "Kill-Switch Helper Not Installed",
        "Install the openvpn3-killswitch-helper package for firewall enforcement.",
        1,
    );
}

/// Shared dedup key — apply and remove notifications use the same id so they
/// replace each other rather than stacking when the user toggles state quickly.
const KILLSWITCH_STATE_KEY: &str = "__killswitch_state__";

async fn send_killswitch_state(
    summary: &str,
    body: &str,
    urgency: u8,
    expire_timeout: i32,
) -> anyhow::Result<u32> {
    let conn = zbus::Connection::session().await?;
    let replaces_id = NOTIFICATION_IDS
        .lock()
        .map(|m| *m.get(KILLSWITCH_STATE_KEY).unwrap_or(&0))
        .unwrap_or(0);
    // Single shared Notify call (core::send_notify) — no retry wrapper, since a
    // stale replaces_id here just means the prior active/inactive toast was
    // already reaped, and a fresh id is the correct fallback for state toggles.
    let new_id = super::core::send_notify(
        &conn,
        "network-vpn",
        summary,
        body,
        &[],
        urgency,
        replaces_id,
        expire_timeout,
    )
    .await?;
    if let Ok(mut map) = NOTIFICATION_IDS.lock() {
        map.insert(KILLSWITCH_STATE_KEY.to_string(), new_id);
    }
    Ok(new_id)
}

pub fn show_killswitch_active_notification() {
    if !Settings::new().show_notifications() {
        return;
    }
    glib::spawn_future_local(async move {
        if let Err(e) = send_killswitch_state(
            "Kill-Switch Active",
            "Non-VPN traffic blocked while the tunnel is up.",
            2,
            0,
        )
        .await
        {
            warn!("Failed to send kill-switch active notification: {}", e);
        }
    });
}

pub fn show_killswitch_inactive_notification() {
    if !Settings::new().show_notifications() {
        return;
    }
    glib::spawn_future_local(async move {
        if let Err(e) = send_killswitch_state(
            "Kill-Switch Inactive",
            "Firewall rules removed. All traffic flows normally.",
            1,
            -1,
        )
        .await
        {
            warn!("Failed to send kill-switch inactive notification: {}", e);
        }
    });
}
