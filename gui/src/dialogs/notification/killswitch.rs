//! Kill-switch state notifications (apply/remove) and the helper-missing toast.
//!
//! Apply and remove share a dedup key so they replace each other rather than
//! stacking when the user toggles state quickly.

use tracing::warn;

use super::core::send_notification;
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
    // Shared state-toast sender: replaces the prior active/inactive toast via
    // KILLSWITCH_STATE_KEY, and on a stale (reaped) replaces_id retries once as
    // a fresh toast rather than dropping the state change (S47-T3).
    super::core::send_state_notification(
        &conn,
        KILLSWITCH_STATE_KEY,
        "network-vpn",
        summary,
        body,
        urgency,
        expire_timeout,
    )
    .await
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
