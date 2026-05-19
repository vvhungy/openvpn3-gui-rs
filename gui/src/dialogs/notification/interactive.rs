//! Interactive notifications with action buttons.
//!
//! Both reconnect and first-run help follow the same pattern: subscribe to
//! `ActionInvoked`/`NotificationClosed`, dispatch on user action, exit on
//! daemon close.

use std::collections::HashMap;

use futures::StreamExt;
use tracing::warn;
use zbus::message::Type as MessageType;

use super::dedup::NOTIFICATION_IDS;
use super::killswitch::show_killswitch_inactive_notification;
use crate::settings::Settings;

/// Show a notification with a "Reconnect" action button for unexpected disconnects.
/// When the user clicks Reconnect, dispatches `TrayAction::Connect(config_path)`.
/// Gated behind `warn-on-unexpected-disconnect` setting.
/// Uses `replaces_id` to prevent stacking on rapid crash/restart cycles.
pub fn show_reconnect_notification(
    config_path: String,
    config_name: String,
    action_tx: crate::tray::ActionSender,
    tray: ksni::blocking::Handle<crate::tray::VpnTray>,
) {
    if !Settings::new().warn_on_unexpected_disconnect() {
        return;
    }
    glib::spawn_future_local(async move {
        if let Err(e) = do_reconnect_notification(config_path, config_name, action_tx, tray).await {
            warn!("Reconnect notification error: {}", e);
        }
    });
}

async fn do_reconnect_notification(
    config_path: String,
    config_name: String,
    action_tx: crate::tray::ActionSender,
    tray: ksni::blocking::Handle<crate::tray::VpnTray>,
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

    // Always create a fresh notification — the reconnect notification is a
    // persistent action-button dialog, not a status toast.  Reusing the ID
    // from a previous connection toast fails when the daemon already reaped it.
    let key = config_name.clone();
    let replaces_id: u32 = 0;

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
                &["reconnect", "Reconnect", "dismiss", "Dismiss"] as &[&str],
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
                {
                    match key {
                        "reconnect" => {
                            // Don't remove rules — the new tunnel's connect path
                            // re-applies them (helper has replace semantics).
                            let _ = action_tx
                                .unbounded_send(crate::tray::TrayAction::Connect(config_path));
                            break;
                        }
                        "dismiss" => {
                            // User gave up on reconnecting — tear down both
                            // KS and bypass. Bypass gateway capture is
                            // ephemeral, so leaving routes installed against
                            // a possibly-stale gateway is a footgun on the
                            // next manual connect.
                            crate::dbus::killswitch::remove_rules().await;
                            crate::dbus::killswitch::remove_bypass_routes().await;
                            tray.update(|t| {
                                for s in t.sessions.values_mut() {
                                    s.kill_switch_active = false;
                                }
                                t.bypass_state = crate::tray::BypassState::Off;
                            });
                            show_killswitch_inactive_notification();
                            break;
                        }
                        _ => {}
                    }
                }
            }
            Some("NotificationClosed") => {
                if let Ok((id, _reason)) = msg.body().deserialize::<(u32, u32)>()
                    && id == notification_id
                {
                    // The daemon closed the notification (timeout, suppression by
                    // GNOME Shell focus rules, or user dismissed via desktop env).
                    // Do NOT release kill-switch rules here — the daemon may close
                    // the notification without user intent (e.g. focus suppression).
                    // The user can release rules via the notification's Dismiss
                    // action, by reconnecting, or by disabling kill-switch in
                    // Preferences.
                    break;
                }
            }
            _ => {}
        }
    }

    Ok(())
}

/// Sentinel key in `NOTIFICATION_IDS` for the first-run help notification.
const FIRST_RUN_HELP_KEY: &str = "__first_run_help__";

/// Show a one-shot help notification when the OpenVPN3 service is persistently
/// absent after startup retries. Gated behind `show-first-run-help` (independent
/// of `show-notifications` — this is an onboarding prompt, not a status event).
pub fn show_first_run_help_notification(action_tx: crate::tray::ActionSender) {
    if !Settings::new().show_first_run_help() {
        return;
    }
    glib::spawn_future_local(async move {
        if let Err(e) = do_first_run_help_notification(action_tx).await {
            warn!("First-run help notification error: {}", e);
        }
    });
}

async fn do_first_run_help_notification(
    action_tx: crate::tray::ActionSender,
) -> anyhow::Result<()> {
    let conn = zbus::Connection::session().await?;

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
        HashMap::from([("urgency", zbus::zvariant::Value::U8(1u8))]);

    let reply = conn
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &(
                "openvpn3-gui-rs",
                0u32,
                "dialog-information",
                "OpenVPN3 Service Not Running",
                "The OpenVPN3 backend could not be reached. VPN profiles will not appear until the service is running.",
                &["preferences", "Open Preferences", "dont-show", "Don't Show Again"] as &[&str],
                hints,
                -1i32,
            ),
        )
        .await?;

    let notification_id: u32 = reply.body().deserialize()?;
    if let Ok(mut map) = NOTIFICATION_IDS.lock() {
        map.insert(FIRST_RUN_HELP_KEY.to_string(), notification_id);
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
                {
                    match key {
                        "preferences" => {
                            let _ = action_tx.unbounded_send(crate::tray::TrayAction::Preferences);
                        }
                        "dont-show" => {
                            Settings::new().set_show_first_run_help(false);
                        }
                        _ => {}
                    }
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

/// Close the first-run help notification if it is currently displayed.
/// Called from `watch_service_restart` when the OpenVPN3 service appears.
pub fn withdraw_first_run_help_notification() {
    let id = NOTIFICATION_IDS
        .lock()
        .ok()
        .and_then(|mut m| m.remove(FIRST_RUN_HELP_KEY))
        .unwrap_or(0);

    if id == 0 {
        return;
    }

    glib::spawn_future_local(async move {
        if let Ok(conn) = zbus::Connection::session().await {
            let _ = conn
                .call_method(
                    Some("org.freedesktop.Notifications"),
                    "/org/freedesktop/Notifications",
                    Some("org.freedesktop.Notifications"),
                    "CloseNotification",
                    &id,
                )
                .await;
        }
    });
}
