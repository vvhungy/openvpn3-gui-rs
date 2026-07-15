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

/// A notification-daemon signal relevant to the interactive notification that
/// owns `target_id`, after filtering out everything addressed elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NotifSignal {
    /// `ActionInvoked` for our notification, carrying the action key.
    Action(String),
    /// `NotificationClosed` for our notification.
    Closed,
}

/// Classify a D-Bus message as a notification signal for `target_id`.
///
/// Returns `None` for everything the interactive-notification loop should
/// skip: non-signals, signals on a different interface, signals for a
/// different notification id, and malformed bodies. Pure — it only reads the
/// message, no connection or I/O.
fn classify_notification_signal(msg: &zbus::Message, target_id: u32) -> Option<NotifSignal> {
    if msg.message_type() != MessageType::Signal {
        return None;
    }
    let header = msg.header();
    if header.interface().map(|i| i.as_str()) != Some("org.freedesktop.Notifications") {
        return None;
    }
    match header.member().map(|m| m.as_str()) {
        Some("ActionInvoked") => msg
            .body()
            .deserialize::<(u32, &str)>()
            .ok()
            .filter(|(id, _)| *id == target_id)
            .map(|(_, key)| NotifSignal::Action(key.to_string())),
        Some("NotificationClosed") => msg
            .body()
            .deserialize::<(u32, u32)>()
            .ok()
            .filter(|(id, _)| *id == target_id)
            .map(|_| NotifSignal::Closed),
        _ => None,
    }
}

/// Subscribe `conn` to `ActionInvoked` and `NotificationClosed` so the
/// interactive-notification loop receives them. Impure transport glue.
async fn subscribe_to_notification_signals(conn: &zbus::Connection) -> anyhow::Result<()> {
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
    Ok(())
}

/// Handle one `ActionInvoked` key for the reconnect dialog.
///
/// Returns `true` when the dialog should close (Reconnect/Dismiss); `false`
/// for an unrecognised key so the loop keeps listening. Impure: on Reconnect it
/// sends a tray action, on Dismiss it tears down the kill-switch and bypass
/// routes before clearing tray state.
async fn handle_reconnect_action(
    key: &str,
    config_path: &str,
    action_tx: &crate::tray::ActionSender,
    tray: &ksni::blocking::Handle<crate::tray::VpnTray>,
) -> bool {
    match key {
        "reconnect" => {
            let _ =
                action_tx.unbounded_send(crate::tray::TrayAction::Connect(config_path.to_string()));
            true
        }
        "dismiss" => {
            // User gave up on reconnecting — tear down both KS and bypass.
            // Bypass gateway capture is ephemeral, so leaving routes installed
            // against a possibly-stale gateway is a footgun on the next manual
            // connect. Don't remove rules here — the new tunnel's connect path
            // re-applies them (helper has replace semantics).
            crate::dbus::killswitch::remove_rules().await;
            crate::dbus::killswitch::remove_bypass_routes().await;
            tray.update(|t| {
                for s in t.sessions.values_mut() {
                    s.kill_switch_active = false;
                }
                t.bypass_state = crate::tray::BypassState::Off;
            });
            show_killswitch_inactive_notification();
            true
        }
        _ => false,
    }
}

/// Handle one `ActionInvoked` key for the first-run help dialog. Impure
/// dispatch: opens Preferences or persists "don't show again".
fn handle_first_run_action(key: &str, action_tx: &crate::tray::ActionSender) {
    match key {
        "preferences" => {
            let _ = action_tx.unbounded_send(crate::tray::TrayAction::Preferences);
        }
        "dont-show" => Settings::new().set_show_first_run_help(false),
        _ => {}
    }
}

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
    subscribe_to_notification_signals(&conn).await?;

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
        match classify_notification_signal(&msg, notification_id) {
            Some(NotifSignal::Action(action_key)) => {
                if handle_reconnect_action(&action_key, &config_path, &action_tx, &tray).await {
                    break;
                }
            }
            Some(NotifSignal::Closed) => break,
            None => {}
        }
    }

    Ok(())
}

/// Sentinel key in `NOTIFICATION_IDS` for the first-run help notification.
const FIRST_RUN_HELP_KEY: &str = "__first_run_help__";

/// Show a one-shot help notification when the OpenVPN3 service is persistently
/// absent after startup retries. Gated behind `show-first-run-help` (independent
/// of `warn-on-unexpected-disconnect`).
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
    subscribe_to_notification_signals(&conn).await?;

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
        match classify_notification_signal(&msg, notification_id) {
            Some(NotifSignal::Action(action_key)) => {
                handle_first_run_action(&action_key, &action_tx);
                break;
            }
            Some(NotifSignal::Closed) => break,
            None => {}
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `org.freedesktop.Notifications` signal message offline (no
    /// connection) so the pure classifier can be exercised end-to-end.
    fn notif_signal(
        member: &str,
        body: &(impl zbus::export::serde::Serialize + zbus::zvariant::Type),
    ) -> zbus::Message {
        zbus::Message::signal(
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
            member,
        )
        .expect("valid signal header")
        .build(body)
        .expect("valid body")
    }

    #[test]
    fn classify_action_invoked_for_our_id() {
        let msg = notif_signal("ActionInvoked", &(7u32, "reconnect"));
        assert_eq!(
            classify_notification_signal(&msg, 7),
            Some(NotifSignal::Action("reconnect".into()))
        );
    }

    #[test]
    fn classify_action_invoked_for_other_id_is_skipped() {
        let msg = notif_signal("ActionInvoked", &(99u32, "reconnect"));
        assert_eq!(classify_notification_signal(&msg, 7), None);
    }

    #[test]
    fn classify_closed_for_our_id() {
        let msg = notif_signal("NotificationClosed", &(7u32, 2u32));
        assert_eq!(
            classify_notification_signal(&msg, 7),
            Some(NotifSignal::Closed)
        );
    }

    #[test]
    fn classify_closed_for_other_id_is_skipped() {
        let msg = notif_signal("NotificationClosed", &(99u32, 2u32));
        assert_eq!(classify_notification_signal(&msg, 7), None);
    }

    #[test]
    fn classify_unknown_member_is_skipped() {
        let msg = notif_signal("UnrelatedSignal", &(7u32, "x"));
        assert_eq!(classify_notification_signal(&msg, 7), None);
    }
}
