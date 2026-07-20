//! Interactive notifications with action buttons.
//!
//! Both reconnect and first-run help follow the same pattern: subscribe to
//! `ActionInvoked`/`NotificationClosed`, dispatch on user action, exit on
//! daemon close.

use std::collections::HashMap;
use std::future::Future;

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
            // Don't remove rules here — the new tunnel's connect path re-applies
            // them (helper has replace semantics).
            let _ =
                action_tx.unbounded_send(crate::tray::TrayAction::Connect(config_path.to_string()));
            true
        }
        "dismiss" => {
            // User gave up on reconnecting — tear down both KS and bypass.
            // Bypass gateway capture is ephemeral, so leaving routes installed
            // against a possibly-stale gateway is a footgun on the next manual
            // connect.
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

/// Payload for an action-button notification: the `Notify` D-Bus call
/// arguments plus the dedup key recorded in [`NOTIFICATION_IDS`]. Reconnect
/// and first-run help differ only in these fields, so both route through one
/// runner.
struct NotifSpec<'a> {
    icon: &'a str,
    summary: &'a str,
    body: String,
    actions: &'a [&'a str],
    urgency: u8,
    /// Expiry hint: `0` = never expire (persistent dialog), `-1` = daemon default.
    expire_timeout: i32,
    /// Key under which the returned notification id is stored, so later code
    /// (e.g. [`withdraw_first_run_help_notification`]) can close it.
    dedup_key: String,
}

/// Post an action-button notification and drive its `ActionInvoked` /
/// `NotificationClosed` stream until the daemon closes it or `on_action`
/// signals a terminal action. Shared scaffold for reconnect and first-run
/// help — only the [`NotifSpec`] and the handler differ.
///
/// Generic over the handler (not `dyn`) so a closure may borrow its enclosing
/// function's locals; the only constraint is that every call returns the *same*
/// concrete future type. Both callers return a `'static` boxed future that owns
/// its data (cloned per click — `ActionSender`/`Handle` are cheap Arc clones),
/// which is what lets the handler run across `await` points without borrowing.
async fn run_action_notification<F, Fut>(spec: NotifSpec<'_>, on_action: F) -> anyhow::Result<()>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = bool>,
{
    let conn = zbus::Connection::session().await?;
    subscribe_to_notification_signals(&conn).await?;

    let hints: HashMap<&str, zbus::zvariant::Value<'_>> =
        HashMap::from([("urgency", zbus::zvariant::Value::U8(spec.urgency))]);

    let reply = conn
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &(
                "openvpn3-gui-rs",
                0u32, // replaces_id — always fresh (see reconnect comment)
                spec.icon,
                spec.summary,
                spec.body.as_str(),
                spec.actions,
                hints,
                spec.expire_timeout,
            ),
        )
        .await?;

    let notification_id: u32 = reply.body().deserialize()?;
    if let Ok(mut map) = NOTIFICATION_IDS.lock() {
        map.insert(spec.dedup_key, notification_id);
    }

    let mut stream = zbus::MessageStream::from(&conn);
    while let Some(Ok(msg)) = stream.next().await {
        match classify_notification_signal(&msg, notification_id) {
            Some(NotifSignal::Action(action_key)) => {
                if on_action(action_key).await {
                    break;
                }
            }
            Some(NotifSignal::Closed) => break,
            None => {}
        }
    }

    Ok(())
}

/// Spawn a notification future on the GLib main loop, logging on error.
/// Both `show_*` entry points share this gate-then-spawn scaffold.
fn spawn_notif<F>(label: &'static str, fut: F)
where
    F: std::future::Future<Output = anyhow::Result<()>> + 'static,
{
    glib::spawn_future_local(async move {
        if let Err(e) = fut.await {
            warn!("{} error: {}", label, e);
        }
    });
}

/// Build the reconnect notification spec. Pure — split out so the fields are
/// testable without a D-Bus connection (I6 pure/impure split).
fn reconnect_spec(config_name: &str) -> NotifSpec<'static> {
    NotifSpec {
        icon: "network-vpn",
        summary: "VPN Disconnected",
        body: format!("'{}' disconnected unexpectedly.", config_name),
        actions: &["reconnect", "Reconnect", "dismiss", "Dismiss"],
        urgency: 2,        // critical — unexpected disconnect
        expire_timeout: 0, // never auto-dismiss; user must acknowledge
        dedup_key: config_name.to_string(),
    }
}

/// Build the first-run help notification spec. Pure — see [`reconnect_spec`].
fn first_run_help_spec() -> NotifSpec<'static> {
    NotifSpec {
        icon: "dialog-information",
        summary: "OpenVPN3 Service Not Running",
        body: "The OpenVPN3 backend could not be reached. VPN profiles will not appear until the service is running."
            .to_string(),
        actions: &[
            "preferences",
            "Open Preferences",
            "dont-show",
            "Don't Show Again",
        ],
        urgency: 1,         // normal — informational
        expire_timeout: -1, // daemon default
        dedup_key: FIRST_RUN_HELP_KEY.to_string(),
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
    spawn_notif(
        "Reconnect notification",
        do_reconnect_notification(config_path, config_name, action_tx, tray),
    );
}

async fn do_reconnect_notification(
    config_path: String,
    config_name: String,
    action_tx: crate::tray::ActionSender,
    tray: ksni::blocking::Handle<crate::tray::VpnTray>,
) -> anyhow::Result<()> {
    // Always create a fresh notification — the reconnect notification is a
    // persistent action-button dialog, not a status toast.  Reusing the ID
    // from a previous connection toast fails when the daemon already reaped it.
    run_action_notification(reconnect_spec(&config_name), |action_key: String| {
        // `Handle`/`ActionSender` are cheap (Arc) clones; moving them into the
        // future (not borrowing fn locals) keeps it `'static` and awaitable
        // across the dispatch loop.
        let config_path = config_path.clone();
        let action_tx = action_tx.clone();
        let tray = tray.clone();
        Box::pin(async move {
            handle_reconnect_action(&action_key, &config_path, &action_tx, &tray).await
        })
    })
    .await
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
    spawn_notif(
        "First-run help notification",
        do_first_run_help_notification(action_tx),
    );
}

async fn do_first_run_help_notification(
    action_tx: crate::tray::ActionSender,
) -> anyhow::Result<()> {
    run_action_notification(first_run_help_spec(), |action_key: String| {
        let action_tx = action_tx.clone();
        Box::pin(async move {
            handle_first_run_action(&action_key, &action_tx);
            true // any action dismisses the first-run dialog
        })
    })
    .await
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

    // --- spec-builder smoke tests (I6: pure half of the DRY'd scaffold) ---

    #[test]
    fn reconnect_spec_is_critical_and_persistent() {
        let s = reconnect_spec("acme");
        assert_eq!(s.icon, "network-vpn");
        assert_eq!(s.summary, "VPN Disconnected");
        assert!(
            s.body.contains("'acme'"),
            "body names the config: {}",
            s.body
        );
        assert_eq!(s.actions, &["reconnect", "Reconnect", "dismiss", "Dismiss"]);
        assert_eq!(s.urgency, 2, "unexpected disconnect is critical");
        assert_eq!(s.expire_timeout, 0, "must not auto-dismiss");
        assert_eq!(s.dedup_key, "acme");
    }

    #[test]
    fn first_run_help_spec_is_informational_with_default_expiry() {
        let s = first_run_help_spec();
        assert_eq!(s.icon, "dialog-information");
        assert_eq!(s.summary, "OpenVPN3 Service Not Running");
        assert!(s.body.contains("could not be reached"));
        assert_eq!(
            s.actions,
            &[
                "preferences",
                "Open Preferences",
                "dont-show",
                "Don't Show Again"
            ]
        );
        assert_eq!(s.urgency, 1, "first-run help is normal urgency");
        assert_eq!(s.expire_timeout, -1, "daemon picks the expiry");
        assert_eq!(s.dedup_key, FIRST_RUN_HELP_KEY);
    }
}
