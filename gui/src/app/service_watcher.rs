//! Watches for OpenVPN3 D-Bus service restarts and re-initializes state.
//!
//! Subscribes to `NameOwnerChanged` for two services:
//!   - `net.openvpn.v3.configuration`: appearance triggers full re-init.
//!   - `net.openvpn.v3.sessions`: disappearance clears stale `tray.sessions`,
//!     tears down kill-switch firewall rules and bypass routes, and resets
//!     `bypass_state`. Without this, killing the sessionmgr leaves dead
//!     SessionInfo entries that silently fail every Disconnect/Pause/Resume.

use futures::StreamExt;
use tracing::{debug, info, warn};
use zbus::MessageStream;
use zbus::message::Type as MessageType;

use crate::config::{OPENVPN3_SERVICE, OPENVPN3_SESSIONS_SERVICE};
use crate::settings::Settings;
use crate::tray::{BypassState, VpnTray};

use super::dbus_init::init_dbus;

pub(crate) async fn watch_service_restart(
    dbus: &zbus::Connection,
    settings: &Settings,
    tray: &ksni::blocking::Handle<VpnTray>,
) {
    if let Err(e) = subscribe_to_owner_changes(dbus).await {
        warn!("Failed to subscribe to NameOwnerChanged: {}", e);
        return;
    }

    let mut stream = MessageStream::from(dbus);
    while let Some(res) = stream.next().await {
        let msg = match classify_stream_item(res) {
            StreamItem::Deliver(m) => m,
            StreamItem::SkipTransientError(e) => {
                warn!("Service watcher stream error: {}", e);
                continue;
            }
        };
        let Some((name, old_owner, new_owner)) = parse_name_owner_changed(&msg) else {
            continue;
        };

        if is_service_appeared(&name, OPENVPN3_SERVICE, &old_owner, &new_owner) {
            handle_config_service_appeared(dbus, settings, tray).await;
        } else if is_service_lost(&name, OPENVPN3_SESSIONS_SERVICE, &old_owner, &new_owner) {
            handle_sessions_service_lost(tray).await;
        }
    }
}

/// What the watcher loop should do with one item yielded by the message stream.
#[derive(Debug)]
enum StreamItem {
    /// A decoded message to inspect for `NameOwnerChanged`.
    Deliver(zbus::Message),
    /// A transient stream error: log it and keep polling — never stop.
    SkipTransientError(zbus::Error),
}

/// Classify one `MessageStream` item.
///
/// The point of this fn is the *absence* of a "stop watching" outcome. The loop
/// used to be written `while let Some(Ok(msg)) = stream.next().await`, which
/// treats the first `Err` as end-of-stream and silently kills the watcher for
/// the rest of the process lifetime — after that, a sessionmgr crash never tears
/// the kill-switch down and the firewall outlives the tunnel. Extracted so the
/// no-terminal-error property is unit-assertable rather than only reviewable.
fn classify_stream_item(item: Result<zbus::Message, zbus::Error>) -> StreamItem {
    match item {
        Ok(m) => StreamItem::Deliver(m),
        Err(e) => StreamItem::SkipTransientError(e),
    }
}

/// Registers `NameOwnerChanged` match rules for the two OpenVPN3 services.
///
/// The match rules outlive this call; a failure here means the stream would
/// silently miss every restart, so it is fatal to the watcher.
async fn subscribe_to_owner_changes(dbus: &zbus::Connection) -> Result<(), zbus::Error> {
    for svc in [OPENVPN3_SERVICE, OPENVPN3_SESSIONS_SERVICE] {
        let match_rule = format!(
            "type='signal',sender='org.freedesktop.DBus',\
             interface='org.freedesktop.DBus',member='NameOwnerChanged',\
             arg0='{}'",
            svc
        );
        dbus.call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "AddMatch",
            &match_rule,
        )
        .await?;
    }
    Ok(())
}

/// Filters a stream message down to a `NameOwnerChanged` signal body, or
/// `None` for anything else (non-signals, other members, undecodable bodies).
fn parse_name_owner_changed(msg: &zbus::Message) -> Option<(String, String, String)> {
    if msg.message_type() != MessageType::Signal {
        return None;
    }
    if msg.header().member().map(|m| m.as_str()) != Some("NameOwnerChanged") {
        return None;
    }
    msg.body().deserialize::<(String, String, String)>().ok()
}

/// Full re-init path for when the configuration service (re)appears: clears
/// cached sessions/configs and re-runs `init_dbus` with a bounded retry.
async fn handle_config_service_appeared(
    dbus: &zbus::Connection,
    settings: &Settings,
    tray: &ksni::blocking::Handle<VpnTray>,
) {
    info!("OpenVPN3 configuration service appeared, re-initializing");
    crate::dialogs::withdraw_first_run_help_notification();
    tray.update(|t| {
        t.sessions.clear();
        t.configs.clear();
    });
    for attempt in 1..=5u32 {
        match init_dbus(dbus, settings, tray).await {
            Ok(_) => {
                info!("Re-initialization after service restart complete");
                break;
            }
            Err(e) => {
                debug!("Re-init attempt {}/5: {}", attempt, e);
                glib::timeout_future(std::time::Duration::from_secs(2)).await;
            }
        }
    }
}

/// Teardown path for when the sessions service disappears: tears down the
/// kill-switch firewall + bypass routes, clears stale session state, and
/// notifies the user if a session was actually active.
async fn handle_sessions_service_lost(tray: &ksni::blocking::Handle<VpnTray>) {
    let had_sessions = tray.update(|t| !t.sessions.is_empty()).unwrap_or(false);
    info!(
        "OpenVPN3 sessions service disappeared, clearing {} stale session(s)",
        if had_sessions { "active" } else { "no" }
    );

    // Tear down kill-switch firewall + bypass routes before clearing state;
    // the rules outlive the sessionmgr and would otherwise block all non-VPN
    // traffic with no live session to remove them.
    crate::dbus::killswitch::remove_rules().await;
    crate::dbus::killswitch::remove_bypass_routes().await;

    tray.update(|t| {
        t.sessions.clear();
        t.bypass_state = BypassState::Off;
    });

    if had_sessions {
        crate::dialogs::show_killswitch_inactive_notification();
        crate::dialogs::show_info_notification(
            "OpenVPN3 Sessions Service Stopped",
            "Active connections were cleared. Reconnect after the service restarts.",
        );
    }
}

fn is_service_appeared(name: &str, expected: &str, old_owner: &str, new_owner: &str) -> bool {
    name == expected && old_owner.is_empty() && !new_owner.is_empty()
}

fn is_service_lost(name: &str, expected: &str, old_owner: &str, new_owner: &str) -> bool {
    name == expected && !old_owner.is_empty() && new_owner.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_appeared_valid() {
        assert!(is_service_appeared(
            "net.openvpn.v3.configuration",
            OPENVPN3_SERVICE,
            "",
            ":1.42"
        ));
    }

    #[test]
    fn test_service_appeared_wrong_name() {
        assert!(!is_service_appeared(
            "com.example.Other",
            OPENVPN3_SERVICE,
            "",
            ":1.42"
        ));
    }

    #[test]
    fn test_service_appeared_old_owner_not_empty() {
        assert!(!is_service_appeared(
            "net.openvpn.v3.configuration",
            OPENVPN3_SERVICE,
            ":1.10",
            ":1.42"
        ));
    }

    #[test]
    fn test_service_appeared_new_owner_empty() {
        assert!(!is_service_appeared(
            "net.openvpn.v3.configuration",
            OPENVPN3_SERVICE,
            "",
            ""
        ));
    }

    #[test]
    fn test_service_appeared_both_owners_empty() {
        assert!(!is_service_appeared(
            "net.openvpn.v3.configuration",
            OPENVPN3_SERVICE,
            "",
            ""
        ));
    }

    #[test]
    fn test_service_lost_valid() {
        assert!(is_service_lost(
            "net.openvpn.v3.sessions",
            OPENVPN3_SESSIONS_SERVICE,
            ":1.42",
            ""
        ));
    }

    #[test]
    fn test_service_lost_wrong_name() {
        assert!(!is_service_lost(
            "com.example.Other",
            OPENVPN3_SESSIONS_SERVICE,
            ":1.42",
            ""
        ));
    }

    #[test]
    fn test_service_lost_old_owner_empty() {
        assert!(!is_service_lost(
            "net.openvpn.v3.sessions",
            OPENVPN3_SESSIONS_SERVICE,
            "",
            ""
        ));
    }

    #[test]
    fn test_service_lost_new_owner_not_empty() {
        // Owner *changed* (restart in place) — not a "lost" event.
        assert!(!is_service_lost(
            "net.openvpn.v3.sessions",
            OPENVPN3_SESSIONS_SERVICE,
            ":1.42",
            ":1.43"
        ));
    }

    #[test]
    fn stream_error_is_skipped_not_terminal() {
        // #4: a transient stream error must not end the watcher. There is no
        // "stop" variant to classify into, so a future edit reintroducing a
        // terminal path has to change this enum and trip this test.
        let item = classify_stream_item(Err(zbus::Error::InvalidReply));
        assert!(matches!(item, StreamItem::SkipTransientError(_)));
    }

    #[test]
    fn every_stream_item_outcome_keeps_watching() {
        // Enumerate the taxonomy (CLAUDE.md §D-Bus: a classifier test asserts
        // every variant). Both outcomes continue the loop — Deliver inspects the
        // message, SkipTransientError logs and polls again.
        for err in [
            zbus::Error::InvalidReply,
            zbus::Error::Unsupported,
            zbus::Error::InvalidField,
        ] {
            match classify_stream_item(Err(err)) {
                StreamItem::SkipTransientError(_) => {}
                StreamItem::Deliver(_) => panic!("an Err must not be delivered as a message"),
            }
        }
    }
}
