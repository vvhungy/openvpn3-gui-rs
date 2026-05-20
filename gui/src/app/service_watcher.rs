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
    for svc in [OPENVPN3_SERVICE, OPENVPN3_SESSIONS_SERVICE] {
        let match_rule = format!(
            "type='signal',sender='org.freedesktop.DBus',\
             interface='org.freedesktop.DBus',member='NameOwnerChanged',\
             arg0='{}'",
            svc
        );
        if let Err(e) = dbus
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "AddMatch",
                &match_rule,
            )
            .await
        {
            warn!("Failed to subscribe to NameOwnerChanged for {}: {}", svc, e);
            return;
        }
    }

    let mut stream = MessageStream::from(dbus);
    while let Some(Ok(msg)) = stream.next().await {
        if msg.message_type() != MessageType::Signal {
            continue;
        }
        if msg.header().member().map(|m| m.as_str()) != Some("NameOwnerChanged") {
            continue;
        }
        let Ok((name, old_owner, new_owner)) = msg.body().deserialize::<(String, String, String)>()
        else {
            continue;
        };

        if is_service_appeared(&name, OPENVPN3_SERVICE, &old_owner, &new_owner) {
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
        } else if is_service_lost(&name, OPENVPN3_SESSIONS_SERVICE, &old_owner, &new_owner) {
            let had_sessions = tray.update(|t| !t.sessions.is_empty()).unwrap_or(false);
            info!(
                "OpenVPN3 sessions service disappeared, clearing {} stale session(s)",
                if had_sessions { "active" } else { "no" }
            );

            // Tear down kill-switch firewall + bypass routes before clearing
            // state; the rules outlive the sessionmgr and would otherwise
            // block all non-VPN traffic with no live session to remove them.
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
}
