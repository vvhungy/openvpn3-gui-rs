//! Watches for OpenVPN3 D-Bus service restarts and re-initializes state.
//!
//! Subscribes to `NameOwnerChanged` on the OpenVPN3 well-known name. When the
//! service comes back after a crash or restart, clears stale tray state and
//! re-runs `init_dbus` (with retries) so the GUI rebinds to the new instance.

use futures::StreamExt;
use tracing::{debug, info, warn};
use zbus::MessageStream;
use zbus::message::Type as MessageType;

use crate::config::OPENVPN3_SERVICE;
use crate::settings::Settings;
use crate::tray::VpnTray;

use super::dbus_init::init_dbus;

pub(crate) async fn watch_service_restart(
    dbus: &zbus::Connection,
    settings: &Settings,
    tray: &ksni::blocking::Handle<VpnTray>,
) {
    let match_rule = format!(
        "type='signal',sender='org.freedesktop.DBus',\
         interface='org.freedesktop.DBus',member='NameOwnerChanged',\
         arg0='{}'",
        OPENVPN3_SERVICE
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
        warn!("Failed to subscribe to NameOwnerChanged: {}", e);
        return;
    }

    let mut stream = MessageStream::from(dbus);
    while let Some(Ok(msg)) = stream.next().await {
        if msg.message_type() != MessageType::Signal {
            continue;
        }
        if msg.header().member().map(|m| m.as_str()) != Some("NameOwnerChanged") {
            continue;
        }
        if let Ok((name, old_owner, new_owner)) =
            msg.body().deserialize::<(String, String, String)>()
        {
            if !is_service_appeared(&name, &old_owner, &new_owner) {
                continue;
            }
            info!("OpenVPN3 service restarted, clearing tray and re-initializing");
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
    }
}

fn is_service_appeared(name: &str, old_owner: &str, new_owner: &str) -> bool {
    name == OPENVPN3_SERVICE && old_owner.is_empty() && !new_owner.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_appeared_valid() {
        assert!(is_service_appeared(
            "net.openvpn.v3.configuration",
            "",
            ":1.42"
        ));
    }

    #[test]
    fn test_service_appeared_wrong_name() {
        assert!(!is_service_appeared("com.example.Other", "", ":1.42"));
    }

    #[test]
    fn test_service_appeared_old_owner_not_empty() {
        assert!(!is_service_appeared(
            "net.openvpn.v3.configuration",
            ":1.10",
            ":1.42"
        ));
    }

    #[test]
    fn test_service_appeared_new_owner_empty() {
        assert!(!is_service_appeared("net.openvpn.v3.configuration", "", ""));
    }

    #[test]
    fn test_service_appeared_both_owners_empty() {
        assert!(!is_service_appeared("net.openvpn.v3.configuration", "", ""));
    }
}
