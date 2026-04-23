//! D-Bus initialization — fetch configs/sessions and populate the tray on startup

use std::collections::HashMap;

use tracing::{debug, error, info, warn};

use zbus::proxy::CacheProperties;

use futures::StreamExt;
use zbus::MessageStream;
use zbus::message::Type as MessageType;

use crate::config::{MANAGER_VERSION_MINIMUM, MANAGER_VERSION_RECOMMENDED, OPENVPN3_SERVICE};
use crate::dbus::{
    configuration::{ConfigurationManagerProxy, ConfigurationProxy},
    session::{SessionManagerProxy, SessionProxy},
    types::SessionStatus,
};
use crate::settings::Settings;
use crate::tray::{ConfigInfo, SessionInfo, VpnTray};

/// Initialize D-Bus: fetch configs/sessions, populate tray
pub(crate) async fn init_dbus(
    dbus: &zbus::Connection,
    settings: &Settings,
    tray: &ksni::blocking::Handle<VpnTray>,
) -> anyhow::Result<()> {
    let config_manager = ConfigurationManagerProxy::builder(dbus)
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    let session_manager = SessionManagerProxy::builder(dbus)
        .cache_properties(CacheProperties::No)
        .build()
        .await?;

    // Detect manager version
    let manager_version = parse_manager_version(config_manager.version().await.ok());

    if manager_version < MANAGER_VERSION_MINIMUM {
        error!(
            "Unsupported OpenVPN3 version: {}. Minimum: {}",
            manager_version, MANAGER_VERSION_MINIMUM
        );
    } else if manager_version < MANAGER_VERSION_RECOMMENDED {
        warn!(
            "OpenVPN3 version {} below recommended {}",
            manager_version, MANAGER_VERSION_RECOMMENDED
        );
    }

    // Fetch configurations — config manager may not be running yet at startup
    let config_paths = match config_manager.FetchAvailableConfigs().await {
        Ok(paths) => paths,
        Err(e) => {
            // Return Err so the caller can retry
            return Err(anyhow::anyhow!("Config manager unavailable: {}", e));
        }
    };
    info!("Found {} configurations", config_paths.len());

    let mut configs = Vec::new();
    for path in &config_paths {
        info!("Fetching config at path: {}", path);
        match ConfigurationProxy::builder(dbus)
            .path(path.clone())?
            .build()
            .await
        {
            Ok(config) => match config.name().await {
                Ok(name) => {
                    info!("Config: {} -> {}", path, name);
                    configs.push(ConfigInfo {
                        path: path.as_str().to_string(),
                        name,
                    });
                }
                Err(e) => warn!("Failed to get config name for {}: {}", path, e),
            },
            Err(e) => warn!("Failed to build config proxy for {}: {}", path, e),
        }
    }

    // Fetch sessions — session manager may not be running when no sessions are active
    let session_paths = match session_manager.FetchAvailableSessions().await {
        Ok(paths) => paths,
        Err(e) => {
            warn!("Session manager unavailable (no active sessions?): {}", e);
            vec![]
        }
    };
    info!("Found {} sessions", session_paths.len());

    let mut sessions = HashMap::new();
    for path in &session_paths {
        match SessionProxy::builder(dbus)
            .path(path.clone())?
            .build()
            .await
        {
            Ok(session) => {
                let (major, minor, message) =
                    session.status().await.unwrap_or((0, 0, String::new()));
                let config_name = session
                    .config_name()
                    .await
                    .unwrap_or_else(|_| "VPN".to_string());
                let config_path = session
                    .config_path()
                    .await
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default();

                info!(
                    "Session: {} -> {} (status: {}/{})",
                    path, config_name, major, minor
                );

                // Enable log/status forwarding so we receive StatusChange signals
                if let Err(e) = session.LogForward(true).await {
                    debug!("LogForward for {}: {}", path, e);
                }

                sessions.insert(
                    path.as_str().to_string(),
                    SessionInfo {
                        session_path: path.as_str().to_string(),
                        config_path,
                        config_name,
                        status: SessionStatus::new(major, minor, message),
                        connected_at: None,
                        bytes_in: 0,
                        bytes_out: 0,
                    },
                );
            }
            Err(e) => warn!("Failed to build session proxy for {}: {}", path, e),
        }
    }

    // Update tray with initial state
    tray.update(move |t| {
        t.configs = configs;
        t.sessions = sessions;
    });

    info!(
        "Tray updated with {} configs, initial state set",
        config_paths.len()
    );

    // Auto-connect on startup based on GSettings preference
    handle_startup_connect(settings, dbus, tray).await;

    Ok(())
}

/// Trigger auto-connect after tray is populated
async fn handle_startup_connect(
    settings: &Settings,
    dbus: &zbus::Connection,
    tray: &ksni::blocking::Handle<VpnTray>,
) {
    let action = settings.startup_action();
    match action.as_str() {
        "connect-recent" => {
            let (path, name) = settings.get_most_recent_config();
            if path.is_empty() {
                info!("Startup auto-connect: no recent config saved");
                return;
            }
            startup_connect(dbus, tray, settings, &path, &name).await;
        }
        "connect-specific" => {
            let path = settings.specific_config_path();
            if path.is_empty() {
                info!("Startup auto-connect: no specific config configured");
                return;
            }
            // Resolve a display name from the loaded config list
            let name = tray
                .update(|t| {
                    t.configs
                        .iter()
                        .find(|c| c.path == path)
                        .map(|c| c.name.clone())
                })
                .flatten()
                .unwrap_or_else(|| path.clone());
            startup_connect(dbus, tray, settings, &path, &name).await;
        }
        _ => {} // "none" or unknown — do nothing
    }
}

async fn startup_connect(
    dbus: &zbus::Connection,
    tray: &ksni::blocking::Handle<VpnTray>,
    settings: &Settings,
    path: &str,
    name: &str,
) {
    let exists = tray
        .update(|t| t.configs.iter().any(|c| c.path == path))
        .unwrap_or(false);
    if !exists {
        warn!(
            "Startup auto-connect: saved config path not found: {}",
            path
        );
        return;
    }
    info!("Startup auto-connect: connecting to '{}'", name);
    if let Err(e) = super::session_ops::connect_to_config(dbus, path, tray, settings).await {
        error!("Startup auto-connect failed: {}", e);
        crate::dialogs::show_error_notification(
            "Connection Failed",
            &format!("Could not connect to '{}': {}", name, e),
        );
    }
}

/// Watch for the OpenVPN3 D-Bus service to restart and re-initialize the tray.
///
/// Subscribes to `NameOwnerChanged` for `net.openvpn.v3.configuration`. When
/// that service reappears after a restart (old_owner="" → new_owner=":1.N"),
/// clears stale tray state and re-runs `init_dbus` with up to 5 retries.
pub(crate) async fn watch_service_restart(
    dbus: &zbus::Connection,
    settings: &Settings,
    tray: &ksni::blocking::Handle<crate::tray::VpnTray>,
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

/// Parse the OpenVPN3 manager version string into a comparable number.
///
/// - `"git:..."` → 9999 (dev build, assume latest)
/// - `"vNN..."`  → leading digits parsed as u32
/// - other/None  → 0
fn parse_manager_version(version: Option<String>) -> u32 {
    let Some(version_str) = version else { return 0 };
    debug!("Manager version: {}", version_str);
    if version_str.starts_with("git:") {
        9999
    } else if let Some(stripped) = version_str.strip_prefix('v') {
        stripped
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse::<u32>()
            .unwrap_or(0)
    } else {
        0
    }
}

/// True when the OpenVPN3 service just appeared on the bus (was absent before).
fn is_service_appeared(name: &str, old_owner: &str, new_owner: &str) -> bool {
    name == OPENVPN3_SERVICE && old_owner.is_empty() && !new_owner.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_manager_version ---

    #[test]
    fn test_parse_version_none() {
        assert_eq!(parse_manager_version(None), 0);
    }

    #[test]
    fn test_parse_version_v_prefix() {
        assert_eq!(parse_manager_version(Some("v18".into())), 18);
    }

    #[test]
    fn test_parse_version_v_prefix_with_suffix() {
        assert_eq!(parse_manager_version(Some("v18.2".into())), 18);
    }

    #[test]
    fn test_parse_version_git() {
        assert_eq!(parse_manager_version(Some("git:abc123".into())), 9999);
    }

    #[test]
    fn test_parse_version_bare_number() {
        assert_eq!(parse_manager_version(Some("42".into())), 0);
    }

    #[test]
    fn test_parse_version_empty_string() {
        assert_eq!(parse_manager_version(Some(String::new())), 0);
    }

    // --- is_service_appeared ---

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
