//! D-Bus initialization — fetch configs/sessions and populate the tray on startup

use std::collections::HashMap;

use tracing::{debug, error, info, warn};

use zbus::proxy::CacheProperties;

use crate::config::{MANAGER_VERSION_MINIMUM, MANAGER_VERSION_RECOMMENDED};
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
    let manager_version = match config_manager.version().await {
        Ok(version_str) => {
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
        Err(e) => {
            warn!("Failed to get manager version: {}", e);
            0
        }
    };

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
        "connect-recent" | "connect-specific" | "restore" => {
            let (path, name) = settings.get_most_recent_config();
            if path.is_empty() {
                info!("Startup auto-connect: no recent config saved");
                return;
            }
            // Verify the config still exists in the loaded list
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
            if let Err(e) = super::session_ops::connect_to_config(dbus, &path, tray, settings).await
            {
                error!("Startup auto-connect failed: {}", e);
                crate::dialogs::show_error_notification(
                    "Connection Failed",
                    &format!("Could not connect to '{}': {}", name, e),
                );
            }
        }
        _ => {} // "none" or unknown — do nothing
    }
}
