//! D-Bus initialization and signal handling

use std::collections::HashMap;

use futures::StreamExt;
use tracing::{debug, error, info, warn};

use zbus::proxy::CacheProperties;

use crate::config::{MANAGER_VERSION_MINIMUM, MANAGER_VERSION_RECOMMENDED};
use crate::dbus::{
    configuration::{ConfigurationManagerProxy, ConfigurationProxy},
    session::{SessionManagerProxy, SessionProxy},
    types::{SessionManagerEventType, SessionStatus},
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
    let startup_action = settings.startup_action();
    tray.update(move |t| {
        t.configs = configs;
        t.sessions = sessions;
        t.startup_action = startup_action;
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
            }
        }
        _ => {} // "none" or unknown — do nothing
    }
}

/// Setup D-Bus signal handlers for session events and status changes
pub(crate) async fn setup_signal_handlers(
    dbus: &zbus::Connection,
    tray: ksni::blocking::Handle<VpnTray>,
) -> anyhow::Result<()> {
    let session_manager = SessionManagerProxy::builder(dbus)
        .cache_properties(CacheProperties::No)
        .build()
        .await?;

    // --- SessionManagerEvent (session created / destroyed) ---
    let mut session_events = session_manager.receive_SessionManagerEvent().await?;
    let tray_for_session = tray.clone();
    glib::spawn_future_local(async move {
        while let Some(signal) = session_events.next().await {
            match signal.args() {
                Ok(args) => {
                    let event_type = args.event_type;
                    let session_path = args.session_path.as_str().to_string();
                    info!(
                        "SessionManagerEvent: type={}, path={}",
                        event_type, session_path
                    );

                    if event_type == SessionManagerEventType::SessDestroyed as u16 {
                        // Session destroyed
                        tray_for_session.update(move |t| {
                            t.sessions.remove(&session_path);
                        });
                        info!("Session removed from tray");
                    }
                }
                Err(e) => warn!("Failed to parse SessionManagerEvent: {}", e),
            }
        }
    });

    // --- StatusChange signals from backends ---
    // Add match rule so the system bus delivers these signals to us
    dbus.call_method(
        Some("org.freedesktop.DBus"),
        "/org/freedesktop/DBus",
        Some("org.freedesktop.DBus"),
        "AddMatch",
        &"type='signal',interface='net.openvpn.v3.backends',member='StatusChange'",
    )
    .await?;
    info!("Added D-Bus match rule for StatusChange signals");

    let conn = dbus.clone();
    let tray_for_status = tray.clone();
    glib::spawn_future_local(async move {
        use zbus::MessageStream;
        use zbus::message::Type as MessageType;

        let mut stream = MessageStream::from(&conn);

        while let Some(msg_result) = stream.next().await {
            let msg = match msg_result {
                Ok(m) => m,
                Err(e) => {
                    warn!("Error receiving message: {}", e);
                    continue;
                }
            };

            if msg.message_type() != MessageType::Signal {
                continue;
            }

            let header = msg.header();
            if header.interface().map(|i| i.as_str()) != Some("net.openvpn.v3.backends") {
                continue;
            }
            if header.member().map(|m| m.as_str()) != Some("StatusChange") {
                continue;
            }

            match msg.body().deserialize::<(u32, u32, &str)>() {
                Ok((major, minor, message)) => {
                    let path = header
                        .path()
                        .map(|p| p.as_str().to_string())
                        .unwrap_or_default();
                    info!(
                        "StatusChange: path={}, major={}, minor={}, message={}",
                        path, major, minor, message
                    );

                    let status = SessionStatus::new(major, minor, message.to_string());

                    // Check if credentials are needed (username/password)
                    if status.needs_credentials() {
                        info!("Session requires credentials (username/password)");
                        let session_path = path.clone();
                        let dbus_conn = conn.clone();

                        let config_name = tray_for_status
                            .update(|t| {
                                t.sessions.get(&session_path).map(|s| s.config_name.clone())
                            })
                            .flatten()
                            .unwrap_or_else(|| "VPN Connection".to_string());

                        glib::spawn_future_local(async move {
                            super::credential_handler::request_credentials(
                                &dbus_conn,
                                &session_path,
                                &config_name,
                            )
                            .await;
                        });
                        continue;
                    }

                    // Check if a challenge/OTP response is needed
                    if status.needs_challenge() {
                        info!("Session requires challenge/OTP response");
                        let session_path = path.clone();
                        let dbus_conn = conn.clone();

                        let config_name = tray_for_status
                            .update(|t| {
                                t.sessions.get(&session_path).map(|s| s.config_name.clone())
                            })
                            .flatten()
                            .unwrap_or_else(|| "VPN Connection".to_string());

                        glib::spawn_future_local(async move {
                            super::credential_handler::request_challenge(
                                &dbus_conn,
                                &session_path,
                                &config_name,
                            )
                            .await;
                        });
                        continue;
                    }

                    // Handle authentication failure
                    if status.major == crate::dbus::types::StatusMajor::Connection
                        && status.minor == crate::dbus::types::StatusMinor::ConnAuthFailed
                    {
                        warn!("Authentication failed for session {}", path);
                        let session_path = path.clone();
                        let dbus_conn = conn.clone();
                        let config_name = tray_for_status
                            .update(|t| {
                                t.sessions.get(&session_path).map(|s| s.config_name.clone())
                            })
                            .flatten()
                            .unwrap_or_else(|| "VPN Connection".to_string());

                        glib::spawn_future_local(async move {
                            super::session_ops::disconnect_with_message(
                                &dbus_conn,
                                &session_path,
                                "Authentication Failed",
                                &format!(
                                    "Authentication failed for '{}'. Please check your credentials.",
                                    config_name
                                ),
                            )
                            .await;
                        });
                        continue;
                    }

                    // Handle connection failure
                    if status.major == crate::dbus::types::StatusMajor::Connection
                        && status.minor == crate::dbus::types::StatusMinor::ConnFailed
                    {
                        warn!("Connection failed for session {}", path);
                        let session_path = path.clone();
                        let dbus_conn = conn.clone();
                        let config_name = tray_for_status
                            .update(|t| {
                                t.sessions.get(&session_path).map(|s| s.config_name.clone())
                            })
                            .flatten()
                            .unwrap_or_else(|| "VPN Connection".to_string());

                        glib::spawn_future_local(async move {
                            super::session_ops::disconnect_with_message(
                                &dbus_conn,
                                &session_path,
                                "Connection Failed",
                                &format!(
                                    "Connection failed for '{}'. Please try again.",
                                    config_name
                                ),
                            )
                            .await;
                        });
                        continue;
                    }

                    // Clear credential attempts on successful connection
                    if status.is_connected()
                        && let Ok(mut attempts) =
                            super::credential_handler::CREDENTIAL_ATTEMPTS.lock()
                    {
                        attempts.remove(&path);
                    }

                    // Get previous status and config name before updating
                    let message_owned = message.to_string();
                    let prev_info: Option<(String, &str)> = tray_for_status
                        .update(|t| {
                            t.sessions.get(&path).map(|s| {
                                let prev = crate::status::get_status_description(
                                    s.status.major,
                                    s.status.minor,
                                );
                                (s.config_name.clone(), prev)
                            })
                        })
                        .flatten();

                    let is_now_connected = status.is_connected();
                    let is_now_disconnected = status.is_disconnected();
                    tray_for_status.update(move |t| {
                        if let Some(session) = t.sessions.get_mut(&path) {
                            session.status = SessionStatus::new(major, minor, message_owned);
                            if is_now_connected && session.connected_at.is_none() {
                                session.connected_at = Some(std::time::Instant::now());
                            } else if is_now_disconnected {
                                session.connected_at = None;
                            }
                        } else {
                            // New session we haven't seen yet
                            t.sessions.insert(
                                path.clone(),
                                SessionInfo {
                                    session_path: path.clone(),
                                    config_path: String::new(),
                                    config_name: "VPN".to_string(),
                                    status: SessionStatus::new(major, minor, message_owned),
                                    connected_at: None,
                                },
                            );
                        }
                    });

                    // Send desktop notification for every status change
                    let new_desc =
                        crate::status::get_status_description(status.major, status.minor);
                    if let Some((cn, prev)) = prev_info {
                        if prev != new_desc {
                            let body =
                                format!("{}: Status change from {} to {}", cn, prev, new_desc);
                            crate::dialogs::show_connection_notification(&cn, &body);
                        }
                    } else {
                        crate::dialogs::show_connection_notification("VPN", new_desc);
                    }
                }
                Err(e) => {
                    warn!("Failed to parse StatusChange signal: {}", e);
                }
            }
        }
    });

    Ok(())
}
