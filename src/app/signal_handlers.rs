//! D-Bus signal listener loops
//!
//! Owns the two long-running async loops that react to OpenVPN3 signals:
//! - `SessionManagerEvent` — session created / destroyed
//! - `StatusChange` — per-session status transitions

use futures::StreamExt;
use tracing::{info, warn};
use zbus::proxy::CacheProperties;

use crate::dbus::{
    session::{SessionManagerProxy, SessionProxy},
    types::{SessionManagerEventType, SessionStatus, StatusMajor, StatusMinor},
};
use crate::tray::{SessionInfo, VpnTray};

/// Handles a newly created session: enables log forwarding and adds it to the tray.
async fn handle_session_created(
    dbus: &zbus::Connection,
    tray: &ksni::blocking::Handle<VpnTray>,
    session_path: &str,
) -> anyhow::Result<()> {
    let session = SessionProxy::builder(dbus)
        .path(session_path)?
        .cache_properties(CacheProperties::No)
        .build()
        .await?;

    if let Err(e) = session.LogForward(true).await {
        warn!("LogForward for {}: {}", session_path, e);
    }

    let config_name = session
        .config_name()
        .await
        .unwrap_or_else(|_| "VPN".to_string());
    let config_path = session
        .config_path()
        .await
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    let (major, minor, message) = session.status().await.unwrap_or((0, 0, String::new()));

    info!("SessCreated: '{}' at {}", config_name, session_path);

    let sp = session_path.to_string();
    tray.update(move |t| {
        t.sessions.entry(sp.clone()).or_insert_with(|| SessionInfo {
            session_path: sp.clone(),
            config_path,
            config_name,
            status: SessionStatus::new(major, minor, message),
            connected_at: None,
        });
    });

    Ok(())
}

/// Attach D-Bus signal handlers for session lifecycle and status changes.
pub(crate) async fn setup_signal_handlers(
    dbus: &zbus::Connection,
    tray: ksni::blocking::Handle<VpnTray>,
    action_tx: crate::tray::ActionSender,
) -> anyhow::Result<()> {
    let session_manager = SessionManagerProxy::builder(dbus)
        .cache_properties(CacheProperties::No)
        .build()
        .await?;

    // --- SessionManagerEvent (session created / destroyed) ---
    let mut session_events = session_manager.receive_SessionManagerEvent().await?;
    let tray_for_session = tray.clone();
    let action_tx_for_session = action_tx.clone();
    let dbus_for_session = dbus.clone();
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

                    if event_type == SessionManagerEventType::SessCreated as u16 {
                        let dbus = dbus_for_session.clone();
                        let tray = tray_for_session.clone();
                        glib::spawn_future_local(async move {
                            if let Err(e) =
                                handle_session_created(&dbus, &tray, &session_path).await
                            {
                                warn!("SessCreated handler error for {}: {}", session_path, e);
                            }
                        });
                    } else if event_type == SessionManagerEventType::SessDestroyed as u16 {
                        // Capture config info before removing from tray
                        let session_info = tray_for_session
                            .update(|t| {
                                t.sessions
                                    .get(&session_path)
                                    .map(|s| (s.config_path.clone(), s.config_name.clone()))
                            })
                            .flatten();

                        let sp = session_path.clone();
                        tray_for_session.update(move |t| {
                            t.sessions.remove(&sp);
                        });
                        info!("Session removed from tray");

                        // Check whether the user initiated this disconnect
                        let user_initiated =
                            if let Ok(mut set) = super::session_ops::USER_DISCONNECTED.lock() {
                                set.remove(&session_path)
                            } else {
                                false
                            };

                        if !user_initiated
                            && let Some((config_path, config_name)) = session_info
                            && !config_path.is_empty()
                        {
                            info!(
                                "Unexpected session drop for '{}', showing reconnect notification",
                                config_name
                            );
                            crate::dialogs::show_reconnect_notification(
                                config_path,
                                config_name,
                                action_tx_for_session.clone(),
                            );
                        }
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
                    if status.major == StatusMajor::Connection
                        && status.minor == StatusMinor::ConnAuthFailed
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
                    if status.major == StatusMajor::Connection
                        && status.minor == StatusMinor::ConnFailed
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

                    // Handle other error states (config errors, process errors)
                    if status.is_error() {
                        warn!(
                            "Session error for {}: major={}, minor={}",
                            path, major, minor
                        );
                        let session_path = path.clone();
                        let dbus_conn = conn.clone();
                        let config_name = tray_for_status
                            .update(|t| {
                                t.sessions.get(&session_path).map(|s| s.config_name.clone())
                            })
                            .flatten()
                            .unwrap_or_else(|| "VPN Connection".to_string());
                        let body = if message.is_empty() {
                            format!("VPN error for '{}'.", config_name)
                        } else {
                            format!("VPN error for '{}': {}", config_name, message)
                        };
                        glib::spawn_future_local(async move {
                            super::session_ops::disconnect_with_message(
                                &dbus_conn,
                                &session_path,
                                "VPN Error",
                                &body,
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
