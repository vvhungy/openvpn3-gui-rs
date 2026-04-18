//! StatusChange signal loop
//!
//! Subscribes to per-session `StatusChange` signals from OpenVPN3 backends
//! and dispatches each status transition to the appropriate handler.

use futures::StreamExt;
use tracing::{info, warn};

use crate::dbus::types::{SessionStatus, StatusMajor, StatusMinor};
use crate::tray::{SessionInfo, VpnTray};

/// Subscribe to StatusChange signals and spawn the handler loop.
pub(super) async fn setup_status_handler(
    dbus: &zbus::Connection,
    tray: &ksni::blocking::Handle<VpnTray>,
) -> anyhow::Result<()> {
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

                    // Server needs user input (CfgRequireUser) — may be credentials
                    // or dynamic challenge. Query the input queue to determine which.
                    if status.needs_user_input() {
                        info!("Server requires user input for {}", path);
                        let session_path = path.clone();
                        let dbus_conn = conn.clone();
                        let config_name = tray_for_status
                            .update(|t| {
                                t.sessions.get(&session_path).map(|s| s.config_name.clone())
                            })
                            .flatten()
                            .unwrap_or_else(|| "VPN Connection".to_string());
                        glib::spawn_future_local(async move {
                            match super::auth_dispatch::dispatch_for_session(
                                &dbus_conn,
                                &session_path,
                            )
                            .await
                            {
                                Some(super::auth_dispatch::AuthDispatch::Credentials) => {
                                    super::credential_handler::request_credentials(
                                        &dbus_conn,
                                        &session_path,
                                        &config_name,
                                        Default::default(),
                                    )
                                    .await;
                                }
                                Some(super::auth_dispatch::AuthDispatch::Challenge) => {
                                    super::challenge_handler::request_challenge(
                                        &dbus_conn,
                                        &session_path,
                                        &config_name,
                                    )
                                    .await;
                                }
                                None => {
                                    warn!("No input slots found for {}", session_path);
                                }
                            }
                        });
                        continue;
                    }

                    // Credentials required (legacy signal from session manager)
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
                                Default::default(),
                            )
                            .await;
                        });
                        continue;
                    }

                    // URL / browser authentication required
                    if status.needs_url_auth() {
                        info!("Session requires browser authentication");
                        let url = message.to_string();
                        let config_name = tray_for_status
                            .update(|t| t.sessions.get(&path).map(|s| s.config_name.clone()))
                            .flatten()
                            .unwrap_or_else(|| "VPN Connection".to_string());
                        let notif_body = if url.is_empty() {
                            "Please complete authentication in your browser.".to_string()
                        } else {
                            format!("Opening browser for authentication:\n{}", url)
                        };
                        crate::dialogs::show_error_notification(
                            &format!("{}: Browser Authentication Required", config_name),
                            &notif_body,
                        );
                        if !url.is_empty()
                            && let Err(e) = gio::AppInfo::launch_default_for_uri(
                                &url,
                                None::<&gio::AppLaunchContext>,
                            )
                        {
                            warn!("Failed to open auth URL in browser: {}", e);
                        }
                        continue;
                    }

                    // Challenge / OTP required
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
                            super::challenge_handler::request_challenge(
                                &dbus_conn,
                                &session_path,
                                &config_name,
                            )
                            .await;
                        });
                        continue;
                    }

                    // Authentication failure
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

                    // Connection failure
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

                    // Generic error states (config errors, process errors)
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

                    // Update tray session state
                    let message_owned = message.to_string();
                    let path_for_timeout = path.clone();
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
                            // New session not yet seen via SessCreated
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

                    // Connection timeout watcher — notify if still connecting after
                    // the user-configured timeout (default 30s).
                    let is_now_connecting = status.is_connecting();
                    if is_now_connecting {
                        let tray_for_timeout = tray_for_status.clone();
                        let timeout_secs = crate::settings::Settings::new().connection_timeout();
                        glib::spawn_future_local(async move {
                            glib::timeout_future_seconds(timeout_secs).await;
                            let still_connecting = tray_for_timeout
                                .update(|t| {
                                    t.sessions
                                        .get(&path_for_timeout)
                                        .map(|s| s.status.is_connecting())
                                })
                                .flatten()
                                .unwrap_or(false);
                            if still_connecting {
                                let config_name = tray_for_timeout
                                    .update(|t| {
                                        t.sessions
                                            .get(&path_for_timeout)
                                            .map(|s| s.config_name.clone())
                                    })
                                    .flatten()
                                    .unwrap_or_else(|| "VPN".to_string());
                                info!(
                                    "Connection timeout watcher: '{}' still connecting after {}s",
                                    config_name, timeout_secs
                                );
                                crate::dialogs::show_error_notification(
                                    &format!("{}: Still Connecting", config_name),
                                    &format!(
                                        "Connection to '{}' is taking longer than expected. \
                                         You can disconnect and try again.",
                                        config_name
                                    ),
                                );
                            }
                        });
                    }

                    // Desktop notification for status change
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
