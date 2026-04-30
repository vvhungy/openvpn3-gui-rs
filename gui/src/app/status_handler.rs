//! StatusChange signal loop
//!
//! Subscribes to per-session `StatusChange` signals from OpenVPN3 backends
//! and dispatches each status transition to the appropriate handler.

use futures::StreamExt;
use tracing::{info, warn};

use crate::dbus::types::{SessionStatus, StatusMajor, StatusMinor};
use crate::tray::{SessionInfo, VpnTray};

/// Fallback label when config/profile name is unavailable.
const FALLBACK_NAME: &str = "VPN Connection";

/// Subscribe to StatusChange signals and spawn the handler loop.
///
/// An AddMatch rule is required for the D-Bus daemon to deliver signals to our
/// connection. `LogForward(true)` tells OpenVPN3 to emit signals, but without
/// AddMatch the daemon won't route them here. Dedup is handled in-line by
/// skipping signals with the same (major, minor) as the previous for each path.
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
    let conn = dbus.clone();
    let tray_for_status = tray.clone();
    glib::spawn_future_local(async move {
        use zbus::MessageStream;
        use zbus::message::Type as MessageType;

        let mut stream = MessageStream::from(&conn);
        let mut last_signal: std::collections::HashMap<String, (u32, u32)> =
            std::collections::HashMap::new();

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

                    // Dedup: skip duplicate (path, major, minor) signals caused by
                    // LogForward + AddMatch both delivering the same signal.
                    if last_signal.get(&path) == Some(&(major, minor)) {
                        continue;
                    }
                    last_signal.insert(path.clone(), (major, minor));

                    // Capture previous status BEFORE the tray update so the
                    // notification at the bottom can detect the transition.
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

                    // Always update the tray session status so the menu reflects the
                    // current state (e.g. "Authentication required") even when auth
                    // handlers dispatch dialogs and `continue` before the generic path.
                    {
                        let p = path.clone();
                        let msg = message.to_string();
                        tray_for_status.update(move |t| {
                            if let Some(session) = t.sessions.get_mut(&p) {
                                session.status = SessionStatus::new(major, minor, msg);
                            }
                        });
                    }

                    // Auth / input dispatch — credentials, URL, challenge, or dynamic.
                    if super::auth_handlers::try_handle_auth(
                        &conn,
                        &tray_for_status,
                        &status,
                        &path,
                        message,
                    ) {
                        continue;
                    }

                    // Authentication failure — auto-retry by creating a new tunnel
                    // up to MAX_CREDENTIAL_ATTEMPTS times, then disconnect.
                    if status.major == StatusMajor::Connection
                        && status.minor == StatusMinor::ConnAuthFailed
                    {
                        let session_path = path.clone();
                        let dbus_conn = conn.clone();
                        let (config_name, config_path) = tray_for_status
                            .update(|t| {
                                t.sessions
                                    .get(&session_path)
                                    .map(|s| (s.config_name.clone(), s.config_path.clone()))
                            })
                            .flatten()
                            .unwrap_or_else(|| (FALLBACK_NAME.to_string(), String::new()));

                        let attempt = {
                            use super::credential_handler::{AUTH_RETRY_WINDOW_SECS, AuthAttempt};
                            let mut attempts = super::credential_handler::CREDENTIAL_ATTEMPTS
                                .lock()
                                .unwrap();
                            let entry =
                                attempts.entry(config_name.clone()).or_insert(AuthAttempt {
                                    count: 0,
                                    last_failure: std::time::Instant::now(),
                                });
                            // Reset counter if last failure was too long ago
                            if entry.last_failure.elapsed().as_secs() > AUTH_RETRY_WINDOW_SECS {
                                entry.count = 0;
                            }
                            entry.count += 1;
                            entry.last_failure = std::time::Instant::now();
                            entry.count
                        };

                        if attempt < super::credential_handler::MAX_CREDENTIAL_ATTEMPTS
                            && !config_path.is_empty()
                        {
                            warn!(
                                "Authentication failed for '{}' (attempt {}/{}) — creating new tunnel",
                                config_name,
                                attempt,
                                super::credential_handler::MAX_CREDENTIAL_ATTEMPTS
                            );
                            crate::dialogs::show_error_notification(
                                &format!("{}: Authentication Failed", config_name),
                                &format!("Wrong credentials for '{}'. Retrying...", config_name,),
                            );
                            // Mark old session so SessDestroyed won't show reconnect prompt
                            super::session_ops::USER_DISCONNECTED
                                .lock()
                                .unwrap()
                                .insert(session_path.clone());
                            let tray_for_retry = tray_for_status.clone();
                            let settings = crate::settings::Settings::new();
                            let sp_for_disconnect = session_path;
                            let dbus_for_disconnect = dbus_conn.clone();
                            glib::spawn_future_local(async move {
                                // Disconnect the failed session on D-Bus to
                                // prevent orphan sessions from accumulating.
                                if let Err(e) = super::session_ops::session_action(
                                    &dbus_for_disconnect,
                                    &sp_for_disconnect,
                                    "disconnect",
                                )
                                .await
                                {
                                    tracing::warn!("Failed to disconnect orphan session: {}", e);
                                }
                                if let Err(e) = super::session_ops::connect_to_config(
                                    &dbus_conn,
                                    &config_path,
                                    &tray_for_retry,
                                    &settings,
                                )
                                .await
                                {
                                    tracing::error!(
                                        "Auto-reconnect after auth failure failed: {}",
                                        e
                                    );
                                }
                            });
                        } else {
                            warn!(
                                "Max auth attempts reached for '{}' — disconnecting",
                                config_name
                            );
                            glib::spawn_future_local(async move {
                                super::session_ops::disconnect_with_message(
                                    &dbus_conn,
                                    &session_path,
                                    &config_name,
                                    "Authentication Failed",
                                    &format!(
                                        "Too many failed attempts for '{}'. Session disconnected.",
                                        config_name
                                    ),
                                )
                                .await;
                            });
                        }
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
                            .unwrap_or_else(|| FALLBACK_NAME.to_string());
                        glib::spawn_future_local(async move {
                            super::session_ops::disconnect_with_message(
                                &dbus_conn,
                                &session_path,
                                &config_name,
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
                            .unwrap_or_else(|| FALLBACK_NAME.to_string());
                        let body = if message.is_empty() {
                            format!("VPN error for '{}'.", config_name)
                        } else {
                            format!("VPN error for '{}': {}", config_name, message)
                        };
                        glib::spawn_future_local(async move {
                            super::session_ops::disconnect_with_message(
                                &dbus_conn,
                                &session_path,
                                &config_name,
                                "VPN Error",
                                &body,
                            )
                            .await;
                        });
                        continue;
                    }

                    // Clear credential attempts on successful connection
                    if status.is_connected() {
                        let cn = tray_for_status
                            .update(|t| t.sessions.get(&path).map(|s| s.config_name.clone()))
                            .flatten();
                        if let Some(cn) = cn
                            && let Ok(mut attempts) =
                                super::credential_handler::CREDENTIAL_ATTEMPTS.lock()
                        {
                            attempts.remove(&cn);
                        }

                        // Kill-switch: apply firewall rules now that the tunnel is up.
                        // Helper has replace semantics, so re-firing on Reconnect is safe.
                        let settings = crate::settings::Settings::new();
                        if settings.enable_kill_switch() {
                            let allow_lan = settings.kill_switch_allow_lan();
                            let path_for_ks = path.clone();
                            let conn_for_ks = conn.clone();
                            glib::spawn_future_local(async move {
                                if let Err(e) =
                                    apply_kill_switch(&conn_for_ks, &path_for_ks, allow_lan).await
                                {
                                    warn!("kill-switch: apply failed: {}", e);
                                }
                            });
                        }
                    }

                    // Update tray session state (connected_at, new sessions, removal)
                    let path_for_timeout = path.clone();
                    let path_for_removal = path.clone(); // moved into delayed removal closure

                    let is_now_connected = status.is_connected();
                    let is_now_disconnected = status.is_disconnected();
                    let msg_owned = message.to_string();
                    tray_for_status.update(move |t| {
                        if let Some(session) = t.sessions.get_mut(&path) {
                            if is_now_connected && session.connected_at.is_none() {
                                session.connected_at = Some(std::time::Instant::now());
                            }
                        } else {
                            // New session not yet seen via SessCreated
                            t.sessions.insert(
                                path.clone(),
                                SessionInfo {
                                    session_path: path.clone(),
                                    config_path: String::new(),
                                    config_name: "VPN".to_string(),
                                    status: SessionStatus::new(major, minor, msg_owned),
                                    connected_at: None,
                                    bytes_in: 0,
                                    bytes_out: 0,
                                    last_bytes_in: 0,
                                    last_bytes_out: 0,
                                    idle_since: None,
                                },
                            );
                        }
                    });

                    // Remove terminal sessions from the tray immediately rather than
                    // waiting for SessDestroyed. Prevents zombie "Profile: Done" entries.
                    if is_now_disconnected {
                        // Delay removal so the notification chain completes with
                        // the correct profile name (Disconnecting → Disconnected → Done).
                        let tray_for_removal = tray_for_status.clone();
                        glib::spawn_future_local(async move {
                            glib::timeout_future_seconds(3).await;
                            tray_for_removal.update(move |t| {
                                t.sessions.remove(&path_for_removal);
                            });
                        });
                    }

                    // Connection timeout watcher — see `timeout_watcher` module.
                    if status.is_connecting() {
                        super::timeout_watcher::spawn_timeout_watcher(
                            &tray_for_status,
                            path_for_timeout,
                        );
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

/// Build a SessionProxy for `path`, read the tun interface name and the
/// currently connected server IP, and ask the kill-switch helper to install
/// rules that block all non-tunnel traffic. Returns `Err` only on real
/// D-Bus or proxy failures; missing helper / empty fields are warned about
/// inside and reported as `Ok(())`.
pub(super) async fn apply_kill_switch(
    conn: &zbus::Connection,
    session_path: &str,
    allow_lan: bool,
) -> anyhow::Result<()> {
    let proxy = crate::dbus::session::SessionProxy::builder(conn)
        .path(session_path)?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await?;

    let device_name = proxy.device_name().await?;
    if device_name.is_empty() {
        warn!("kill-switch: device_name empty on connected session — rules NOT applied");
        return Ok(());
    }

    let (_proto, server_ip, _port) = proxy.connected_to().await?;
    if server_ip.is_empty() {
        warn!("kill-switch: connected_to address empty — rules NOT applied");
        return Ok(());
    }

    crate::dbus::killswitch::add_rules(&device_name, vec![server_ip], allow_lan).await;
    Ok(())
}
