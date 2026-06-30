//! StatusChange signal loop
//!
//! Subscribes to per-session `StatusChange` signals from OpenVPN3 backends
//! and dispatches each status transition to the appropriate handler.
//!
//! No testable pure surface — async D-Bus event loop. Pure transition logic
//! (e.g. stall detection) lives in `crate::status::stats_poller` with its own
//! unit tests.

use futures::StreamExt;
use tracing::{info, warn};

use crate::dbus::types::{SessionStatus, StatusMajor, StatusMinor};
use crate::tray::{SessionInfo, VpnTray};

mod killswitch_glue;

pub(crate) use killswitch_glue::apply_kill_switch;

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
                    // Auth requests are exempted — a re-emitted credential challenge
                    // after Resume on an invalidated session must still reach the
                    // dispatcher even if the same (major, minor) was seen earlier.
                    let is_auth = status.is_auth_request();
                    let prev = last_signal.get(&path).copied();
                    if !is_auth && prev == Some((major, minor)) {
                        continue;
                    }
                    if is_auth && prev == Some((major, minor)) {
                        info!(
                            "Auth signal re-emitted for {} (major={}, minor={}) — dedup-exempt, dispatching",
                            path, major, minor
                        );
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
                                let was_connected = session.status.is_connected();
                                session.status = SessionStatus::new(major, minor, msg);
                                // Reset stats baseline when (re)entering Connected so the
                                // next poll sees a non-zero delta. Frozen counters from
                                // before Pause would otherwise trigger idle_since on the
                                // first poll after Resume and flip the icon to "loading".
                                if !was_connected && session.status.is_connected() {
                                    session.last_bytes_in = 0;
                                    session.last_bytes_out = 0;
                                    session.idle_started_at = None;
                                    session.idle_since = None;
                                }
                                // The idle clock/warning are only meaningful while
                                // Connected. On any drop out of Connected (Error,
                                // Disconnected, Paused) clear both — otherwise the stale
                                // `idle_since` wins the `current_icon()` priority check
                                // (`error > loading`) and masks the error icon with the
                                // idle/warning icon.
                                if was_connected && !session.status.is_connected() {
                                    session.idle_started_at = None;
                                    session.idle_since = None;
                                }
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
                            if config_path.is_empty() {
                                // No config path to retry against — nothing to
                                // reconnect to. Skip the retry counter entirely:
                                // an empty key would be a shared bucket across
                                // all un-keyed failures (see next_attempt's doc),
                                // and the debug_assert there panics on empty.
                                // Returning MAX makes the retry gate below fall
                                // straight to the disconnect branch.
                                super::credential_handler::MAX_CREDENTIAL_ATTEMPTS
                            } else if let Ok(mut attempts) =
                                super::credential_handler::CREDENTIAL_ATTEMPTS.lock()
                            {
                                // Poison-tolerant: a prior panic in a holder of
                                // this lock must not brick auth-retry bookkeeping.
                                // Treat a poisoned lock as a fresh attempt (count 1).
                                super::credential_handler::next_attempt(
                                    &mut attempts,
                                    std::time::Instant::now(),
                                    &config_path,
                                )
                            } else {
                                warn!(
                                    "CREDENTIAL_ATTEMPTS lock poisoned — \
                                     treating as first attempt"
                                );
                                1
                            }
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
                            // Mark old session so SessDestroyed won't show reconnect prompt.
                            // Poison-tolerant: a poisoned lock must not skip this bookkeeping
                            // (best-effort insert; worst case SessDestroyed shows a redundant
                            // reconnect prompt, which is safe).
                            if let Ok(mut set) = super::session_ops::USER_DISCONNECTED.lock() {
                                set.insert(session_path.clone());
                            } else {
                                warn!(
                                    "USER_DISCONNECTED lock poisoned — \
                                     SessDestroyed may show reconnect prompt"
                                );
                            }
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
                            // Reset this config's retry budget so the user can
                            // reconnect within the 5-min window (otherwise the
                            // path-keyed counter stays at/near MAX and the next
                            // wrong password instantly disconnects again).
                            // disconnect_with_message no longer clears the counter
                            // (it doesn't receive the path); clear it here instead.
                            if let Ok(mut attempts) =
                                super::credential_handler::CREDENTIAL_ATTEMPTS.lock()
                            {
                                attempts.remove(&config_path);
                            }
                            glib::spawn_future_local(async move {
                                super::session_ops::disconnect_with_message(
                                    &dbus_conn,
                                    &session_path,
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
                                "VPN Error",
                                &body,
                            )
                            .await;
                        });
                        continue;
                    }

                    // Clear credential attempts on successful connection.
                    // Key on the config PATH (same scheme as next_attempt) — a
                    // dup-named sibling must not share/clear the other's budget.
                    if status.is_connected() {
                        let cp = tray_for_status
                            .update(|t| t.sessions.get(&path).map(|s| s.config_path.clone()))
                            .flatten();
                        if let Some(cp) = cp
                            && !cp.is_empty()
                            && let Ok(mut attempts) =
                                super::credential_handler::CREDENTIAL_ATTEMPTS.lock()
                        {
                            attempts.remove(&cp);
                        }

                        // Kill-switch: apply firewall rules now that the tunnel is up.
                        // Helper has replace semantics, so re-firing on Reconnect is safe.
                        killswitch_glue::on_connected(&conn, &path, &tray_for_status);
                    }

                    // Kill-switch: remove rules on Pause unless user chose
                    // block-during-pause.  Resume needs no explicit code —
                    // the ConnConnected transition re-fires apply_kill_switch.
                    if status.is_paused() {
                        killswitch_glue::on_paused(&tray_for_status);
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
                                    idle_started_at: None,
                                    idle_since: None,
                                    auto_reconnect_attempted_at: None,
                                    kill_switch_active: false,
                                },
                            );
                        }
                    });

                    // Remove terminal sessions from the tray immediately rather than
                    // waiting for SessDestroyed. Prevents zombie "Profile: Done" entries.
                    if is_now_disconnected {
                        // Cache (config_path, config_name) so the SessDestroyed
                        // handler can still fire its reconnect notification after
                        // we remove the session from the tray (SessDestroyed can
                        // arrive several seconds after the 3s removal below).
                        let path_for_cache = path_for_removal.clone();
                        let tray_for_cache = tray_for_status.clone();
                        if let Some((cp, cn)) = tray_for_cache
                            .update(|t| {
                                t.sessions
                                    .get(&path_for_cache)
                                    .map(|s| (s.config_path.clone(), s.config_name.clone()))
                            })
                            .flatten()
                            && !cp.is_empty()
                            && let Ok(mut map) =
                                super::session_ops::RECENT_DESTROYED_SESSIONS.lock()
                        {
                            map.insert(path_for_cache, (cp, cn));
                        }

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
