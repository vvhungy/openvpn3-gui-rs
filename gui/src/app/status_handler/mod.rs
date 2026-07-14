//! StatusChange signal loop
//!
//! Subscribes to per-session `StatusChange` signals from OpenVPN3 backends
//! and dispatches each status transition to the appropriate handler.
//!
//! The signal loop itself is async D-Bus with no unit surface, but the pure
//! transition logic (`apply_status_transition`) is extracted and tested below.

use futures::StreamExt;
use tracing::{info, warn};

use crate::dbus::types::{SessionStatus, StatusMajor, StatusMinor};
use crate::tray::{SessionInfo, VpnTray};

mod killswitch_glue;

pub(crate) use killswitch_glue::apply_kill_switch;

/// Update a session's status and reset the stats/idle baseline when the
/// transition crosses the Connected boundary. Pure over `&mut SessionInfo`
/// — no async, no D-Bus, no tray — so the transition rules are unit-testable.
///
/// Two directional resets:
/// - **into** Connected (from a non-connected state): zero byte counters +
///   clear idle. Frozen counters from before Pause would otherwise make the
///   first post-Resume poll see a zero delta and falsely trip `idle_since`.
/// - **out of** Connected (→ Error/Disconnected/Paused): clear the idle clock
///   and warning flag. A stale `idle_since` would win the `current_icon()`
///   priority check (`error > loading`) and mask the error icon.
///
/// Called on every StatusChange before the specialized auth/error/connected
/// branches fire, so the menu label ("Authentication required", etc.) stays
/// current even when a branch `continue`s before the generic path.
pub(super) fn apply_status_transition(session: &mut SessionInfo, status: SessionStatus) {
    let was_connected = session.status.is_connected();
    session.status = status;
    let now_connected = session.status.is_connected();
    if !was_connected && now_connected {
        session.last_bytes_in = 0;
        session.last_bytes_out = 0;
        session.idle_started_at = None;
        session.idle_since = None;
    }
    if was_connected && !now_connected {
        session.idle_started_at = None;
        session.idle_since = None;
    }
}

/// Pure signal-relevance filter. A message is a `StatusChange` from the
/// OpenVPN3 backend only if it is `Signal`-typed, carries the
/// `net.openvpn.v3.backends` interface, and has member `StatusChange`.
/// Extracted from the three inline `continue` guards so the contract is
/// unit-testable.
pub(super) fn is_status_change(
    msg_type: zbus::message::Type,
    interface: Option<&str>,
    member: Option<&str>,
) -> bool {
    msg_type == zbus::message::Type::Signal
        && interface == Some("net.openvpn.v3.backends")
        && member == Some("StatusChange")
}

/// Pure dedup predicate. OpenVPN3 delivers each `StatusChange` twice (once via
/// `LogForward(true)`, once via the `AddMatch` rule), so a repeat `(major,
/// minor)` for an already-seen path is skipped. Auth challenges are **exempt**:
/// a re-emitted credential request after Resume on an invalidated session must
/// still reach the dispatcher even if the same `(major, minor)` was seen
/// earlier. Returns `true` when the signal should be dispatched.
pub(super) fn should_dispatch(
    prev: Option<(u32, u32)>,
    major: u32,
    minor: u32,
    is_auth: bool,
) -> bool {
    is_auth || prev != Some((major, minor))
}

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

            let msg_type = msg.message_type();
            let header = msg.header();
            if !is_status_change(
                msg_type,
                header.interface().map(|i| i.as_str()),
                header.member().map(|m| m.as_str()),
            ) {
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

                    // Dedup: skip a repeat (major, minor) for an already-seen
                    // path; auth challenges are exempt (a re-emitted credential
                    // request after Resume on an invalidated session must still
                    // dispatch). See `should_dispatch`.
                    let is_auth = status.is_auth_request();
                    let prev = last_signal.get(&path).copied();
                    if !should_dispatch(prev, major, minor, is_auth) {
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
                        let status = SessionStatus::new(major, minor, message.to_string());
                        tray_for_status.update(move |t| {
                            if let Some(session) = t.sessions.get_mut(&p) {
                                apply_status_transition(session, status.clone());
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
                        handle_auth_failed(&conn, &tray_for_status, &path);
                        continue;
                    }

                    // Connection failure
                    if status.major == StatusMajor::Connection
                        && status.minor == StatusMinor::ConnFailed
                    {
                        handle_conn_failed(&conn, &tray_for_status, &path);
                        continue;
                    }

                    // Generic error states (config errors, process errors)
                    if status.is_error() {
                        handle_session_error(&conn, &tray_for_status, &path, major, minor, message);
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
                                    config_name: crate::tray::FALLBACK_NAME.to_string(),
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
                        crate::dialogs::show_connection_notification(
                            crate::tray::FALLBACK_NAME,
                            new_desc,
                        );
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

// --- status-dispatch handlers -----------------------------------------------
// Extracted from the `StatusChange` loop so `setup_status_handler` is thin
// wiring. Each handler is impure (D-Bus calls, tray mutation, spawned futures)
// and carries no unit-test surface — named for readability, not testability
// (CLAUDE.md §Testing: orchestration wrappers with no pure branch need no
// unit test).

/// Authentication failed on `path`: auto-retry by creating a new tunnel up to
/// `MAX_CREDENTIAL_ATTEMPTS`, then disconnect with a message and reset the
/// per-config retry budget so the user can reconnect within the window.
fn handle_auth_failed(
    conn: &zbus::Connection,
    tray_for_status: &ksni::blocking::Handle<VpnTray>,
    path: &str,
) {
    let session_path = path.to_string();
    let dbus_conn = conn.clone();
    let (config_name, config_path) =
        crate::tray::session_config_identity(tray_for_status, &session_path);

    let attempt = {
        if config_path.is_empty() {
            // No config path to retry against — nothing to reconnect to. Skip
            // the retry counter entirely: an empty key would be a shared bucket
            // across all un-keyed failures (see next_attempt's doc), and the
            // debug_assert there panics on empty. Returning MAX makes the retry
            // gate below fall straight to the disconnect branch.
            super::credential_handler::MAX_CREDENTIAL_ATTEMPTS
        } else if let Ok(mut attempts) = super::credential_handler::CREDENTIAL_ATTEMPTS.lock() {
            // Poison-tolerant: a prior panic in a holder of this lock must not
            // brick auth-retry bookkeeping. Treat a poisoned lock as a fresh
            // attempt (count 1).
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

    if attempt < super::credential_handler::MAX_CREDENTIAL_ATTEMPTS && !config_path.is_empty() {
        warn!(
            "Authentication failed for '{}' (attempt {}/{}) — creating new tunnel",
            config_name,
            attempt,
            super::credential_handler::MAX_CREDENTIAL_ATTEMPTS
        );
        crate::dialogs::show_error_notification(
            &format!("{}: Authentication Failed", config_name),
            &format!("Wrong credentials for '{}'. Retrying...", config_name),
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
            // Disconnect the failed session on D-Bus to prevent orphan
            // sessions from accumulating.
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
                tracing::error!("Auto-reconnect after auth failure failed: {}", e);
            }
        });
    } else {
        warn!(
            "Max auth attempts reached for '{}' — disconnecting",
            config_name
        );
        // Reset this config's retry budget so the user can reconnect within
        // the 5-min window (otherwise the path-keyed counter stays at/near MAX
        // and the next wrong password instantly disconnects again).
        // disconnect_with_message no longer clears the counter (it doesn't
        // receive the path); clear it here instead.
        if let Ok(mut attempts) = super::credential_handler::CREDENTIAL_ATTEMPTS.lock() {
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
}

/// Connection failure on `path`: disconnect the session with a user-facing message.
fn handle_conn_failed(
    conn: &zbus::Connection,
    tray_for_status: &ksni::blocking::Handle<VpnTray>,
    path: &str,
) {
    warn!("Connection failed for session {}", path);
    let session_path = path.to_string();
    let dbus_conn = conn.clone();
    let config_name = crate::tray::session_config_name(tray_for_status, &session_path);
    glib::spawn_future_local(async move {
        super::session_ops::disconnect_with_message(
            &dbus_conn,
            &session_path,
            "Connection Failed",
            &format!("Connection failed for '{}'. Please try again.", config_name),
        )
        .await;
    });
}

/// Generic session error (config/process errors) on `path`: disconnect with a
/// message built from `message` (empty → generic). `major`/`minor` are logged.
fn handle_session_error(
    conn: &zbus::Connection,
    tray_for_status: &ksni::blocking::Handle<VpnTray>,
    path: &str,
    major: u32,
    minor: u32,
    message: &str,
) {
    warn!(
        "Session error for {}: major={}, minor={}",
        path, major, minor
    );
    let session_path = path.to_string();
    let dbus_conn = conn.clone();
    let config_name = crate::tray::session_config_name(tray_for_status, &session_path);
    let body = if message.is_empty() {
        format!("VPN error for '{}'.", config_name)
    } else {
        format!("VPN error for '{}': {}", config_name, message)
    };
    glib::spawn_future_local(async move {
        super::session_ops::disconnect_with_message(&dbus_conn, &session_path, "VPN Error", &body)
            .await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbus::types::{StatusMajor, StatusMinor};
    use crate::tray::SessionInfo;

    fn connected() -> SessionStatus {
        SessionStatus {
            major: StatusMajor::Connection,
            minor: StatusMinor::ConnConnected,
        }
    }

    fn failed() -> SessionStatus {
        SessionStatus {
            major: StatusMajor::Connection,
            minor: StatusMinor::ConnFailed,
        }
    }

    /// Seed a session whose counters are non-zero + idle flags set, so a reset
    /// is observable. Starts Connected since that's the only state whose
    /// transitions the reset logic cares about.
    fn seeded_connected() -> SessionInfo {
        SessionInfo {
            session_path: "/t".into(),
            config_path: String::new(),
            config_name: "T".into(),
            status: connected(),
            connected_at: None,
            bytes_in: 999,
            bytes_out: 888,
            last_bytes_in: 999,
            last_bytes_out: 888,
            idle_started_at: Some(std::time::Instant::now()),
            idle_since: Some(std::time::Instant::now()),
            auto_reconnect_attempted_at: None,
            kill_switch_active: false,
        }
    }

    #[test]
    fn into_connected_resets_baseline_and_idle() {
        // Non-connected seed → Connected: frozen counters + idle flags clear.
        let mut s = seeded_connected();
        s.status = failed();
        s.last_bytes_in = 100;
        s.idle_since = Some(std::time::Instant::now());
        apply_status_transition(&mut s, connected());
        assert_eq!(s.last_bytes_in, 0);
        assert_eq!(s.last_bytes_out, 0);
        assert!(s.idle_started_at.is_none());
        assert!(s.idle_since.is_none());
        assert!(s.status.is_connected());
    }

    #[test]
    fn out_of_connected_clears_idle_only() {
        // Connected → Failed: idle flags clear but byte counters are untouched
        // (a transition out of Connected is not a stats-baseline reset — the
        // next connect re-zeroes them).
        let mut s = seeded_connected();
        apply_status_transition(&mut s, failed());
        assert_eq!(s.last_bytes_in, 999, "counters preserved out of Connected");
        assert!(s.idle_started_at.is_none());
        assert!(s.idle_since.is_none());
    }

    #[test]
    fn same_connected_state_no_reset() {
        // Connected → Connected: no resets (was_connected && now_connected).
        let mut s = seeded_connected();
        let before = s.last_bytes_in;
        apply_status_transition(&mut s, connected());
        assert_eq!(s.last_bytes_in, before, "no reset on Connected→Connected");
    }

    #[test]
    fn status_field_always_updated() {
        // Even with no boundary reset, the new status must land so the menu
        // reflects the current state before specialized branches dispatch.
        let mut s = seeded_connected();
        apply_status_transition(&mut s, failed());
        assert!(!s.status.is_connected());
    }

    // --- is_status_change ---------------------------------------------------

    #[test]
    fn is_status_change_accepts_backend_statuschange_signal() {
        use zbus::message::Type as MessageType;
        assert!(is_status_change(
            MessageType::Signal,
            Some("net.openvpn.v3.backends"),
            Some("StatusChange"),
        ));
    }

    #[test]
    fn is_status_change_rejects_non_signal_method_call() {
        use zbus::message::Type as MessageType;
        assert!(!is_status_change(
            MessageType::MethodCall,
            Some("net.openvpn.v3.backends"),
            Some("StatusChange"),
        ));
    }

    #[test]
    fn is_status_change_rejects_wrong_interface() {
        use zbus::message::Type as MessageType;
        // A StatusChange on the wrong interface is not ours.
        assert!(!is_status_change(
            MessageType::Signal,
            Some("net.openvpn.v3.sessions"),
            Some("StatusChange"),
        ));
    }

    #[test]
    fn is_status_change_rejects_wrong_member() {
        use zbus::message::Type as MessageType;
        // Log signals share the interface but a different member.
        assert!(!is_status_change(
            MessageType::Signal,
            Some("net.openvpn.v3.backends"),
            Some("Log"),
        ));
    }

    #[test]
    fn is_status_change_rejects_missing_interface_or_member() {
        use zbus::message::Type as MessageType;
        assert!(!is_status_change(
            MessageType::Signal,
            None,
            Some("StatusChange")
        ));
        assert!(!is_status_change(
            MessageType::Signal,
            Some("net.openvpn.v3.backends"),
            None,
        ));
    }

    // --- should_dispatch ----------------------------------------------------

    #[test]
    fn should_dispatch_true_for_first_seen_tuple() {
        // No prior signal for this path → always dispatch.
        assert!(should_dispatch(None, 3, 4, false));
    }

    #[test]
    fn should_dispatch_false_for_repeat_non_auth() {
        // Same (major, minor) seen earlier, not an auth challenge → skip.
        assert!(!should_dispatch(Some((3, 4)), 3, 4, false));
    }

    #[test]
    fn should_dispatch_true_for_repeat_with_new_minor() {
        // Same path, different minor → dispatch.
        assert!(should_dispatch(Some((3, 4)), 3, 5, false));
    }

    #[test]
    fn should_dispatch_auth_exempt_for_repeat() {
        // Auth challenge re-emitted with the same (major, minor) after Resume
        // must still dispatch.
        assert!(should_dispatch(Some((7, 8)), 7, 8, true));
    }

    #[test]
    fn should_dispatch_auth_first_seen_also_dispatches() {
        assert!(should_dispatch(None, 7, 8, true));
    }
}
