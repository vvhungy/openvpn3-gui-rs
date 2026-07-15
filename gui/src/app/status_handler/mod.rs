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

/// Why an incoming StatusChange for a path is dispatched after the per-path
/// dedup check, or `None` to skip it.
///
/// OpenVPN3 delivers each `StatusChange` twice (once via `LogForward(true)`,
/// once via the `AddMatch` rule), so a repeat `(major, minor)` for an
/// already-seen path is skipped. Auth challenges are **exempt**: a re-emitted
/// credential request after Resume on an invalidated session must still reach
/// the dispatcher even if the same `(major, minor)` was seen earlier.
///
/// Returning the *reason* (rather than a bool) lets the caller branch on the
/// dedup-exempt auth case without re-deriving `prev == Some((major, minor))`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DispatchReason {
    /// First signal for this path.
    FirstSeen,
    /// `(major, minor)` changed since the last signal for this path.
    Changed,
    /// Repeat `(major, minor)` on a path, but auth challenges are dedup-exempt.
    AuthExempt,
}

/// Classify an incoming StatusChange against the last-seen `(major, minor)` for
/// its path. Returns `None` to skip (a non-auth repeat), otherwise the reason
/// it should dispatch.
pub(super) fn should_dispatch(
    prev: Option<(u32, u32)>,
    major: u32,
    minor: u32,
    is_auth: bool,
) -> Option<DispatchReason> {
    let cur = (major, minor);
    match prev {
        None => Some(DispatchReason::FirstSeen),
        Some(prev) if prev != cur => Some(DispatchReason::Changed),
        Some(_) if is_auth => Some(DispatchReason::AuthExempt),
        Some(_) => None,
    }
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
                    // Branch on the reason rather than re-deriving
                    // `prev == Some((major, minor))`: should_dispatch already
                    // classified the dedup-exempt auth re-emit as AuthExempt.
                    match should_dispatch(prev, major, minor, is_auth) {
                        None => continue,
                        Some(DispatchReason::AuthExempt) => {
                            info!(
                                "Auth signal re-emitted for {} (major={}, minor={}) — dedup-exempt, dispatching",
                                path, major, minor
                            );
                        }
                        Some(_) => {}
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

                    // Terminal/error dispatch. `is_error()` also matches
                    // ConnAuthFailed/ConnFailed, so `classify_error` fixes the
                    // precedence (AuthFailed > ConnFailed > generic error).
                    match classify_error(&status) {
                        ErrorAction::AuthFailed => {
                            handle_auth_failed(&conn, &tray_for_status, &path);
                            continue;
                        }
                        ErrorAction::ConnFailed => {
                            handle_conn_failed(&conn, &tray_for_status, &path);
                            continue;
                        }
                        ErrorAction::SessionError => {
                            handle_session_error(
                                &conn,
                                &tray_for_status,
                                &path,
                                major,
                                minor,
                                message,
                            );
                            continue;
                        }
                        ErrorAction::None => {}
                    }

                    // On successful connect: clear this config's retry budget, then apply
                    // kill-switch rules (helper has replace semantics, so re-firing
                    // on Reconnect is safe).
                    if status.is_connected() {
                        clear_credential_attempts_on_connect(&tray_for_status, &path);
                        killswitch_glue::on_connected(&conn, &path, &tray_for_status);
                    }

                    // Kill-switch: remove rules on Pause unless user chose
                    // block-during-pause.  Resume needs no explicit code —
                    // the ConnConnected transition re-fires apply_kill_switch.
                    if status.is_paused() {
                        killswitch_glue::on_paused(&tray_for_status);
                    }

                    // Update tray session state (connected_at, new sessions).
                    let path_for_timeout = path.clone();
                    let is_now_disconnected = status.is_disconnected();
                    upsert_session_state(&tray_for_status, &path, status.clone());

                    // Remove terminal sessions from the tray (3s delayed so the
                    // notification chain completes with the correct profile name).
                    if is_now_disconnected {
                        schedule_disconnected_removal(&tray_for_status, &path);
                    }

                    // Connection timeout watcher — see `timeout_watcher` module.
                    if status.is_connecting() {
                        super::timeout_watcher::spawn_timeout_watcher(
                            &tray_for_status,
                            path_for_timeout,
                        );
                    }

                    // Desktop notification for the status transition.
                    send_status_notification(prev_info, &status);
                }
                Err(e) => {
                    warn!("Failed to parse StatusChange signal: {}", e);
                }
            }
        }
    });

    Ok(())
}

// --- status classification & tray-state helpers ----------------------------
// Pure classifiers/builders extracted from the StatusChange loop so the
// dispatch precedence and the unseen-session field list are unit-tested
// rather than buried in async wiring.

/// Discrete terminal/error action for a StatusChange after auth dispatch
/// declines it.
///
/// `SessionStatus::is_error()` also matches `ConnAuthFailed` and `ConnFailed`,
/// so [`classify_error`] fixes the precedence: AuthFailed > ConnFailed > generic
/// SessionError — each routes to its own handler before the `is_error()` bucket
/// would swallow the more specific cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ErrorAction {
    AuthFailed,
    ConnFailed,
    SessionError,
    /// No terminal/error minor — proceed with the connected/paused/dispatch path.
    None,
}

/// Classify a non-auth StatusChange into its terminal/error action.
///
/// Pure over `&SessionStatus`. The order of the checks encodes the precedence
/// documented on [`ErrorAction`] (auth-failed and conn-failed are checked
/// before the broader `is_error()`).
pub(super) fn classify_error(status: &SessionStatus) -> ErrorAction {
    if status.major == StatusMajor::Connection && status.minor == StatusMinor::ConnAuthFailed {
        ErrorAction::AuthFailed
    } else if status.major == StatusMajor::Connection && status.minor == StatusMinor::ConnFailed {
        ErrorAction::ConnFailed
    } else if status.is_error() {
        ErrorAction::SessionError
    } else {
        ErrorAction::None
    }
}

/// Build a fallback [`SessionInfo`] for a path the tray has not yet seen via
/// `SessCreated`. Extracted so the field list (and its zeroed baselines) lives
/// in one tested place rather than an inline literal in the signal loop.
pub(super) fn build_unseen_session(path: &str, status: SessionStatus) -> SessionInfo {
    SessionInfo {
        session_path: path.to_string(),
        config_path: String::new(),
        config_name: crate::tray::FALLBACK_NAME.to_string(),
        status,
        connected_at: None,
        bytes_in: 0,
        bytes_out: 0,
        last_bytes_in: 0,
        last_bytes_out: 0,
        idle_started_at: None,
        idle_since: None,
        auto_reconnect_attempted_at: None,
        kill_switch_active: false,
    }
}

/// Clear this session's credential-retry budget once it connects.
///
/// Keyed on the config PATH (same scheme as `next_attempt`) — a dup-named
/// sibling must not share/clear the other's budget. Impure tray + global-lock
/// glue; the retry *gate* itself is the unit-tested `should_retry_auth`.
fn clear_credential_attempts_on_connect(tray: &ksni::blocking::Handle<VpnTray>, path: &str) {
    let cp = tray
        .update(|t| t.sessions.get(path).map(|s| s.config_path.clone()))
        .flatten();
    if let Some(cp) = cp
        && !cp.is_empty()
        && let Ok(mut attempts) = super::credential_handler::CREDENTIAL_ATTEMPTS.lock()
    {
        attempts.remove(&cp);
    }
}

/// Upsert the tray session entry: stamp `connected_at` on a Connected
/// transition for a known session, or insert a fallback entry for a path the
/// tray has not yet seen. Impure tray glue.
fn upsert_session_state(tray: &ksni::blocking::Handle<VpnTray>, path: &str, status: SessionStatus) {
    let is_now_connected = status.is_connected();
    let path = path.to_string();
    tray.update(move |t| {
        if let Some(session) = t.sessions.get_mut(&path) {
            if is_now_connected && session.connected_at.is_none() {
                session.connected_at = Some(std::time::Instant::now());
            }
        } else {
            t.sessions
                .insert(path.clone(), build_unseen_session(&path, status));
        }
    });
}

/// Cache a dying session's identity for the `SessDestroyed` reconnect hook,
/// then remove it from the tray after 3s so the notification chain
/// (Disconnecting → Disconnected → Done) completes with the correct profile
/// name. Impure (spawned future + global map).
fn schedule_disconnected_removal(tray: &ksni::blocking::Handle<VpnTray>, path: &str) {
    // Cache (config_path, config_name) so the SessDestroyed handler can still
    // fire its reconnect notification after removal (SessDestroyed can arrive
    // several seconds after the 3s removal below).
    let path_for_cache = path.to_string();
    let tray_for_cache = tray.clone();
    if let Some((cp, cn)) = tray_for_cache
        .update(|t| {
            t.sessions
                .get(&path_for_cache)
                .map(|s| (s.config_path.clone(), s.config_name.clone()))
        })
        .flatten()
        && !cp.is_empty()
        && let Ok(mut map) = super::session_ops::RECENT_DESTROYED_SESSIONS.lock()
    {
        map.insert(path_for_cache, (cp, cn));
    }

    let path_for_removal = path.to_string();
    let tray_for_removal = tray.clone();
    glib::spawn_future_local(async move {
        glib::timeout_future_seconds(3).await;
        tray_for_removal.update(move |t| {
            t.sessions.remove(&path_for_removal);
        });
    });
}

/// Show a desktop notification for the status transition, comparing the
/// session's previous description to the new one. Impure (notification).
fn send_status_notification(prev_info: Option<(String, &str)>, status: &SessionStatus) {
    let new_desc = crate::status::get_status_description(status.major, status.minor);
    match prev_info {
        Some((cn, prev)) if prev != new_desc => {
            let body = format!("{}: Status change from {} to {}", cn, prev, new_desc);
            crate::dialogs::show_connection_notification(&cn, &body);
        }
        Some(_) => {}
        None => {
            crate::dialogs::show_connection_notification(crate::tray::FALLBACK_NAME, new_desc);
        }
    }
}

// --- status-dispatch handlers -----------------------------------------------
// Extracted from the `StatusChange` loop so `setup_status_handler` is thin
// wiring. Each handler is impure (D-Bus calls, tray mutation, spawned futures)
// and carries no unit-test surface — named for readability, not testability
// (CLAUDE.md §Testing: orchestration wrappers with no pure branch need no
// unit test).

/// Record one auth failure for `config_path` and return the running attempt
/// count for the retry decision in [`handle_auth_failed`].
///
/// Extracted to keep `handle_auth_failed` under the complexity gate. The
/// pure retry *gate* lives in [`credential_handler::should_retry_auth`]
/// (unit-tested); this is the impure glue that mutates the live counter map.
///
/// - empty path → [`MAX_CREDENTIAL_ATTEMPTS`], so the retry gate always answers
///   false (straight to disconnect). Also avoids `next_attempt`'s empty-key
///   debug_assert (see its doc) — an empty key would be a shared bucket across
///   all un-keyed failures.
/// - poisoned bookkeeping lock → log and treat as a first attempt (count 1), so
///   a prior panic elsewhere can't brick auth-retry bookkeeping.
/// - otherwise → [`next_attempt`] on the live map.
fn record_auth_attempt(config_path: &str) -> u32 {
    use super::credential_handler::{CREDENTIAL_ATTEMPTS, MAX_CREDENTIAL_ATTEMPTS, next_attempt};
    if config_path.is_empty() {
        MAX_CREDENTIAL_ATTEMPTS
    } else if let Ok(mut attempts) = CREDENTIAL_ATTEMPTS.lock() {
        next_attempt(&mut attempts, std::time::Instant::now(), config_path)
    } else {
        warn!(
            "CREDENTIAL_ATTEMPTS lock poisoned — \
             treating as first attempt"
        );
        1
    }
}
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

    let attempt = record_auth_attempt(&config_path);

    if super::credential_handler::should_retry_auth(attempt, &config_path) {
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

/// Disconnect `path` asynchronously and surface `title`/`body` to the user.
///
/// Owns the clone-and-spawn pattern shared by the failure/error handlers below:
/// every session-level disconnect-with-notification now routes through one
/// place, so a future fix (e.g. clearing kill-switch state on failure) lands
/// once instead of drifting between two copies.
fn disconnect_with_notification(conn: &zbus::Connection, path: &str, title: &str, body: String) {
    let session_path = path.to_string();
    let dbus_conn = conn.clone();
    let title = title.to_string();
    glib::spawn_future_local(async move {
        super::session_ops::disconnect_with_message(&dbus_conn, &session_path, &title, &body).await;
    });
}

/// Connection failure on `path`: disconnect the session with a user-facing message.
fn handle_conn_failed(
    conn: &zbus::Connection,
    tray_for_status: &ksni::blocking::Handle<VpnTray>,
    path: &str,
) {
    warn!("Connection failed for session {}", path);
    let config_name = crate::tray::session_config_name(tray_for_status, path);
    disconnect_with_notification(
        conn,
        path,
        "Connection Failed",
        format!("Connection failed for '{}'. Please try again.", config_name),
    );
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
    let config_name = crate::tray::session_config_name(tray_for_status, path);
    let body = if message.is_empty() {
        format!("VPN error for '{}'.", config_name)
    } else {
        format!("VPN error for '{}': {}", config_name, message)
    };
    disconnect_with_notification(conn, path, "VPN Error", body);
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
    fn should_dispatch_first_seen_for_new_path() {
        // No prior signal for this path → dispatch, classified as first-seen.
        assert_eq!(
            should_dispatch(None, 3, 4, false),
            Some(DispatchReason::FirstSeen)
        );
    }

    #[test]
    fn should_dispatch_none_for_repeat_non_auth() {
        // Same (major, minor) seen earlier, not an auth challenge → skip.
        assert_eq!(should_dispatch(Some((3, 4)), 3, 4, false), None);
    }

    #[test]
    fn should_dispatch_changed_for_repeat_with_new_minor() {
        // Same path, different minor → dispatch, classified as changed.
        assert_eq!(
            should_dispatch(Some((3, 4)), 3, 5, false),
            Some(DispatchReason::Changed)
        );
    }

    #[test]
    fn should_dispatch_auth_exempt_for_repeat() {
        // Auth challenge re-emitted with the same (major, minor) after Resume
        // must still dispatch — and as AuthExempt, not FirstSeen/Changed, so the
        // caller can log the dedup-exempt case without re-deriving prev.
        assert_eq!(
            should_dispatch(Some((7, 8)), 7, 8, true),
            Some(DispatchReason::AuthExempt)
        );
    }

    #[test]
    fn should_dispatch_first_seen_dominates_auth() {
        // First signal for a path is FirstSeen even when it's an auth challenge
        // (nothing to be exempt from yet).
        assert_eq!(
            should_dispatch(None, 7, 8, true),
            Some(DispatchReason::FirstSeen)
        );
    }

    #[test]
    fn should_dispatch_changed_when_auth_and_minor_differ() {
        // Auth + a genuinely changed tuple dispatches as Changed (changed
        // dominates; AuthExempt is only for an exact-repeat auth re-emit).
        assert_eq!(
            should_dispatch(Some((7, 8)), 7, 9, true),
            Some(DispatchReason::Changed)
        );
    }

    // --- classify_error -----------------------------------------------------

    fn status_of(major: StatusMajor, minor: StatusMinor) -> SessionStatus {
        SessionStatus { major, minor }
    }

    #[test]
    fn classify_error_auth_failed_dominates_is_error() {
        // ConnAuthFailed is also matched by is_error(); it must classify as
        // AuthFailed (its own handler), not the generic SessionError bucket.
        assert_eq!(
            classify_error(&status_of(
                StatusMajor::Connection,
                StatusMinor::ConnAuthFailed
            )),
            ErrorAction::AuthFailed
        );
    }

    #[test]
    fn classify_error_conn_failed_dominates_is_error() {
        // ConnFailed is also matched by is_error(); it must classify as
        // ConnFailed, not SessionError.
        assert_eq!(
            classify_error(&status_of(StatusMajor::Connection, StatusMinor::ConnFailed)),
            ErrorAction::ConnFailed
        );
    }

    #[test]
    fn classify_error_cfg_error_is_session_error() {
        // A config error with no more-specific minor routes to the generic handler.
        assert_eq!(
            classify_error(&status_of(StatusMajor::CfgError, StatusMinor::CfgError)),
            ErrorAction::SessionError
        );
    }

    #[test]
    fn classify_error_connected_is_none() {
        // A healthy Connected transition is not terminal — proceed with the
        // connected/paused/dispatch path.
        assert_eq!(
            classify_error(&status_of(
                StatusMajor::Connection,
                StatusMinor::ConnConnected
            )),
            ErrorAction::None
        );
    }

    // --- build_unseen_session -----------------------------------------------

    #[test]
    fn build_unseen_session_has_zeroed_baselines_and_fallback_name() {
        // A path the tray has not yet seen gets a fallback entry with zeroed
        // byte/idle baselines (so the first stats poll computes a real delta)
        // and no connected_at timestamp.
        let s = build_unseen_session("/x/y", connected());
        assert_eq!(s.session_path, "/x/y");
        assert_eq!(s.config_name, crate::tray::FALLBACK_NAME.to_string());
        assert_eq!(s.config_path, "");
        assert_eq!(s.bytes_in, 0);
        assert_eq!(s.bytes_out, 0);
        assert_eq!(s.last_bytes_in, 0);
        assert_eq!(s.last_bytes_out, 0);
        assert!(s.connected_at.is_none());
        assert!(s.idle_since.is_none());
        assert!(s.status.is_connected());
    }
}
