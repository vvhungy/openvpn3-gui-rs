//! Per-status dispatch helpers extracted from `setup_status_handler`.
//!
//! Pure classifiers (`classify_error`, `build_unseen_session`) and the impure
//! tray/D-Bus glue handlers, kept here so `mod.rs` stays a thin signal loop
//! under the file-health gate. Pure structural extraction — zero behavior change.

use tracing::warn;

use crate::dbus::types::{SessionStatus, StatusMajor, StatusMinor};
use crate::tray::{SessionInfo, VpnTray};

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
        kill_switch_active: false,
    }
}

/// Clear this session's credential-retry budget once it connects.
///
/// Keyed on the config PATH (same scheme as `next_attempt`) — a dup-named
/// sibling must not share/clear the other's budget. Impure tray + global-lock
/// glue; the retry *gate* itself is the unit-tested `should_retry_auth`.
pub(super) fn clear_credential_attempts_on_connect(
    tray: &ksni::blocking::Handle<VpnTray>,
    path: &str,
) {
    let cp = tray
        .update(|t| t.sessions.get(path).map(|s| s.config_path.clone()))
        .flatten();
    if let Some(cp) = cp
        && !cp.is_empty()
        && let Ok(mut attempts) = crate::app::credential_handler::CREDENTIAL_ATTEMPTS.lock()
    {
        attempts.remove(&cp);
    }
}

/// Upsert the tray session entry: stamp `connected_at` on a Connected
/// transition for a known session, or insert a fallback entry for a path the
/// tray has not yet seen. Returns `true` when a new (unseen) session was just
/// inserted, so the caller can backfill its real identity (H4 — see
/// `backfill_session_identity`). Impure tray glue.
pub(super) fn upsert_session_state(
    tray: &ksni::blocking::Handle<VpnTray>,
    path: &str,
    status: SessionStatus,
) -> bool {
    let is_now_connected = status.is_connected();
    let path = path.to_string();
    tray.update(move |t| {
        if let Some(session) = t.sessions.get_mut(&path) {
            if is_now_connected && session.connected_at.is_none() {
                session.connected_at = Some(std::time::Instant::now());
            }
            false
        } else {
            t.sessions
                .insert(path.clone(), build_unseen_session(&path, status));
            true
        }
    })
    .unwrap_or(false)
}

/// Fetch the real `config_path` + `config_name` for a session that was inserted
/// via `build_unseen_session` (Connected won the race over SessionCreated, so
/// the entry landed with an empty config_path). Without this, an unexpected drop
/// of that session is silently swallowed: `handle_session_destroyed`'s reconnect
/// branch gates on `!config_path.is_empty()`, and `schedule_disconnected_removal`
/// skips the `RECENT_DESTROYED_SESSIONS` cache for the same reason — so neither
/// auto-reconnect nor the notification ever fires (H4). Backfills only while the
/// session is alive (by SessDestroyed the session is gone and the proxy fails).
/// No-op if the entry no longer exists or already has a real config_path (e.g.
/// a late SessCreated filled it). Impure async D-Bus + tray glue.
pub(super) async fn backfill_session_identity(
    conn: &zbus::Connection,
    tray: &ksni::blocking::Handle<VpnTray>,
    path: &str,
) {
    let Ok(obj_path) = zbus::zvariant::OwnedObjectPath::try_from(path) else {
        return;
    };
    let proxy = match crate::dbus::session::SessionProxy::builder(conn).path(obj_path) {
        Ok(builder) => match builder.build().await {
            Ok(p) => p,
            Err(e) => {
                warn!("backfill identity: proxy build failed for {path}: {e}");
                return;
            }
        },
        Err(e) => {
            warn!("backfill identity: proxy path failed for {path}: {e}");
            return;
        }
    };
    let config_path = proxy
        .config_path()
        .await
        .ok()
        .map(|p| p.as_str().to_string())
        .filter(|s| !s.is_empty());
    let config_name = proxy.config_name().await.ok();
    let path = path.to_string();
    tray.update(move |t| {
        if let Some(s) = t.sessions.get_mut(&path)
            && s.config_path.is_empty()
        {
            if let Some(cp) = config_path {
                s.config_path = cp;
            }
            if let Some(cn) = config_name {
                s.config_name = cn;
            }
        }
    });
}

/// Cache a dying session's identity for the `SessDestroyed` reconnect hook,
/// then remove it from the tray after 3s so the notification chain
/// (Disconnecting → Disconnected → Done) completes with the correct profile
/// name. Impure (spawned future + global map).
pub(super) fn schedule_disconnected_removal(tray: &ksni::blocking::Handle<VpnTray>, path: &str) {
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
        && let Ok(mut map) = crate::app::session_ops::RECENT_DESTROYED_SESSIONS.lock()
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
pub(super) fn send_status_notification(prev_info: Option<(String, &str)>, status: &SessionStatus) {
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
pub(super) fn record_auth_attempt(config_path: &str) -> u32 {
    use crate::app::credential_handler::{
        CREDENTIAL_ATTEMPTS, MAX_CREDENTIAL_ATTEMPTS, next_attempt,
    };
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
pub(super) fn handle_auth_failed(
    conn: &zbus::Connection,
    tray_for_status: &ksni::blocking::Handle<VpnTray>,
    path: &str,
) {
    let session_path = path.to_string();
    let dbus_conn = conn.clone();
    let (config_name, config_path) =
        crate::tray::session_config_identity(tray_for_status, &session_path);

    let attempt = record_auth_attempt(&config_path);

    if crate::app::credential_handler::should_retry_auth(attempt, &config_path) {
        warn!(
            "Authentication failed for '{}' (attempt {}/{}) — creating new tunnel",
            config_name,
            attempt,
            crate::app::credential_handler::MAX_CREDENTIAL_ATTEMPTS
        );
        crate::dialogs::show_error_notification(
            &format!("{}: Authentication Failed", config_name),
            &format!("Wrong credentials for '{}'. Retrying...", config_name),
        );
        // Mark old session as an auth-retry teardown, NOT a user disconnect.
        // Both suppress the SessDestroyed reconnect prompt, but the auth-retry
        // marker also tells the kill-switch teardown path to leave the firewall
        // in place — a replacement tunnel for the same config is coming, so
        // dropping protection here would briefly expose traffic mid-swap (H3).
        // Poison-tolerant: a poisoned lock must not skip this bookkeeping
        // (best-effort insert; worst case SessDestroyed shows a redundant
        // reconnect prompt, which is safe).
        if let Ok(mut set) = crate::app::session_ops::AUTH_RETRY_SESSIONS.lock() {
            set.insert(session_path.clone());
        } else {
            warn!(
                "AUTH_RETRY_SESSIONS lock poisoned — \
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
            if let Err(e) = crate::app::session_ops::session_action(
                &dbus_for_disconnect,
                &sp_for_disconnect,
                "disconnect",
            )
            .await
            {
                tracing::warn!("Failed to disconnect orphan session: {}", e);
            }
            if let Err(e) = crate::app::session_ops::connect_to_config(
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
        if let Ok(mut attempts) = crate::app::credential_handler::CREDENTIAL_ATTEMPTS.lock() {
            attempts.remove(&config_path);
        }
        glib::spawn_future_local(async move {
            crate::app::session_ops::disconnect_with_message(
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
pub(super) fn disconnect_with_notification(
    conn: &zbus::Connection,
    path: &str,
    title: &str,
    body: String,
) {
    let session_path = path.to_string();
    let dbus_conn = conn.clone();
    let title = title.to_string();
    glib::spawn_future_local(async move {
        crate::app::session_ops::disconnect_with_message(&dbus_conn, &session_path, &title, &body)
            .await;
    });
}

/// Connection failure on `path`: disconnect the session with a user-facing message.
pub(super) fn handle_conn_failed(
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
pub(super) fn handle_session_error(
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

    fn connected() -> SessionStatus {
        SessionStatus {
            major: StatusMajor::Connection,
            minor: StatusMinor::ConnConnected,
        }
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
