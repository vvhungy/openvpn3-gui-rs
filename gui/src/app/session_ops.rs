//! Session D-Bus operations

use std::collections::{HashMap, HashSet};

use tracing::{error, info, warn};

/// Session paths the user explicitly disconnected (not unexpected drops)
pub(crate) static USER_DISCONNECTED: std::sync::LazyLock<std::sync::Mutex<HashSet<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashSet::new()));

/// Session paths torn down by the auth-retry loop (wrong-password → recreate a
/// fresh tunnel for the same config). Like `USER_DISCONNECTED` these suppress
/// the SessDestroyed reconnect prompt, but they are NOT a user request to drop
/// protection: a replacement session is coming, so the kill-switch teardown
/// path must skip them. Keeping this separate from `USER_DISCONNECTED` is what
/// stops an auth retry from stripping the firewall mid-swap (H3).
pub(crate) static AUTH_RETRY_SESSIONS: std::sync::LazyLock<std::sync::Mutex<HashSet<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashSet::new()));

/// Last stall-driven auto-reconnect attempt, keyed by **config_path** — the
/// stable identity across a session's destroy/recreate cycle. A stall-driven
/// disconnect tears down the session (SessDestroyed) and the reconnect builds a
/// fresh one, so a per-session timestamp would be lost at exactly the boundary
/// it needs to survive → against a dead server reconnect fired every
/// `stall_threshold` instead of `cooldown_secs` (H5). Scoping by config_path
/// makes the cooldown outlive the session it throttles.
pub(crate) static AUTO_RECONNECT_ATTEMPTED_AT: std::sync::LazyLock<
    std::sync::Mutex<HashMap<String, std::time::Instant>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// Read this config's last stall-driven reconnect attempt (for cooldown check).
/// Poison-tolerant: a poisoned lock reads as "never attempted" (worst case one
/// un-throttled reconnect, which is safe).
pub(crate) fn last_auto_reconnect_attempt(config_path: &str) -> Option<std::time::Instant> {
    AUTO_RECONNECT_ATTEMPTED_AT
        .lock()
        .ok()
        .and_then(|m| m.get(config_path).copied())
}

/// Stamp that a stall-driven reconnect fired for this config now.
/// Poison-tolerant: a poisoned lock skips the stamp (worst case one extra
/// reconnect sooner, which is safe).
pub(crate) fn record_auto_reconnect_attempt(config_path: &str) {
    if let Ok(mut m) = AUTO_RECONNECT_ATTEMPTED_AT.lock() {
        m.insert(config_path.to_string(), std::time::Instant::now());
    }
}

/// Side-channel cache of (config_path, config_name) for sessions removed from
/// the tray on `ConnDisconnected` before `SessDestroyed` arrives.
///
/// `status_handler` schedules a 3s `tray.sessions.remove()` on disconnect to
/// suppress zombie "Profile: Done" entries, but the SessionManager's
/// `SessDestroyed` event can take ~8s after that. Without this cache, the
/// SessDestroyed handler reads `tray.sessions.get()` and gets `None`, so the
/// unexpected-drop reconnect notification silently fails to fire. Populated
/// before removal; drained on SessDestroyed read.
pub(crate) static RECENT_DESTROYED_SESSIONS: std::sync::LazyLock<
    std::sync::Mutex<HashMap<String, (String, String)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));
use zbus::proxy::CacheProperties;
use zbus::zvariant::OwnedObjectPath;

use crate::dbus::session::{SessionManagerProxy, SessionProxy};
use crate::dbus::types::SessionStatus;
use crate::settings::Settings;
use crate::tray::{SessionInfo, VpnTray};

/// D-Bus error names that indicate cold-start activation race — first
/// `NewTunnel` after fresh login can fire before openvpn3-sessionmgr has
/// spawned; the service activates on demand and subsequent attempts succeed.
fn is_retryable_activation_error_name(name: &str) -> bool {
    matches!(
        name,
        "org.freedesktop.DBus.Error.UnknownObject"
            | "org.freedesktop.DBus.Error.UnknownMethod"
            | "org.freedesktop.DBus.Error.ServiceUnknown"
            | "org.freedesktop.DBus.Error.NameHasNoOwner"
    )
}

fn is_retryable_activation_error(err: &zbus::Error) -> bool {
    matches!(err, zbus::Error::MethodError(name, _, _) if is_retryable_activation_error_name(name.as_str()))
}

/// Wrap `NewTunnel` with backoff for cold-start D-Bus activation races.
/// 3 retries at 500ms / 1s / 2s; non-activation errors bubble up immediately.
async fn new_tunnel_with_retry(
    session_manager: &SessionManagerProxy<'_>,
    obj_path: zbus::zvariant::ObjectPath<'_>,
) -> zbus::Result<OwnedObjectPath> {
    const BACKOFFS_MS: [u64; 3] = [500, 1000, 2000];
    for (attempt, delay_ms) in BACKOFFS_MS.iter().enumerate() {
        match session_manager.NewTunnel(obj_path.clone()).await {
            Ok(p) => return Ok(p),
            Err(e) if is_retryable_activation_error(&e) => {
                warn!(
                    "NewTunnel attempt {}/4 failed (activation race): {}; retrying in {}ms",
                    attempt + 1,
                    e,
                    delay_ms
                );
                glib::timeout_future(std::time::Duration::from_millis(*delay_ms)).await;
            }
            Err(e) => return Err(e),
        }
    }
    session_manager.NewTunnel(obj_path).await
}

/// Connect to a VPN configuration
pub(crate) async fn connect_to_config(
    dbus: &zbus::Connection,
    config_path_str: &str,
    tray: &ksni::blocking::Handle<VpnTray>,
    settings: &Settings,
) -> anyhow::Result<()> {
    // Get config name (canonical VpnTray lookup; falls back to UNKNOWN_CONFIG_NAME).
    let config_name = crate::tray::resolve_config_name(tray, config_path_str);

    // Save as most recent
    settings.set_most_recent_config(config_path_str, &config_name);

    // Remove any stale sessions for this config before creating a new one.
    // Sessions linger in the tray for 3-5s after disconnect (delayed removal);
    // without cleanup, reconnecting would leave duplicate entries.
    {
        let cp = config_path_str.to_string();
        tray.update(move |t| {
            t.sessions.retain(|_, s| s.config_path != cp);
        });
    }

    // Create session
    let session_manager = SessionManagerProxy::builder(dbus)
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    let obj_path = zbus::zvariant::ObjectPath::try_from(config_path_str)?;
    let session_path = new_tunnel_with_retry(&session_manager, obj_path).await?;
    info!("Session created: {}", session_path);

    // Add session to tray immediately
    let sp = session_path.as_str().to_string();
    let cp = config_path_str.to_string();
    let cn = config_name.clone();
    tray.update(move |t| {
        t.sessions.insert(
            sp.clone(),
            SessionInfo {
                session_path: sp,
                config_path: cp,
                config_name: cn,
                status: SessionStatus::new(0, 0, "Connecting".to_string()),
                connected_at: None,
                bytes_in: 0,
                bytes_out: 0,
                last_bytes_in: 0,
                last_bytes_out: 0,
                idle_started_at: None,
                idle_since: None,
                kill_switch_active: false,
            },
        );
    });

    // Try Ready() — will fail if credentials are needed
    let session = SessionProxy::builder(dbus)
        .path(session_path.clone())?
        .build()
        .await?;

    // Try Ready() — will fail if credentials are needed
    match session.Ready().await {
        Ok(()) => {
            session.Connect().await?;
            info!("Session connected: {}", session_path);
        }
        Err(e) => {
            info!("Session not ready (needs credentials): {}", e);
            let sp = session_path.as_str().to_string();
            super::credential_handler::request_credentials(
                dbus,
                &sp,
                config_path_str,
                &config_name,
                HashMap::new(),
            )
            .await;
        }
    }

    Ok(())
}

/// Perform a session action (disconnect, pause, resume, restart)
pub(crate) async fn session_action(
    dbus: &zbus::Connection,
    session_path_str: &str,
    action: &str,
) -> anyhow::Result<()> {
    let session_path = OwnedObjectPath::try_from(session_path_str)?;
    let session = SessionProxy::builder(dbus)
        .path(session_path)?
        .build()
        .await?;

    match action {
        "disconnect" => session.Disconnect().await?,
        "pause" => session.Pause("User requested").await?,
        "resume" => session.Resume().await?,
        "restart" => session.Restart().await?,
        _ => warn!("Unknown session action: {}", action),
    }

    info!("Session {}: {}", action, session_path_str);
    Ok(())
}

/// Resume a paused session, re-requesting credentials if the server
/// invalidated the session while paused (e.g. session timeout).
pub(crate) async fn resume_session(
    dbus: &zbus::Connection,
    session_path_str: &str,
    tray: &ksni::blocking::Handle<VpnTray>,
) -> anyhow::Result<()> {
    let session_path = OwnedObjectPath::try_from(session_path_str)?;
    let session = SessionProxy::builder(dbus)
        .path(session_path)?
        .build()
        .await?;

    session.Resume().await?;
    info!("Session resumed: {}", session_path_str);

    match session.Ready().await {
        Ok(()) => {
            info!(
                "Session {} ready after resume — no credentials needed (re-auth, if required, will arrive via StatusChange)",
                session_path_str
            );
        }
        Err(e) => {
            info!("Session not ready after resume (needs credentials): {}", e);
            let (config_name, config_path) =
                crate::tray::session_config_identity(tray, session_path_str);
            let sp = session_path_str.to_string();
            super::credential_handler::request_credentials(
                dbus,
                &sp,
                &config_path,
                &config_name,
                HashMap::new(),
            )
            .await;
        }
    }

    Ok(())
}

/// Disconnect a session and show an error notification.
/// Marks the session as user-initiated so SessDestroyed won't show a redundant reconnect prompt.
pub(crate) async fn disconnect_with_message(
    dbus: &zbus::Connection,
    session_path: &str,
    title: &str,
    message: &str,
) {
    // NOTE: the auth-retry counter is NOT cleared here. It is keyed on the
    // config *path* (see credential_handler::retry), which this generic
    // disconnect/notify helper does not receive. Clearing it was a pre-T1
    // no-op anyway once the map became path-keyed. The one caller that must
    // reset the budget (max-attempts lockout, status_handler) clears it
    // explicitly on the path; the happy path clears on ConnConnected.
    // Mark as user-initiated to suppress the SessDestroyed reconnect notification.
    // Poison-tolerant: matches the rest of session_ops; worst case is a redundant
    // reconnect prompt, never a panic that blocks the disconnect.
    if let Ok(mut set) = USER_DISCONNECTED.lock() {
        set.insert(session_path.to_string());
    } else {
        warn!("USER_DISCONNECTED lock poisoned — SessDestroyed may show reconnect prompt");
    }
    if let Err(e) = session_action(dbus, session_path, "disconnect").await {
        error!("Failed to disconnect session {}: {}", session_path, e);
    }
    crate::dialogs::show_error_notification(title, message);
}

#[cfg(test)]
mod tests {
    use super::*;

    const P1: &str = "/net/openvpn/v3/sessions/test000000000001";
    const P2: &str = "/net/openvpn/v3/sessions/test000000000002";

    fn cleanup(paths: &[&str]) {
        if let Ok(mut set) = USER_DISCONNECTED.lock() {
            for p in paths {
                set.remove(*p);
            }
        }
    }

    #[test]
    fn test_user_disconnected_insert_and_remove() {
        cleanup(&[P1]);
        USER_DISCONNECTED.lock().unwrap().insert(P1.to_string());
        let removed = USER_DISCONNECTED.lock().unwrap().remove(P1);
        assert!(removed, "inserted path should be removable");
        let again = USER_DISCONNECTED.lock().unwrap().remove(P1);
        assert!(!again, "second remove of same path should return false");
    }

    #[test]
    fn test_user_disconnected_missing_path_returns_false() {
        cleanup(&[P2]);
        let removed = USER_DISCONNECTED.lock().unwrap().remove(P2);
        assert!(!removed, "removing absent path should return false");
    }

    #[test]
    fn test_user_disconnected_multiple_sessions() {
        cleanup(&[P1, P2]);
        {
            let mut set = USER_DISCONNECTED.lock().unwrap();
            set.insert(P1.to_string());
            set.insert(P2.to_string());
        }
        USER_DISCONNECTED.lock().unwrap().remove(P1);
        let p2_present = USER_DISCONNECTED.lock().unwrap().contains(P2);
        assert!(p2_present, "P2 should still be present after removing P1");
        cleanup(&[P2]);
    }

    #[test]
    fn test_user_disconnected_lock_accessible() {
        let _guard = USER_DISCONNECTED.lock().unwrap();
    }

    #[test]
    fn test_retryable_activation_error_unknown_object() {
        assert!(is_retryable_activation_error_name(
            "org.freedesktop.DBus.Error.UnknownObject"
        ));
    }

    #[test]
    fn test_retryable_activation_error_unknown_method() {
        // Observed on real cold-start: openvpn3-sessions service activates
        // mid-call and replies UnknownMethod before the object is registered.
        assert!(is_retryable_activation_error_name(
            "org.freedesktop.DBus.Error.UnknownMethod"
        ));
    }

    #[test]
    fn test_retryable_activation_error_service_unknown() {
        assert!(is_retryable_activation_error_name(
            "org.freedesktop.DBus.Error.ServiceUnknown"
        ));
    }

    #[test]
    fn test_retryable_activation_error_name_has_no_owner() {
        assert!(is_retryable_activation_error_name(
            "org.freedesktop.DBus.Error.NameHasNoOwner"
        ));
    }

    #[test]
    fn test_retryable_activation_error_rejects_access_denied() {
        // Credential / auth errors must NOT be masked by retry.
        assert!(!is_retryable_activation_error_name(
            "org.freedesktop.DBus.Error.AccessDenied"
        ));
    }

    #[test]
    fn test_retryable_activation_error_rejects_no_reply() {
        assert!(!is_retryable_activation_error_name(
            "org.freedesktop.DBus.Error.NoReply"
        ));
    }

    #[test]
    fn test_retryable_activation_error_rejects_empty() {
        assert!(!is_retryable_activation_error_name(""));
    }
}
