//! Session D-Bus operations

use std::collections::{HashMap, HashSet};

use tracing::{debug, error, info, warn};

/// Session paths the user explicitly disconnected (not unexpected drops)
pub(crate) static USER_DISCONNECTED: std::sync::LazyLock<std::sync::Mutex<HashSet<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashSet::new()));
use zbus::proxy::CacheProperties;
use zbus::zvariant::OwnedObjectPath;

use crate::dbus::session::{SessionManagerProxy, SessionProxy};
use crate::dbus::types::SessionStatus;
use crate::settings::Settings;
use crate::tray::{SessionInfo, VpnTray};

/// Connect to a VPN configuration
pub(crate) async fn connect_to_config(
    dbus: &zbus::Connection,
    config_path_str: &str,
    tray: &ksni::blocking::Handle<VpnTray>,
    settings: &Settings,
) -> anyhow::Result<()> {
    let config_path = OwnedObjectPath::try_from(config_path_str)?;

    // Get config name
    let config_name = tray
        .update(|t| {
            t.configs
                .iter()
                .find(|c| c.path == config_path_str)
                .map(|c| c.name.clone())
        })
        .flatten()
        .unwrap_or_else(|| "VPN".to_string());

    // Save as most recent
    settings.set_most_recent_config(config_path_str, &config_name);

    // Create session
    let session_manager = SessionManagerProxy::builder(dbus)
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    let obj_path = zbus::zvariant::ObjectPath::try_from(config_path_str)?;
    let session_path = session_manager.NewTunnel(obj_path).await?;
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
            },
        );
    });

    // Enable log/status forwarding so we receive StatusChange signals
    let session = SessionProxy::builder(dbus)
        .path(session_path.clone())?
        .build()
        .await?;
    if let Err(e) = session.LogForward(true).await {
        debug!("LogForward not available (ok for older versions): {}", e);
    }

    // Try Ready() — will fail if credentials are needed
    match session.Ready().await {
        Ok(()) => {
            session.Connect().await?;
            info!("Session connected: {}", session_path);
        }
        Err(e) => {
            info!("Session not ready (needs credentials): {}", e);
            let sp = session_path.as_str().to_string();
            super::credential_handler::request_credentials(dbus, &sp, &config_name, HashMap::new())
                .await;
        }
    }

    // config_path is used to build the proxy above; suppress unused warning
    let _ = config_path;

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

/// Disconnect a session and show an error notification.
/// Marks the session as user-initiated so SessDestroyed won't show a redundant reconnect prompt.
pub(crate) async fn disconnect_with_message(
    dbus: &zbus::Connection,
    session_path: &str,
    title: &str,
    message: &str,
) {
    // Clear attempt counter
    if let Ok(mut attempts) = super::credential_handler::CREDENTIAL_ATTEMPTS.lock() {
        attempts.remove(session_path);
    }
    // Mark as user-initiated to suppress the SessDestroyed reconnect notification
    USER_DISCONNECTED
        .lock()
        .unwrap()
        .insert(session_path.to_string());
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
}
