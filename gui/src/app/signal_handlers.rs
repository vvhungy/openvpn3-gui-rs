//! Session lifecycle signal handler
//!
//! Owns the `SessionManagerEvent` loop that reacts to sessions being
//! created and destroyed.  StatusChange is handled in `status_handler`.
//!
//! No testable pure surface — async D-Bus signal loop + side effects.

use futures::StreamExt;
use tracing::{info, warn};
use zbus::proxy::CacheProperties;

use crate::dbus::{
    session::{SessionManagerProxy, SessionProxy},
    types::{SessionManagerEventType, SessionStatus},
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
        t.sessions
            .entry(sp.clone())
            .and_modify(|e| {
                // Update placeholder inserted by a StatusChange that arrived before SessCreated
                if e.config_path.is_empty() {
                    e.config_path = config_path.clone();
                    e.config_name = config_name.clone();
                }
            })
            .or_insert_with(|| SessionInfo {
                session_path: sp.clone(),
                config_path,
                config_name,
                status: SessionStatus::new(major, minor, message),
                connected_at: None,
                bytes_in: 0,
                bytes_out: 0,
                last_bytes_in: 0,
                last_bytes_out: 0,
                idle_since: None,
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

                        // Delay removal so status notifications complete with the
                        // correct profile name. The status_handler also schedules a
                        // 3s delayed removal on is_disconnected(); this 5s removal
                        // is a safety net in case no terminal StatusChange arrives.
                        let sp = session_path.clone();
                        let tray_for_removal = tray_for_session.clone();
                        glib::spawn_future_local(async move {
                            glib::timeout_future_seconds(5).await;
                            tray_for_removal.update(move |t| {
                                t.sessions.remove(&sp);
                            });
                        });
                        info!("Session destroyed, scheduled delayed removal");

                        // Check whether the user initiated this disconnect
                        let user_initiated =
                            if let Ok(mut set) = super::session_ops::USER_DISCONNECTED.lock() {
                                set.remove(&session_path)
                            } else {
                                false
                            };

                        if user_initiated {
                            // Expected disconnect — release any kill-switch rules so
                            // the user's internet keeps working. No-op when helper
                            // not installed or kill-switch was never engaged.
                            glib::spawn_future_local(async move {
                                crate::dbus::killswitch::remove_rules().await;
                            });
                        } else if let Some((config_path, config_name)) = session_info
                            && !config_path.is_empty()
                        {
                            // Unexpected drop — keep rules in place; the
                            // notification's Reconnect/Dismiss handlers manage
                            // their lifecycle from here.
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

    super::status_handler::setup_status_handler(dbus, &tray).await?;

    Ok(())
}
