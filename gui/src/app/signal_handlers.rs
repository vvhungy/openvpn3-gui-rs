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
        .unwrap_or_else(|_| crate::tray::FALLBACK_NAME.to_string());
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
                idle_started_at: None,
                idle_since: None,
                kill_switch_active: false,
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
                        handle_session_destroyed(
                            &dbus_for_session,
                            &tray_for_session,
                            &action_tx_for_session,
                            session_path,
                        );
                    }
                }
                Err(e) => warn!("Failed to parse SessionManagerEvent: {}", e),
            }
        }
    });

    super::status_handler::setup_status_handler(dbus, &tray).await?;

    Ok(())
}

/// What the kill-switch teardown path should do when a protected session is
/// destroyed. The helper's kill-switch is a *single global nft table* bound to
/// one tunnel interface (`AddRules` replaces it wholesale), so tearing it down
/// on any disconnect strips protection from every *other* still-connected
/// session — and even leaving it in place would keep the table bound to the
/// dying interface. The correct response depends on whether a protected
/// survivor remains.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum KillSwitchTeardown {
    /// No protected session remains — release rules + bypass and clear all flags.
    Full,
    /// Another kill-switch-active session is still connected — leave the rules
    /// up, clear only the destroyed session's flag, and rebind the global table
    /// to the survivor at `session_path`.
    RebindTo { session_path: String },
    /// This drop was not a genuine user disconnect (auth-retry swap) — leave the
    /// firewall entirely untouched; a replacement tunnel is coming.
    Skip,
}

/// Decide the teardown action for a destroyed session. Pure: the caller passes
/// the destroyed path, whether it was an auth-retry teardown, and the surviving
/// sessions as `(path, is_connected, kill_switch_active)` tuples, so this is
/// hermetic and unit-testable while the async teardown that consumes it is not.
pub(super) fn decide_kill_switch_teardown(
    destroyed_path: &str,
    is_auth_retry: bool,
    survivors: impl IntoIterator<Item = (String, bool, bool)>,
) -> KillSwitchTeardown {
    if is_auth_retry {
        return KillSwitchTeardown::Skip;
    }
    // A survivor keeps the firewall alive only if it is both still connected
    // and was itself kill-switch-protected. Ignore the destroyed session's own
    // lingering entry (SessDestroyed can race its tray removal).
    let survivor = survivors
        .into_iter()
        .find(|(path, connected, ks_active)| path != destroyed_path && *connected && *ks_active);
    match survivor {
        Some((session_path, _, _)) => KillSwitchTeardown::RebindTo { session_path },
        None => KillSwitchTeardown::Full,
    }
}

/// Full kill-switch teardown: release rules + bypass routes, clear every
/// session's `kill_switch_active` flag, reset bypass tray state, notify. The
/// one path for "no protected survivor remains" — called both for the `Full`
/// decision and as the fallback when a `RebindTo` can't actually keep a live
/// rule bound to the survivor (apply_kill_switch returned Ok(false)/Err).
/// Impure (D-Bus + tray + notification); no test surface.
async fn full_killswitch_teardown(tray: &ksni::blocking::Handle<VpnTray>) {
    crate::dbus::killswitch::remove_rules().await;
    crate::dbus::killswitch::remove_bypass_routes().await;
    tray.update(|t| {
        for s in t.sessions.values_mut() {
            s.kill_switch_active = false;
        }
        t.bypass_state = crate::tray::BypassState::Off;
    });
    crate::dialogs::show_killswitch_inactive_notification();
}

/// React to a destroyed session: schedule its tray removal, then either release
/// kill-switch rules (user-initiated disconnect) or surface a reconnect path
/// (unexpected drop — auto-reconnect if enabled, else a notification).
///
/// Impure (tray mutation, spawned futures, D-Bus via spawned tasks); named for
/// readability, no unit-test surface (CLAUDE.md §Testing).
fn handle_session_destroyed(
    dbus: &zbus::Connection,
    tray: &ksni::blocking::Handle<VpnTray>,
    action_tx: &crate::tray::ActionSender,
    session_path: String,
) {
    // Capture config info before removing from tray. Fall back to
    // RECENT_DESTROYED_SESSIONS — status_handler removes the entry from
    // tray.sessions 3s after Disconnected, but SessDestroyed can arrive
    // several seconds later (~9s in the resume-after-long-pause path), so
    // without this cache the reconnect notification silently fails to fire.
    let session_info = tray
        .update(|t| {
            t.sessions
                .get(&session_path)
                .map(|s| (s.config_path.clone(), s.config_name.clone()))
        })
        .flatten()
        .or_else(|| {
            super::session_ops::RECENT_DESTROYED_SESSIONS
                .lock()
                .ok()
                .and_then(|mut m| m.remove(&session_path))
        });

    // Delay removal so status notifications complete with the correct profile
    // name. The status_handler also schedules a 3s delayed removal on
    // is_disconnected(); this 5s removal is a safety net in case no terminal
    // StatusChange arrives.
    let sp = session_path.clone();
    let tray_for_removal = tray.clone();
    glib::spawn_future_local(async move {
        glib::timeout_future_seconds(5).await;
        tray_for_removal.update(move |t| {
            t.sessions.remove(&sp);
        });
    });
    info!("Session destroyed, scheduled delayed removal");

    // Classify the drop. USER_DISCONNECTED = a real user disconnect (tear the
    // firewall down). AUTH_RETRY_SESSIONS = a wrong-password swap (suppress the
    // reconnect prompt but leave the firewall alone — a replacement tunnel is
    // coming). Drain both so the markers don't leak across sessions.
    let user_initiated = if let Ok(mut set) = super::session_ops::USER_DISCONNECTED.lock() {
        set.remove(&session_path)
    } else {
        false
    };
    let auth_retry = if let Ok(mut set) = super::session_ops::AUTH_RETRY_SESSIONS.lock() {
        set.remove(&session_path)
    } else {
        false
    };

    if user_initiated || auth_retry {
        // Expected disconnect — release kill-switch rules so the user's internet
        // keeps working, UNLESS another protected session is still connected (the
        // helper's kill-switch is a single global table; a blanket teardown would
        // strip that survivor's protection — H2) or this was an auth-retry swap
        // (Skip — H3). The pure decision runs against a live tray snapshot.
        let tray_clear = tray.clone();
        let dbus_rebind = dbus.clone();
        let destroyed = session_path.clone();
        glib::spawn_future_local(async move {
            let survivors = tray_clear
                .update(|t| {
                    t.sessions
                        .iter()
                        .map(|(p, s)| (p.clone(), s.status.is_connected(), s.kill_switch_active))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            match decide_kill_switch_teardown(&destroyed, auth_retry, survivors) {
                KillSwitchTeardown::Full => {
                    full_killswitch_teardown(&tray_clear).await;
                }
                KillSwitchTeardown::RebindTo { session_path } => {
                    // Keep the firewall up; rebind the global table to the
                    // surviving protected tunnel's interface (the destroyed
                    // session's `oifname accept` is now stale). Bypass routes
                    // are global and independent — leave them in place.
                    let settings = crate::settings::Settings::new();
                    let allow_lan = settings.kill_switch_allow_lan();
                    // apply_kill_switch returns Ok(false) (not Err) when the
                    // survivor can't anchor a live rule — device_name/server_ip
                    // still empty, or the helper isn't installed. A swallowed
                    // Ok(false) would leave the survivor flagged active while
                    // the global table stays bound to the dead interface (leak),
                    // so treat Ok(false) as a rebind failure and fall back to a
                    // full teardown.
                    let rebind_ok = match super::status_handler::apply_kill_switch(
                        &dbus_rebind,
                        &session_path,
                        allow_lan,
                    )
                    .await
                    {
                        Ok(true) => true,
                        Ok(false) => {
                            warn!(
                                "kill-switch: rebind to surviving session {} skipped (not ready / helper absent); falling back to full teardown",
                                session_path
                            );
                            false
                        }
                        Err(e) => {
                            warn!(
                                "kill-switch: rebind to surviving session {} failed: {}; falling back to full teardown",
                                session_path, e
                            );
                            false
                        }
                    };
                    if rebind_ok {
                        // Rebind succeeded: keep rules up, clear only the
                        // destroyed session's flag.
                        let destroyed = destroyed.clone();
                        tray_clear.update(move |t| {
                            if let Some(s) = t.sessions.get_mut(&destroyed) {
                                s.kill_switch_active = false;
                            }
                        });
                    } else {
                        full_killswitch_teardown(&tray_clear).await;
                    }
                }
                KillSwitchTeardown::Skip => {}
            }
        });
    } else if let Some((config_path, config_name)) = session_info.as_ref()
        && !config_path.is_empty()
    {
        // Unexpected drop — keep rules in place; the notification's
        // Reconnect/Dismiss handlers manage their lifecycle from here.
        let settings = crate::settings::Settings::new();
        if settings.auto_reconnect() {
            // Pass only the resolved delay: the spawned future rebuilds
            // Settings::new() itself, so capturing a whole Settings here would
            // hold a live GSettings client for the reconnect window for nothing.
            let delay = settings.auto_reconnect_delay_seconds();
            spawn_auto_reconnect(
                dbus,
                tray,
                action_tx,
                config_path.clone(),
                config_name.clone(),
                delay,
            );
        } else {
            info!(
                "Unexpected session drop for '{}', showing reconnect notification",
                config_name
            );
            crate::dialogs::show_reconnect_notification(
                config_path.clone(),
                config_name.clone(),
                action_tx.clone(),
                tray.clone(),
            );
        }
    } else {
        // Deliberate no-op, logged so it isn't silent (H4): either we have no
        // captured identity for this path, or its config_path is empty — the
        // race where Connected beat SessCreated and the identity backfill hadn't
        // landed before the drop. With nothing to reconnect to, there's no
        // notification or auto-reconnect to fire.
        match session_info.as_ref() {
            Some((cp, cn)) if cp.is_empty() => {
                info!(
                    "Unexpected drop for '{}' has no config_path (backfill not yet complete); reconnect suppressed",
                    cn
                );
            }
            None => {
                info!("Session destroyed with no captured identity; no reconnect action");
            }
            _ => {}
        }
    }
}

/// On an unexpected session drop with auto-reconnect enabled, wait `delay`
/// seconds then try to re-establish the tunnel; fall back to a reconnect
/// notification on failure. Impure (spawned future + D-Bus); no test surface.
fn spawn_auto_reconnect(
    dbus: &zbus::Connection,
    tray: &ksni::blocking::Handle<VpnTray>,
    action_tx: &crate::tray::ActionSender,
    config_path: String,
    config_name: String,
    delay: u32,
) {
    info!(
        "Unexpected session drop for '{}', auto-reconnect in {}s",
        config_name, delay
    );
    let dbus = dbus.clone();
    let tray = tray.clone();
    let action_tx = action_tx.clone();
    glib::spawn_future_local(async move {
        glib::timeout_future_seconds(delay).await;
        let settings = crate::settings::Settings::new();
        match super::session_ops::connect_to_config(&dbus, &config_path, &tray, &settings).await {
            Ok(()) => info!("Auto-reconnect succeeded for '{}'", config_name),
            Err(e) => {
                warn!(
                    "Auto-reconnect failed for '{}': {}; falling back to notification",
                    config_name, e
                );
                crate::dialogs::show_reconnect_notification(
                    config_path,
                    config_name,
                    action_tx,
                    tray,
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{KillSwitchTeardown, decide_kill_switch_teardown};

    const A: &str = "/net/openvpn/v3/sessions/aaaa";
    const B: &str = "/net/openvpn/v3/sessions/bbbb";

    // (path, is_connected, kill_switch_active)
    fn sess(path: &str, connected: bool, ks: bool) -> (String, bool, bool) {
        (path.to_string(), connected, ks)
    }

    #[test]
    fn auth_retry_always_skips_teardown() {
        // Even with no survivors, an auth-retry swap must leave the firewall up.
        let d = decide_kill_switch_teardown(A, true, vec![]);
        assert_eq!(d, KillSwitchTeardown::Skip);
    }

    #[test]
    fn last_protected_session_tears_down_fully() {
        // Only the destroyed session remains in the map (SessDestroyed races its
        // own tray removal) — no survivor, so full teardown.
        let d = decide_kill_switch_teardown(A, false, vec![sess(A, true, true)]);
        assert_eq!(d, KillSwitchTeardown::Full);
    }

    #[test]
    fn no_sessions_left_tears_down_fully() {
        let d = decide_kill_switch_teardown(A, false, vec![]);
        assert_eq!(d, KillSwitchTeardown::Full);
    }

    #[test]
    fn surviving_protected_session_triggers_rebind() {
        // H2 core: disconnect A while B is connected + kill-switch-active → keep
        // the firewall up and rebind the global table to B, never a blanket wipe.
        let d =
            decide_kill_switch_teardown(A, false, vec![sess(A, false, true), sess(B, true, true)]);
        assert_eq!(
            d,
            KillSwitchTeardown::RebindTo {
                session_path: B.to_string()
            }
        );
    }

    #[test]
    fn survivor_without_kill_switch_does_not_block_teardown() {
        // B is connected but was never kill-switch-protected — nothing to
        // preserve, so tearing down is correct.
        let d = decide_kill_switch_teardown(A, false, vec![sess(B, true, false)]);
        assert_eq!(d, KillSwitchTeardown::Full);
    }

    #[test]
    fn disconnected_protected_survivor_does_not_block_teardown() {
        // B carries a stale kill_switch_active flag but is no longer connected —
        // it can't keep the firewall meaningful, so full teardown.
        let d = decide_kill_switch_teardown(A, false, vec![sess(B, false, true)]);
        assert_eq!(d, KillSwitchTeardown::Full);
    }

    #[test]
    fn auth_retry_wins_even_with_protected_survivor() {
        // Skip takes precedence over Rebind: an auth-retry swap must not touch
        // the firewall at all, regardless of survivors.
        let d = decide_kill_switch_teardown(A, true, vec![sess(B, true, true)]);
        assert_eq!(d, KillSwitchTeardown::Skip);
    }
}
