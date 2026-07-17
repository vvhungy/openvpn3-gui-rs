//! StatusChange signal loop
//!
//! Subscribes to per-session `StatusChange` signals from OpenVPN3 backends
//! and dispatches each status transition to the appropriate handler.
//!
//! The signal loop itself is async D-Bus with no unit surface, but the pure
//! transition logic (`apply_status_transition`) is extracted and tested below.

use futures::StreamExt;
use tracing::{info, warn};

use crate::dbus::types::SessionStatus;
use crate::tray::{SessionInfo, VpnTray};
use handlers::{
    ErrorAction, backfill_session_identity, classify_error, clear_credential_attempts_on_connect,
    handle_auth_failed, handle_conn_failed, handle_session_error, schedule_disconnected_removal,
    send_status_notification, upsert_session_state,
};

mod handlers;
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
                    let inserted_new =
                        upsert_session_state(&tray_for_status, &path, status.clone());

                    // H4: if Connected won the race over SessionCreated, the
                    // newly-inserted entry has an empty config_path and a later
                    // unexpected drop would be silently swallowed (both the
                    // reconnect branch and the RECENT_DESTROYED_SESSIONS cache
                    // gate on !config_path.is_empty()). Backfill the real
                    // identity from the live session proxy while it's still up.
                    if inserted_new && status.is_connected() {
                        let conn_bf = conn.clone();
                        let tray_bf = tray_for_status.clone();
                        let path_bf = path.clone();
                        glib::spawn_future_local(async move {
                            backfill_session_identity(&conn_bf, &tray_bf, &path_bf).await;
                        });
                    }

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
}
