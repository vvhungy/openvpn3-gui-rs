//! Core transport + simple fire-and-forget notifications.
//!
//! `send_notify` is the low-level shim around
//! `org.freedesktop.Notifications.Notify` (one call, one reply). The
//! `send_dbus_notification` and `send_state_notification` wrappers sit on top of
//! it, sharing the [`next_retry_id`] policy: a stale `replaces_id` retries once
//! as a fresh toast, a deserialize failure is terminal.

use std::collections::HashMap;

use tracing::warn;

use super::dedup::{self, NOTIFICATION_IDS};
use crate::settings::Settings;

/// Which stage of a `send_notify` attempt failed. The distinction drives the
/// retry policy: a failed Notify *call* with a stale `replaces_id` is
/// retryable (fall back to a fresh toast), but a reply that arrived and then
/// failed to deserialize is **terminal** — the daemon already displayed a
/// toast, so retrying would stack a duplicate on top of it (Finding A / S47-T1).
#[derive(Debug)]
pub(super) enum SendError {
    /// The `org.freedesktop.Notifications.Notify` call itself failed
    /// (transport error, or a stale `replaces_id` the daemon rejected).
    Call(anyhow::Error),
    /// The call returned a reply but its body did not deserialize to a `u32`.
    /// Terminal: the notification was already shown.
    Deserialize(anyhow::Error),
}

impl From<SendError> for anyhow::Error {
    fn from(e: SendError) -> Self {
        match e {
            SendError::Call(e) | SendError::Deserialize(e) => e,
        }
    }
}

/// Shared retry policy for both send wrappers (`send_dbus_notification` and
/// `send_state_notification`) — pure, so it is unit-testable without a live
/// D-Bus session (S47-T4). Given the failure and the
/// `replaces_id` that was used, returns `Some(new_id)` to retry with that id,
/// or `None` to stop (terminal).
///
/// The only retryable case is a failed Notify *call* whose `replaces_id` was
/// non-zero (the stale-id case): retry once as a brand-new toast (`0`). A
/// deserialize failure is always terminal — the toast was already displayed,
/// so a retry would duplicate it. A call failure that already used a fresh id
/// (`replaces_id == 0`) has nothing left to fall back to.
pub(super) fn next_retry_id(err: &SendError, replaces_id: u32) -> Option<u32> {
    match err {
        SendError::Call(_) if replaces_id != 0 => Some(0),
        _ => None,
    }
}

/// Resolve the `replaces_id` to send for a dedup key: the id last stored under
/// `key` (so the new toast replaces it), or `0` for a brand-new toast when the
/// key has no entry. Pure over an injected map so the dedup routing is
/// unit-testable without the `NOTIFICATION_IDS` global (S47-T5).
pub(super) fn resolve_replaces_id(map: &HashMap<String, u32>, key: &str) -> u32 {
    *map.get(key).unwrap_or(&0)
}

/// Send one `org.freedesktop.Notifications.Notify` call and return the
/// daemon-assigned id. Shared transport primitive — every notification path
/// routes through here (the fire-and-forget retry wrapper below, the kill-switch
/// state toasts, and the interactive action-button loop), so the Notify
/// tuple construction lives in exactly one place. `actions` is empty for
/// non-interactive toasts; `replaces_id`/`expire_timeout` are caller-controlled.
///
/// The two failure stages are kept distinct in [`SendError`] so the retry
/// wrapper can tell a retryable call failure from a terminal deserialize
/// failure; direct callers that don't retry just `?` it into `anyhow::Error`.
// 8 args mirror the org.freedesktop.Notifications.Notify signature 1:1;
// grouping into a struct would just re-spread these fields at every call site.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_notify(
    conn: &zbus::Connection,
    icon: &str,
    summary: &str,
    body: &str,
    actions: &[&str],
    urgency: u8,
    replaces_id: u32,
    expire_timeout: i32,
) -> Result<u32, SendError> {
    let hints: HashMap<&str, zbus::zvariant::Value<'_>> =
        HashMap::from([("urgency", zbus::zvariant::Value::U8(urgency))]);
    let reply = conn
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &(
                "openvpn3-gui-rs",
                replaces_id,
                icon,
                summary,
                body,
                actions,
                &hints,
                expire_timeout,
            ),
        )
        .await
        .map_err(|e| SendError::Call(e.into()))?;
    reply
        .body()
        .deserialize()
        .map_err(|e| SendError::Deserialize(e.into()))
}

/// Send a notification, optionally replacing an existing one.
/// Returns the notification ID assigned by the daemon.
/// If `replaces_id` is stale (notification already reaped), falls back to
/// a fresh notification silently. Fire-and-forget toasts use the fixed
/// `network-vpn` icon, no actions, and the daemon-default expiry (-1).
pub(super) async fn send_dbus_notification(
    summary: &str,
    body: &str,
    urgency: u8,
    replaces_id: u32,
) -> anyhow::Result<u32> {
    let conn = zbus::Connection::session().await?;
    let mut rid = replaces_id;
    loop {
        match send_notify(&conn, "network-vpn", summary, body, &[], urgency, rid, -1).await {
            Ok(id) => return Ok(id),
            Err(e) => match next_retry_id(&e, rid) {
                Some(new_rid) => {
                    rid = new_rid;
                    continue;
                }
                None => return Err(e.into()),
            },
        }
    }
}

/// Send a state-transition toast keyed on `dedup_key`, sharing the retry
/// policy with the fire-and-forget wrapper. State toasts (kill-switch
/// active/inactive, bypass apply/drift/recovered) all replace a prior toast via
/// the id stored under `dedup_key`; when that id is stale ([`next_retry_id`]
/// returns `Some(0)`) this retries once as a fresh toast rather than dropping
/// the notification — closing the `NOTIFICATION_IDS` TOCTOU where a reaped
/// `replaces_id` made the send error and the state change went unsignalled
/// (Finding C / S47-T3). On success the freshly assigned id is stored back
/// under `dedup_key` for the next replace. `conn` is caller-owned so the
/// kill-switch and bypass paths keep their own session connections.
pub(super) async fn send_state_notification(
    conn: &zbus::Connection,
    dedup_key: &str,
    icon: &str,
    summary: &str,
    body: &str,
    urgency: u8,
    expire_timeout: i32,
) -> anyhow::Result<u32> {
    let mut rid = NOTIFICATION_IDS
        .lock()
        .map(|m| resolve_replaces_id(&m, dedup_key))
        .unwrap_or(0);
    let new_id = loop {
        match send_notify(conn, icon, summary, body, &[], urgency, rid, expire_timeout).await {
            Ok(id) => break id,
            Err(e) => match next_retry_id(&e, rid) {
                Some(new_rid) => {
                    rid = new_rid;
                    continue;
                }
                None => return Err(e.into()),
            },
        }
    };
    dedup::record(dedup_key, new_id);
    Ok(new_id)
}

/// Fire-and-forget notification, deduped on `summary`. A second call with the
/// same summary replaces the prior toast instead of stacking. The dedup key is
/// the summary (the title) because info/error toasts are categorized by title
/// (e.g. "Import Failed", "Clear Credentials Failed"); repeated failures of the
/// same kind should coalesce, not pile up. Per CLAUDE.md every notification
/// must route through the `NOTIFICATION_IDS` dedup map — these generic toasts
/// previously bypassed it.
pub(super) fn send_notification(summary: &str, body: &str, urgency: u8) {
    let summary = summary.to_string();
    let body = body.to_string();
    let key = summary.clone();
    let replaces_id = NOTIFICATION_IDS
        .lock()
        .map(|m| *m.get(&key).unwrap_or(&0))
        .unwrap_or(0);
    glib::spawn_future_local(async move {
        match send_dbus_notification(&summary, &body, urgency, replaces_id).await {
            Ok(new_id) => {
                dedup::record(&key, new_id);
            }
            Err(e) => warn!("Failed to send notification: {}", e),
        }
    });
}

/// Show an info notification (suppressed when show_notifications is off)
pub fn show_info_notification(title: &str, message: &str) {
    if !Settings::new().show_notifications() {
        return;
    }
    send_notification(title, message, 1);
}

/// Show an error notification (always shown regardless of show_notifications)
pub fn show_error_notification(title: &str, message: &str) {
    send_notification(title, message, 2);
}

/// Show a connection status notification, replacing any previous toast for this
/// config so rapid status transitions don't stack separate notifications.
/// Suppressed when show_notifications is off.
pub fn show_connection_notification(config_name: &str, status: &str) {
    if !Settings::new().show_notifications() {
        return;
    }
    let title = format!("VPN: {}", config_name);
    let status = status.to_string();
    let key = config_name.to_string();
    let replaces_id = NOTIFICATION_IDS
        .lock()
        .map(|m| *m.get(&key).unwrap_or(&0))
        .unwrap_or(0);
    glib::spawn_future_local(async move {
        match send_dbus_notification(&title, &status, 1, replaces_id).await {
            Ok(new_id) => {
                dedup::record(&key, new_id);
            }
            Err(e) => warn!("Failed to send notification: {}", e),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- T4: retry policy (next_retry_id) — all three arms ----

    #[test]
    fn call_failure_with_stale_id_retries_fresh() {
        // Stale replaces_id: the Notify *call* failed with a non-zero id.
        // Retry once as a brand-new toast (0).
        let err = SendError::Call(anyhow::anyhow!("stale replaces_id"));
        assert_eq!(next_retry_id(&err, 42), Some(0));
    }

    #[test]
    fn call_failure_with_fresh_id_is_terminal() {
        // Already used a fresh id — nothing left to fall back to.
        let err = SendError::Call(anyhow::anyhow!("transport error"));
        assert_eq!(next_retry_id(&err, 0), None);
    }

    #[test]
    fn deserialize_failure_is_always_terminal() {
        // Finding A: a reply arrived and the daemon already showed a toast.
        // Retrying would duplicate it — terminal regardless of replaces_id.
        let err = SendError::Deserialize(anyhow::anyhow!("bad body"));
        assert_eq!(next_retry_id(&err, 99), None);
        assert_eq!(next_retry_id(&err, 0), None);
    }

    // ---- T5: dedup routing (resolve_replaces_id) — hermetic, injected map ----

    #[test]
    fn matching_key_reuses_stored_id() {
        // A stored id under the key → replace that toast.
        let mut map = HashMap::new();
        map.insert("__killswitch_state__".to_string(), 7u32);
        assert_eq!(resolve_replaces_id(&map, "__killswitch_state__"), 7);
    }

    #[test]
    fn no_match_uses_fresh_zero() {
        // No entry → brand-new toast (0).
        let map: HashMap<String, u32> = HashMap::new();
        assert_eq!(resolve_replaces_id(&map, "__bypass_state__"), 0);
    }

    #[test]
    fn stale_id_send_falls_back_fresh() {
        // The TOCTOU (Finding C): the map still holds an id (resolve returns it),
        // but the daemon reaped it — the send fails with a Call error and the
        // retry policy falls back to a fresh toast rather than dropping it.
        let mut map = HashMap::new();
        map.insert("__bypass_state__".to_string(), 5u32);
        let rid = resolve_replaces_id(&map, "__bypass_state__");
        assert_eq!(rid, 5);
        let err = SendError::Call(anyhow::anyhow!("id 5 was reaped"));
        assert_eq!(next_retry_id(&err, rid), Some(0));
    }
}
