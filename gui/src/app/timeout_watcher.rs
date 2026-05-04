//! 60-second connection timeout watcher.
//!
//! When a session enters the `Connecting` state, spawn a watcher that fires a
//! warning notification if the session is still connecting after the
//! user-configured timeout. A per-session generation counter ensures only the
//! latest watcher can fire — older watchers compare their stored generation
//! to the current value and bail out when superseded.
//!
//! No testable pure surface — `glib::spawn_future_local` + thread-local
//! generation map mutation. Generation-counter behaviour is covered by the
//! integration smoke test.

use std::cell::RefCell;
use std::collections::HashMap;

use tracing::info;

use crate::tray::VpnTray;

thread_local! {
    /// Per-session generation counter. Incremented every time a new watcher is
    /// spawned for a session; stored generation < current means a newer
    /// watcher has taken over and the old one must bail out.
    static TIMEOUT_GEN: RefCell<HashMap<String, u64>> = RefCell::new(HashMap::new());
}

/// Spawn a timeout watcher for a session entering the Connecting state.
pub(super) fn spawn_timeout_watcher(tray: &ksni::blocking::Handle<VpnTray>, path: String) {
    let expected_gen = TIMEOUT_GEN.with(|tg| {
        let mut tg = tg.borrow_mut();
        let entry = tg.entry(path.clone()).or_insert(0);
        *entry += 1;
        *entry
    });
    let tray_for_timeout = tray.clone();
    let timeout_secs = crate::settings::Settings::new().connection_timeout();
    glib::spawn_future_local(async move {
        glib::timeout_future_seconds(timeout_secs).await;
        let current_gen = TIMEOUT_GEN.with(|tg| tg.borrow().get(&path).copied());
        if current_gen != Some(expected_gen) {
            return;
        }
        let still_connecting = tray_for_timeout
            .update(|t| t.sessions.get(&path).map(|s| s.status.is_connecting()))
            .flatten()
            .unwrap_or(false);
        if still_connecting {
            let config_name = tray_for_timeout
                .update(|t| t.sessions.get(&path).map(|s| s.config_name.clone()))
                .flatten()
                .unwrap_or_else(|| "VPN".to_string());
            info!(
                "Connection timeout watcher: '{}' still connecting after {}s",
                config_name, timeout_secs
            );
            crate::dialogs::show_error_notification(
                &format!("{}: Still Connecting", config_name),
                &format!(
                    "Connection to '{}' is taking longer than expected. \
                     You can disconnect and try again.",
                    config_name
                ),
            );
        }
    });
}
