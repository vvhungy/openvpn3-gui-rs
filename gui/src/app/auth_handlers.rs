//! Authentication and input-request dispatch for StatusChange signals.
//!
//! Centralises the "session needs user input" branches (user-input query,
//! credentials, URL/browser auth) so the main status stream stays readable.
//! Challenge/OTP is now handled by the credentials dialog (always shows 3
//! fields) rather than a separate single-field dialog.
//!
//! No testable pure surface — async dispatch with no branching logic to unit test.

use tracing::{info, warn};

use crate::dbus::types::SessionStatus;
use crate::tray::VpnTray;

const FALLBACK_NAME: &str = "VPN Connection";

/// Returns `true` if `status` requested auth/input and the corresponding
/// handler was dispatched. Callers should `continue` the signal loop.
pub(super) fn try_handle_auth(
    conn: &zbus::Connection,
    tray: &ksni::blocking::Handle<VpnTray>,
    status: &SessionStatus,
    path: &str,
    message: &str,
) -> bool {
    if status.needs_user_input() {
        handle_user_input_required(conn, tray, path);
        return true;
    }
    if status.needs_credentials() {
        handle_credentials_required(conn, tray, path);
        return true;
    }
    if status.needs_url_auth() {
        handle_url_auth_required(tray, path, message);
        return true;
    }
    if status.needs_challenge() {
        // Challenge/OTP is now routed through credentials dialog (always 3 fields)
        handle_credentials_required(conn, tray, path);
        return true;
    }
    false
}

/// Resolve a session's config identity. Returns the **display name** (for the
/// dialog label) and the **unique config D-Bus path** (the keyring key — #2
/// fix: keyed by path, not name, since two configs may share a name and would
/// cross-wipe).
///
/// Both fall back to sentinels on a tray miss; the credential store treats a
/// sentinel path as "no pre-fill / no migration" rather than a real query.
fn lookup_config_identity(tray: &ksni::blocking::Handle<VpnTray>, path: &str) -> (String, String) {
    tray.update(|t| {
        t.sessions
            .get(path)
            .map(|s| (s.config_name.clone(), s.config_path.clone()))
    })
    .flatten()
    .unwrap_or_else(|| (FALLBACK_NAME.to_string(), String::new()))
}

fn handle_user_input_required(
    conn: &zbus::Connection,
    tray: &ksni::blocking::Handle<VpnTray>,
    path: &str,
) {
    info!("Server requires user input for {}", path);
    let session_path = path.to_string();
    let dbus_conn = conn.clone();
    let (config_name, config_path) = lookup_config_identity(tray, path);
    glib::spawn_future_local(async move {
        match super::auth_dispatch::dispatch_for_session(&dbus_conn, &session_path).await {
            Some(super::auth_dispatch::AuthDispatch::Credentials) => {
                super::credential_handler::request_credentials(
                    &dbus_conn,
                    &session_path,
                    &config_path,
                    &config_name,
                    Default::default(),
                )
                .await;
            }
            None => {
                warn!("No input slots found for {}", session_path);
            }
        }
    });
}

fn handle_credentials_required(
    conn: &zbus::Connection,
    tray: &ksni::blocking::Handle<VpnTray>,
    path: &str,
) {
    info!("Session requires credentials (username/password)");
    let session_path = path.to_string();
    let dbus_conn = conn.clone();
    let (config_name, config_path) = lookup_config_identity(tray, path);
    glib::spawn_future_local(async move {
        super::credential_handler::request_credentials(
            &dbus_conn,
            &session_path,
            &config_path,
            &config_name,
            Default::default(),
        )
        .await;
    });
}

fn handle_url_auth_required(tray: &ksni::blocking::Handle<VpnTray>, path: &str, message: &str) {
    info!("Session requires browser authentication");
    let url = message.to_string();
    let (config_name, _config_path) = lookup_config_identity(tray, path);
    let notif_body = if url.is_empty() {
        "Please complete authentication in your browser.".to_string()
    } else {
        format!("Opening browser for authentication:\n{}", url)
    };
    crate::dialogs::show_info_notification(
        &format!("{}: Browser Authentication Required", config_name),
        &notif_body,
    );
    if !url.is_empty()
        && let Err(e) = gio::AppInfo::launch_default_for_uri(&url, None::<&gio::AppLaunchContext>)
    {
        warn!("Failed to open auth URL in browser: {}", e);
    }
}
