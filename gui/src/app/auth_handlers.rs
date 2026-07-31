//! Authentication and input-request dispatch for StatusChange signals.
//!
//! Centralises the "session needs user input" branches (user-input query,
//! credentials, URL/browser auth) so the main status stream stays readable.
//! Challenge/OTP is now handled by the credentials dialog (always shows 3
//! fields) rather than a separate single-field dialog.
//!
//! The only pure surface is [`classify_auth_uri`], which gates the
//! server-controlled browser-auth URI before it reaches the default handler;
//! the dispatch fns themselves are async with no branching logic to unit test.

use tracing::{info, warn};

use crate::dbus::types::SessionStatus;
use crate::tray::VpnTray;

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

fn handle_user_input_required(
    conn: &zbus::Connection,
    tray: &ksni::blocking::Handle<VpnTray>,
    path: &str,
) {
    info!("Server requires user input for {}", path);
    let session_path = path.to_string();
    let dbus_conn = conn.clone();
    let (config_name, config_path) = crate::tray::session_config_identity(tray, path);
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
    let (config_name, config_path) = crate::tray::session_config_identity(tray, path);
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

/// Outcome of validating the server-supplied browser-authentication URI.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum AuthUriVerdict {
    /// No URI supplied — show the generic "finish in your browser" prompt.
    Empty,
    /// An `http`/`https` URI, safe to hand to the default handler.
    Launchable,
    /// Anything else — render as inert text, never launch.
    Blocked,
}

/// Classify the server-controlled "URL" `StatusChange` message.
///
/// The VPN server controls this string, so launching it unconditionally would
/// let a malicious server make the client's `xdg-open` execute `file://`,
/// `javascript:`, or a custom-handler URI. Only `http`/`https` reach the
/// default handler; everything else (including a scheme-less string) is
/// treated as untrusted text.
pub(super) fn classify_auth_uri(message: &str) -> AuthUriVerdict {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return AuthUriVerdict::Empty;
    }
    match glib::Uri::peek_scheme(trimmed) {
        Some(scheme) if matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") => {
            AuthUriVerdict::Launchable
        }
        _ => AuthUriVerdict::Blocked,
    }
}

fn handle_url_auth_required(tray: &ksni::blocking::Handle<VpnTray>, path: &str, message: &str) {
    info!("Session requires browser authentication");
    let url = message.trim().to_string();
    let (config_name, _config_path) = crate::tray::session_config_identity(tray, path);
    let verdict = classify_auth_uri(&url);
    let notif_body = match verdict {
        AuthUriVerdict::Empty => "Please complete authentication in your browser.".to_string(),
        AuthUriVerdict::Launchable => format!("Opening browser for authentication:\n{}", url),
        // Show the address so the user can act on it, but as inert text only.
        AuthUriVerdict::Blocked => format!(
            "The VPN server sent an authentication address that is not a web link, so it was not opened:\n{}",
            url
        ),
    };
    crate::dialogs::show_info_notification(
        &format!("{}: Browser Authentication Required", config_name),
        &notif_body,
    );
    match verdict {
        AuthUriVerdict::Launchable => {
            if let Err(e) =
                gio::AppInfo::launch_default_for_uri(&url, None::<&gio::AppLaunchContext>)
            {
                warn!("Failed to open auth URL in browser: {}", e);
            }
        }
        // `escape_debug` keeps a newline-bearing server string from forging log lines.
        AuthUriVerdict::Blocked => warn!(
            "Refusing to launch non-http(s) auth URI for {}: {}",
            path,
            url.escape_debug()
        ),
        AuthUriVerdict::Empty => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthUriVerdict, classify_auth_uri};

    #[test]
    fn auth_uri_allows_http_and_https() {
        assert_eq!(
            classify_auth_uri("https://vpn.example.com/auth?token=abc"),
            AuthUriVerdict::Launchable
        );
        assert_eq!(
            classify_auth_uri("http://vpn.example.com/auth"),
            AuthUriVerdict::Launchable
        );
        // Scheme comparison is case-insensitive per RFC 3986.
        assert_eq!(
            classify_auth_uri("HTTPS://vpn.example.com/auth"),
            AuthUriVerdict::Launchable
        );
        // Surrounding whitespace from the D-Bus message must not defeat the check.
        assert_eq!(
            classify_auth_uri("  https://vpn.example.com/auth\n"),
            AuthUriVerdict::Launchable
        );
    }

    #[test]
    fn auth_uri_blocks_dangerous_schemes() {
        for hostile in [
            "file:///etc/passwd",
            "file://~/.ssh/id_rsa",
            "javascript:alert(1)",
            "JavaScript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "smb://attacker/share",
            "ms-msdt:/id",
            "vnc://attacker:5900",
            "ssh://attacker",
            // Scheme-less strings would be resolved as a relative path.
            "vpn.example.com/auth",
            "/etc/passwd",
        ] {
            assert_eq!(
                classify_auth_uri(hostile),
                AuthUriVerdict::Blocked,
                "{hostile} must not be launched"
            );
        }
    }

    #[test]
    fn auth_uri_empty_message_is_generic_prompt() {
        assert_eq!(classify_auth_uri(""), AuthUriVerdict::Empty);
        assert_eq!(classify_auth_uri("   \n"), AuthUriVerdict::Empty);
    }
}
