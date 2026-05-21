//! D-Bus initialization — fetch configs/sessions and populate the tray on startup

use std::collections::HashMap;

use tracing::{debug, error, info, warn};

use zbus::proxy::CacheProperties;

use super::bypass_apply::apply_bypass_outcome_to_tray;
use crate::config::{MANAGER_VERSION_MINIMUM, MANAGER_VERSION_RECOMMENDED, MIN_HELPER_VERSION};
use crate::dbus::{
    configuration::{ConfigurationManagerProxy, ConfigurationProxy},
    session::{SessionManagerProxy, SessionProxy},
    types::SessionStatus,
};
use crate::settings::Settings;
use crate::tray::{ConfigInfo, SessionInfo, VpnTray};

/// Initialize D-Bus: fetch configs/sessions, populate tray
pub(crate) async fn init_dbus(
    dbus: &zbus::Connection,
    settings: &Settings,
    tray: &ksni::blocking::Handle<VpnTray>,
) -> anyhow::Result<()> {
    let config_manager = ConfigurationManagerProxy::builder(dbus)
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    let session_manager = SessionManagerProxy::builder(dbus)
        .cache_properties(CacheProperties::No)
        .build()
        .await?;

    // Detect manager version
    let manager_version = parse_manager_version(config_manager.version().await.ok());

    if manager_version < MANAGER_VERSION_MINIMUM {
        error!(
            "Unsupported OpenVPN3 version: {}. Minimum: {}",
            manager_version, MANAGER_VERSION_MINIMUM
        );
    } else if manager_version < MANAGER_VERSION_RECOMMENDED {
        warn!(
            "OpenVPN3 version {} below recommended {}",
            manager_version, MANAGER_VERSION_RECOMMENDED
        );
    }

    // Probe the kill-switch helper's Version property. Informational only —
    // a mismatch logs a warning, never blocks startup or any kill-switch
    // call. Helper not present is a normal state (package not installed).
    match crate::dbus::killswitch::probe_version().await {
        Some(helper_version) => {
            if helper_version_below_min(&helper_version, MIN_HELPER_VERSION) {
                warn!(
                    "kill-switch helper version {} is below minimum supported {} \
                     — consider upgrading the openvpn3-killswitch-helper package",
                    helper_version, MIN_HELPER_VERSION
                );
            } else {
                info!("kill-switch helper version: {}", helper_version);
            }
        }
        None => debug!("kill-switch helper not present (skipping version probe)"),
    }

    // Fetch configurations — config manager may not be running yet at startup
    let config_paths = match config_manager.FetchAvailableConfigs().await {
        Ok(paths) => paths,
        Err(e) => {
            // Return Err so the caller can retry
            return Err(anyhow::anyhow!("Config manager unavailable: {}", e));
        }
    };
    info!("Found {} configurations", config_paths.len());

    let mut configs = Vec::new();
    for path in &config_paths {
        info!("Fetching config at path: {}", path);
        match ConfigurationProxy::builder(dbus)
            .path(path.clone())?
            .build()
            .await
        {
            Ok(config) => match config.name().await {
                Ok(name) => {
                    info!("Config: {} -> {}", path, name);
                    configs.push(ConfigInfo {
                        path: path.as_str().to_string(),
                        name,
                    });
                }
                Err(e) => warn!("Failed to get config name for {}: {}", path, e),
            },
            Err(e) => warn!("Failed to build config proxy for {}: {}", path, e),
        }
    }

    // Fetch sessions — session manager may not be running when no sessions are active
    let session_paths = match session_manager.FetchAvailableSessions().await {
        Ok(paths) => paths,
        Err(e) => {
            warn!("Session manager unavailable (no active sessions?): {}", e);
            vec![]
        }
    };
    info!("Found {} sessions", session_paths.len());

    let mut sessions = HashMap::new();
    let mut connected_paths: Vec<String> = Vec::new();
    // Cold-start auth dispatch: sessions already in a "needs input" state
    // when the GUI starts won't re-emit StatusChange, so collect them here
    // and dispatch after tray.update so config_name lookups succeed.
    let mut pending_auth: Vec<(String, SessionStatus, String)> = Vec::new();
    for path in &session_paths {
        match SessionProxy::builder(dbus)
            .path(path.clone())?
            .build()
            .await
        {
            Ok(session) => {
                let (major, minor, message) =
                    session.status().await.unwrap_or((0, 0, String::new()));
                let config_name = session
                    .config_name()
                    .await
                    .unwrap_or_else(|_| "VPN".to_string());
                let config_path = session
                    .config_path()
                    .await
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default();

                info!(
                    "Session: {} -> {} (status: {}/{})",
                    path, config_name, major, minor
                );

                // Enable log/status forwarding so we receive StatusChange signals
                if let Err(e) = session.LogForward(true).await {
                    debug!("LogForward for {}: {}", path, e);
                }

                let status = SessionStatus::new(major, minor, message.clone());
                if status.is_connected() {
                    connected_paths.push(path.as_str().to_string());
                }
                if status.needs_user_input()
                    || status.needs_credentials()
                    || status.needs_url_auth()
                    || status.needs_challenge()
                {
                    pending_auth.push((path.as_str().to_string(), status.clone(), message));
                }
                sessions.insert(
                    path.as_str().to_string(),
                    SessionInfo {
                        session_path: path.as_str().to_string(),
                        config_path,
                        config_name,
                        status,
                        connected_at: None,
                        bytes_in: 0,
                        bytes_out: 0,
                        last_bytes_in: 0,
                        last_bytes_out: 0,
                        idle_since: None,
                        kill_switch_active: false,
                    },
                );
            }
            Err(e) => warn!("Failed to build session proxy for {}: {}", path, e),
        }
    }

    // Update tray with initial state
    tray.update(move |t| {
        t.configs = configs;
        t.sessions = sessions;
    });

    info!(
        "Tray updated with {} configs, initial state set",
        config_paths.len()
    );

    // Cold-start auth: replay missed StatusChange dispatch for sessions that
    // were already waiting on user input when the GUI started. Without this,
    // a session in "Authentication required" at app launch never gets its
    // credentials/challenge dialog.
    for (path, status, message) in pending_auth {
        info!("Cold-start: dispatching auth handler for session {}", path);
        super::auth_handlers::try_handle_auth(dbus, tray, &status, &path, &message);
    }

    // Re-apply bypass + kill-switch state for sessions that were already
    // connected before this GUI instance started (e.g., after a GUI restart).
    // The helper's watcher cleaned the rules when the previous instance exited.
    //
    // ORDER MATTERS: bypass must land at the helper before `AddRules`. The
    // helper snapshots `state.bypass_cidrs` inside `AddRules` and bakes it
    // into the nft script (bypass accept rules + MSS clamp). Two independent
    // spawns would race — if KS won, the firewall would drop bypassed
    // traffic until the next manual reconnect.
    let has_connected = !connected_paths.is_empty();
    let bypass_cidrs =
        crate::settings::enabled_cidrs(&settings.bypass_cidrs(), &settings.bypass_cidrs_disabled());
    let ks_enabled = settings.enable_kill_switch();
    if has_connected && (ks_enabled || !bypass_cidrs.is_empty()) {
        let allow_lan = settings.kill_switch_allow_lan();
        let dbus_clone = dbus.clone();
        let tray_clone = tray.clone();
        glib::spawn_future_local(async move {
            if !bypass_cidrs.is_empty() {
                let set_ok = crate::dbus::killswitch::set_bypass_cidrs(bypass_cidrs).await;
                let outcome = if set_ok {
                    crate::dbus::killswitch::apply_bypass_routes().await
                } else {
                    None
                };
                apply_bypass_outcome_to_tray(&tray_clone, outcome, "startup re-apply");
            }

            if ks_enabled {
                for path in connected_paths {
                    match super::status_handler::apply_kill_switch(&dbus_clone, &path, allow_lan)
                        .await
                    {
                        Ok(true) => {
                            let p = path.clone();
                            tray_clone.update(move |t| {
                                if let Some(s) = t.sessions.get_mut(&p) {
                                    s.kill_switch_active = true;
                                }
                            });
                            crate::dialogs::show_killswitch_active_notification();
                        }
                        Ok(false) => {}
                        Err(e) => {
                            warn!("kill-switch: startup re-apply failed for {}: {}", path, e);
                            crate::dialogs::show_error_notification(
                                "Kill-Switch Re-Apply Failed",
                                &format!(
                                    "Firewall rules could not be re-applied after restart: {}",
                                    e
                                ),
                            );
                        }
                    }
                }
            }
        });
    }

    // Auto-connect on startup based on GSettings preference
    handle_startup_connect(settings, dbus, tray).await;

    Ok(())
}

/// Trigger auto-connect after tray is populated
async fn handle_startup_connect(
    settings: &Settings,
    dbus: &zbus::Connection,
    tray: &ksni::blocking::Handle<VpnTray>,
) {
    let action = settings.startup_action();
    match action.as_str() {
        "connect-recent" => {
            let (path, name) = settings.get_most_recent_config();
            if path.is_empty() {
                info!("Startup auto-connect: no recent config saved");
                return;
            }
            startup_connect(dbus, tray, settings, &path, &name).await;
        }
        "connect-specific" => {
            let path = settings.specific_config_path();
            if path.is_empty() {
                info!("Startup auto-connect: no specific config configured");
                return;
            }
            // Resolve a display name from the loaded config list
            let name = tray
                .update(|t| {
                    t.configs
                        .iter()
                        .find(|c| c.path == path)
                        .map(|c| c.name.clone())
                })
                .flatten()
                .unwrap_or_else(|| path.clone());
            startup_connect(dbus, tray, settings, &path, &name).await;
        }
        _ => {} // "none" or unknown — do nothing
    }
}

async fn startup_connect(
    dbus: &zbus::Connection,
    tray: &ksni::blocking::Handle<VpnTray>,
    settings: &Settings,
    path: &str,
    name: &str,
) {
    let exists = tray
        .update(|t| t.configs.iter().any(|c| c.path == path))
        .unwrap_or(false);
    if !exists {
        warn!(
            "Startup auto-connect: saved config path not found: {}",
            path
        );
        return;
    }
    info!("Startup auto-connect: connecting to '{}'", name);
    if let Err(e) = super::session_ops::connect_to_config(dbus, path, tray, settings).await {
        error!("Startup auto-connect failed: {}", e);
        crate::dialogs::show_error_notification(
            "Connection Failed",
            &format!("Could not connect to '{}': {}", name, e),
        );
    }
}

/// True if `version` (semver string) compares as less than `minimum`.
/// Non-numeric tails on each component are stripped — `"1.2.3-beta"`
/// parses as `(1, 2, 3)`. Missing components default to 0.
fn helper_version_below_min(version: &str, minimum: &str) -> bool {
    parse_semver(version) < parse_semver(minimum)
}

fn parse_semver(s: &str) -> (u32, u32, u32) {
    let mut parts = s.split('.').map(|p| {
        p.chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse::<u32>()
            .unwrap_or(0)
    });
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    let patch = parts.next().unwrap_or(0);
    (major, minor, patch)
}

/// Parse the OpenVPN3 manager version string into a comparable number.
///
/// - `"git:..."` → 9999 (dev build, assume latest)
/// - `"vNN..."`  → leading digits parsed as u32
/// - other/None  → 0
fn parse_manager_version(version: Option<String>) -> u32 {
    let Some(version_str) = version else { return 0 };
    debug!("Manager version: {}", version_str);
    if version_str.starts_with("git:") {
        9999
    } else if let Some(stripped) = version_str.strip_prefix('v') {
        stripped
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse::<u32>()
            .unwrap_or(0)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_none() {
        assert_eq!(parse_manager_version(None), 0);
    }

    #[test]
    fn test_parse_version_v_prefix() {
        assert_eq!(parse_manager_version(Some("v18".into())), 18);
    }

    #[test]
    fn test_parse_version_v_prefix_with_suffix() {
        assert_eq!(parse_manager_version(Some("v18.2".into())), 18);
    }

    #[test]
    fn test_parse_version_git() {
        assert_eq!(parse_manager_version(Some("git:abc123".into())), 9999);
    }

    #[test]
    fn test_parse_version_bare_number() {
        assert_eq!(parse_manager_version(Some("42".into())), 0);
    }

    #[test]
    fn test_parse_version_empty_string() {
        assert_eq!(parse_manager_version(Some(String::new())), 0);
    }

    #[test]
    fn semver_basic() {
        assert_eq!(parse_semver("0.1.0"), (0, 1, 0));
        assert_eq!(parse_semver("1.2.3"), (1, 2, 3));
        assert_eq!(parse_semver("10.20.30"), (10, 20, 30));
    }

    #[test]
    fn semver_partial_components_default_to_zero() {
        assert_eq!(parse_semver("1"), (1, 0, 0));
        assert_eq!(parse_semver("1.2"), (1, 2, 0));
        assert_eq!(parse_semver(""), (0, 0, 0));
    }

    #[test]
    fn semver_strips_non_numeric_suffix() {
        assert_eq!(parse_semver("1.2.3-beta"), (1, 2, 3));
        assert_eq!(parse_semver("1.2.3+build42"), (1, 2, 3));
    }

    #[test]
    fn semver_below_min_compares_correctly() {
        assert!(helper_version_below_min("0.0.9", "0.1.0"));
        assert!(!helper_version_below_min("0.1.0", "0.1.0"));
        assert!(!helper_version_below_min("1.0.0", "0.1.0"));
        assert!(helper_version_below_min("0.1.0", "0.2.0"));
        assert!(!helper_version_below_min("0.2.0", "0.2.0"));
    }
}
