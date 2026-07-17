//! D-Bus initialization — fetch configs/sessions and populate the tray on startup

use std::collections::HashMap;

use tracing::{debug, error, info, warn};

use zbus::proxy::CacheProperties;

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
    log_manager_version_assessment(parse_manager_version(config_manager.version().await.ok()));

    // Configs, sessions, and the kill-switch-helper version probe are three
    // independent bus reads. The probe is informational only (feeds a log line,
    // never blocks) — run it concurrently so a slow or absent helper can't delay
    // startup-to-tray. try_join short-circuits on the first Err; the probe
    // returns Ok(()) unconditionally, so it can never abort the join, and if a
    // scan errors the probe is simply dropped (only a log line is lost).
    let (configs, initial_sessions, _helper_probe) = futures::future::try_join3(
        fetch_config_infos(&config_manager, dbus),
        scan_initial_sessions(&session_manager, dbus),
        async {
            probe_killswitch_helper_version().await;
            Ok(())
        },
    )
    .await?;
    let InitialSessions {
        sessions,
        connected_paths,
        pending_auth,
    } = initial_sessions;

    // Update tray with initial state
    let config_count = configs.len();
    tray.update(move |t| {
        t.configs = configs;
        t.sessions = sessions;
    });
    info!(
        "Tray updated with {} configs, initial state set",
        config_count
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
    reapply_firewall_on_startup(dbus, tray, settings, connected_paths).await;

    // Auto-connect on startup based on GSettings preference
    handle_startup_connect(settings, dbus, tray).await;

    Ok(())
}

/// Log whether the detected OpenVPN3 manager version is unsupported / below
/// recommended / ok (the ok tier is silent). Extracted from `init_dbus` so the
/// tier decision is named rather than three inline branches.
fn log_manager_version_assessment(manager_version: u32) {
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
}

/// Probe the kill-switch helper's Version property. Informational only —
/// a mismatch logs a warning, never blocks startup or any kill-switch
/// call. Helper not present is a normal state (package not installed).
async fn probe_killswitch_helper_version() {
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
}

/// Fetch all available VPN configurations and resolve their display names.
/// Returns `Err` if the config manager is unavailable so the caller can retry.
async fn fetch_config_infos(
    config_manager: &ConfigurationManagerProxy<'_>,
    dbus: &zbus::Connection,
) -> anyhow::Result<Vec<ConfigInfo>> {
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
    Ok(configs)
}

/// Cold-start scan output: the session map plus bookkeeping for already-connected
/// sessions (firewall re-apply) and sessions already waiting on user input
/// (cold-start auth dispatch).
struct InitialSessions {
    sessions: HashMap<String, SessionInfo>,
    connected_paths: Vec<String>,
    pending_auth: Vec<(String, SessionStatus, String)>,
}

/// Scan active sessions: enable log forwarding, build the tray session map, and
/// collect (a) connected paths for firewall re-apply and (b) sessions already
/// waiting on user input for cold-start auth dispatch. A missing session manager
/// (no active sessions) yields an empty scan, not an error.
async fn scan_initial_sessions(
    session_manager: &SessionManagerProxy<'_>,
    dbus: &zbus::Connection,
) -> anyhow::Result<InitialSessions> {
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
                let scanned = build_session_entry(&session, path).await;
                if let Some(p) = scanned.connected_path {
                    connected_paths.push(p);
                }
                if let Some(auth) = scanned.pending_auth {
                    pending_auth.push(auth);
                }
                sessions.insert(path.as_str().to_string(), scanned.entry);
            }
            Err(e) => warn!("Failed to build session proxy for {}: {}", path, e),
        }
    }
    Ok(InitialSessions {
        sessions,
        connected_paths,
        pending_auth,
    })
}

/// One session's cold-start scan result: the tray entry plus whether the
/// session is already connected (→ firewall re-apply) and/or waiting on user
/// input (→ cold-start auth dispatch). Extracted from `scan_initial_sessions`
/// so the session loop is a thin fold.
struct ScannedSession {
    entry: SessionInfo,
    connected_path: Option<String>,
    pending_auth: Option<(String, SessionStatus, String)>,
}

/// Build the tray entry for one session and flag connected / needs-input
/// state. The D-Bus reads and status predicates live here so the caller's
/// loop body is a thin fold.
async fn build_session_entry(session: &SessionProxy<'_>, path: &str) -> ScannedSession {
    // The three per-session reads are independent (status / config_name /
    // config_path); run them concurrently so N sessions cost N round-trips,
    // not 3N. Each falls back to its pre-existing default on D-Bus error.
    let ((major, minor, message), config_name, config_path) = futures::future::join3(
        async { session.status().await.unwrap_or((0, 0, String::new())) },
        async {
            session
                .config_name()
                .await
                .unwrap_or_else(|_| crate::tray::FALLBACK_NAME.to_string())
        },
        async {
            session
                .config_path()
                .await
                .map(|p| p.as_str().to_string())
                .unwrap_or_default()
        },
    )
    .await;

    info!(
        "Session: {} -> {} (status: {}/{})",
        path, config_name, major, minor
    );

    // Enable log/status forwarding so we receive StatusChange signals
    if let Err(e) = session.LogForward(true).await {
        debug!("LogForward for {}: {}", path, e);
    }

    let status = SessionStatus::new(major, minor, message.clone());
    let connected_path = if status.is_connected() {
        Some(path.to_string())
    } else {
        None
    };
    let pending_auth = if status.is_auth_request() {
        Some((path.to_string(), status.clone(), message))
    } else {
        None
    };
    // Cold-start path (H1): a tunnel already up at GUI launch never emits a
    // fresh Connected StatusChange, so the normal producer in
    // upsert_session_state wouldn't stamp connected_at — Stats would render
    // Duration/Since as "—". Stamp the GUI-launch instant instead. The openvpn3
    // Session D-Bus interface exposes no connect timestamp, so this is an
    // approximation (elapsed shown is "since GUI saw it"). `connected_path` is
    // already `Some` exactly when status.is_connected(), so reuse it here
    // instead of touching the `status` value (moved into the struct below).
    let connected_at = if connected_path.is_some() {
        Some(std::time::Instant::now())
    } else {
        None
    };
    ScannedSession {
        entry: SessionInfo {
            session_path: path.to_string(),
            config_path,
            config_name,
            status,
            connected_at,
            bytes_in: 0,
            bytes_out: 0,
            last_bytes_in: 0,
            last_bytes_out: 0,
            idle_started_at: None,
            idle_since: None,
            kill_switch_active: false,
        },
        connected_path,
        pending_auth,
    }
}

/// Re-apply bypass + kill-switch state for sessions that were already
/// connected before this GUI instance started (e.g., after a GUI restart).
/// The helper's watcher cleaned the rules when the previous instance exited.
///
/// ORDER MATTERS: bypass must land at the helper before `AddRules`. The
/// helper snapshots `state.bypass_cidrs` inside `AddRules` and bakes it
/// into the nft script (bypass accept rules + MSS clamp). Two independent
/// spawns would race — if KS won, the firewall would drop bypassed
/// traffic until the next manual reconnect.
async fn reapply_firewall_on_startup(
    dbus: &zbus::Connection,
    tray: &ksni::blocking::Handle<VpnTray>,
    settings: &Settings,
    connected_paths: Vec<String>,
) {
    let bypass_cidrs =
        crate::settings::enabled_cidrs(&settings.bypass_cidrs(), &settings.bypass_cidrs_disabled());
    let ks_enabled = settings.enable_kill_switch();
    // Re-apply only when a connected session exists AND either the kill-switch
    // or bypass rules need restoring (the helper cleaned them when the previous
    // instance exited). Negation of `has_connected && (ks_enabled || has_bypass)`.
    if connected_paths.is_empty() || (!ks_enabled && bypass_cidrs.is_empty()) {
        return;
    }
    let allow_lan = settings.kill_switch_allow_lan();
    let dbus_clone = dbus.clone();
    let tray_clone = tray.clone();
    glib::spawn_future_local(async move {
        crate::app::bypass_apply::apply_bypass(&tray_clone, bypass_cidrs, "startup re-apply").await;

        if ks_enabled {
            for path in connected_paths {
                match super::status_handler::apply_kill_switch(&dbus_clone, &path, allow_lan).await
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
