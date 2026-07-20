//! Single-source helpers for resolving a session/config display name from the
//! tray.
//!
//! Centralises the fallback string so a session with no tray entry shows the
//! same label regardless of which code path fired (auth, timeout, log, error,
//! resume …). Before this module the fallback was duplicated as `"VPN"` at five
//! sites and `"VPN Connection"` at two — a session dropped from the tray could
//! surface a different name depending on the notification path.
//!
//! The pure lookup logic lives on [`VpnTray`] (testable without a live ksni
//! handle); the free fns are thin adapters over the blocking `Handle`, which
//! returns `None` only when the tray itself has been torn down.

use ksni::blocking::Handle;

use super::VpnTray;

/// Fallback label when a session/config name is unavailable (no tray entry).
pub(crate) const FALLBACK_NAME: &str = "VPN Connection";

/// Fallback label when a *config path* has no entry in the loaded config list
/// (removed between menu render and click, or deleted since last run).
pub(crate) const UNKNOWN_CONFIG_NAME: &str = "Unknown";

impl VpnTray {
    /// Display name of the session at `session_path`, or [`FALLBACK_NAME`] if
    /// the session is no longer in the tray (e.g. already removed on disconnect).
    pub(crate) fn session_config_name(&self, session_path: &str) -> String {
        self.sessions
            .get(session_path)
            .map(|s| s.config_name.clone())
            .unwrap_or_else(|| FALLBACK_NAME.to_string())
    }

    /// `(config_name, config_path)` of the session at `session_path`, or
    /// `([`FALLBACK_NAME`], "")` if the session is gone from the tray.
    pub(crate) fn session_config_identity(&self, session_path: &str) -> (String, String) {
        self.sessions
            .get(session_path)
            .map(|s| (s.config_name.clone(), s.config_path.clone()))
            .unwrap_or_else(|| (FALLBACK_NAME.to_string(), String::new()))
    }

    /// Display name of the config at `config_path`, or [`UNKNOWN_CONFIG_NAME`]
    /// if it is no longer in the loaded config list (e.g. removed between the
    /// menu render and the click, or deleted since last run). The single
    /// canonical path→name lookup — every call site routes through here.
    pub(crate) fn resolve_config_name(&self, config_path: &str) -> String {
        self.configs
            .iter()
            .find(|c| c.path == config_path)
            .map(|c| c.name.clone())
            .unwrap_or_else(|| UNKNOWN_CONFIG_NAME.to_string())
    }
}

/// Display name of the session at `session_path`, or [`FALLBACK_NAME`] if the
/// session is no longer in the tray, or the tray handle itself is gone.
pub(crate) fn session_config_name(tray: &Handle<VpnTray>, session_path: &str) -> String {
    tray.update(|t| t.session_config_name(session_path))
        .unwrap_or_else(|| FALLBACK_NAME.to_string())
}

/// `(config_name, config_path)` of the session at `session_path`, or
/// `([`FALLBACK_NAME`], "")` if the session is gone from the tray, or the tray
/// handle itself is gone.
pub(crate) fn session_config_identity(
    tray: &Handle<VpnTray>,
    session_path: &str,
) -> (String, String) {
    tray.update(|t| t.session_config_identity(session_path))
        .unwrap_or_else(|| (FALLBACK_NAME.to_string(), String::new()))
}

/// Display name of the config at `config_path`, or [`UNKNOWN_CONFIG_NAME`] if
/// the config is gone from the tray's loaded list, or the tray handle itself
/// is gone. Thin adapter over the blocking `Handle`.
pub(crate) fn resolve_config_name(tray: &Handle<VpnTray>, config_path: &str) -> String {
    tray.update(|t| t.resolve_config_name(config_path))
        .unwrap_or_else(|| UNKNOWN_CONFIG_NAME.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbus::types::SessionStatus;
    use crate::tray::{ConfigInfo, SessionInfo, TrayAction};
    use futures::channel::mpsc;

    fn empty_tray() -> VpnTray {
        let (tx, _rx) = mpsc::unbounded::<TrayAction>();
        VpnTray::new(tx)
    }

    fn named_session(path: &str, name: &str, cfg_path: &str) -> SessionInfo {
        SessionInfo {
            session_path: path.to_string(),
            config_path: cfg_path.to_string(),
            config_name: name.to_string(),
            status: SessionStatus::new(0, 0, String::new()),
            connected_at: None,
            bytes_in: 0,
            bytes_out: 0,
            last_bytes_in: 0,
            last_bytes_out: 0,
            idle_started_at: None,
            idle_since: None,
            kill_switch_active: false,
        }
    }

    #[test]
    fn fallback_name_is_canonical() {
        // Guards the exact inconsistency T1 unified: five sites used "VPN",
        // two used "VPN Connection". A session with no tray entry must show
        // one label everywhere.
        assert_eq!(FALLBACK_NAME, "VPN Connection");
    }

    #[test]
    fn miss_returns_fallback_name() {
        let tray = empty_tray();
        assert_eq!(tray.session_config_name("/missing"), FALLBACK_NAME);
    }

    #[test]
    fn miss_returns_fallback_identity_with_empty_path() {
        let tray = empty_tray();
        let (name, path) = tray.session_config_identity("/missing");
        assert_eq!(name, FALLBACK_NAME);
        assert!(path.is_empty());
    }

    #[test]
    fn hit_returns_stored_name_and_path() {
        let mut tray = empty_tray();
        tray.sessions.insert(
            "/sess/1".to_string(),
            named_session("/sess/1", "Work VPN", "/cfg/1"),
        );
        assert_eq!(tray.session_config_name("/sess/1"), "Work VPN");
        let (name, path) = tray.session_config_identity("/sess/1");
        assert_eq!(name, "Work VPN");
        assert_eq!(path, "/cfg/1");
    }

    #[test]
    fn lookup_is_keyed_by_session_path_not_name() {
        // Two sessions sharing a display name must still resolve by path, so
        // one miss can't shadow the other (matters for the keyring key path,
        // which must stay unique per session).
        let mut tray = empty_tray();
        tray.sessions.insert(
            "/sess/1".to_string(),
            named_session("/sess/1", "Shared", "/cfg/1"),
        );
        tray.sessions.insert(
            "/sess/2".to_string(),
            named_session("/sess/2", "Shared", "/cfg/2"),
        );
        assert_eq!(tray.session_config_identity("/sess/2").1, "/cfg/2");
        assert_eq!(tray.session_config_name("/sess/3"), FALLBACK_NAME);
    }

    // --- resolve_config_name (config-path lookup, moved from app/actions.rs) ---

    fn cfg(path: &str, name: &str) -> ConfigInfo {
        ConfigInfo {
            path: path.to_string(),
            name: name.to_string(),
        }
    }

    fn tray_with_configs(configs: &[ConfigInfo]) -> VpnTray {
        let mut tray = empty_tray();
        tray.configs = configs.to_vec();
        tray
    }

    #[test]
    fn resolve_config_name_matches_by_path() {
        let tray = tray_with_configs(&[cfg("/a.ovpn", "Alpha"), cfg("/b.ovpn", "Beta")]);
        assert_eq!(tray.resolve_config_name("/b.ovpn"), "Beta");
    }

    #[test]
    fn resolve_config_name_unknown_when_missing() {
        let tray = tray_with_configs(&[cfg("/a.ovpn", "Alpha")]);
        assert_eq!(
            tray.resolve_config_name("/missing.ovpn"),
            UNKNOWN_CONFIG_NAME
        );
    }

    #[test]
    fn resolve_config_name_unknown_when_empty() {
        let tray = tray_with_configs(&[]);
        assert_eq!(
            tray.resolve_config_name("/anything.ovpn"),
            UNKNOWN_CONFIG_NAME
        );
    }

    #[test]
    fn resolve_config_name_first_match_wins_on_duplicate_paths() {
        // Duplicate paths aren't expected, but resolution must stay
        // deterministic: first match wins (mirrors the original `.find`).
        let tray = tray_with_configs(&[cfg("/dup.ovpn", "First"), cfg("/dup.ovpn", "Second")]);
        assert_eq!(tray.resolve_config_name("/dup.ovpn"), "First");
    }
}
