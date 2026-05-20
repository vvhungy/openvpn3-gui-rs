//! Tray menu construction
//!
//! Builds the ksni menu tree for `VpnTray`. Separated from indicator.rs so
//! that the menu logic can grow independently of the tray state definitions.

use ksni::MenuItem;
use ksni::menu::{StandardItem, SubMenu};

use super::indicator::{BypassState, TrayAction, VpnTray};

mod submenus;

use submenus::{config_submenu, session_submenu};

/// Format the tray "Split tunnel" row body for an `Active` bypass state.
/// Shape: `"N active"` (no failures), `"N active, M failed"` (partial), or
/// `"Apply failed"` (zero applied — surface this rather than say "0 active").
fn format_bypass_active(applied: usize, failed: usize) -> String {
    match (applied, failed) {
        (0, 0) => "🌐 Split tunnel: Off".to_string(),
        (0, _) => "⚠️ Split tunnel: Apply failed".to_string(),
        (1, 0) => "🌐 Split tunnel: 1 network".to_string(),
        (a, 0) => format!("🌐 Split tunnel: {a} networks"),
        (a, f) => format!("⚠️ Split tunnel: {a} active, {f} failed"),
    }
}

/// Build the full tray menu for the given tray state.
pub(super) fn build_menu(tray: &VpnTray) -> Vec<MenuItem<VpnTray>> {
    let mut items: Vec<MenuItem<VpnTray>> = Vec::new();

    let label = if tray.kill_switch_enabled {
        "🔒 Kill-switch: On".to_string()
    } else {
        "🔓 Kill-switch: Off".to_string()
    };
    items.push(
        StandardItem {
            label,
            enabled: false,
            ..Default::default()
        }
        .into(),
    );

    let bypass_label = match &tray.bypass_state {
        BypassState::Off => "🌐 Split tunnel: Off".to_string(),
        BypassState::Active { applied, failed } => format_bypass_active(*applied, *failed),
        BypassState::Failed => "⚠️ Split tunnel: Apply failed".to_string(),
    };
    items.push(
        StandardItem {
            label: bypass_label,
            enabled: false,
            ..Default::default()
        }
        .into(),
    );

    items.push(MenuItem::Separator);

    if tray.configs.is_empty() && tray.sessions.is_empty() {
        items.push(
            StandardItem {
                label: "No profiles imported".into(),
                enabled: false,
                ..Default::default()
            }
            .into(),
        );
    }

    // --- Active sessions ---
    for session in tray.sessions.values() {
        items.push(
            SubMenu {
                label: session.status_label(),
                submenu: session_submenu(session),
                ..Default::default()
            }
            .into(),
        );
    }

    // --- Configs without an active session ---
    let active_config_paths: Vec<&str> = tray
        .sessions
        .values()
        .map(|s| s.config_path.as_str())
        .collect();

    for config in &tray.configs {
        if active_config_paths.contains(&config.path.as_str()) {
            continue;
        }
        items.push(
            SubMenu {
                label: config.name.clone(),
                submenu: config_submenu(config),
                ..Default::default()
            }
            .into(),
        );
    }

    // --- Separator if we had any configs/sessions ---
    if !items.is_empty() {
        items.push(MenuItem::Separator);
    }

    // --- Import Config ---
    items.push(
        StandardItem {
            label: "Import Config...".into(),
            activate: Box::new(|tray: &mut VpnTray| {
                tray.send_action(TrayAction::ImportConfig);
            }),
            ..Default::default()
        }
        .into(),
    );

    items.push(MenuItem::Separator);

    // --- View Logs (always visible) ---
    items.push(
        StandardItem {
            label: "View Logs".into(),
            activate: Box::new(|tray: &mut VpnTray| {
                tray.send_action(TrayAction::ViewLogs);
            }),
            ..Default::default()
        }
        .into(),
    );

    // --- Preferences ---
    items.push(
        StandardItem {
            label: "Preferences...".into(),
            activate: Box::new(|tray: &mut VpnTray| {
                tray.send_action(TrayAction::Preferences);
            }),
            ..Default::default()
        }
        .into(),
    );

    // --- About ---
    items.push(
        StandardItem {
            label: "About".into(),
            activate: Box::new(|tray: &mut VpnTray| {
                tray.send_action(TrayAction::About);
            }),
            ..Default::default()
        }
        .into(),
    );

    // --- Quit ---
    items.push(
        StandardItem {
            label: "Quit".into(),
            activate: Box::new(|tray: &mut VpnTray| {
                tray.send_action(TrayAction::Quit);
            }),
            ..Default::default()
        }
        .into(),
    );

    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbus::types::{SessionStatus, StatusMajor, StatusMinor};
    use crate::tray::indicator::{ConfigInfo, SessionInfo};

    fn menu_labels(items: &[MenuItem<VpnTray>]) -> Vec<String> {
        items
            .iter()
            .map(|item| match item {
                MenuItem::Standard(s) => s.label.clone(),
                MenuItem::SubMenu(s) => format!("[{}]", s.label),
                MenuItem::Separator => "---".into(),
                _ => "?".into(),
            })
            .collect()
    }

    fn make_tray() -> VpnTray {
        let (tx, _rx) = futures::channel::mpsc::unbounded();
        VpnTray::new(tx)
    }

    fn make_session(
        session_path: &str,
        config_path: &str,
        config_name: &str,
        minor: StatusMinor,
    ) -> SessionInfo {
        SessionInfo {
            session_path: session_path.into(),
            config_path: config_path.into(),
            config_name: config_name.into(),
            status: SessionStatus {
                major: StatusMajor::Connection,
                minor,
            },
            connected_at: None,
            bytes_in: 0,
            bytes_out: 0,
            last_bytes_in: 0,
            last_bytes_out: 0,
            idle_since: None,
            kill_switch_active: false,
        }
    }

    #[test]
    fn test_empty_tray_menu() {
        let tray = make_tray();
        let labels = menu_labels(&build_menu(&tray));
        assert_eq!(
            labels,
            [
                "🔓 Kill-switch: Off",
                "🌐 Split tunnel: Off",
                "---",
                "No profiles imported",
                "---",
                "Import Config...",
                "---",
                "View Logs",
                "Preferences...",
                "About",
                "Quit"
            ]
        );
    }

    #[test]
    fn test_no_hint_when_session_present() {
        let mut tray = make_tray();
        tray.sessions.insert(
            "/sess/1".into(),
            make_session("/sess/1", "", "VPN", StatusMinor::ConnConnected),
        );
        let labels = menu_labels(&build_menu(&tray));
        assert!(!labels.contains(&"No profiles imported".into()));
    }

    #[test]
    fn test_menu_with_config_only() {
        let mut tray = make_tray();
        tray.configs.push(ConfigInfo {
            path: "/cfg/1".into(),
            name: "Work VPN".into(),
        });
        let labels = menu_labels(&build_menu(&tray));
        assert_eq!(labels[0], "🔓 Kill-switch: Off");
        assert_eq!(labels[1], "🌐 Split tunnel: Off");
        assert_eq!(labels[2], "---");
        assert_eq!(labels[3], "[Work VPN]");
        assert_eq!(labels[4], "---");
    }

    #[test]
    fn test_kill_switch_enabled_row() {
        let mut tray = make_tray();
        tray.kill_switch_enabled = true;
        let labels = menu_labels(&build_menu(&tray));
        assert_eq!(labels[0], "🔒 Kill-switch: On");
    }

    #[test]
    fn test_menu_with_active_session_hides_config() {
        let mut tray = make_tray();
        tray.configs.push(ConfigInfo {
            path: "/cfg/1".into(),
            name: "Work VPN".into(),
        });
        tray.sessions.insert(
            "/sess/1".into(),
            make_session("/sess/1", "/cfg/1", "Work VPN", StatusMinor::ConnConnected),
        );
        let labels = menu_labels(&build_menu(&tray));
        assert!(labels[3].starts_with("[Work VPN:"));
        assert!(!labels.contains(&"[Work VPN]".into()));
    }

    #[test]
    fn test_bypass_row_off_when_default() {
        let tray = make_tray();
        let labels = menu_labels(&build_menu(&tray));
        assert_eq!(labels[1], "🌐 Split tunnel: Off");
    }

    #[test]
    fn test_bypass_row_singular_when_one() {
        let mut tray = make_tray();
        tray.bypass_state = BypassState::Active {
            applied: 1,
            failed: 0,
        };
        let labels = menu_labels(&build_menu(&tray));
        assert_eq!(labels[1], "🌐 Split tunnel: 1 network");
    }

    #[test]
    fn test_bypass_row_plural_when_many() {
        let mut tray = make_tray();
        tray.bypass_state = BypassState::Active {
            applied: 3,
            failed: 0,
        };
        let labels = menu_labels(&build_menu(&tray));
        assert_eq!(labels[1], "🌐 Split tunnel: 3 networks");
    }

    #[test]
    fn test_bypass_row_failed_state() {
        let mut tray = make_tray();
        tray.bypass_state = BypassState::Failed;
        let labels = menu_labels(&build_menu(&tray));
        assert_eq!(labels[1], "⚠️ Split tunnel: Apply failed");
    }

    #[test]
    fn test_bypass_row_partial_failure() {
        let mut tray = make_tray();
        tray.bypass_state = BypassState::Active {
            applied: 3,
            failed: 2,
        };
        let labels = menu_labels(&build_menu(&tray));
        assert_eq!(labels[1], "⚠️ Split tunnel: 3 active, 2 failed");
    }

    #[test]
    fn test_bypass_row_all_failed_renders_as_failed() {
        // Zero successful applies — render as "Apply failed" rather than
        // "0 active, N failed" which would read as still-partial-working.
        let mut tray = make_tray();
        tray.bypass_state = BypassState::Active {
            applied: 0,
            failed: 2,
        };
        let labels = menu_labels(&build_menu(&tray));
        assert_eq!(labels[1], "⚠️ Split tunnel: Apply failed");
    }
}
