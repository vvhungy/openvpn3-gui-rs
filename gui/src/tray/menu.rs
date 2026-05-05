//! Tray menu construction
//!
//! Builds the ksni menu tree for `VpnTray`. Separated from indicator.rs so
//! that the menu logic can grow independently of the tray state definitions.

use ksni::MenuItem;
use ksni::menu::{StandardItem, SubMenu};

use crate::dbus::types::StatusMinor;

use super::indicator::{ConfigInfo, SessionInfo, TrayAction, VpnTray};

/// Build the full tray menu for the given tray state.
pub(super) fn build_menu(tray: &VpnTray) -> Vec<MenuItem<VpnTray>> {
    let mut items: Vec<MenuItem<VpnTray>> = Vec::new();

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

/// Build session submenu actions based on session state.
pub(super) fn session_submenu(session: &SessionInfo) -> Vec<MenuItem<VpnTray>> {
    let session_path = session.session_path.clone();
    let config_path = session.config_path.clone();
    let mut items = Vec::new();

    match session.status.minor {
        StatusMinor::ConnConnected => {
            let p = session_path.clone();
            items.push(
                StandardItem {
                    label: "Pause".into(),
                    activate: Box::new(move |tray: &mut VpnTray| {
                        tray.send_action(TrayAction::Pause(p.clone()));
                    }),
                    ..Default::default()
                }
                .into(),
            );
            let p = session_path.clone();
            items.push(
                StandardItem {
                    label: "Restart".into(),
                    activate: Box::new(move |tray: &mut VpnTray| {
                        tray.send_action(TrayAction::Restart(p.clone()));
                    }),
                    ..Default::default()
                }
                .into(),
            );
        }
        StatusMinor::ConnPaused => {
            let p = session_path.clone();
            items.push(
                StandardItem {
                    label: "Resume".into(),
                    activate: Box::new(move |tray: &mut VpnTray| {
                        tray.send_action(TrayAction::Resume(p.clone()));
                    }),
                    ..Default::default()
                }
                .into(),
            );
            let p = session_path.clone();
            items.push(
                StandardItem {
                    label: "Restart".into(),
                    activate: Box::new(move |tray: &mut VpnTray| {
                        tray.send_action(TrayAction::Restart(p.clone()));
                    }),
                    ..Default::default()
                }
                .into(),
            );
        }
        _ => {}
    }

    // Reconnect for disconnected/error sessions (creates a new session from the config)
    if session.status.is_reconnectable() && !config_path.is_empty() {
        let cp = config_path.clone();
        let sp = session_path.clone();
        items.push(
            StandardItem {
                label: "Reconnect".into(),
                activate: Box::new(move |tray: &mut VpnTray| {
                    tray.send_action(TrayAction::Reconnect(sp.clone(), cp.clone()));
                }),
                ..Default::default()
            }
            .into(),
        );
    }

    // Disconnect is always available
    let p = session_path.clone();
    items.push(
        StandardItem {
            label: "Disconnect".into(),
            activate: Box::new(move |tray: &mut VpnTray| {
                tray.send_action(TrayAction::Disconnect(p.clone()));
            }),
            ..Default::default()
        }
        .into(),
    );

    items
}

/// Build config submenu (Connect / Remove).
pub(super) fn config_submenu(config: &ConfigInfo) -> Vec<MenuItem<VpnTray>> {
    let path = config.path.clone();
    let p2 = config.path.clone();
    vec![
        StandardItem {
            label: "Connect".into(),
            activate: Box::new(move |tray: &mut VpnTray| {
                tray.send_action(TrayAction::Connect(path.clone()));
            }),
            ..Default::default()
        }
        .into(),
        StandardItem {
            label: "Remove".into(),
            activate: Box::new(move |tray: &mut VpnTray| {
                tray.send_action(TrayAction::RemoveConfig(p2.clone()));
            }),
            ..Default::default()
        }
        .into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbus::types::{SessionStatus, StatusMajor, StatusMinor};

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
        assert_eq!(labels[0], "[Work VPN]");
        assert_eq!(labels[1], "---");
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
        assert!(labels[0].starts_with("[Work VPN:"));
        assert!(!labels.contains(&"[Work VPN]".into()));
    }

    #[test]
    fn test_session_submenu_connected() {
        let session = make_session("/sess/1", "/cfg/1", "VPN", StatusMinor::ConnConnected);
        let labels = menu_labels(&session_submenu(&session));
        assert_eq!(labels, ["Pause", "Restart", "Disconnect"]);
    }

    #[test]
    fn test_session_submenu_paused() {
        let session = make_session("/sess/1", "/cfg/1", "VPN", StatusMinor::ConnPaused);
        let labels = menu_labels(&session_submenu(&session));
        assert_eq!(labels, ["Resume", "Restart", "Disconnect"]);
    }

    #[test]
    fn test_session_submenu_connecting() {
        let session = make_session("/sess/1", "/cfg/1", "VPN", StatusMinor::ConnConnecting);
        let labels = menu_labels(&session_submenu(&session));
        assert_eq!(labels, ["Disconnect"]);
    }

    #[test]
    fn test_session_submenu_disconnected_shows_reconnect() {
        let session = make_session("/sess/1", "/cfg/1", "VPN", StatusMinor::ConnDisconnected);
        let labels = menu_labels(&session_submenu(&session));
        assert_eq!(labels, ["Reconnect", "Disconnect"]);
    }

    #[test]
    fn test_session_submenu_error_shows_reconnect() {
        let session = make_session("/sess/1", "/cfg/1", "VPN", StatusMinor::CfgError);
        let labels = menu_labels(&session_submenu(&session));
        assert_eq!(labels, ["Reconnect", "Disconnect"]);
    }

    #[test]
    fn test_session_submenu_no_reconnect_without_config_path() {
        let session = make_session("/sess/1", "", "VPN", StatusMinor::ConnDisconnected);
        let labels = menu_labels(&session_submenu(&session));
        assert_eq!(labels, ["Disconnect"]);
    }

    #[test]
    fn test_config_submenu() {
        let config = ConfigInfo {
            path: "/cfg/1".into(),
            name: "VPN".into(),
        };
        let labels = menu_labels(&config_submenu(&config));
        assert_eq!(labels, ["Connect", "Remove"]);
    }
}
