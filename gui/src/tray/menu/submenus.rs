//! Per-session and per-config submenu builders.
//!
//! Split out of `mod.rs` so the menu shell (`build_menu`) and the per-row
//! submenu logic can grow independently.

use ksni::MenuItem;
use ksni::menu::StandardItem;

use crate::dbus::types::StatusMinor;
use crate::tray::indicator::{ConfigInfo, SessionInfo, TrayAction, VpnTray};

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
                    label: "Statistics".into(),
                    activate: Box::new(move |tray: &mut VpnTray| {
                        tray.send_action(TrayAction::Statistics(p.clone()));
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
                    label: "Statistics".into(),
                    activate: Box::new(move |tray: &mut VpnTray| {
                        tray.send_action(TrayAction::Statistics(p.clone()));
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
    use crate::dbus::types::{SessionStatus, StatusMajor};

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
            auto_reconnect_attempted_at: None,
            kill_switch_active: false,
        }
    }

    #[test]
    fn test_session_submenu_connected() {
        let session = make_session("/sess/1", "/cfg/1", "VPN", StatusMinor::ConnConnected);
        let labels = menu_labels(&session_submenu(&session));
        assert_eq!(labels, ["Pause", "Statistics", "Restart", "Disconnect"]);
    }

    #[test]
    fn test_session_submenu_paused() {
        let session = make_session("/sess/1", "/cfg/1", "VPN", StatusMinor::ConnPaused);
        let labels = menu_labels(&session_submenu(&session));
        assert_eq!(labels, ["Resume", "Statistics", "Restart", "Disconnect"]);
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
