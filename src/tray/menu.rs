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
