//! Tray action dispatch

use tracing::{error, info};

use gtk4::Application as GtkApplication;
use gtk4::prelude::*;

use crate::credentials::CredentialStore;
use crate::settings::Settings;
use crate::tray::{TrayAction, VpnTray};

use super::config_ops::{import_config, refresh_configs, remove_config};
use super::session_ops::{connect_to_config, session_action};

/// Handle an action dispatched from the tray menu
pub(crate) fn handle_tray_action(
    action: &TrayAction,
    dbus: &zbus::Connection,
    settings: &Settings,
    tray: &ksni::blocking::Handle<VpnTray>,
    gtk_app: &GtkApplication,
) {
    match action {
        TrayAction::Connect(config_path) => {
            info!("Tray action: Connect to {}", config_path);
            let dbus = dbus.clone();
            let config_path = config_path.clone();
            let tray = tray.clone();
            let settings = settings.clone();
            glib::spawn_future_local(async move {
                if let Err(e) = connect_to_config(&dbus, &config_path, &tray, &settings).await {
                    error!("Failed to connect: {}", e);
                    crate::dialogs::show_error_notification(
                        "Connection Failed",
                        &format!("Could not connect to VPN: {}", e),
                    );
                }
            });
        }
        TrayAction::Disconnect(session_path) => {
            info!("Tray action: Disconnect {}", session_path);
            // Mark as user-initiated so the SessDestroyed handler skips the reconnect prompt
            if let Ok(mut set) = super::session_ops::USER_DISCONNECTED.lock() {
                set.insert(session_path.clone());
            }
            let dbus = dbus.clone();
            let session_path = session_path.clone();
            glib::spawn_future_local(async move {
                if let Err(e) = session_action(&dbus, &session_path, "disconnect").await {
                    error!("Failed to disconnect: {}", e);
                }
                // Session destruction will be handled by SessionManagerEvent signal
            });
        }
        TrayAction::Pause(session_path) => {
            info!("Tray action: Pause {}", session_path);
            let dbus = dbus.clone();
            let session_path = session_path.clone();
            glib::spawn_future_local(async move {
                if let Err(e) = session_action(&dbus, &session_path, "pause").await {
                    error!("Failed to pause: {}", e);
                }
            });
        }
        TrayAction::Resume(session_path) => {
            info!("Tray action: Resume {}", session_path);
            let dbus = dbus.clone();
            let session_path = session_path.clone();
            glib::spawn_future_local(async move {
                if let Err(e) = session_action(&dbus, &session_path, "resume").await {
                    error!("Failed to resume: {}", e);
                }
            });
        }
        TrayAction::Restart(session_path) => {
            info!("Tray action: Restart {}", session_path);
            let dbus = dbus.clone();
            let session_path = session_path.clone();
            glib::spawn_future_local(async move {
                if let Err(e) = session_action(&dbus, &session_path, "restart").await {
                    error!("Failed to restart: {}", e);
                }
            });
        }
        TrayAction::RemoveConfig(config_path) => {
            info!("Tray action: Remove config {}", config_path);
            let dbus = dbus.clone();
            let config_path = config_path.clone();
            let tray = tray.clone();

            // Get config name for confirmation dialog
            let name = tray
                .update(|t| {
                    t.configs
                        .iter()
                        .find(|c| c.path == config_path)
                        .map(|c| c.name.clone())
                })
                .flatten()
                .unwrap_or_else(|| "Unknown".to_string());

            crate::dialogs::show_config_remove_dialog(None, &name, move || {
                let dbus = dbus.clone();
                let config_path = config_path.clone();
                let tray = tray.clone();
                glib::spawn_future_local(async move {
                    match remove_config(&dbus, &config_path).await {
                        Ok(_) => {
                            crate::dialogs::show_info_notification(
                                "Configuration Removed",
                                "Configuration has been removed",
                            );
                            refresh_configs(&dbus, &tray).await;
                        }
                        Err(e) => {
                            error!("Failed to remove config: {}", e);
                            crate::dialogs::show_error_notification(
                                "Remove Failed",
                                &format!("Could not remove configuration: {}", e),
                            );
                        }
                    }
                });
            });
        }
        TrayAction::ImportConfig => {
            info!("Tray action: Import config");
            let dbus = dbus.clone();
            let tray = tray.clone();
            crate::dialogs::show_config_select_dialog(None, move |path| {
                let dbus = dbus.clone();
                let tray = tray.clone();
                crate::dialogs::show_config_import_dialog(None, path, move |name, path| {
                    let dbus = dbus.clone();
                    let tray = tray.clone();
                    glib::spawn_future_local(async move {
                        match import_config(&dbus, &name, &path).await {
                            Ok(_) => {
                                refresh_configs(&dbus, &tray).await;
                            }
                            Err(e) => {
                                error!("Failed to import config: {}", e);
                                crate::dialogs::show_error_notification(
                                    "Import Failed",
                                    &format!("Could not import configuration: {}", e),
                                );
                            }
                        }
                    });
                });
            });
        }
        TrayAction::Preferences => {
            info!("Tray action: Preferences");
            let configs = tray.update(|t| t.configs.clone()).unwrap_or_default();
            crate::dialogs::show_preferences_dialog(None, settings, configs);
        }
        TrayAction::About => {
            info!("Tray action: About");
            crate::dialogs::show_about_dialog(None);
        }
        TrayAction::Quit => {
            info!("Tray action: Quit");
            gtk_app.quit();
        }
        TrayAction::ClearCredentials => {
            info!("Tray action: Clear saved credentials");
            glib::spawn_future_local(async move {
                let store = match CredentialStore::new() {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to open credential store: {}", e);
                        return;
                    }
                };
                match store.clear_all_async().await {
                    Ok(0) => crate::dialogs::show_info_notification(
                        "Credentials Cleared",
                        "No saved credentials found.",
                    ),
                    Ok(n) => crate::dialogs::show_info_notification(
                        "Credentials Cleared",
                        &format!("{} saved credential(s) removed.", n),
                    ),
                    Err(e) => {
                        error!("Failed to clear credentials: {}", e);
                        crate::dialogs::show_error_notification(
                            "Clear Failed",
                            &format!("Could not clear credentials: {}", e),
                        );
                    }
                }
            });
        }
    }
}
