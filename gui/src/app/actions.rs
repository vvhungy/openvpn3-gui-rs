//! Tray action dispatch
//!
//! No testable pure surface — dispatch into async helpers; covered by smoke tests.

use tracing::{error, info};

use gtk4::prelude::*;
use gtk4::{Application as GtkApplication, ApplicationWindow};

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
    parent: &ApplicationWindow,
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
        TrayAction::Reconnect(session_path, config_path) => {
            info!(
                "Tray action: Reconnect {} via {}",
                session_path, config_path
            );
            if let Ok(mut set) = super::session_ops::USER_DISCONNECTED.lock() {
                set.insert(session_path.clone());
            }
            let dbus = dbus.clone();
            let config_path = config_path.clone();
            let tray = tray.clone();
            let settings = settings.clone();
            glib::spawn_future_local(async move {
                if let Err(e) = connect_to_config(&dbus, &config_path, &tray, &settings).await {
                    error!("Failed to reconnect: {}", e);
                    crate::dialogs::show_error_notification(
                        "Reconnect Failed",
                        &format!("Could not reconnect to VPN: {}", e),
                    );
                }
            });
        }
        TrayAction::Statistics(session_path) => {
            info!("Tray action: Statistics {}", session_path);
            crate::dialogs::show_stats_dialog(Some(parent.upcast_ref()), dbus, tray, session_path);
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
                    crate::dialogs::show_error_notification(
                        "Disconnect Failed",
                        &format!("Could not disconnect VPN session: {}", e),
                    );
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
                    crate::dialogs::show_error_notification(
                        "Pause Failed",
                        &format!("Could not pause VPN session: {}", e),
                    );
                }
            });
        }
        TrayAction::Resume(session_path) => {
            info!("Tray action: Resume {}", session_path);
            let dbus = dbus.clone();
            let session_path = session_path.clone();
            let tray = tray.clone();
            glib::spawn_future_local(async move {
                if let Err(e) =
                    super::session_ops::resume_session(&dbus, &session_path, &tray).await
                {
                    error!("Failed to resume: {}", e);
                    crate::dialogs::show_error_notification(
                        "Resume Failed",
                        &format!("Could not resume VPN session: {}", e),
                    );
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
                    crate::dialogs::show_error_notification(
                        "Restart Failed",
                        &format!("Could not restart VPN session: {}", e),
                    );
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

            let parent = parent.clone();
            // Clone for the closure: the dialog borrows `name` for its label,
            // and the Fn closure (may fire repeatedly) must own its own copy.
            let name_for_closure = name.clone();
            crate::dialogs::show_config_remove_dialog(
                Some(parent.upcast_ref()),
                &config_path.clone(),
                &name,
                move || {
                    let dbus = dbus.clone();
                    let config_path = config_path.clone();
                    let tray = tray.clone();
                    let name = name_for_closure.clone();
                    glib::spawn_future_local(async move {
                        match remove_config(&dbus, &config_path, &name).await {
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
                },
            );
        }
        TrayAction::ForgetCredentials(config_path) => {
            info!("Tray action: Forget credentials {}", config_path);
            let config_path = config_path.clone();
            let tray = tray.clone();

            // Resolve the display name for the confirm dialog. Key the
            // keyring delete on config_path (S35 scheme) — never the name,
            // which two configs may share and would cross-wipe.
            let name = tray
                .update(|t| {
                    t.configs
                        .iter()
                        .find(|c| c.path == config_path)
                        .map(|c| c.name.clone())
                })
                .flatten()
                .unwrap_or_else(|| "Unknown".to_string());

            let parent = parent.clone();
            let key = format!("forget-{}", config_path);
            let name_for_closure = name.clone();
            crate::dialogs::show_config_forget_dialog(
                Some(parent.upcast_ref()),
                &key,
                &name,
                move || {
                    let config_path = config_path.clone();
                    let name = name_for_closure.clone();
                    glib::spawn_future_local(async move {
                        let store = crate::credentials::CredentialStore::default();
                        match store.delete_for_config_async(&config_path).await {
                            Ok(0) => crate::dialogs::show_info_notification(
                                "Credentials Forgotten",
                                &format!("No saved credentials found for '{}'.", name),
                            ),
                            Ok(n) => crate::dialogs::show_info_notification(
                                "Credentials Forgotten",
                                &format!("{} saved credential(s) removed for '{}'.", n, name),
                            ),
                            Err(e) => {
                                error!("Failed to forget credentials: {}", e);
                                crate::dialogs::show_error_notification(
                                    "Forget Failed",
                                    &format!("Could not forget credentials: {}", e),
                                );
                            }
                        }
                    });
                },
            );
        }
        TrayAction::ImportConfig => {
            info!("Tray action: Import config");
            let dbus = dbus.clone();
            let tray = tray.clone();
            let p_select = parent.clone();
            let p_import = parent.clone();
            crate::dialogs::show_config_select_dialog(Some(p_select.upcast_ref()), move |path| {
                let dbus = dbus.clone();
                let tray = tray.clone();
                let p = p_import.clone();
                let p_dialog = p.clone();
                crate::dialogs::show_config_import_dialog(
                    Some(p_dialog.upcast_ref()),
                    path,
                    move |name, path| {
                        let dbus = dbus.clone();
                        let tray = tray.clone();
                        // Clone per closure invocation: the outer closure is Fn
                        // (may fire several times), but the async block consumes
                        // its captures once.
                        let p_result = p.clone();
                        glib::spawn_future_local(async move {
                            let parent: Option<&gtk4::Window> = Some(p_result.upcast_ref());
                            match import_config(&dbus, &name, &path).await {
                                Ok(_) => {
                                    refresh_configs(&dbus, &tray).await;
                                    crate::dialogs::show_import_result_dialog(
                                        parent, true, &name, None,
                                    );
                                }
                                Err(e) => {
                                    error!("Failed to import config: {}", e);
                                    let detail = format!("{e}");
                                    crate::dialogs::show_error_notification(
                                        "Import Failed",
                                        &format!("Could not import configuration: {}", detail),
                                    );
                                    crate::dialogs::show_import_result_dialog(
                                        parent,
                                        false,
                                        &name,
                                        Some(&detail),
                                    );
                                }
                            }
                        });
                    },
                );
            });
        }
        TrayAction::Preferences => {
            info!("Tray action: Preferences");
            let configs = tray.update(|t| t.configs.clone()).unwrap_or_default();
            crate::dialogs::show_preferences_dialog(
                Some(parent.upcast_ref()),
                settings,
                configs,
                tray.clone(),
                dbus.clone(),
            );
        }
        TrayAction::ViewLogs => {
            info!("Tray action: View Logs");
            crate::dialogs::show_log_viewer(Some(parent.upcast_ref()), tray, dbus);
        }
        TrayAction::About => {
            info!("Tray action: About");
            crate::dialogs::show_about_dialog(Some(parent.upcast_ref()));
        }
        TrayAction::Quit => {
            info!("Tray action: Quit");
            let has_connected = tray
                .update(|t| t.sessions.values().any(|s| s.status.is_connected()))
                .unwrap_or(false);
            if has_connected && settings.enable_kill_switch() {
                let parent = parent.clone();
                let gtk_app = gtk_app.clone();
                crate::dialogs::show_quit_confirmation_dialog(Some(parent.upcast_ref()), gtk_app);
            } else {
                gtk_app.quit();
            }
        }
    }
}
