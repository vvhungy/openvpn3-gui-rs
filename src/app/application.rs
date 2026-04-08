//! GTK Application — entry point and GTK signal wiring

use futures::StreamExt;
use gio::ApplicationFlags;
use glib::ExitCode;
use gtk4::Application as GtkApplication;
use gtk4::prelude::*;
use tracing::{error, info};

use crate::config::APPLICATION_ID;
use crate::credentials::CredentialStore;
use crate::settings::Settings;
use crate::tray::{TrayAction, VpnTray};

use super::actions::handle_tray_action;
use super::config_ops::{import_config, refresh_configs};
use super::dbus_init::init_dbus;
use super::signal_handlers::setup_signal_handlers;

/// Command-line arguments
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct AppArgs {
    pub verbose: u8,
    pub debug: bool,
    pub silent: bool,
    pub clear_secret_storage: bool,
}

/// Main application
pub struct Application;

impl Application {
    pub fn run(args: AppArgs) -> anyhow::Result<ExitCode> {
        let gtk_app = GtkApplication::builder()
            .application_id(APPLICATION_ID)
            .flags(ApplicationFlags::HANDLES_OPEN)
            .build();

        let settings = Settings::new();
        let credentials = CredentialStore::new()?;

        if args.clear_secret_storage {
            info!("Clearing secret storage");
            let rt = tokio::runtime::Handle::current();
            match rt.block_on(credentials.clear_all_async()) {
                Ok(0) => info!("No saved credentials found"),
                Ok(n) => info!("Cleared {} saved credential(s)", n),
                Err(e) => error!("Failed to clear credentials: {}", e),
            }
        }

        // Create D-Bus system connection (for OpenVPN3)
        let rt = tokio::runtime::Handle::current();
        let dbus_connection = rt.block_on(zbus::Connection::system())?;

        // Create the action channel (tray callbacks → GTK main loop)
        let (action_tx, action_rx) = futures::channel::mpsc::unbounded::<TrayAction>();

        // Keep a sender clone for signal handlers (reconnect notifications etc.)
        let action_tx_for_signals = action_tx.clone();

        // Spawn the ksni tray using the blocking API (spawns its own thread)
        let tray_handle = {
            use ksni::blocking::TrayMethods;
            let tray = VpnTray::new(action_tx);
            tray.assume_sni_available(true).spawn()?
        };
        info!("Tray indicator spawned");

        // --- Startup signal ---
        let dbus_conn = dbus_connection.clone();
        let settings_clone = settings.clone();
        let tray_handle_clone = tray_handle.clone();
        let action_rx = std::cell::RefCell::new(Some(action_rx));

        gtk_app.connect_startup(move |gtk_app| {
            info!("Application startup");

            // Wire up the action receiver on the glib main loop
            let dbus = dbus_conn.clone();
            let settings_for_actions = settings_clone.clone();
            let tray = tray_handle_clone.clone();
            let gtk_app_clone = gtk_app.clone();
            let rx = action_rx.borrow_mut().take().expect("startup called once");
            glib::spawn_future_local(async move {
                let mut rx = rx;
                while let Some(action) = rx.next().await {
                    handle_tray_action(
                        &action,
                        &dbus,
                        &settings_for_actions,
                        &tray,
                        &gtk_app_clone,
                    );
                }
            });

            // Periodic timer — refreshes tooltip duration for connected sessions
            let tray_for_timer = tray_handle_clone.clone();
            glib::timeout_add_seconds(30, move || {
                tray_for_timer.update(|_| {});
                glib::ControlFlow::Continue
            });

            // Initialize D-Bus and populate tray, with retry until the service is up
            let dbus = dbus_conn.clone();
            let settings = settings_clone.clone();
            let tray = tray_handle_clone.clone();
            let action_tx = action_tx_for_signals.clone();
            glib::spawn_future_local(async move {
                // Retry init up to 10 times (max ~30s) to handle slow service activation
                let mut initialized = false;
                for attempt in 1..=10u32 {
                    match init_dbus(&dbus, &settings, &tray).await {
                        Ok(_) => {
                            info!("D-Bus initialization complete");
                            initialized = true;
                            break;
                        }
                        Err(e) => {
                            if attempt == 1 {
                                info!("OpenVPN3 service not ready, retrying…");
                            }
                            tracing::debug!("D-Bus init attempt {}/10: {}", attempt, e);
                            glib::timeout_future(std::time::Duration::from_secs(3)).await;
                        }
                    }
                }
                if !initialized {
                    error!("Failed to connect to OpenVPN3 D-Bus service after 10 attempts");
                }

                match setup_signal_handlers(&dbus, tray.clone(), action_tx).await {
                    Ok(_) => info!("Signal handlers setup complete"),
                    Err(e) => error!("Failed to setup signal handlers: {}", e),
                }
            });
        });

        // --- Activate signal ---
        gtk_app.connect_activate(|_| {
            info!("Application activated");
        });

        // --- Open signal (file associations) ---
        let dbus_conn = dbus_connection.clone();
        let tray_for_open = tray_handle.clone();
        gtk_app.connect_open(move |_app, files, _hint| {
            for file in files {
                if let Some(path) = file.path() {
                    info!("Open file: {:?}", path);
                    let dbus = dbus_conn.clone();
                    let tray = tray_for_open.clone();
                    crate::dialogs::show_config_import_dialog(
                        None,
                        path.clone(),
                        move |name, path| {
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
                        },
                    );
                }
            }
        });

        // suppress unused variable warning for credentials (held for its lifetime)
        let _ = credentials;

        let _hold = gtk_app.hold();
        let code = gtk_app.run();
        Ok(code)
    }
}
