//! GTK Application — entry point and GTK signal wiring
//!
//! No testable pure surface — GTK Application bootstrap and signal wiring.

use futures::StreamExt;
use gio::ApplicationFlags;
use glib::ExitCode;
use gtk4::prelude::*;
use gtk4::{Application as GtkApplication, ApplicationWindow};
use tracing::{error, info};

use crate::config::APPLICATION_ID;
use crate::credentials::CredentialStore;
use crate::settings::Settings;
use crate::tray::{TrayAction, VpnTray};

use super::actions::handle_tray_action;
use super::config_ops::{import_config, refresh_configs};
use super::dbus_init::init_dbus;
use super::service_watcher::watch_service_restart;
use super::signal_handlers::setup_signal_handlers;

/// Command-line arguments consumed by the application
#[derive(Debug, Clone, Default)]
pub struct AppArgs {
    pub clear_secret_storage: bool,
}

/// Main application
pub struct Application;

impl Application {
    pub fn run(args: AppArgs) -> anyhow::Result<ExitCode> {
        libadwaita::init()?;
        let gtk_app = GtkApplication::builder()
            .application_id(APPLICATION_ID)
            .flags(ApplicationFlags::HANDLES_OPEN)
            .build();

        let settings = Settings::new();
        crate::autostart::sync_gsettings_from_fs(&settings);
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

            // Register bundled icons so adw::AboutWindow (and any icon-name
            // lookup) finds them both when running from the build directory
            // and when installed.
            if let Some(display) = gtk4::gdk::Display::default() {
                let theme = gtk4::IconTheme::for_display(&display);
                theme.add_search_path("data/icons");
            }

            // Hidden window — never shown, used as transient parent for all dialogs
            // so GTK doesn't warn about dialogs without a transient parent.
            let parent_window = ApplicationWindow::builder().application(gtk_app).build();
            super::set_dialog_parent(parent_window.clone());

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
                        &parent_window,
                    );
                }
            });

            // Periodic stats poller — doubles as the tooltip-refresh tick.
            super::stats_poller::setup_stats_poller(&dbus_conn, &tray_handle_clone);

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
                            let ks = settings.enable_kill_switch();
                            tray.update(move |t| {
                                t.kill_switch_enabled = ks;
                            });
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
                    crate::dialogs::show_first_run_help_notification(action_tx.clone());
                }

                match setup_signal_handlers(&dbus, tray.clone(), action_tx).await {
                    Ok(_) => info!("Signal handlers setup complete"),
                    Err(e) => {
                        error!("Failed to setup signal handlers: {}", e);
                        crate::dialogs::show_error_notification(
                            "Status Monitoring Failed",
                            "Could not subscribe to VPN status updates. \
                             The app will run but may not reflect connection changes.",
                        );
                    }
                }

                // Start buffering Log signals for the log viewer
                super::log_buffer::subscribe(&dbus, &tray).await;
            });

            // Watch for OpenVPN3 service restart — re-initializes tray on recovery
            let dbus = dbus_conn.clone();
            let settings = settings_clone.clone();
            let tray = tray_handle_clone.clone();
            glib::spawn_future_local(async move {
                watch_service_restart(&dbus, &settings, &tray).await;
            });
        });

        // --- Activate signal ---
        gtk_app.connect_activate(|_| {
            info!("Application activated");
        });

        // --- Open signal (file associations) ---
        let dbus_conn = dbus_connection.clone();
        let tray_for_open = tray_handle.clone();
        gtk_app.connect_open(move |app, files, _hint| {
            let parent = app.windows().into_iter().next();
            for file in files {
                if let Some(path) = file.path() {
                    info!("Open file: {:?}", path);
                    let dbus = dbus_conn.clone();
                    let tray = tray_for_open.clone();
                    // Clone per iteration: the move closure below captures this,
                    // and `connect_open` may fire multiple times for one window.
                    let p_result = parent.clone();
                    let p_dialog = p_result.clone();
                    crate::dialogs::show_config_import_dialog(
                        p_dialog.as_ref(),
                        path.clone(),
                        move |name, path| {
                            let dbus = dbus.clone();
                            let tray = tray.clone();
                            // Clone per closure invocation: the outer closure is Fn
                            // (may fire several times), but the async block consumes
                            // its captures once.
                            let p_result = p_result.clone();
                            glib::spawn_future_local(async move {
                                let parent: Option<&gtk4::Window> =
                                    p_result.as_ref().map(|w| w.upcast_ref::<gtk4::Window>());
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
