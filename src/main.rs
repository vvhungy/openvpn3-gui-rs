//! OpenVPN3 Indicator - A system tray application for managing OpenVPN3 tunnels
//!
//! This is a Rust/GTK4 rewrite of the original Python/GTK3 implementation.

mod app;
mod config;
mod credentials;
mod dbus;
mod dialogs;
mod settings;
mod status;
mod tray;

use clap::Parser;
use glib::ExitCode;
use tracing::{Level, debug, error, info};
use tracing_subscriber::EnvFilter;

use crate::app::{AppArgs, Application};
use crate::config::{APPLICATION_NAME, APPLICATION_VERSION};

/// Command-line arguments
#[derive(Parser, Debug)]
#[command(name = APPLICATION_NAME)]
#[command(version = APPLICATION_VERSION)]
#[command(about = "Simple indicator application for OpenVPN3")]
struct Args {
    /// Show more info (lower log level)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Show debug info
    #[arg(short, long)]
    debug: bool,

    /// Show less info (higher log level)
    #[arg(short, long)]
    silent: bool,

    /// Remove all data stored in secret storage
    #[arg(short, long)]
    clear_secret_storage: bool,
}

fn setup_logging(args: &Args) {
    let level = if args.debug {
        Level::DEBUG
    } else if args.silent {
        Level::ERROR
    } else if args.verbose > 0 {
        Level::INFO
    } else {
        Level::WARN
    };

    let filter = EnvFilter::builder()
        .with_default_directive(level.into())
        .from_env_lossy()
        // Suppress noisy zbus internals (e.g. GTK4's ProvideXdgActivationToken on unsupported compositors)
        .add_directive("zbus=warn".parse().unwrap());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn main() -> ExitCode {
    // Parse arguments, ignoring unknown ones (which will be passed to GTK)
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(e) => {
            // If it's a help or version request, let clap handle it
            e.print().unwrap();
            if e.kind() == clap::error::ErrorKind::DisplayHelp
                || e.kind() == clap::error::ErrorKind::DisplayVersion
            {
                return ExitCode::SUCCESS;
            }
            // Otherwise, try with defaults
            Args {
                verbose: 0,
                debug: false,
                silent: false,
                clear_secret_storage: false,
            }
        }
    };

    setup_logging(&args);

    info!("Starting {APPLICATION_NAME} {APPLICATION_VERSION}");
    debug!("Arguments: {:?}", args);

    // Create tokio runtime for async operations
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    let _guard = rt.enter();

    // Convert args to AppArgs
    let app_args = AppArgs {
        verbose: args.verbose,
        debug: args.debug,
        silent: args.silent,
        clear_secret_storage: args.clear_secret_storage,
    };

    // Run the GTK application
    match Application::run(app_args) {
        Ok(code) => code,
        Err(e) => {
            error!("Application error: {e}");
            ExitCode::FAILURE
        }
    }
}
