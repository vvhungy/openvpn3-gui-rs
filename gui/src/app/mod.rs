//! Application module
//!
//! No testable pure surface — thread-local parent-window slot + module re-exports.

use std::cell::RefCell;

thread_local! {
    /// Hidden ApplicationWindow used as transient parent for all dialogs.
    /// Set once at startup; accessible from any code running on the GTK thread.
    static DIALOG_PARENT: RefCell<Option<gtk4::ApplicationWindow>> =
        const { RefCell::new(None) };
}

/// Store the hidden parent window (called once from application startup).
pub(crate) fn set_dialog_parent(w: gtk4::ApplicationWindow) {
    DIALOG_PARENT.with(|cell| *cell.borrow_mut() = Some(w));
}

/// Retrieve a clone of the hidden parent window for use as a dialog transient parent.
pub(crate) fn dialog_parent() -> Option<gtk4::ApplicationWindow> {
    DIALOG_PARENT.with(|cell| cell.borrow().clone())
}

mod actions;
mod application;
mod auth_dispatch;
mod auth_handlers;
mod challenge_handler;
mod config_ops;
mod credential_handler;
mod dbus_init;
pub(crate) mod log_buffer;
mod session_ops;
mod signal_handlers;
mod stats_poller;
mod status_handler;
pub(crate) use status_handler::apply_kill_switch;
mod timeout_watcher;

pub use application::{AppArgs, Application};
