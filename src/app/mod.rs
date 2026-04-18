//! Application module

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
mod challenge_handler;
mod config_ops;
mod credential_handler;
mod dbus_init;
pub(crate) mod log_buffer;
mod session_ops;
mod signal_handlers;
mod status_handler;

pub use application::{AppArgs, Application};
