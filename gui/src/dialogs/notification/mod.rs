//! Desktop notifications
//!
//! Sends notifications via org.freedesktop.Notifications D-Bus interface,
//! which works without a .desktop file installed.

mod bypass;
mod core;
mod dedup;
mod interactive;
mod killswitch;

pub use bypass::{
    show_bypass_active_notification, show_bypass_drift_notification,
    show_bypass_failed_notification, show_bypass_partial_notification,
};
pub use core::{show_connection_notification, show_error_notification, show_info_notification};
pub use interactive::{
    show_first_run_help_notification, show_reconnect_notification,
    withdraw_first_run_help_notification,
};
pub use killswitch::{
    show_helper_missing_notification, show_killswitch_active_notification,
    show_killswitch_inactive_notification,
};
