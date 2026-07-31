//! Desktop notifications
//!
//! Sends notifications via org.freedesktop.Notifications D-Bus interface,
//! which works without a .desktop file installed.

mod bypass;
mod core;
mod dedup;
mod interactive;
mod killswitch;

/// Drop every tracked notification `replaces_id`. Exposed so the session
/// lifecycle can prune the dedup map when the sessions service vanishes
/// permanently (#2, T4) — at that point every toast it tracked is stale.
pub(crate) fn clear_notification_dedup() {
    dedup::clear_all();
}

pub use bypass::{
    show_bypass_active_notification, show_bypass_drift_notification,
    show_bypass_failed_notification, show_bypass_partial_notification,
    show_bypass_recovered_notification,
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
