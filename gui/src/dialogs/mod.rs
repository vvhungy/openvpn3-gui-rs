//! Dialogs module

mod about;
mod configuration;
mod credentials;
pub(crate) mod layout;
mod logs;
mod notification;
mod preferences;

pub use about::show_about_dialog;
pub use configuration::{
    show_config_import_dialog, show_config_remove_dialog, show_config_select_dialog,
};
pub use credentials::{CredentialField, show_challenge_dialog, show_credentials_dialog};
pub use logs::show_log_viewer;
pub use notification::{
    show_connection_notification, show_error_notification, show_first_run_help_notification,
    show_info_notification, show_reconnect_notification, withdraw_first_run_help_notification,
};
pub use preferences::show_preferences_dialog;
