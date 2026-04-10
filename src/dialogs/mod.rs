//! Dialogs module

mod about;
mod configuration;
mod credentials;
mod logs;
mod notification;
mod preferences;

pub use about::show_about_dialog;
pub use configuration::{
    show_config_import_dialog, show_config_remove_dialog, show_config_select_dialog,
};
pub use credentials::{CredentialField, show_challenge_dialog, show_credentials_dialog};
pub use logs::show_session_log_dialog;
pub use notification::{
    show_connection_notification, show_error_notification, show_info_notification,
    show_reconnect_notification,
};
pub use preferences::show_preferences_dialog;
