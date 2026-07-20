//! System tray module

mod indicator;
mod lookup;
mod menu;
mod pixmaps;
mod shared_state;

pub(crate) use lookup::{
    FALLBACK_NAME, config_exists, resolve_config_name, resolve_config_name_or,
    session_config_identity, session_config_name,
};

pub use indicator::{ActionSender, BypassState, ConfigInfo, SessionInfo, TrayAction, VpnTray};
