//! System tray module

mod indicator;
mod lookup;
mod menu;
mod pixmaps;
mod shared_state;

pub(crate) use lookup::{
    FALLBACK_NAME, resolve_config_name, session_config_identity, session_config_name,
};

pub use indicator::{ActionSender, BypassState, ConfigInfo, SessionInfo, TrayAction, VpnTray};
