//! System tray module

mod indicator;
mod shared_state;

pub use indicator::{ActionSender, ConfigInfo, SessionInfo, TrayAction, VpnTray};
