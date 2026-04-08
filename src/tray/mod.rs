//! System tray module

mod indicator;
mod menu;
mod shared_state;

pub use indicator::{ActionSender, ConfigInfo, SessionInfo, TrayAction, VpnTray};
