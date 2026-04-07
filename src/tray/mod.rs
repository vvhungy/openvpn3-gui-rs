//! System tray module

mod indicator;
mod shared_state;

pub use indicator::{ConfigInfo, SessionInfo, TrayAction, VpnTray};
