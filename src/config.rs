//! Application constants and metadata

/// Application name (internal identifier)
pub const APPLICATION_NAME: &str = "openvpn3-gui-rs";

/// Application title (user-visible)
pub const APPLICATION_TITLE: &str = "OpenVPN3 GUI";

/// Application ID (D-Bus name, GApplication ID)
pub const APPLICATION_ID: &str = "net.openvpn.openvpn3_gui_rs";

/// Application version
pub const APPLICATION_VERSION: &str = "0.2.0";

/// OpenVPN3 configuration manager D-Bus service name (used to detect restarts)
pub const OPENVPN3_SERVICE: &str = "net.openvpn.v3.configuration";

/// Minimum supported OpenVPN3 manager version
pub const MANAGER_VERSION_MINIMUM: u32 = 20;

/// Recommended OpenVPN3 manager version
pub const MANAGER_VERSION_RECOMMENDED: u32 = 21;

/// Default icon name
pub const DEFAULT_ICON: &str = "openvpn3-gui-rs-idle";

/// Default status description
pub const DEFAULT_DESCRIPTION: &str = "Unknown";
