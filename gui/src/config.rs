//! Application constants and metadata
//!
//! No testable pure surface — string constants only.

/// Application name (internal identifier)
pub const APPLICATION_NAME: &str = "openvpn3-gui-rs";

/// Application title (user-visible)
pub const APPLICATION_TITLE: &str = "OpenVPN3 GUI";

/// Application ID (D-Bus name, GApplication ID)
pub const APPLICATION_ID: &str = "net.openvpn.openvpn3_gui_rs";

/// Application version — derived from Cargo.toml at compile time.
pub const APPLICATION_VERSION: &str = env!("CARGO_PKG_VERSION");

/// OpenVPN3 configuration manager D-Bus service name (used to detect restarts)
pub const OPENVPN3_SERVICE: &str = "net.openvpn.v3.configuration";

/// OpenVPN3 sessions manager D-Bus service name. Independent of OPENVPN3_SERVICE:
/// killing only sessionmgr leaves configuration alive, and tray sessions go stale.
pub const OPENVPN3_SESSIONS_SERVICE: &str = "net.openvpn.v3.sessions";

/// Minimum supported OpenVPN3 manager version
pub const MANAGER_VERSION_MINIMUM: u32 = 20;

/// Recommended OpenVPN3 manager version
pub const MANAGER_VERSION_RECOMMENDED: u32 = 21;

/// Minimum supported kill-switch helper version (semver).
/// Bump only when the helper's D-Bus interface changes incompatibly:
/// method removed, required method added, or property type changed.
/// Do NOT bump for helper bug fixes or internal-only changes.
pub const MIN_HELPER_VERSION: &str = "0.1.0";

/// Default icon name
pub const DEFAULT_ICON: &str = "openvpn3-gui-rs-idle";

/// Default status description
pub const DEFAULT_DESCRIPTION: &str = "Unknown";
