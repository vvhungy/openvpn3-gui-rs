//! D-Bus proxies for OpenVPN3 Session Manager
//!
//! No testable pure surface — declarative `#[zbus::proxy]` traits.

use zbus::proxy;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

/// Session Manager D-Bus proxy
///
/// Interface: `net.openvpn.v3.sessions`
/// Service: `net.openvpn.v3.sessions`
/// Path: `/net/openvpn/v3/sessions`
#[proxy(
    interface = "net.openvpn.v3.sessions",
    default_service = "net.openvpn.v3.sessions",
    default_path = "/net/openvpn/v3/sessions"
)]
pub trait SessionManager {
    /// Create a new tunnel from a configuration
    fn NewTunnel(&self, config_path: ObjectPath<'_>) -> zbus::Result<OwnedObjectPath>;

    /// Fetch all available session paths
    fn FetchAvailableSessions(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Lookup sessions by configuration name
    fn LookupConfigName(&self, name: &str) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Transfer ownership of a session
    fn TransferOwnership(&self, session_path: ObjectPath<'_>, uid: u32) -> zbus::Result<()>;

    /// Signal emitted when a session is created or destroyed
    /// D-Bus signature: (oqu) = (session_path, event_type, owner_uid)
    #[zbus(signal)]
    fn SessionManagerEvent(
        &self,
        session_path: OwnedObjectPath,
        event_type: u16,
        owner_uid: u32,
    ) -> zbus::Result<()>;

    /// Get the manager version (via Properties interface)
    #[zbus(property, name = "version")]
    fn version(&self) -> zbus::Result<String>;
}

/// Individual Session D-Bus proxy
///
/// Interface: `net.openvpn.v3.sessions`
/// Service: `net.openvpn.v3.sessions`
/// Path: Dynamic (e.g., `/net/openvpn/v3/sessions/sess_12345`)
#[proxy(
    interface = "net.openvpn.v3.sessions",
    default_service = "net.openvpn.v3.sessions"
)]
pub trait Session {
    /// Signal that the session is ready to connect
    fn Ready(&self) -> zbus::Result<()>;

    /// Start the VPN connection
    fn Connect(&self) -> zbus::Result<()>;

    /// Disconnect and shut down the session
    fn Disconnect(&self) -> zbus::Result<()>;

    /// Pause the connection
    fn Pause(&self, reason: &str) -> zbus::Result<()>;

    /// Resume a paused connection
    fn Resume(&self) -> zbus::Result<()>;

    /// Restart the connection
    fn Restart(&self) -> zbus::Result<()>;

    /// Enable or disable log forwarding
    fn LogForward(&self, enable: bool) -> zbus::Result<()>;

    /// Get the list of (type, group) pairs needing user input
    fn UserInputQueueGetTypeGroup(&self) -> zbus::Result<Vec<(u32, u32)>>;

    /// Get queue IDs for a given (type, group)
    fn UserInputQueueCheck(&self, attention_type: u32, group: u32) -> zbus::Result<Vec<u32>>;

    /// Fetch a specific user input slot
    /// Returns (type, group, id, label, description, mask)
    fn UserInputQueueFetch(
        &self,
        attention_type: u32,
        group: u32,
        id: u32,
    ) -> zbus::Result<(u32, u32, u32, String, String, bool)>;

    /// Provide user input
    fn UserInputProvide(
        &self,
        attention_type: u32,
        group: u32,
        id: u32,
        value: &str,
    ) -> zbus::Result<()>;

    /// Get the session status as (major, minor, message)
    #[zbus(property, name = "status")]
    fn status(&self) -> zbus::Result<(u32, u32, String)>;

    /// Get the config name associated with this session
    #[zbus(property, name = "config_name")]
    fn config_name(&self) -> zbus::Result<String>;

    /// Get the config path associated with this session
    #[zbus(property, name = "config_path")]
    fn config_path(&self) -> zbus::Result<OwnedObjectPath>;

    /// Get connection statistics (BYTES_IN, BYTES_OUT, etc.)
    #[zbus(property, name = "statistics")]
    fn statistics(&self) -> zbus::Result<std::collections::HashMap<String, i64>>;

    /// Get connected-to info: (protocol, address, port)
    #[zbus(property, name = "connected_to")]
    fn connected_to(&self) -> zbus::Result<(String, String, u32)>;

    /// Virtual network interface name used by this session (e.g. "tun0").
    /// Read after the session reaches the connected state.
    #[zbus(property, name = "device_name")]
    fn device_name(&self) -> zbus::Result<String>;
}

/// Backend signals interface (received from net.openvpn.v3.log)
///
/// Interface: `net.openvpn.v3.backends`
/// Service: `net.openvpn.v3.log`
/// Path: Session object path
#[proxy(
    interface = "net.openvpn.v3.backends",
    default_service = "net.openvpn.v3.log"
)]
pub trait BackendSignals {
    /// Status change signal
    #[zbus(signal)]
    fn StatusChange(&self, major: u32, minor: u32, message: &str) -> zbus::Result<()>;

    /// Log signal
    #[zbus(signal)]
    fn Log(&self, group: u32, category: u32, message: &str) -> zbus::Result<()>;
}
