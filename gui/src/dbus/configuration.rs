//! D-Bus proxies for OpenVPN3 Configuration Manager
//!
//! No testable pure surface — declarative `#[zbus::proxy]` traits.

use zbus::proxy;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, Value};

/// Configuration Manager D-Bus proxy
///
/// Interface: `net.openvpn.v3.configuration`
/// Service: `net.openvpn.v3.configuration`
/// Path: `/net/openvpn/v3/configuration`
#[proxy(
    interface = "net.openvpn.v3.configuration",
    default_service = "net.openvpn.v3.configuration",
    default_path = "/net/openvpn/v3/configuration"
)]
pub trait ConfigurationManager {
    /// Import a new configuration
    fn Import(
        &self,
        name: &str,
        config: &str,
        single_use: bool,
        persistent: bool,
    ) -> zbus::Result<OwnedObjectPath>;

    /// Fetch all available configuration paths
    fn FetchAvailableConfigs(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Lookup configurations by name
    fn LookupConfigName(&self, name: &str) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Search configurations by tag
    fn SearchByTag(&self, tag: &str) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Transfer ownership of a configuration
    fn TransferOwnership(&self, config_path: ObjectPath<'_>, uid: u32) -> zbus::Result<()>;

    /// Get the manager version (via Properties interface)
    #[zbus(property, name = "version")]
    fn version(&self) -> zbus::Result<String>;
}

/// Individual Configuration D-Bus proxy
///
/// Interface: `net.openvpn.v3.configuration`
/// Service: `net.openvpn.v3.configuration`
/// Path: Dynamic (e.g., `/net/openvpn/v3/configuration/cfg_12345`)
#[proxy(
    interface = "net.openvpn.v3.configuration",
    default_service = "net.openvpn.v3.configuration"
)]
pub trait Configuration {
    /// Remove this configuration
    fn Remove(&self) -> zbus::Result<()>;

    /// Fetch configuration as text
    fn Fetch(&self) -> zbus::Result<String>;

    /// Fetch configuration as JSON
    fn FetchJSON(&self) -> zbus::Result<String>;

    /// Validate the configuration (v22+)
    fn Validate(&self) -> zbus::Result<()>;

    /// Add a tag to the configuration
    fn AddTag(&self, tag: &str) -> zbus::Result<()>;

    /// Remove a tag from the configuration
    fn RemoveTag(&self, tag: &str) -> zbus::Result<()>;

    /// Set an override parameter
    fn SetOverride(&self, key: &str, value: Value<'_>) -> zbus::Result<()>;

    /// Unset an override parameter
    fn UnsetOverride(&self, key: &str) -> zbus::Result<()>;

    /// Seal the configuration (prevent modifications)
    fn Seal(&self) -> zbus::Result<()>;

    /// Grant access to a UID
    fn AccessGrant(&self, uid: u32) -> zbus::Result<()>;

    /// Revoke access from a UID
    fn AccessRevoke(&self, uid: u32) -> zbus::Result<()>;

    /// Get the configuration name
    #[zbus(property, name = "name")]
    fn name(&self) -> zbus::Result<String>;

    /// Get the configuration tags
    #[zbus(property, name = "tags")]
    fn tags(&self) -> zbus::Result<Vec<String>>;
}
