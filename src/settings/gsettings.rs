//! GSettings integration
//!
//! Provides type-safe access to application settings stored in GSettings.

use gio::Settings as GioSettings;
use gio::prelude::*;
use tracing::{error, warn};

/// Schema ID for the application settings
const SCHEMA_ID: &str = "net.openvpn.openvpn3-gui-rs";

/// Application settings wrapper
#[derive(Clone)]
pub struct Settings {
    settings: Option<GioSettings>,
}

impl Settings {
    /// Create a new Settings instance
    pub fn new() -> Self {
        // Check if schema is available before creating settings
        let settings = Self::try_new_settings();
        if settings.is_none() {
            warn!(
                "GSettings schema '{}' not found — settings will not be persisted.",
                SCHEMA_ID
            );
        }
        Self { settings }
    }

    /// Try to create a Settings instance, returns None if schema not found
    fn try_new_settings() -> Option<GioSettings> {
        // Check if the schema is available
        let schema_source = gio::SettingsSchemaSource::default()?;
        let _schema = schema_source.lookup(SCHEMA_ID, true)?;
        Some(GioSettings::new(SCHEMA_ID))
    }

    /// Get the startup action
    pub fn startup_action(&self) -> String {
        self.settings
            .as_ref()
            .map(|s| s.string("startup-action").to_string())
            .unwrap_or_default()
    }

    /// Set the startup action
    pub fn set_startup_action(&self, action: &str) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_string("startup-action", action)
        {
            error!("Failed to set startup-action: {}", e);
        }
    }

    /// Get the most recent configuration ID
    pub fn most_recent_config_id(&self) -> String {
        self.settings
            .as_ref()
            .map(|s| s.string("most-recent-config-id").to_string())
            .unwrap_or_default()
    }

    /// Set the most recent configuration ID
    pub fn set_most_recent_config_id(&self, id: &str) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_string("most-recent-config-id", id)
        {
            error!("Failed to set most-recent-config-id: {}", e);
        }
    }

    /// Get the most recent configuration name
    pub fn most_recent_config_name(&self) -> String {
        self.settings
            .as_ref()
            .map(|s| s.string("most-recent-config-name").to_string())
            .unwrap_or_default()
    }

    /// Set the most recent configuration name
    pub fn set_most_recent_config_name(&self, name: &str) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_string("most-recent-config-name", name)
        {
            error!("Failed to set most-recent-config-name: {}", e);
        }
    }

    /// Get the most recent configuration ID and name as a tuple
    pub fn get_most_recent_config(&self) -> (String, String) {
        (self.most_recent_config_id(), self.most_recent_config_name())
    }

    /// Set the most recent configuration
    pub fn set_most_recent_config(&self, id: &str, name: &str) {
        self.set_most_recent_config_id(id);
        self.set_most_recent_config_name(name);
    }

    /// Get specific config path
    pub fn specific_config_path(&self) -> String {
        self.settings
            .as_ref()
            .map(|s| s.string("specific-config-path").to_string())
            .unwrap_or_default()
    }

    /// Set specific config path
    pub fn set_specific_config_path(&self, path: &str) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_string("specific-config-path", path)
        {
            error!("Failed to set specific-config-path: {}", e);
        }
    }

    /// Get the tooltip refresh interval in seconds (default 30)
    pub fn tooltip_refresh_interval(&self) -> u32 {
        self.settings
            .as_ref()
            .map(|s| s.uint("tooltip-refresh-interval"))
            .unwrap_or(30)
            .clamp(10, 300)
    }

    /// Set the tooltip refresh interval in seconds
    pub fn set_tooltip_refresh_interval(&self, secs: u32) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_uint("tooltip-refresh-interval", secs.clamp(10, 300))
        {
            error!("Failed to set tooltip-refresh-interval: {}", e);
        }
    }

    /// Get the connection timeout in seconds (default 30)
    pub fn connection_timeout(&self) -> u32 {
        self.settings
            .as_ref()
            .map(|s| s.uint("connection-timeout"))
            .unwrap_or(30)
            .clamp(5, 300)
    }

    /// Set the connection timeout in seconds
    pub fn set_connection_timeout(&self, secs: u32) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_uint("connection-timeout", secs.clamp(5, 300))
        {
            error!("Failed to set connection-timeout: {}", e);
        }
    }

    /// Check if notifications are enabled
    pub fn show_notifications(&self) -> bool {
        self.settings
            .as_ref()
            .map(|s| s.boolean("show-notifications"))
            .unwrap_or(true)
    }

    /// Set whether notifications are enabled
    pub fn set_show_notifications(&self, enabled: bool) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_boolean("show-notifications", enabled)
        {
            error!("Failed to set show-notifications: {}", e);
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl Settings {
    /// Construct a Settings with no backing schema (for unit tests).
    fn new_empty() -> Self {
        Self { settings: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Fallback behaviour when GSettings schema is absent ---

    #[test]
    fn test_startup_action_default() {
        assert_eq!(Settings::new_empty().startup_action(), "");
    }

    #[test]
    fn test_show_notifications_default() {
        assert!(Settings::new_empty().show_notifications());
    }

    #[test]
    fn test_most_recent_config_default() {
        let s = Settings::new_empty();
        assert_eq!(s.get_most_recent_config(), ("".into(), "".into()));
    }

    #[test]
    fn test_specific_config_path_default() {
        assert_eq!(Settings::new_empty().specific_config_path(), "");
    }

    // --- Setters do not panic when schema is absent ---

    #[test]
    fn test_set_startup_action_no_panic() {
        Settings::new_empty().set_startup_action("connect-recent");
    }

    #[test]
    fn test_set_most_recent_config_no_panic() {
        Settings::new_empty().set_most_recent_config("/some/path", "My VPN");
    }

    #[test]
    fn test_set_show_notifications_no_panic() {
        Settings::new_empty().set_show_notifications(false);
    }

    #[test]
    fn test_tooltip_refresh_interval_default() {
        assert_eq!(Settings::new_empty().tooltip_refresh_interval(), 30);
    }

    #[test]
    fn test_set_tooltip_refresh_interval_no_panic() {
        Settings::new_empty().set_tooltip_refresh_interval(60);
    }

    #[test]
    fn test_connection_timeout_default() {
        assert_eq!(Settings::new_empty().connection_timeout(), 30);
    }

    #[test]
    fn test_set_connection_timeout_no_panic() {
        Settings::new_empty().set_connection_timeout(60);
    }
}
