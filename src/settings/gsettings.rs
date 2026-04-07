//! GSettings integration
//!
//! Provides type-safe access to application settings stored in GSettings.

use gio::Settings as GioSettings;
use gio::prelude::*;

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
            eprintln!("Warning: GSettings schema '{}' not found. Settings will not be persisted.", SCHEMA_ID);
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

    /// Create Settings with a specific GioSettings instance (for testing)
    pub fn new_with_settings(settings: GioSettings) -> Self {
        Self { settings: Some(settings) }
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
        if let Some(settings) = &self.settings {
            if let Err(e) = settings.set_string("startup-action", action) {
                eprintln!("Failed to set startup-action: {}", e);
            }
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
        if let Some(settings) = &self.settings {
            if let Err(e) = settings.set_string("most-recent-config-id", id) {
                eprintln!("Failed to set most-recent-config-id: {}", e);
            }
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
        if let Some(settings) = &self.settings {
            if let Err(e) = settings.set_string("most-recent-config-name", name) {
                eprintln!("Failed to set most-recent-config-name: {}", e);
            }
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

    /// Set the most recent config (alias for compatibility)
    pub fn set_most_recent_config_path(&self, path: &str, name: &str) {
        self.set_most_recent_config(path, name);
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
        if let Some(settings) = &self.settings {
            if let Err(e) = settings.set_string("specific-config-path", path) {
                eprintln!("Failed to set specific-config-path: {}", e);
            }
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
        if let Some(settings) = &self.settings {
            if let Err(e) = settings.set_boolean("show-notifications", enabled) {
                eprintln!("Failed to set show-notifications: {}", e);
            }
        }
    }

    /// Check if should restore on startup
    pub fn should_restore_on_startup(&self) -> bool {
        self.startup_action() == "restore"
    }

    /// Check if should connect to most recent on startup
    pub fn should_connect_recent_on_startup(&self) -> bool {
        self.startup_action() == "connect-recent"
    }

    /// Check if should connect to specific config on startup
    pub fn should_connect_specific_on_startup(&self) -> bool {
        self.startup_action() == "connect-specific"
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::new()
    }
}
