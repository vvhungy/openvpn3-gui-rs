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

    /// Get the stats refresh interval in seconds (default 30)
    pub fn stats_refresh_interval(&self) -> u32 {
        self.settings
            .as_ref()
            .map(|s| s.uint("stats-refresh-interval"))
            .unwrap_or(30)
            .clamp(10, 300)
    }

    /// Set the stats refresh interval in seconds
    pub fn set_stats_refresh_interval(&self, secs: u32) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_uint("stats-refresh-interval", secs.clamp(10, 300))
        {
            error!("Failed to set stats-refresh-interval: {}", e);
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

    /// Get the stall detection threshold in seconds (default 60; 0 = disabled)
    pub fn health_check_stall_seconds(&self) -> u32 {
        self.settings
            .as_ref()
            .map(|s| s.uint("health-check-stall-seconds"))
            .unwrap_or(60)
            .clamp(0, 600)
    }

    /// Set the stall detection threshold in seconds
    pub fn set_health_check_stall_seconds(&self, secs: u32) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_uint("health-check-stall-seconds", secs.clamp(0, 600))
        {
            error!("Failed to set health-check-stall-seconds: {}", e);
        }
    }

    /// Check if the unexpected-disconnect warning is enabled (default true)
    pub fn warn_on_unexpected_disconnect(&self) -> bool {
        self.settings
            .as_ref()
            .map(|s| s.boolean("warn-on-unexpected-disconnect"))
            .unwrap_or(true)
    }

    /// Set whether the unexpected-disconnect warning is enabled
    pub fn set_warn_on_unexpected_disconnect(&self, enabled: bool) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_boolean("warn-on-unexpected-disconnect", enabled)
        {
            error!("Failed to set warn-on-unexpected-disconnect: {}", e);
        }
    }

    /// Auto-reconnect after unexpected disconnect (default false)
    pub fn auto_reconnect(&self) -> bool {
        self.settings
            .as_ref()
            .map(|s| s.boolean("auto-reconnect"))
            .unwrap_or(false)
    }

    pub fn set_auto_reconnect(&self, enabled: bool) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_boolean("auto-reconnect", enabled)
        {
            error!("Failed to set auto-reconnect: {}", e);
        }
    }

    /// Auto-reconnect delay in seconds (default 30, clamped 5..=300)
    pub fn auto_reconnect_delay_seconds(&self) -> u32 {
        self.settings
            .as_ref()
            .map(|s| s.uint("auto-reconnect-delay-seconds"))
            .unwrap_or(30)
            .clamp(5, 300)
    }

    pub fn set_auto_reconnect_delay_seconds(&self, secs: u32) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_uint("auto-reconnect-delay-seconds", secs.clamp(5, 300))
        {
            error!("Failed to set auto-reconnect-delay-seconds: {}", e);
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

    /// Check if the kill-switch is enabled (default false)
    pub fn enable_kill_switch(&self) -> bool {
        self.settings
            .as_ref()
            .map(|s| s.boolean("enable-kill-switch"))
            .unwrap_or(false)
    }

    /// Set whether the kill-switch is enabled
    pub fn set_enable_kill_switch(&self, enabled: bool) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_boolean("enable-kill-switch", enabled)
        {
            error!("Failed to set enable-kill-switch: {}", e);
        }
    }

    /// Check if LAN traffic is allowed under the kill-switch (default true)
    pub fn kill_switch_allow_lan(&self) -> bool {
        self.settings
            .as_ref()
            .map(|s| s.boolean("kill-switch-allow-lan"))
            .unwrap_or(true)
    }

    /// Set whether LAN traffic is allowed under the kill-switch
    pub fn set_kill_switch_allow_lan(&self, enabled: bool) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_boolean("kill-switch-allow-lan", enabled)
        {
            error!("Failed to set kill-switch-allow-lan: {}", e);
        }
    }

    /// Check if first-run help notification is enabled (default true)
    pub fn show_first_run_help(&self) -> bool {
        self.settings
            .as_ref()
            .map(|s| s.boolean("show-first-run-help"))
            .unwrap_or(true)
    }

    /// Set whether first-run help notification is enabled
    pub fn set_show_first_run_help(&self, enabled: bool) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_boolean("show-first-run-help", enabled)
        {
            error!("Failed to set show-first-run-help: {}", e);
        }
    }

    /// Launch-on-login mirror. Filesystem (`autostart::is_enabled`) is the
    /// source of truth; this key is re-synced from disk on startup.
    pub fn launch_on_login(&self) -> bool {
        self.settings
            .as_ref()
            .map(|s| s.boolean("launch-on-login"))
            .unwrap_or(false)
    }

    /// Persist the launch-on-login mirror.
    pub fn set_launch_on_login(&self, enabled: bool) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_boolean("launch-on-login", enabled)
        {
            error!("Failed to set launch-on-login: {}", e);
        }
    }

    pub fn kill_switch_block_during_pause(&self) -> bool {
        self.settings
            .as_ref()
            .map(|s| s.boolean("kill-switch-block-during-pause"))
            .unwrap_or(false)
    }

    pub fn set_kill_switch_block_during_pause(&self, enabled: bool) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_boolean("kill-switch-block-during-pause", enabled)
        {
            error!("Failed to set kill-switch-block-during-pause: {}", e);
        }
    }

    /// Bypass CIDR list — CIDRs routed via the physical interface outside the
    /// VPN tunnel. Empty list means no split-tunneling.
    pub fn bypass_cidrs(&self) -> Vec<String> {
        self.settings
            .as_ref()
            .map(|s| {
                s.strv("bypass-cidrs")
                    .into_iter()
                    .map(|g| g.to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Persist the bypass CIDR list. The list is the user's *intent* (durable);
    /// the helper re-validates at the trust boundary on every `SetBypassCidrs`
    /// call.
    #[allow(dead_code)] // T3 ships plumbing; first call site lands in T4 (Preferences).
    pub fn set_bypass_cidrs(&self, cidrs: &[String]) {
        if let Some(settings) = &self.settings {
            let values: Vec<&str> = cidrs.iter().map(|s| s.as_str()).collect();
            if let Err(e) = settings.set_strv("bypass-cidrs", values) {
                error!("Failed to set bypass-cidrs: {}", e);
            }
        }
    }

    /// Bypass CIDR entries temporarily disabled by the user (subset of
    /// `bypass_cidrs`). Filtered out before pushing to the helper.
    pub fn bypass_cidrs_disabled(&self) -> Vec<String> {
        self.settings
            .as_ref()
            .map(|s| {
                s.strv("bypass-cidrs-disabled")
                    .into_iter()
                    .map(|g| g.to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Persist the disabled-bypass-CIDR list.
    pub fn set_bypass_cidrs_disabled(&self, cidrs: &[String]) {
        if let Some(settings) = &self.settings {
            let values: Vec<&str> = cidrs.iter().map(|s| s.as_str()).collect();
            if let Err(e) = settings.set_strv("bypass-cidrs-disabled", values) {
                error!("Failed to set bypass-cidrs-disabled: {}", e);
            }
        }
    }

    /// User-facing limit on the number of bypass CIDR entries. Clamped to
    /// [1, 128] where 128 is the helper's hard ceiling.
    #[allow(dead_code)] // T3 ships plumbing; first call site lands in T4 (Preferences).
    pub fn bypass_cidrs_max_count(&self) -> i32 {
        self.settings
            .as_ref()
            .map(|s| s.int("bypass-cidrs-max-count"))
            .unwrap_or(32)
            .clamp(1, 128)
    }

    /// Persisted logs viewer window width in pixels (default 800, clamped 400..=4000).
    pub fn logs_window_width(&self) -> i32 {
        self.settings
            .as_ref()
            .map(|s| s.int("logs-window-width"))
            .unwrap_or(800)
            .clamp(400, 4000)
    }

    /// Persist logs viewer window width in pixels.
    pub fn set_logs_window_width(&self, px: i32) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_int("logs-window-width", px.clamp(400, 4000))
        {
            error!("Failed to set logs-window-width: {}", e);
        }
    }

    /// Persisted logs viewer window height in pixels (default 600, clamped 300..=3000).
    pub fn logs_window_height(&self) -> i32 {
        self.settings
            .as_ref()
            .map(|s| s.int("logs-window-height"))
            .unwrap_or(600)
            .clamp(300, 3000)
    }

    /// Persist logs viewer window height in pixels.
    pub fn set_logs_window_height(&self, px: i32) {
        if let Some(settings) = &self.settings
            && let Err(e) = settings.set_int("logs-window-height", px.clamp(300, 3000))
        {
            error!("Failed to set logs-window-height: {}", e);
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
    pub(super) fn new_empty() -> Self {
        Self { settings: None }
    }
}

#[cfg(test)]
#[path = "gsettings_tests.rs"]
mod gsettings_tests;
