//! Tray indicator using ksni (StatusNotifierItem + dbusmenu)

use std::collections::HashMap;

use futures::channel::mpsc::UnboundedSender;
use ksni::{self, MenuItem, ToolTip};

use crate::dbus::types::SessionStatus;
use crate::status::{get_status_description, get_status_icon};
use tracing::error;

/// Action to dispatch from tray menu clicks back to the GTK app
#[derive(Debug, Clone)]
pub enum TrayAction {
    Connect(String),           // config D-Bus path
    Disconnect(String),        // session D-Bus path
    Pause(String),             // session D-Bus path
    Resume(String),            // session D-Bus path
    Restart(String),           // session D-Bus path
    Reconnect(String, String), // (session_path, config_path) for disconnected/error sessions
    RemoveConfig(String),      // config D-Bus path
    ImportConfig,
    About,
    Quit,

    Preferences,
    ViewLogs,
}

/// A known VPN configuration
#[derive(Debug, Clone)]
pub struct ConfigInfo {
    pub path: String,
    pub name: String,
}

/// An active VPN session
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_path: String,
    pub config_path: String,
    pub config_name: String,
    pub status: SessionStatus,
    pub connected_at: Option<std::time::Instant>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl SessionInfo {
    pub fn status_label(&self) -> String {
        let desc = get_status_description(self.status.major, self.status.minor);
        if self.status.is_connected() && (self.bytes_in > 0 || self.bytes_out > 0) {
            format!(
                "{}: {} ↓ {} ↑ {}",
                self.config_name,
                desc,
                format_bytes(self.bytes_in),
                format_bytes(self.bytes_out)
            )
        } else {
            format!("{}: {}", self.config_name, desc)
        }
    }

    fn tooltip_line(&self) -> String {
        let desc = get_status_description(self.status.major, self.status.minor);
        if self.status.is_connected()
            && let Some(at) = self.connected_at
        {
            let secs = at.elapsed().as_secs();
            let duration = if secs < 60 {
                format!("{}s", secs)
            } else if secs < 3600 {
                format!("{}m {}s", secs / 60, secs % 60)
            } else {
                format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
            };
            let stats = if self.bytes_in > 0 || self.bytes_out > 0 {
                format!(
                    " | {} | {}",
                    format_bytes(self.bytes_in),
                    format_bytes(self.bytes_out)
                )
            } else {
                String::new()
            };
            return format!("{} — {} ({}{})", self.config_name, desc, duration, stats);
        }
        format!("{} — {}", self.config_name, desc)
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Channel sender for dispatching tray actions to the GTK main loop
pub type ActionSender = UnboundedSender<TrayAction>;

/// The tray state, owned by ksni
pub struct VpnTray {
    /// Available configurations
    pub configs: Vec<ConfigInfo>,
    /// Active sessions (keyed by session D-Bus path)
    pub sessions: HashMap<String, SessionInfo>,
    /// Channel to send actions to the GTK main loop
    pub action_tx: ActionSender,
}

impl VpnTray {
    pub fn new(action_tx: ActionSender) -> Self {
        Self {
            configs: Vec::new(),
            sessions: HashMap::new(),
            action_tx,
        }
    }

    /// Get the icon theme paths where our custom icons are installed
    fn icon_theme_paths() -> String {
        // Check common install locations
        for path in &[
            format!(
                "{}/.local/share/icons",
                std::env::var("HOME").unwrap_or_default()
            ),
            "/usr/local/share/icons".to_string(),
            "/usr/share/icons".to_string(),
        ] {
            if std::path::Path::new(path).exists() {
                return path.clone();
            }
        }
        String::new()
    }

    /// Determine the aggregate icon based on all session states
    fn current_icon(&self) -> &'static str {
        if self.sessions.is_empty() {
            return "openvpn3-gui-rs-idle";
        }

        // Priority: error > loading > active > paused > idle
        let mut has_error = false;
        let mut has_loading = false;
        let mut has_active = false;
        let mut has_paused = false;

        for session in self.sessions.values() {
            let icon = get_status_icon(session.status.major, session.status.minor);
            match icon {
                "openvpn3-gui-rs-idle-error" => has_error = true,
                "openvpn3-gui-rs-loading" => has_loading = true,
                "openvpn3-gui-rs-active" => has_active = true,
                "openvpn3-gui-rs-paused" => has_paused = true,
                _ => {}
            }
        }

        if has_error {
            "openvpn3-gui-rs-idle-error"
        } else if has_loading {
            "openvpn3-gui-rs-loading"
        } else if has_active {
            "openvpn3-gui-rs-active"
        } else if has_paused {
            "openvpn3-gui-rs-paused"
        } else {
            "openvpn3-gui-rs-idle"
        }
    }

    /// Send an action to the GTK main loop
    pub(super) fn send_action(&self, action: TrayAction) {
        if let Err(e) = self.action_tx.unbounded_send(action) {
            error!("Failed to send tray action: {}", e);
        }
    }
}

impl ksni::Tray for VpnTray {
    fn id(&self) -> String {
        "openvpn3-gui-rs".into()
    }

    fn category(&self) -> ksni::Category {
        ksni::Category::SystemServices
    }

    fn title(&self) -> String {
        "OpenVPN3 Indicator".into()
    }

    fn icon_name(&self) -> String {
        self.current_icon().into()
    }

    fn icon_theme_path(&self) -> String {
        Self::icon_theme_paths()
    }

    fn tool_tip(&self) -> ToolTip {
        let description = if self.sessions.is_empty() {
            "No active connections".to_string()
        } else {
            self.sessions
                .values()
                .map(|s| s.tooltip_line())
                .collect::<Vec<_>>()
                .join("\n")
        };

        ToolTip {
            title: "OpenVPN3 GUI".into(),
            description,
            ..Default::default()
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        super::menu::build_menu(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbus::types::{SessionStatus, StatusMajor, StatusMinor};

    fn make_session(major: StatusMajor, minor: StatusMinor, name: &str) -> SessionInfo {
        SessionInfo {
            session_path: "/test/path".into(),
            config_path: "/test/config".into(),
            config_name: name.into(),
            status: SessionStatus { major, minor },
            connected_at: None,
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    #[test]
    fn test_status_label_format() {
        let s = make_session(StatusMajor::Connection, StatusMinor::ConnConnected, "MyVPN");
        assert_eq!(s.status_label(), "MyVPN: Connected");
    }

    #[test]
    fn test_status_label_with_stats() {
        let mut s = make_session(StatusMajor::Connection, StatusMinor::ConnConnected, "MyVPN");
        s.bytes_in = 1024 * 1024 * 42; // 42 MB
        s.bytes_out = 1024 * 1024 * 33; // 33 MB
        assert_eq!(s.status_label(), "MyVPN: Connected ↓ 42.0 MB ↑ 33.0 MB");
    }

    #[test]
    fn test_status_label_disconnected() {
        let s = make_session(
            StatusMajor::Connection,
            StatusMinor::ConnDisconnected,
            "Work VPN",
        );
        assert_eq!(s.status_label(), "Work VPN: Disconnected");
    }

    #[test]
    fn test_tooltip_line_not_connected() {
        let s = make_session(
            StatusMajor::Connection,
            StatusMinor::ConnConnecting,
            "MyVPN",
        );
        assert_eq!(s.tooltip_line(), "MyVPN — Connecting");
    }

    #[test]
    fn test_tooltip_line_connected_no_timer() {
        // Connected but no connected_at set — no duration shown
        let s = make_session(StatusMajor::Connection, StatusMinor::ConnConnected, "MyVPN");
        assert_eq!(s.tooltip_line(), "MyVPN — Connected");
    }

    #[test]
    fn test_tooltip_line_connected_with_timer() {
        let mut s = make_session(StatusMajor::Connection, StatusMinor::ConnConnected, "MyVPN");
        s.connected_at = Some(std::time::Instant::now());
        let line = s.tooltip_line();
        // Should contain duration suffix in parentheses
        assert!(line.starts_with("MyVPN — Connected ("), "got: {}", line);
    }

    #[test]
    fn test_tooltip_line_unset() {
        let s = make_session(StatusMajor::Unset, StatusMinor::Unset, "MyVPN");
        assert_eq!(s.tooltip_line(), "MyVPN — Unknown");
    }
}
