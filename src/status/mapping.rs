//! Status to icon and description mapping

use crate::config::{DEFAULT_DESCRIPTION, DEFAULT_ICON};
use crate::dbus::types::{StatusMajor, StatusMinor};

/// Get the icon name for a given status
pub fn get_status_icon(major: StatusMajor, minor: StatusMinor) -> &'static str {
    match (major, minor) {
        // Active (connected)
        (StatusMajor::Connection, StatusMinor::ConnConnected) => "openvpn3-gui-rs-active",

        // Paused
        (StatusMajor::Connection, StatusMinor::ConnPaused) => "openvpn3-gui-rs-paused",

        // Loading states
        (StatusMajor::Connection, StatusMinor::CfgOk) => "openvpn3-gui-rs-loading",
        (StatusMajor::Connection, StatusMinor::CfgRequireUser) => "openvpn3-gui-rs-loading",
        (StatusMajor::Connection, StatusMinor::ConnInit) => "openvpn3-gui-rs-loading",
        (StatusMajor::Connection, StatusMinor::ConnConnecting) => "openvpn3-gui-rs-loading",
        (StatusMajor::Connection, StatusMinor::ConnDisconnecting) => "openvpn3-gui-rs-loading",
        (StatusMajor::Connection, StatusMinor::ConnReconnecting) => "openvpn3-gui-rs-loading",
        (StatusMajor::Connection, StatusMinor::ConnPausing) => "openvpn3-gui-rs-loading",
        (StatusMajor::Connection, StatusMinor::ConnResuming) => "openvpn3-gui-rs-loading",
        (StatusMajor::Session, StatusMinor::SessNew) => "openvpn3-gui-rs-loading",
        (StatusMajor::Session, StatusMinor::SessBackendCompleted) => "openvpn3-gui-rs-loading",
        (StatusMajor::Session, StatusMinor::SessAuthUserpass) => "openvpn3-gui-rs-loading",
        (StatusMajor::Session, StatusMinor::SessAuthChallenge) => "openvpn3-gui-rs-loading",
        (StatusMajor::Session, StatusMinor::SessAuthUrl) => "openvpn3-gui-rs-loading",
        (StatusMajor::Pkcs11, StatusMinor::Pkcs11Sign) => "openvpn3-gui-rs-loading",
        (StatusMajor::Pkcs11, StatusMinor::Pkcs11Encrypt) => "openvpn3-gui-rs-loading",
        (StatusMajor::Pkcs11, StatusMinor::Pkcs11Decrypt) => "openvpn3-gui-rs-loading",
        (StatusMajor::Pkcs11, StatusMinor::Pkcs11Verify) => "openvpn3-gui-rs-loading",
        (StatusMajor::Process, StatusMinor::ProcStarted) => "openvpn3-gui-rs-loading",

        // Error states
        (StatusMajor::CfgError, _) => "openvpn3-gui-rs-idle-error",
        (StatusMajor::Connection, StatusMinor::CfgError) => "openvpn3-gui-rs-idle-error",
        (StatusMajor::Connection, StatusMinor::CfgInlineMissing) => "openvpn3-gui-rs-idle-error",
        (StatusMajor::Connection, StatusMinor::ConnFailed) => "openvpn3-gui-rs-idle-error",
        (StatusMajor::Connection, StatusMinor::ConnAuthFailed) => "openvpn3-gui-rs-idle-error",
        (StatusMajor::Process, StatusMinor::ProcStopped) => "openvpn3-gui-rs-idle-error",
        (StatusMajor::Process, StatusMinor::ProcKilled) => "openvpn3-gui-rs-idle-error",

        // Idle states
        (StatusMajor::Connection, StatusMinor::ConnDisconnected) => "openvpn3-gui-rs-idle",
        (StatusMajor::Connection, StatusMinor::ConnDone) => "openvpn3-gui-rs-idle",
        (StatusMajor::Session, StatusMinor::SessRemoved) => "openvpn3-gui-rs-idle",
        (StatusMajor::Unset, _) => "openvpn3-gui-rs-idle",

        // Default
        _ => DEFAULT_ICON,
    }
}

/// Get the description for a given status
pub fn get_status_description(major: StatusMajor, minor: StatusMinor) -> &'static str {
    match (major, minor) {
        // Connection states
        (StatusMajor::Connection, StatusMinor::CfgOk) => "Ready to connect",
        (StatusMajor::Connection, StatusMinor::CfgRequireUser) => "Authentication required",
        (StatusMajor::Connection, StatusMinor::ConnInit) => "Initializing",
        (StatusMajor::Connection, StatusMinor::ConnConnecting) => "Connecting",
        (StatusMajor::Connection, StatusMinor::ConnConnected) => "Connected",
        (StatusMajor::Connection, StatusMinor::ConnDisconnecting) => "Disconnecting",
        (StatusMajor::Connection, StatusMinor::ConnDisconnected) => "Disconnected",
        (StatusMajor::Connection, StatusMinor::ConnFailed) => "Connection failed",
        (StatusMajor::Connection, StatusMinor::ConnAuthFailed) => "Authentication failed",
        (StatusMajor::Connection, StatusMinor::ConnReconnecting) => "Reconnecting",
        (StatusMajor::Connection, StatusMinor::ConnPausing) => "Pausing",
        (StatusMajor::Connection, StatusMinor::ConnPaused) => "Paused",
        (StatusMajor::Connection, StatusMinor::ConnResuming) => "Resuming",
        (StatusMajor::Connection, StatusMinor::ConnDone) => "Done",

        // Configuration states
        (StatusMajor::CfgError, StatusMinor::CfgError) => "Configuration error",
        (StatusMajor::Connection, StatusMinor::CfgError) => "Configuration error",
        (StatusMajor::Connection, StatusMinor::CfgInlineMissing) => "Missing inline configuration",

        // Session states
        (StatusMajor::Session, StatusMinor::SessNew) => "New session",
        (StatusMajor::Session, StatusMinor::SessBackendCompleted) => "Backend completed",
        (StatusMajor::Session, StatusMinor::SessRemoved) => "Session removed",
        (StatusMajor::Session, StatusMinor::SessAuthUserpass) => "User authentication",
        (StatusMajor::Session, StatusMinor::SessAuthChallenge) => "Challenge authentication",
        (StatusMajor::Session, StatusMinor::SessAuthUrl) => "URL authentication",

        // Process states
        (StatusMajor::Process, StatusMinor::ProcStarted) => "Process started",
        (StatusMajor::Process, StatusMinor::ProcStopped) => "Process stopped",
        (StatusMajor::Process, StatusMinor::ProcKilled) => "Process killed",

        // Unset
        (StatusMajor::Unset, _) => "Unknown",

        // Default
        _ => DEFAULT_DESCRIPTION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connected_icon() {
        assert_eq!(
            get_status_icon(StatusMajor::Connection, StatusMinor::ConnConnected),
            "openvpn3-gui-rs-active"
        );
    }

    #[test]
    fn test_paused_icon() {
        assert_eq!(
            get_status_icon(StatusMajor::Connection, StatusMinor::ConnPaused),
            "openvpn3-gui-rs-paused"
        );
    }

    #[test]
    fn test_idle_icon() {
        assert_eq!(
            get_status_icon(StatusMajor::Connection, StatusMinor::ConnDisconnected),
            "openvpn3-gui-rs-idle"
        );
    }

    #[test]
    fn test_error_icon() {
        assert_eq!(
            get_status_icon(StatusMajor::Connection, StatusMinor::ConnFailed),
            "openvpn3-gui-rs-idle-error"
        );
    }

    #[test]
    fn test_connecting_icon() {
        assert_eq!(
            get_status_icon(StatusMajor::Connection, StatusMinor::ConnConnecting),
            "openvpn3-gui-rs-loading"
        );
        assert_eq!(
            get_status_icon(StatusMajor::Connection, StatusMinor::ConnInit),
            "openvpn3-gui-rs-loading"
        );
        assert_eq!(
            get_status_icon(StatusMajor::Connection, StatusMinor::ConnReconnecting),
            "openvpn3-gui-rs-loading"
        );
    }

    #[test]
    fn test_connected_description() {
        assert_eq!(
            get_status_description(StatusMajor::Connection, StatusMinor::ConnConnected),
            "Connected"
        );
    }

    #[test]
    fn test_connecting_description() {
        assert_eq!(
            get_status_description(StatusMajor::Connection, StatusMinor::ConnConnecting),
            "Connecting"
        );
    }

    #[test]
    fn test_auth_descriptions() {
        assert_eq!(
            get_status_description(StatusMajor::Session, StatusMinor::SessAuthUserpass),
            "User authentication"
        );
        assert_eq!(
            get_status_description(StatusMajor::Session, StatusMinor::SessAuthChallenge),
            "Challenge authentication"
        );
    }

    #[test]
    fn test_process_descriptions() {
        assert_eq!(
            get_status_description(StatusMajor::Process, StatusMinor::ProcStarted),
            "Process started"
        );
        assert_eq!(
            get_status_description(StatusMajor::Process, StatusMinor::ProcStopped),
            "Process stopped"
        );
    }

    #[test]
    fn test_unset_status() {
        assert_eq!(
            get_status_icon(StatusMajor::Unset, StatusMinor::Unset),
            "openvpn3-gui-rs-idle"
        );
        assert_eq!(
            get_status_description(StatusMajor::Unset, StatusMinor::Unset),
            "Unknown"
        );
    }
}
