//! Session status — application-level interpretation of OpenVPN3 status codes

use super::types::{StatusMajor, StatusMinor};

/// Decoded status of a VPN session
#[derive(Debug, Clone)]
pub struct SessionStatus {
    pub major: StatusMajor,
    pub minor: StatusMinor,
}

impl SessionStatus {
    pub fn new(major: u32, minor: u32, _message: String) -> Self {
        Self {
            major: StatusMajor::from_u32(major),
            minor: StatusMinor::from_u32(minor),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.major == StatusMajor::Connection && self.minor == StatusMinor::ConnConnected
    }

    pub fn is_disconnected(&self) -> bool {
        self.major == StatusMajor::Connection
            && matches!(
                self.minor,
                StatusMinor::ConnDisconnected | StatusMinor::ConnDone
            )
    }

    pub fn needs_credentials(&self) -> bool {
        self.major == StatusMajor::Session && self.minor == StatusMinor::SessAuthUserpass
    }

    pub fn needs_challenge(&self) -> bool {
        self.major == StatusMajor::Session && self.minor == StatusMinor::SessAuthChallenge
    }

    pub fn is_error(&self) -> bool {
        self.major == StatusMajor::CfgError
            || (self.major == StatusMajor::Connection
                && matches!(
                    self.minor,
                    StatusMinor::CfgError
                        | StatusMinor::CfgInlineMissing
                        | StatusMinor::ConnFailed
                        | StatusMinor::ConnAuthFailed
                ))
            || (self.major == StatusMajor::Process
                && matches!(
                    self.minor,
                    StatusMinor::ProcStopped | StatusMinor::ProcKilled
                ))
    }
}

#[cfg(test)]
impl SessionStatus {
    pub fn is_connecting(&self) -> bool {
        self.major == StatusMajor::Connection
            && matches!(
                self.minor,
                StatusMinor::ConnInit | StatusMinor::ConnConnecting | StatusMinor::ConnReconnecting
            )
    }

    pub fn is_paused(&self) -> bool {
        self.major == StatusMajor::Connection && self.minor == StatusMinor::ConnPaused
    }

    pub fn needs_url_auth(&self) -> bool {
        self.major == StatusMajor::Session && self.minor == StatusMinor::SessAuthUrl
    }
}

impl Default for SessionStatus {
    fn default() -> Self {
        Self {
            major: StatusMajor::Unset,
            minor: StatusMinor::Unset,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_status_new() {
        let s = SessionStatus::new(2, 7, "Connected".to_string());
        assert_eq!(s.major, StatusMajor::Connection);
        assert_eq!(s.minor, StatusMinor::ConnConnected);
    }

    #[test]
    fn test_session_status_default() {
        let s = SessionStatus::default();
        assert_eq!(s.major, StatusMajor::Unset);
        assert_eq!(s.minor, StatusMinor::Unset);
    }

    #[test]
    fn test_is_connected() {
        assert!(SessionStatus::new(2, 7, String::new()).is_connected());
        assert!(!SessionStatus::new(2, 6, String::new()).is_connected());
        assert!(!SessionStatus::new(3, 7, String::new()).is_connected());
    }

    #[test]
    fn test_is_connecting() {
        // ConnInit=5, ConnConnecting=6, ConnReconnecting=12
        assert!(SessionStatus::new(2, 5, String::new()).is_connecting());
        assert!(SessionStatus::new(2, 6, String::new()).is_connecting());
        assert!(SessionStatus::new(2, 12, String::new()).is_connecting());
        assert!(!SessionStatus::new(2, 7, String::new()).is_connecting());
    }

    #[test]
    fn test_is_paused() {
        assert!(SessionStatus::new(2, 14, String::new()).is_paused());
        assert!(!SessionStatus::new(2, 7, String::new()).is_paused());
    }

    #[test]
    fn test_is_disconnected() {
        // ConnDisconnected=9, ConnDone=16
        assert!(SessionStatus::new(2, 9, String::new()).is_disconnected());
        assert!(SessionStatus::new(2, 16, String::new()).is_disconnected());
        assert!(!SessionStatus::new(2, 7, String::new()).is_disconnected());
    }

    #[test]
    fn test_is_error() {
        assert!(SessionStatus::new(1, 0, String::new()).is_error());
        assert!(SessionStatus::new(2, 10, String::new()).is_error());
        assert!(SessionStatus::new(2, 11, String::new()).is_error());
        assert!(SessionStatus::new(5, 28, String::new()).is_error());
        assert!(SessionStatus::new(5, 29, String::new()).is_error());
        assert!(!SessionStatus::new(2, 7, String::new()).is_error());
    }
}
