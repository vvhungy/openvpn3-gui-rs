//! D-Bus type definitions for OpenVPN3
//!
//! These enums correspond to the OpenVPN3 Linux client D-Bus API.

use zbus::zvariant::Type;

/// Status major codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type)]
#[zvariant(signature = "u")]
#[repr(u32)]
pub enum StatusMajor {
    /// Unset status
    Unset = 0,
    /// Configuration error
    CfgError = 1,
    /// Connection status
    Connection = 2,
    /// Session status
    Session = 3,
    /// PKCS#11 status
    Pkcs11 = 4,
    /// Process status
    Process = 5,
}

impl StatusMajor {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::Unset,
            1 => Self::CfgError,
            2 => Self::Connection,
            3 => Self::Session,
            4 => Self::Pkcs11,
            5 => Self::Process,
            _ => Self::Unset,
        }
    }
}

/// Status minor codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type)]
#[zvariant(signature = "u")]
#[repr(u32)]
pub enum StatusMinor {
    /// Unset status
    Unset = 0,
    /// Configuration error
    CfgError = 1,
    /// Configuration OK
    CfgOk = 2,
    /// Missing inline configuration
    CfgInlineMissing = 3,
    /// User input required
    CfgRequireUser = 4,
    /// Connection initializing
    ConnInit = 5,
    /// Connection in progress
    ConnConnecting = 6,
    /// Connection established
    ConnConnected = 7,
    /// Connection disconnecting
    ConnDisconnecting = 8,
    /// Connection disconnected
    ConnDisconnected = 9,
    /// Connection failed
    ConnFailed = 10,
    /// Authentication failed
    ConnAuthFailed = 11,
    /// Reconnecting
    ConnReconnecting = 12,
    /// Pausing connection
    ConnPausing = 13,
    /// Connection paused
    ConnPaused = 14,
    /// Resuming connection
    ConnResuming = 15,
    /// Connection done
    ConnDone = 16,
    /// New session
    SessNew = 17,
    /// Backend completed
    SessBackendCompleted = 18,
    /// Session removed
    SessRemoved = 19,
    /// User/password authentication
    SessAuthUserpass = 20,
    /// Challenge authentication
    SessAuthChallenge = 21,
    /// URL authentication
    SessAuthUrl = 22,
    /// PKCS#11 sign operation
    Pkcs11Sign = 23,
    /// PKCS#11 encrypt operation
    Pkcs11Encrypt = 24,
    /// PKCS#11 decrypt operation
    Pkcs11Decrypt = 25,
    /// PKCS#11 verify operation
    Pkcs11Verify = 26,
    /// Process started
    ProcStarted = 27,
    /// Process stopped
    ProcStopped = 28,
    /// Process killed
    ProcKilled = 29,
}

impl StatusMinor {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::Unset,
            1 => Self::CfgError,
            2 => Self::CfgOk,
            3 => Self::CfgInlineMissing,
            4 => Self::CfgRequireUser,
            5 => Self::ConnInit,
            6 => Self::ConnConnecting,
            7 => Self::ConnConnected,
            8 => Self::ConnDisconnecting,
            9 => Self::ConnDisconnected,
            10 => Self::ConnFailed,
            11 => Self::ConnAuthFailed,
            12 => Self::ConnReconnecting,
            13 => Self::ConnPausing,
            14 => Self::ConnPaused,
            15 => Self::ConnResuming,
            16 => Self::ConnDone,
            17 => Self::SessNew,
            18 => Self::SessBackendCompleted,
            19 => Self::SessRemoved,
            20 => Self::SessAuthUserpass,
            21 => Self::SessAuthChallenge,
            22 => Self::SessAuthUrl,
            23 => Self::Pkcs11Sign,
            24 => Self::Pkcs11Encrypt,
            25 => Self::Pkcs11Decrypt,
            26 => Self::Pkcs11Verify,
            27 => Self::ProcStarted,
            28 => Self::ProcStopped,
            29 => Self::ProcKilled,
            _ => Self::Unset,
        }
    }
}

/// Session manager event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type)]
#[zvariant(signature = "q")]
#[repr(u16)]
#[allow(dead_code)] // Documents D-Bus API; not all variants are actively dispatched
pub enum SessionManagerEventType {
    /// Session created
    SessCreated = 1,
    /// Session destroyed
    SessDestroyed = 2,
}

#[cfg(test)]
impl SessionManagerEventType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::SessCreated),
            2 => Some(Self::SessDestroyed),
            _ => None,
        }
    }
}

/// Client attention type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Type)]
#[zvariant(signature = "u")]
#[repr(u32)]
#[allow(dead_code)] // Documents D-Bus API; not all variants are actively dispatched
pub enum ClientAttentionType {
    /// Unset
    Unset = 0,
    /// Credentials required
    Credentials = 1,
    /// PKCS#11 interaction
    Pkcs11 = 2,
    /// Access permission
    AccessPerm = 3,
}

#[cfg(test)]
impl ClientAttentionType {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::Unset,
            1 => Self::Credentials,
            2 => Self::Pkcs11,
            3 => Self::AccessPerm,
            _ => Self::Unset,
        }
    }
}

/// Session status structure
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

    // --- StatusMajor::from_u32 ---

    #[test]
    fn test_status_major_known_values() {
        assert_eq!(StatusMajor::from_u32(0), StatusMajor::Unset);
        assert_eq!(StatusMajor::from_u32(1), StatusMajor::CfgError);
        assert_eq!(StatusMajor::from_u32(2), StatusMajor::Connection);
        assert_eq!(StatusMajor::from_u32(3), StatusMajor::Session);
        assert_eq!(StatusMajor::from_u32(4), StatusMajor::Pkcs11);
        assert_eq!(StatusMajor::from_u32(5), StatusMajor::Process);
    }

    #[test]
    fn test_status_major_unknown_falls_back_to_unset() {
        assert_eq!(StatusMajor::from_u32(99), StatusMajor::Unset);
    }

    // --- StatusMinor::from_u32 ---

    #[test]
    fn test_status_minor_connection_range() {
        assert_eq!(StatusMinor::from_u32(6), StatusMinor::ConnConnecting);
        assert_eq!(StatusMinor::from_u32(7), StatusMinor::ConnConnected);
        assert_eq!(StatusMinor::from_u32(9), StatusMinor::ConnDisconnected);
        assert_eq!(StatusMinor::from_u32(10), StatusMinor::ConnFailed);
        assert_eq!(StatusMinor::from_u32(11), StatusMinor::ConnAuthFailed);
        assert_eq!(StatusMinor::from_u32(14), StatusMinor::ConnPaused);
        assert_eq!(StatusMinor::from_u32(16), StatusMinor::ConnDone);
    }

    #[test]
    fn test_status_minor_session_range() {
        assert_eq!(StatusMinor::from_u32(20), StatusMinor::SessAuthUserpass);
        assert_eq!(StatusMinor::from_u32(21), StatusMinor::SessAuthChallenge);
        assert_eq!(StatusMinor::from_u32(22), StatusMinor::SessAuthUrl);
    }

    #[test]
    fn test_status_minor_unknown_falls_back_to_unset() {
        assert_eq!(StatusMinor::from_u32(999), StatusMinor::Unset);
    }

    // --- SessionManagerEventType::from_u16 ---

    #[test]
    fn test_session_manager_event_type() {
        assert_eq!(
            SessionManagerEventType::from_u16(1),
            Some(SessionManagerEventType::SessCreated)
        );
        assert_eq!(
            SessionManagerEventType::from_u16(2),
            Some(SessionManagerEventType::SessDestroyed)
        );
        assert_eq!(SessionManagerEventType::from_u16(0), None);
        assert_eq!(SessionManagerEventType::from_u16(99), None);
    }

    // --- ClientAttentionType::from_u32 ---

    #[test]
    fn test_client_attention_type() {
        assert_eq!(ClientAttentionType::from_u32(0), ClientAttentionType::Unset);
        assert_eq!(
            ClientAttentionType::from_u32(1),
            ClientAttentionType::Credentials
        );
        assert_eq!(
            ClientAttentionType::from_u32(99),
            ClientAttentionType::Unset
        );
    }

    // --- SessionStatus construction ---

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

    // --- SessionStatus predicates ---

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
        // CfgError major (1)
        assert!(SessionStatus::new(1, 0, String::new()).is_error());
        // ConnFailed (2/10)
        assert!(SessionStatus::new(2, 10, String::new()).is_error());
        // ConnAuthFailed (2/11)
        assert!(SessionStatus::new(2, 11, String::new()).is_error());
        // ProcStopped (5/28), ProcKilled (5/29)
        assert!(SessionStatus::new(5, 28, String::new()).is_error());
        assert!(SessionStatus::new(5, 29, String::new()).is_error());
        // Connected is not an error
        assert!(!SessionStatus::new(2, 7, String::new()).is_error());
    }
}
