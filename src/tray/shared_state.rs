//! Session status tests

#[cfg(test)]
mod tests {
    use crate::dbus::types::SessionStatus;

    #[test]
    fn test_session_status_is_connected() {
        let status = SessionStatus::new(2, 7, "Connected".to_string());
        assert!(status.is_connected());
        assert!(!status.is_connecting());
        assert!(!status.is_paused());
        assert!(!status.is_disconnected());
    }

    #[test]
    fn test_session_status_is_connecting() {
        let status = SessionStatus::new(2, 5, "Initializing".to_string());
        assert!(!status.is_connected());
        assert!(status.is_connecting());
        assert!(!status.is_paused());

        let status = SessionStatus::new(2, 6, "Connecting".to_string());
        assert!(status.is_connecting());

        let status = SessionStatus::new(2, 12, "Reconnecting".to_string());
        assert!(status.is_connecting());
    }

    #[test]
    fn test_session_status_is_paused() {
        let status = SessionStatus::new(2, 14, "Paused".to_string());
        assert!(!status.is_connected());
        assert!(status.is_paused());
        assert!(!status.is_connecting());
    }

    #[test]
    fn test_session_status_is_disconnected() {
        let status = SessionStatus::new(2, 9, "Disconnected".to_string());
        assert!(status.is_disconnected());
        assert!(!status.is_connected());

        let status = SessionStatus::new(2, 16, "Done".to_string());
        assert!(status.is_disconnected());
    }

    #[test]
    fn test_session_status_is_error() {
        let status = SessionStatus::new(1, 1, "Error".to_string());
        assert!(status.is_error());

        let status = SessionStatus::new(2, 10, "Failed".to_string());
        assert!(status.is_error());

        let status = SessionStatus::new(2, 11, "Auth failed".to_string());
        assert!(status.is_error());
    }

    #[test]
    fn test_session_status_needs_credentials() {
        let status = SessionStatus::new(3, 20, "Need credentials".to_string());
        assert!(status.needs_credentials());
        assert!(!status.needs_challenge());
        assert!(!status.needs_url_auth());
    }

    #[test]
    fn test_session_status_needs_challenge() {
        let status = SessionStatus::new(3, 21, "Challenge".to_string());
        assert!(status.needs_challenge());
        assert!(!status.needs_credentials());
    }

    #[test]
    fn test_session_status_needs_url_auth() {
        let status = SessionStatus::new(3, 22, "URL auth".to_string());
        assert!(status.needs_url_auth());
        assert!(!status.needs_credentials());
        assert!(!status.needs_challenge());
    }
}
