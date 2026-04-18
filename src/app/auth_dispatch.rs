//! Auth dispatch — maps D-Bus input queue groups to the correct handler.
//!
//! Pure routing logic (testable) + async D-Bus query helper.

use tracing::warn;
use zbus::zvariant::OwnedObjectPath;

use crate::dbus::session::SessionProxy;

/// Which handler to invoke based on the server's input queue group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthDispatch {
    /// Username/password (and possibly static_challenge) needed
    Credentials,
    /// Dynamic or static challenge / OTP needed
    Challenge,
}

/// Determine which handler to dispatch to based on the (type, group) pairs
/// returned by `UserInputQueueGetTypeGroup()`.
///
/// Group values from OpenVPN3:
/// - 1 = USER_PASSWORD → credentials dialog
/// - 4 = CHALLENGE_STATIC → challenge dialog
/// - 5 = CHALLENGE_DYNAMIC → challenge dialog
/// - 6 = CHALLENGE_AUTH_PENDING → challenge dialog
pub fn dispatch_from_groups(type_groups: &[(u32, u32)]) -> Option<AuthDispatch> {
    // Only handle CREDENTIALS type (1)
    let groups: Vec<u32> = type_groups
        .iter()
        .filter(|(t, _)| *t == 1)
        .map(|(_, g)| *g)
        .collect();

    if groups.is_empty() {
        return None;
    }

    // Challenge groups: 4 (static), 5 (dynamic), 6 (auth pending)
    let challenge_groups = [4u32, 5, 6];
    let has_challenge = groups.iter().any(|g| challenge_groups.contains(g));
    let has_credentials = groups.contains(&1);

    if has_challenge {
        Some(AuthDispatch::Challenge)
    } else if has_credentials {
        Some(AuthDispatch::Credentials)
    } else {
        None
    }
}

/// Query the session's D-Bus input queue and determine which handler to dispatch to.
pub(crate) async fn dispatch_for_session(
    dbus: &zbus::Connection,
    session_path: &str,
) -> Option<AuthDispatch> {
    let session_path_obj = match OwnedObjectPath::try_from(session_path) {
        Ok(p) => p,
        Err(e) => {
            warn!("Invalid session path for auth dispatch: {}", e);
            return None;
        }
    };
    let session = match SessionProxy::builder(dbus)
        .path(session_path_obj)
        .ok()
        .map(|b| b.build())
    {
        Some(fut) => match fut.await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to create session proxy for auth dispatch: {}", e);
                return None;
            }
        },
        None => return None,
    };

    match session.UserInputQueueGetTypeGroup().await {
        Ok(type_groups) => dispatch_from_groups(&type_groups),
        Err(e) => {
            warn!("Failed to query input queue for auth dispatch: {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dispatch_user_password() {
        // (type=CREDENTIALS, group=USER_PASSWORD)
        assert_eq!(
            dispatch_from_groups(&[(1, 1)]),
            Some(AuthDispatch::Credentials)
        );
    }

    #[test]
    fn test_dispatch_static_challenge() {
        assert_eq!(
            dispatch_from_groups(&[(1, 4)]),
            Some(AuthDispatch::Challenge)
        );
    }

    #[test]
    fn test_dispatch_dynamic_challenge() {
        assert_eq!(
            dispatch_from_groups(&[(1, 5)]),
            Some(AuthDispatch::Challenge)
        );
    }

    #[test]
    fn test_dispatch_auth_pending() {
        assert_eq!(
            dispatch_from_groups(&[(1, 6)]),
            Some(AuthDispatch::Challenge)
        );
    }

    #[test]
    fn test_dispatch_mixed_credentials_and_challenge() {
        // When both user_password and challenge groups exist, challenge takes priority
        // because credentials dialog already shows static_challenge fields
        assert_eq!(
            dispatch_from_groups(&[(1, 1), (1, 4)]),
            Some(AuthDispatch::Challenge)
        );
    }

    #[test]
    fn test_dispatch_unknown_group() {
        // Unknown group but type=1 → no match
        assert_eq!(dispatch_from_groups(&[(1, 99)]), None);
    }

    #[test]
    fn test_dispatch_wrong_type() {
        // type=2 (PKCS11) → ignored
        assert_eq!(dispatch_from_groups(&[(2, 1)]), None);
    }

    #[test]
    fn test_dispatch_empty() {
        assert_eq!(dispatch_from_groups(&[]), None);
    }
}
