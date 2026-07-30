//! Pure policy decisions for credential prompt slots.
//!
//! Separated from the async D-Bus dispatch in `app::credential_handler` so
//! the rules for "which slots are storable in the keyring" and "what label do
//! we show users" can be unit-tested without any GTK or zbus dependencies.

/// Whether a credential slot should be offered for keyring storage.
///
/// Username and password slots are always storable; arbitrary masked slots
/// (typically OTP fields) are also storable. Unmasked non-credential slots
/// (e.g. plaintext challenges) are not storable.
///
/// **One-time / challenge values are never storable** even when masked: a
/// replayed TOTP, OTP, or challenge response is useless at best (expired) and a
/// credential-reuse hazard at worst, so persisting it across reconnects is
/// never correct regardless of how the server labels the slot. This also
/// closes the old bypass where `mask=true` alone made any masked slot storable.
pub(crate) fn is_storable_field(label: &str, mask: bool) -> bool {
    let lower = label.to_lowercase();
    let is_credential = lower.contains("username") || lower.contains("password") || mask;
    let is_single_use = lower.contains("one-time")
        || lower.contains("otp")
        || lower.contains("code")
        || lower.contains("challenge");
    is_credential && !is_single_use
}

/// User-facing label for a credential slot, normalising upstream variations
/// ("username", "Username", "Enter username") into stable strings.
pub(crate) fn display_label_for(label: &str) -> String {
    let lower = label.to_lowercase();
    if lower.contains("username") {
        "Auth Username".to_string()
    } else if lower.contains("password") {
        "Auth Password".to_string()
    } else {
        "Authentication Code".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_storable_field ---

    #[test]
    fn test_storable_username() {
        assert!(is_storable_field("Username", false));
        assert!(is_storable_field("username", false));
    }

    #[test]
    fn test_storable_password() {
        assert!(is_storable_field("Password", false));
        assert!(is_storable_field("password", false));
    }

    #[test]
    fn test_storable_masked_field() {
        // A masked slot that is neither a username/password nor a single-use
        // value stays storable — e.g. a server-declared "Token" secret.
        assert!(is_storable_field("Token", true));
        assert!(is_storable_field("Private Key", true));
    }

    #[test]
    fn test_single_use_fields_never_storable() {
        // #8: one-time / OTP / code / challenge values must never persist,
        // even when masked, regardless of label casing.
        for label in [
            "One-Time Code",
            "OTP",
            "TOTP",
            "Two-Factor Code",
            "Challenge Response",
            "Verification Code",
        ] {
            assert!(
                !is_storable_field(label, true),
                "{label} must not be storable"
            );
            assert!(
                !is_storable_field(label, false),
                "{label} must not be storable even when unmasked"
            );
        }
    }

    #[test]
    fn test_not_storable_unmasked_other() {
        assert!(!is_storable_field("Token", false));
        assert!(!is_storable_field("Private Key", false));
    }

    // --- display_label_for ---

    #[test]
    fn test_display_label_username() {
        assert_eq!(display_label_for("Username"), "Auth Username");
        assert_eq!(display_label_for("Enter username"), "Auth Username");
    }

    #[test]
    fn test_display_label_password() {
        assert_eq!(display_label_for("Password"), "Auth Password");
        assert_eq!(display_label_for("Your password"), "Auth Password");
    }

    #[test]
    fn test_display_label_fallback() {
        assert_eq!(display_label_for("One-Time Code"), "Authentication Code");
        assert_eq!(display_label_for("challenge"), "Authentication Code");
    }
}
