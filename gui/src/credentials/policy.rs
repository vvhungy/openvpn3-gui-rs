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
pub(crate) fn is_storable_field(label: &str, mask: bool) -> bool {
    let lower = label.to_lowercase();
    lower.contains("username") || lower.contains("password") || mask
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
        assert!(is_storable_field("One-Time Code", true));
    }

    #[test]
    fn test_not_storable_unmasked_other() {
        assert!(!is_storable_field("One-Time Code", false));
        assert!(!is_storable_field("challenge", false));
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
