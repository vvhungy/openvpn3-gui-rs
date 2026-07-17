//! Pure credential-slot / label-matching logic for the credentials dialog.
//!
//! Split out of `mod` so the dialog's async D-Bus loop stays separate from the
//! unit-testable label-probing helpers. The dialog queries the D-Bus queue once
//! into a `Vec<(u32, u32, u32, String, bool)>` — `(attention_type, group, id,
//! label, masked)` — and these functions decide which keyring labels to probe
//! and how to map queue slots onto the standard dialog fields. No I/O, no
//! tray/D-Bus state: hermetic, unit-tested here.

/// Standard credential field labels — the dialog always shows all 3 regardless
/// of which slots the D-Bus queue currently holds. Extra dialog fields with no
/// matching queue slot are silently ignored on submit. The `bool` is whether
/// the field is masked (password / one-time code).
pub(super) const STANDARD_FIELDS: [(&str, bool); 3] = [
    ("Username", false),
    ("Password", true),
    ("One-Time Code", true),
];

/// Common D-Bus label variants seen from different OpenVPN3 servers. Used to
/// probe the keyring when the actual queue slot label doesn't match the
/// standard field label.
pub(super) fn keyring_label_variants(standard_label: &str) -> &'static [&'static str] {
    match standard_label {
        "Username" => &["username", "Enter Username", "Enter username"],
        "Password" => &[
            "password",
            "Enter Password",
            "Enter password",
            "Your password",
        ],
        "One-Time Code" => &["one-time code", "Authenticator Code", "One Time Password"],
        _ => &[],
    }
}

/// Check whether a D-Bus label belongs to a standard field category.
pub(super) fn label_matches_category(label: &str, standard_label: &str) -> bool {
    let lower = label.to_lowercase();
    match standard_label {
        "Username" => lower.contains("username"),
        "Password" => lower.contains("password"),
        // OTP / challenge: anything that isn't username or password
        _ => !lower.contains("username") && !lower.contains("password"),
    }
}

/// Build the ordered list of labels to probe against the keyring for a set of
/// queue slots. Queue-slot labels come first (the server's actual label wins
/// when it matches a keyring attribute), then each standard field name and its
/// known variants.
pub(super) fn build_labels_to_try(slots: &[(u32, u32, u32, String, bool)]) -> Vec<String> {
    let mut labels: Vec<String> = slots.iter().map(|(_, _, _, l, _)| l.clone()).collect();
    for (standard_label, _) in &STANDARD_FIELDS {
        labels.push(standard_label.to_string());
        for variant in keyring_label_variants(standard_label) {
            labels.push(variant.to_string());
        }
    }
    labels
}

/// Look up a label's `masked` flag in the queue slots. `false` when the label
/// isn't present (treated as unmasked — the dialog defaults to showing input).
pub(super) fn slot_mask(label: &str, slots: &[(u32, u32, u32, String, bool)]) -> bool {
    slots
        .iter()
        .find(|(_, _, _, l, _)| l == label)
        .map(|(_, _, _, _, m)| *m)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{build_labels_to_try, slot_mask};

    #[test]
    fn build_labels_starts_with_slot_labels() {
        // Queue-slot labels are probed before the standard field names so the
        // server's actual label wins when it matches a keyring attribute.
        let slots = vec![(1, 0, 0, "Server User".to_string(), false)];
        let labels = build_labels_to_try(&slots);
        assert_eq!(labels.first().map(String::as_str), Some("Server User"));
        assert!(labels.contains(&"Username".to_string()));
        assert!(labels.contains(&"Password".to_string()));
        assert!(labels.contains(&"One-Time Code".to_string()));
    }

    #[test]
    fn build_labels_includes_common_variants() {
        // Different OpenVPN3 servers emit varying label prose for the same
        // field; all known variants are appended so the keyring is probed once
        // per spelling.
        let labels = build_labels_to_try(&[]);
        assert!(labels.contains(&"Enter Password".to_string()));
        assert!(labels.contains(&"Your password".to_string()));
        assert!(labels.contains(&"one-time code".to_string()));
    }

    #[test]
    fn slot_mask_finds_masked_label() {
        let slots = vec![(1, 0, 0, "Password".to_string(), true)];
        assert!(slot_mask("Password", &slots));
    }

    #[test]
    fn slot_mask_unmasked_slot_is_false() {
        let slots = vec![(1, 0, 0, "Username".to_string(), false)];
        assert!(!slot_mask("Username", &slots));
    }

    #[test]
    fn slot_mask_missing_label_is_false() {
        let slots = vec![(1, 0, 0, "Password".to_string(), true)];
        assert!(!slot_mask("Username", &slots));
    }
}
