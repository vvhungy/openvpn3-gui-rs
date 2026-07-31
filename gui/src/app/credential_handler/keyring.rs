//! Keyring access for the credential flow — open/unlock, read-back, persist.
//!
//! Split out of `mod` so the dialog's D-Bus dispatch stays separate from the
//! secret-store side. Everything here is impure async glue over `oo7` and
//! [`crate::credentials::CredentialStore`], except the two pure `*_hint`
//! functions whose locked-vs-generic branch is unit-tested below.
//!
//! Both the read path ([`resolve_keyring_values`]) and the write path
//! ([`save_remembered_credentials`]) apply the **same** storability policy
//! through [`is_storable_field`] + [`slot_mask`], so a field the write side
//! refuses to store (one-time codes) is never probed for pre-fill either.

use std::collections::HashMap;

use tracing::warn;

use crate::credentials::policy::is_storable_field;

use super::slots::slot_mask;

/// Open the default keyring and unlock it once, returning a usable handle or
/// `None` (after a single user-facing notification) if either step fails.
///
/// Extracted from `request_credentials`. Dropping the handle on unlock failure
/// keeps the read loop below from logging N near-identical `warn!` lines.
/// Impure async glue — no unit surface.
pub(super) async fn open_and_unlock_keyring() -> Option<oo7::Keyring> {
    let mut keyring = match oo7::Keyring::new().await {
        Ok(k) => Some(k),
        Err(e) => {
            warn!("Failed to open keyring — saved credentials unavailable: {e}");
            crate::dialogs::show_error_notification(
                "Saved Credentials Unavailable",
                "Could not open the keyring. Enter credentials manually.",
            );
            None
        }
    };
    if let Some(k) = &keyring
        && let Err(e) = crate::credentials::store::ensure_unlocked(k).await
    {
        warn!("Failed to unlock keyring — pre-fill disabled: {e}");
        crate::dialogs::show_error_notification(
            "Saved Credentials Unavailable",
            keyring_unlock_hint(crate::credentials::store::is_locked_error(&e)),
        );
        // Drop the handle so the read loop short-circuits. Otherwise it stays
        // `Some` and every label logs its own read-failure `warn!` (N
        // near-identical lines for one root cause). One notification + one log
        // line above is enough; pre-fill is simply blank.
        keyring = None;
    }
    keyring
}

/// Human-readable hint for a keyring *unlock* failure, given whether the
/// underlying error was a lock/refusal.
///
/// Pure (bool -> message) so the locked-vs-generic branch is unit-testable; the
/// impure error classification ([`crate::credentials::store::is_locked_error`])
/// stays at the call site.
fn keyring_unlock_hint(locked: bool) -> &'static str {
    if locked {
        "Keyring is locked. Enter credentials manually."
    } else {
        "Could not unlock the keyring. Enter credentials manually."
    }
}

/// Resolve keyring values into `resolved`, keyed by label.
///
/// Prefilled entries already in `resolved` win and are skipped; non-storable
/// labels (e.g. OTP) are skipped. Outcome is classified so a *locked/error*
/// read never reads as *absent*. Extracted from `request_credentials`'s read
/// loop. Impure async glue — no unit surface.
///
/// `slots` is the live D-Bus queue so the read path applies the **same**
/// storability policy as the write path: previously it passed a hardcoded
/// `mask=true`, which made the read side try to prefill any field the server
/// marked masked — including one-time codes the write side correctly refuses
/// to store (#14). Now both sides agree through [`slot_mask`].
pub(super) async fn resolve_keyring_values(
    labels: &[String],
    slots: &[(u32, u32, u32, String, bool)],
    keyring: Option<&oo7::Keyring>,
    cred_store: &crate::credentials::CredentialStore,
    cred_key: &str,
    config_name: &str,
    resolved: &mut HashMap<String, String>,
) {
    let Some(k) = keyring else {
        return;
    };
    for label in labels {
        if resolved.contains_key(label) {
            continue;
        }
        if !is_storable_field(label, slot_mask(label, slots)) {
            continue;
        }
        match cred_store
            .get_with_keyring(k, cred_key, config_name, label)
            .await
        {
            Ok(Some(val)) => {
                resolved.insert(label.clone(), val);
            }
            Ok(None) => {} // genuinely absent — leave blank
            Err(e) => warn!("Failed to read saved credential '{label}': {e}"),
        }
    }
}

/// User-facing hint for a credential *save* failure, given whether the
/// underlying keyring error was a lock/refusal.
///
/// Pure (bool -> message) so the locked-vs-generic branch is unit-testable; the
/// impure error classification ([`crate::credentials::store::is_locked_error`])
/// stays at the call site.
fn save_failure_hint(locked: bool) -> &'static str {
    if locked {
        "Keyring is locked — credentials could not be saved."
    } else {
        "Could not save credentials to the keyring."
    }
}

/// Persist submitted "remembered" credentials to the keyring, one label at a
/// time.
///
/// Extracted from the dialog submit callback's `Ok(true)` arm. Only storable
/// fields (username/password, not OTP) are written; the "save failed"
/// notification fires at most once per submit (a locked keyring fails every
/// label but the user needs one toast for the single root cause). Impure async
/// glue — no unit surface.
pub(super) async fn save_remembered_credentials(
    values: &[(String, String)],
    slots: &[(u32, u32, u32, String, bool)],
    cred_key: &str,
    store: &crate::credentials::CredentialStore,
) {
    let mut save_failure_notified = false;
    for (label, value) in values {
        if !is_storable_field(label, slot_mask(label, slots)) {
            continue;
        }
        if let Err(e) = store.set_async(cred_key, label, value).await {
            // A failed "remember" must not be silent — the user believes
            // credentials were saved when they weren't.
            warn!("Failed to save credential '{}' to keyring: {}", label, e);
            if !save_failure_notified {
                save_failure_notified = true;
                crate::dialogs::show_error_notification(
                    "Credential Save Failed",
                    save_failure_hint(crate::credentials::store::is_locked_error(&e)),
                );
            }
        }
    }
}

/// Delete submitted credentials from the keyring when "remember" was unticked.
///
/// Extracted from the dialog submit callback's `Ok(true)` arm. Delete failure
/// is lower-stakes than save failure (worst case: a stale entry), so it only
/// logs. Impure async glue — no unit surface.
pub(super) async fn delete_remembered_credentials(
    values: &[(String, String)],
    slots: &[(u32, u32, u32, String, bool)],
    cred_key: &str,
    store: &crate::credentials::CredentialStore,
) {
    for (label, _value) in values {
        if !is_storable_field(label, slot_mask(label, slots)) {
            continue;
        }
        if let Err(e) = store.delete_async(cred_key, label).await {
            warn!(
                "Failed to delete credential '{}' from keyring: {}",
                label, e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{keyring_unlock_hint, save_failure_hint};

    #[test]
    fn save_failure_hint_distinguishes_locked() {
        assert_eq!(
            save_failure_hint(true),
            "Keyring is locked — credentials could not be saved."
        );
        assert_eq!(
            save_failure_hint(false),
            "Could not save credentials to the keyring."
        );
    }

    #[test]
    fn keyring_unlock_hint_distinguishes_locked() {
        assert_eq!(
            keyring_unlock_hint(true),
            "Keyring is locked. Enter credentials manually."
        );
        assert_eq!(
            keyring_unlock_hint(false),
            "Could not unlock the keyring. Enter credentials manually."
        );
    }
}
