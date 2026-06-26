//! Credential storage using Secret Service (oo7)
//!
//! Provides secure storage for VPN credentials using the freedesktop Secret Service API.

use anyhow::{Context, Result};

/// Application identifier for the secret collection
const APP_ID: &str = "net.openvpn.openvpn3-gui-rs";

/// Classify whether a credential error is "the collection is locked".
///
/// Walks the anyhow error chain (which includes the store methods' own
/// `.context()` wrappers) looking for the Secret Service locked-collection
/// signal: `oo7::Error::DBus(oo7::dbus::Error::Service(oo7::dbus::ServiceError::IsLocked(_)))`.
///
/// Pure (no I/O) so the chain-walk + variant match is unit-testable without a
/// keyring — callers use it to pick a user-facing message ("keyring locked")
/// over a generic one.
pub(crate) fn is_locked_error(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause.downcast_ref::<oo7::Error>().is_some_and(|o| {
            matches!(
                o,
                oo7::Error::DBus(oo7::dbus::Error::Service(
                    oo7::dbus::ServiceError::IsLocked(_)
                ))
            )
        })
    })
}

/// Ensure the keyring collection is unlocked before reading or writing.
///
/// `Keyring::unlock` is a noop on the file backend, so flatpak/sandboxed runs
/// are unaffected. On the DBus backend it triggers the Secret Service
/// `Service.Unlock` call, which surfaces the system prompt (GNOME Keyring
/// login dialog) and awaits the user; unlocking an already-unlocked collection
/// is a spec'd noop (no prompt). We call `unlock` unconditionally rather than
/// gating on a lock check — oo7 0.4.3 exposes no `Keyring::is_locked` (only
/// `Item::is_locked`), and the round-trip is cheap. Errors (user dismissed
/// the prompt, no secret service running) propagate to the caller, which must
/// NOT treat a locked/refused keyring as fatal — pre-fill is a convenience,
/// not a gate.
pub(crate) async fn ensure_unlocked(keyring: &oo7::Keyring) -> Result<()> {
    keyring
        .unlock()
        .await
        .context("Failed to unlock keyring (dismissed or no secret service)")
}

/// Attribute map for the per-config delete query: `application` + `config-id`,
/// deliberately **without** the `key` field, so a single config's whole set of
/// stored labels is matched. This is what makes `delete_for_config_async` the
/// "forget this config" operation vs. `delete_async`'s "forget one field".
///
/// Pure (no keyring I/O) so the attribute contract — must include `config-id`,
/// must NOT include `key` — is unit-testable.
fn search_attrs_for_config(config_id: &str) -> std::collections::HashMap<&str, String> {
    let mut attributes = std::collections::HashMap::new();
    attributes.insert("application", APP_ID.to_string());
    attributes.insert("config-id", config_id.to_string());
    attributes
}

/// Credential storage using Secret Service
pub struct CredentialStore {
    // Keyring is created lazily when needed
}

impl CredentialStore {
    /// Create a new CredentialStore instance
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }

    /// Create a new CredentialStore instance (sync wrapper)
    pub fn new_sync() -> Self {
        Self {}
    }
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new_sync()
    }
}

/// Async functions for credential operations
impl CredentialStore {
    /// Get a credential using a **caller-opened** keyring handle.
    ///
    /// Lets a caller open one `oo7::Keyring`, unlock it once via
    /// [`ensure_unlocked`], then loop reads against the same handle — so the
    /// unlock state is shared and we avoid N separate `Keyring::new()` opens
    /// for N labels. Errors propagate (callers must NOT conflate error with
    /// absent — see the read loop in `credential_handler::request_credentials`).
    pub(crate) async fn get_with_keyring(
        &self,
        keyring: &oo7::Keyring,
        config_id: &str,
        key: &str,
    ) -> Result<Option<String>> {
        use std::collections::HashMap;

        let mut attributes = HashMap::new();
        attributes.insert("application", APP_ID);
        attributes.insert("config-id", config_id);
        attributes.insert("key", key);

        let items = keyring
            .search_items(&attributes)
            .await
            .context("Failed to search for credential")?;

        if let Some(item) = items.first() {
            let secret = item.secret().await.context("Failed to retrieve secret")?;
            let password = String::from_utf8(secret.to_vec()).context("Invalid UTF-8 in secret")?;
            Ok(Some(password))
        } else {
            Ok(None)
        }
    }

    /// Store a credential asynchronously
    pub async fn set_async(&self, config_id: &str, key: &str, value: &str) -> Result<()> {
        use oo7::Keyring;
        use std::collections::HashMap;

        let keyring = Keyring::new().await.context("Failed to open keyring")?;

        let mut attributes = HashMap::new();
        attributes.insert("application", APP_ID);
        attributes.insert("config-id", config_id);
        attributes.insert("key", key);

        let label = format!("OpenVPN3 GUI: {} - {}", config_id, key);

        keyring
            .create_item(&label, &attributes, value.as_bytes(), true)
            .await
            .context("Failed to store credential")?;

        Ok(())
    }

    /// Delete all credentials stored by this application
    pub async fn clear_all_async(&self) -> Result<usize> {
        use oo7::Keyring;
        use std::collections::HashMap;

        let keyring = Keyring::new().await.context("Failed to open keyring")?;

        let mut attributes = HashMap::new();
        attributes.insert("application", APP_ID);

        let items = keyring
            .search_items(&attributes)
            .await
            .context("Failed to search for credentials")?;

        let count = items.len();
        for item in items {
            item.delete().await.context("Failed to delete credential")?;
        }

        Ok(count)
    }

    /// Delete every credential stored for one config (by `config-id`),
    /// leaving other configs' credentials intact.
    ///
    /// The middle ground between [`delete_async`] (one label, full triple) and
    /// [`clear_all_async`] (every config, by `application` only). Used when a
    /// config is removed so its saved username/password don't orphan in the
    /// keyring. Returns the number of items deleted.
    pub async fn delete_for_config_async(&self, config_id: &str) -> Result<usize> {
        use oo7::Keyring;

        let keyring = Keyring::new().await.context("Failed to open keyring")?;

        let attributes = search_attrs_for_config(config_id);
        let items = keyring
            .search_items(&attributes)
            .await
            .context("Failed to search for credentials")?;

        let count = items.len();
        for item in items {
            item.delete().await.context("Failed to delete credential")?;
        }

        Ok(count)
    }

    /// Delete a credential asynchronously
    pub async fn delete_async(&self, config_id: &str, key: &str) -> Result<()> {
        use oo7::Keyring;
        use std::collections::HashMap;

        let keyring = Keyring::new().await.context("Failed to open keyring")?;

        let mut attributes = HashMap::new();
        attributes.insert("application", APP_ID);
        attributes.insert("config-id", config_id);
        attributes.insert("key", key);

        let items = keyring
            .search_items(&attributes)
            .await
            .context("Failed to search for credential")?;

        for item in items {
            item.delete().await.context("Failed to delete credential")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_succeeds() {
        assert!(CredentialStore::new().is_ok());
    }

    #[test]
    fn test_default_creates_instance() {
        let _store = CredentialStore::default();
    }

    #[test]
    fn search_attrs_for_config_includes_config_id_not_key() {
        // The per-config delete must scope by config-id but NOT key, so removing
        // a config wipes all its stored labels (username + password + OTP), not
        // just one. This pins the contract: include application + config-id,
        // exclude key.
        let attrs = search_attrs_for_config("work-vpn");
        assert_eq!(attrs.get("application").map(|s| s.as_str()), Some(APP_ID));
        assert_eq!(attrs.get("config-id").map(|s| s.as_str()), Some("work-vpn"));
        assert!(
            !attrs.contains_key("key"),
            "per-config delete must NOT include the `key` attribute, or it would only match one field"
        );
        assert_eq!(
            attrs.len(),
            2,
            "exactly application + config-id, nothing else"
        );
    }

    #[test]
    fn search_attrs_for_config_isolates_configs() {
        // Distinct config names produce distinct queries — config A's delete
        // query must not match config B's items.
        let a = search_attrs_for_config("alpha");
        let b = search_attrs_for_config("beta");
        assert_ne!(
            a.get("config-id"),
            b.get("config-id"),
            "per-config queries must be config-specific"
        );
        // Both still share the application scope.
        assert_eq!(a.get("application"), b.get("application"));
    }

    #[test]
    fn is_locked_error_detects_islocked_variant() {
        // The exact shape the Secret Service produces when a collection is locked,
        // wrapped in anyhow as the store methods return it.
        let err: anyhow::Error = anyhow::Error::new(oo7::Error::DBus(oo7::dbus::Error::Service(
            oo7::dbus::ServiceError::IsLocked("/org/freedesktop/secrets/collection/default".into()),
        )));
        assert!(is_locked_error(&err));
    }

    #[test]
    fn is_locked_error_walks_anyhow_context_chain() {
        // Store methods add `.context()` on top of the raw oo7 error. The
        // classifier must find IsLocked through the wrapped chain.
        let raw = oo7::Error::DBus(oo7::dbus::Error::Service(
            oo7::dbus::ServiceError::IsLocked("default".into()),
        ));
        let wrapped: anyhow::Error = anyhow::Error::new(raw).context("get_with_keyring failed");
        assert!(
            is_locked_error(&wrapped),
            "must detect locked state through an anyhow context chain"
        );
    }

    #[test]
    fn is_locked_error_rejects_non_locked_error() {
        // A dismissed prompt, a transport error, a missing service — none of these
        // mean "locked". The classifier must return false so the UI shows a
        // generic failure message, not the unlock hint.
        let dismissed: anyhow::Error =
            anyhow::Error::new(oo7::Error::DBus(oo7::dbus::Error::Dismissed));
        assert!(!is_locked_error(&dismissed));
    }
}
