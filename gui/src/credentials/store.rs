//! Credential storage using Secret Service (oo7)
//!
//! Provides secure storage for VPN credentials using the freedesktop Secret Service API.

use anyhow::{Context, Result};

/// Application identifier for the secret collection
const APP_ID: &str = "net.openvpn.openvpn3-gui-rs";

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
    /// Get a credential asynchronously
    pub async fn get_async(&self, config_id: &str, key: &str) -> Result<Option<String>> {
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
}
