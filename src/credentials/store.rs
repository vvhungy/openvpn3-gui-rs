//! Credential storage using Secret Service (oo7)
//!
//! Provides secure storage for VPN credentials using the freedesktop Secret Service API.

use anyhow::{Context, Result};

/// Application identifier for the secret collection
const APP_ID: &str = "net.openvpn.openvpn3-gui-rs";

/// Credential storage using Secret Service
#[allow(dead_code)]
pub struct CredentialStore {
    // Keyring is created lazily when needed
}

#[allow(dead_code)]
impl CredentialStore {
    /// Create a new CredentialStore instance
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }

    /// Create a new CredentialStore instance (sync wrapper)
    pub fn new_sync() -> Self {
        Self {}
    }

    /// Get a credential from the store (sync - returns None, use get_async)
    pub fn get(&self, _config_id: &str, _key: &str) -> Result<Option<String>> {
        // Use get_async instead
        Ok(None)
    }

    /// Store a credential (sync - does nothing, use set_async)
    pub fn set(&self, _config_id: &str, _key: &str, _value: &str) -> Result<()> {
        // Use set_async instead
        Ok(())
    }

    /// Delete a credential from the store (sync - does nothing, use delete_async)
    pub fn delete(&self, _config_id: &str, _key: &str) -> Result<()> {
        // Use delete_async instead
        Ok(())
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

        let label = format!("OpenVPN3 Indicator: {} - {}", config_id, key);

        keyring
            .create_item(&label, &attributes, value.as_bytes(), true)
            .await
            .context("Failed to store credential")?;

        Ok(())
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
    fn test_sync_get_returns_none() {
        let store = CredentialStore::default();
        let result = store.get("my-vpn", "username");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_sync_set_is_ok() {
        let store = CredentialStore::default();
        assert!(store.set("my-vpn", "username", "user@example.com").is_ok());
    }

    #[test]
    fn test_sync_delete_is_ok() {
        let store = CredentialStore::default();
        assert!(store.delete("my-vpn", "username").is_ok());
    }
}
