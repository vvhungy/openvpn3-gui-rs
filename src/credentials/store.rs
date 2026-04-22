//! Credential storage using Secret Service (oo7)
//!
//! Provides secure storage for VPN credentials using the freedesktop Secret Service API.

use anyhow::{Context, Result};

/// Application identifier for the secret collection
const APP_ID: &str = "net.openvpn.openvpn3-gui-rs";

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
}
