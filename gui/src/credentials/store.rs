//! Credential storage using Secret Service (oo7)
//!
//! Provides secure storage for VPN credentials using the freedesktop Secret Service API.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

/// Application identifier for the secret collection
const APP_ID: &str = "net.openvpn.openvpn3-gui-rs";

/// One-way keyring attribute for a config's unique D-Bus object path.
///
/// Secret Service stores attributes **unencrypted** — they index the collection
/// so callers can search without unlocking it. A raw object path here would
/// therefore leak which configs are stored and which fields each has to anyone
/// who can read the keyring file (backup leak, lost laptop). A SHA-256 digest
/// keeps the value unique and searchable without revealing the path.
///
/// `v1:` prefix lets a future scheme change detect the encoding. Pure — the
/// attribute contract + collision behaviour is unit-tested.
fn config_id_key(config_path: &str) -> String {
    let digest = Sha256::digest(config_path.as_bytes());
    format!("v1:{digest:x}")
}

/// Classify whether a credential error means "the keyring is locked (or
/// the user declined the unlock prompt, so it stayed locked)".
///
/// Walks the anyhow error chain (which includes the store methods' own
/// `.context()` wrappers) for two Secret Service conditions:
/// - `oo7::dbus::ServiceError::IsLocked(_)` — the collection is locked.
/// - `oo7::dbus::Error::Dismissed` — the user cancelled the unlock dialog.
///
/// Both warrant the same user-facing hint: the keyring stayed locked, so the
/// credential op couldn't proceed. The unlock dialog only appears because the
/// collection was locked, so a dismissed prompt means it *remains* locked.
///
/// Invariant: `Dismissed` only ever arises from `Keyring::unlock()` here —
/// `search_items`/`create_item`/`delete` do not prompt on their own — so any
/// `Dismissed` reaching the error path is an unlock dismissal, not some other
/// cancelled prompt. If a future store method issues its own prompt, this
/// classification must be re-checked.
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
                )) | oo7::Error::DBus(oo7::dbus::Error::Dismissed)
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
    // Hashed so the unencrypted attribute reveals no path (#3); uniqueness is
    // preserved because the hash is deterministic on the unique D-Bus path.
    attributes.insert("config-id", config_id_key(config_id));
    attributes
}

/// Attribute map for a single legacy (pre-0.3.11) secret, keyed by the config
/// **display name** — the scheme the #2 fix migrates away from, because two
/// configs can share a name and collide. Used only by [`migrate_legacy_secret`]
/// for the one-time read-on-miss upgrade path; new writes never use it.
///
/// Pure (no keyring I/O) so the legacy attribute contract is unit-testable.
fn legacy_search_attrs(
    config_name: &str,
    key: &str,
) -> std::collections::HashMap<&'static str, String> {
    let mut attributes = std::collections::HashMap::new();
    attributes.insert("application", APP_ID.to_string());
    attributes.insert("config-id", config_name.to_string());
    attributes.insert("key", key.to_string());
    attributes
}

/// Read the first secret matching `application` + `config-id` + `key`.
///
/// `config_id_attr` is already the value to store under `config-id` — callers
/// pass [`config_id_key`] for the hashed scheme or the raw path for the
/// pre-0.4.5 backward-compat probe. Returns `Ok(None)` on a clean miss.
/// Factored so the read path can try both key forms without duplicating the
/// decode chain.
async fn read_secret_for(
    keyring: &oo7::Keyring,
    config_id_attr: &str,
    key: &str,
) -> Result<Option<String>> {
    let attributes = legacy_search_attrs(config_id_attr, key);
    // `legacy_search_attrs` builds the exact `application + config-id + key`
    // triple we need; it is named for its original caller but is a generic
    // three-field attribute map, so reuse it here rather than duplicate.
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

/// Delete every item matching `application` + `config-id` + `key`.
///
/// Like [`read_secret_for`], `config_id_attr` is the resolved attribute value
/// (hashed or raw path). Best-effort across matched items: each delete is
/// reported independently so one failure doesn't mask the rest.
async fn delete_matching(keyring: &oo7::Keyring, config_id_attr: &str, key: &str) -> Result<()> {
    let attributes = legacy_search_attrs(config_id_attr, key);
    let items = keyring
        .search_items(&attributes)
        .await
        .context("Failed to search for credential")?;
    for item in items {
        item.delete().await.context("Failed to delete credential")?;
    }
    Ok(())
}

/// One-time migration of a single secret from the legacy name-keyed scheme to
/// the path-keyed scheme, run on a read-miss under the new key.
///
/// Pre-0.3.11 the keyring `config-id` was the config display name; #2 (S34
/// review) showed two configs may share a name and cross-wipe, so the key is
/// now the unique D-Bus path. This bridges existing users: if a secret is
/// found under the old name key, re-store it under the path key and delete the
/// legacy item.
///
/// Best-effort and **never lossy**: any error (legacy item missing, keyring
/// write/delete failure) returns `Ok(None)` and leaves the legacy item intact,
/// so a subsequent read can retry and the secret is never destroyed. Only a
/// confirmed successful re-store + legacy delete returns the migrated value.
async fn migrate_legacy_secret(
    keyring: &oo7::Keyring,
    config_id: &str,
    legacy_config_name: &str,
    key: &str,
) -> Result<Option<String>> {
    // Guard against sentinel identities: when the caller couldn't resolve a
    // real config (tray miss → fallback name, empty path), the config_id we'd
    // migrate *to* is empty and the legacy name is a fallback string
    // ("VPN Connection"/"VPN"). Migrating under an empty path key would
    // re-key a legit legacy entry to a bogus target, and on a later real
    // import the bogus one could shadow the real secret. Treat as absent.
    // Guard on the PATH (the migration target), not the display name — the
    // path is the unique key and is empty precisely when identity is unknown.
    if config_id.is_empty() {
        return Ok(None);
    }

    let legacy_attrs = legacy_search_attrs(legacy_config_name, key);
    let legacy_items = match keyring.search_items(&legacy_attrs).await {
        Ok(items) => items,
        Err(e) => {
            // Unreliable search — don't claim absence; just skip migration.
            warn!(
                "Legacy credential migration: search failed for '{legacy_config_name}/{key}': {e}"
            );
            return Ok(None);
        }
    };
    let Some(legacy_item) = legacy_items.first() else {
        return Ok(None); // nothing to migrate
    };

    let secret = match legacy_item.secret().await {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!("Legacy credential migration: read failed for '{legacy_config_name}/{key}': {e}");
            return Ok(None);
        }
    };
    let password = match String::from_utf8(secret.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "Legacy credential migration: invalid UTF-8 for '{legacy_config_name}/{key}': {e}"
            );
            return Ok(None);
        }
    };

    // Re-store under the new path key before deleting the legacy item — if the
    // create fails, the old secret survives.
    let mut new_attrs = search_attrs_for_config(config_id);
    new_attrs.insert("key", key.to_string());
    // Generic label (#3): re-storing under the hashed path key must not re-leak
    // the path in the human-facing label.
    if let Err(e) = keyring
        .create_item(
            "OpenVPN3 GUI credential",
            &new_attrs,
            password.as_bytes(),
            true,
        )
        .await
    {
        warn!("Legacy credential migration: re-store failed for '{config_id}/{key}': {e}");
        return Ok(None);
    }

    // Legacy delete is last — best-effort; a leftover stale item is harmless
    // (never read again once the path key is populated) and must not undo a
    // successful migration.
    if let Err(e) = legacy_item.delete().await {
        warn!(
            "Legacy credential migration: legacy delete failed for '{legacy_config_name}/{key}': {e}"
        );
    }
    info!("Migrated legacy credential '{legacy_config_name}/{key}' -> path key '{config_id}'");
    Ok(Some(password))
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
    /// `config_id` is the config's **unique D-Bus object path** (not the
    /// display name) — see the #2 fix: two configs may share a name, so the
    /// keyring namespace is keyed by the path to keep their secrets isolated.
    ///
    /// On a miss under the path key, attempts a **one-time migration** from
    /// the pre-0.3.11 name-keyed scheme via [`migrate_legacy_secret`]:
    /// `legacy_config_name` is the old display-name key. If a secret is found
    /// there it is re-stored under the path key and the legacy item deleted,
    /// so existing users don't lose saved credentials on upgrade. Migration is
    /// best-effort — on any error the legacy item is left intact (returning
    /// `None`) so a later read can retry and the secret is never lost.
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
        legacy_config_name: &str,
        key: &str,
    ) -> Result<Option<String>> {
        // Try the hashed config-id first (post-0.4.5 scheme, #3): the unencrypted
        // attribute reveals no path, while the deterministic hash keeps the
        // value unique and searchable.
        if let Some(val) = read_secret_for(keyring, &config_id_key(config_id), key).await? {
            return Ok(Some(val));
        }

        // Backward-compat: pre-0.4.5 stored the raw path as `config-id`. A
        // transparent re-read keeps an upgrade from blanking saved credentials;
        // the old entry lingers until the user re-saves (documented limitation).
        if let Some(val) = read_secret_for(keyring, config_id, key).await? {
            return Ok(Some(val));
        }

        // Miss under both path keys — try migrating from the legacy name-keyed
        // scheme before reporting absence.
        migrate_legacy_secret(keyring, config_id, legacy_config_name, key).await
    }

    /// Store a credential asynchronously. `config_id` is the config's unique
    /// D-Bus object path (post-#2 keying; the display name is legacy-only).
    pub async fn set_async(&self, config_id: &str, key: &str, value: &str) -> Result<()> {
        use oo7::Keyring;
        use std::collections::HashMap;

        let keyring = Keyring::new().await.context("Failed to open keyring")?;

        // Unlock before writing. On a locked DBus collection create_item is
        // not persisted, so without this a "Remember" save would appear to
        // succeed yet store nothing — exactly the locked-keyring gap the read
        // path already closes. Noop on the file backend. Mirrors
        // delete_for_config_async and the read path in request_credentials.
        ensure_unlocked(&keyring).await?;

        let mut attributes = HashMap::new();
        attributes.insert("application", APP_ID.to_string());
        // Hashed config-id (#3): the unencrypted attribute reveals no path. The
        // label is path-agnostic for the same reason — a human-facing label
        // would re-leak what the hash hides.
        attributes.insert("config-id", config_id_key(config_id));
        attributes.insert("key", key.to_string());

        let label = "OpenVPN3 GUI credential";

        keyring
            .create_item(label, &attributes, value.as_bytes(), true)
            .await
            .context("Failed to store credential")?;

        Ok(())
    }

    /// Delete all credentials stored by this application
    pub async fn clear_all_async(&self) -> Result<usize> {
        use oo7::Keyring;
        use std::collections::HashMap;

        let keyring = Keyring::new().await.context("Failed to open keyring")?;

        // Unlock before searching. On a locked DBus collection search_items
        // returns no usable items, so without this a global clear would
        // silently report Ok(0) and every secret survive — exactly the
        // locked-keyring gap delete_for_config_async closes. Noop on the file
        // backend. Affects Preferences ▸ Security “Clear all” and the
        // `--clear-secret-storage` startup flag.
        ensure_unlocked(&keyring).await?;

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

    /// Delete every credential stored for one config (by `config-id`), leaving
    /// other configs' credentials intact.
    ///
    /// `config_id` is the config's unique D-Bus object path — so a removal
    /// wipes only that config's path-keyed secrets, even if another config
    /// shares its display name (the #2 fix: previously keyed by name, a
    /// same-named sibling would cross-wipe). Legacy pre-0.3.11 name-keyed
    /// items are deliberately NOT matched here: a name is not unique, so
    /// deleting by name reintroduces the cross-wipe. Such orphans are
    /// harmless (never read again once the path key is populated; migrated on
    /// read otherwise) and age out with [`Self::clear_all_async`].
    ///
    /// The middle ground between [`Self::delete_async`] (one label, full triple) and
    /// [`Self::clear_all_async`] (every config, by `application` only). Used when a
    /// config is removed so its saved username/password don't orphan in the
    /// keyring. Returns the number of items deleted.
    pub async fn delete_for_config_async(&self, config_id: &str) -> Result<usize> {
        use oo7::Keyring;

        let keyring = Keyring::new().await.context("Failed to open keyring")?;

        // Unlock before searching. On a locked DBus collection search_items
        // returns no/locked items, so without this a remove-time wipe would
        // silently no-op and the config's credentials would orphan — exactly
        // the locked-keyring gap the read path already closes. Noop on the
        // file backend. Mirrors the unlock the read path does in
        // credential_handler::request_credentials.
        ensure_unlocked(&keyring).await?;

        // Match both the hashed (#3) and pre-0.4.5 raw-path entries so removing
        // a config wipes its secrets regardless of which scheme stored them.
        let hashed_attrs = search_attrs_for_config(config_id);
        let mut items = keyring
            .search_items(&hashed_attrs)
            .await
            .context("Failed to search for credentials")?;

        let mut raw_attrs = std::collections::HashMap::new();
        raw_attrs.insert("application", APP_ID.to_string());
        raw_attrs.insert("config-id", config_id.to_string());
        items.extend(
            keyring
                .search_items(&raw_attrs)
                .await
                .context("Failed to search for legacy credentials")?,
        );

        let count = items.len();
        for item in items {
            item.delete().await.context("Failed to delete credential")?;
        }

        Ok(count)
    }

    /// Delete a credential asynchronously
    pub async fn delete_async(&self, config_id: &str, key: &str) -> Result<()> {
        use oo7::Keyring;

        let keyring = Keyring::new().await.context("Failed to open keyring")?;

        // Unlock before searching. On a locked DBus collection search_items
        // returns no usable items, so without this a field-delete would
        // silently report Ok(()) and the stale entry survive — same
        // locked-keyring gap the sibling delete paths close. Noop on the
        // file backend.
        ensure_unlocked(&keyring).await?;

        // Delete both the hashed (#3) and the pre-0.4.5 raw-path entries, so a
        // "forget this field" fully cleans up regardless of which scheme stored
        // the secret. Ordering: hashed first (the live scheme), raw path second
        // (legacy). A miss in either is a no-op.
        delete_matching(&keyring, &config_id_key(config_id), key).await?;
        delete_matching(&keyring, config_id, key).await?;

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
        // just one. This pins the contract: include application + config-id
        // (hashed, #3), exclude key.
        let attrs = search_attrs_for_config("work-vpn");
        assert_eq!(attrs.get("application").map(|s| s.as_str()), Some(APP_ID));
        assert_eq!(
            attrs.get("config-id").map(|s| s.as_str()),
            Some(config_id_key("work-vpn").as_str()),
            "config-id must be the hashed path, not the raw path (#3)"
        );
        // The hash must NOT equal the raw path — that's the whole point.
        assert_ne!(
            attrs.get("config-id").map(|s| s.as_str()),
            Some("work-vpn"),
            "the raw path must not appear verbatim in the unencrypted attribute"
        );
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

    // --- config_id_key (#3) ---

    #[test]
    fn config_id_key_is_deterministic_and_path_specific() {
        // Same path → same digest (searchability depends on this).
        assert_eq!(
            config_id_key("/net/openvpn/v3/configuration/cfg/1"),
            config_id_key("/net/openvpn/v3/configuration/cfg/1")
        );
        // Different paths → different digests (config isolation).
        assert_ne!(
            config_id_key("/net/openvpn/v3/configuration/cfg/1"),
            config_id_key("/net/openvpn/v3/configuration/cfg/2")
        );
    }

    #[test]
    fn config_id_key_hides_the_raw_path() {
        // The attribute is stored unencrypted for searchability, so it must not
        // contain the path or any recognizable fragment of it.
        let path = "/net/openvpn/v3/configuration/cfg/1";
        let key = config_id_key(path);
        assert!(
            !key.contains(path),
            "hashed config-id must not embed the raw path"
        );
        assert!(
            !key.contains("openvpn") && !key.contains("configuration"),
            "hashed config-id must not leak recognizable path tokens"
        );
        assert!(
            key.starts_with("v1:"),
            "version prefix must tag the encoding scheme for future migrations"
        );
        // Same-named configs on different paths must collide-proof (the #2 fix
        // invariant survives hashing): distinct paths stay distinct even if the
        // trailing path segment is identical.
        assert_ne!(config_id_key("/a/cfg/1"), config_id_key("/b/cfg/1"));
    }

    #[test]
    fn config_id_key_is_one_way() {
        // Not a real inversion test (can't prove a negative over all inputs),
        // but pin the digest shape: 64 hex chars after the v1: prefix, so a
        // future regression to a reversible encoding (e.g. base64 of the path)
        // changes the length/charset and trips this.
        let key = config_id_key("/net/openvpn/v3/configuration/cfg/1");
        let digest = key.strip_prefix("v1:").unwrap_or(&key);
        assert_eq!(digest.len(), 64, "expected SHA-256 hex (64 chars)");
        assert!(
            digest.chars().all(|c| c.is_ascii_hexdigit()),
            "digest must be lowercase hex"
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
    fn search_attrs_for_config_isolates_same_named_configs() {
        // The #2 fix core: two configs that SHARE a display name must still
        // get distinct keyring namespaces, because the key is now the unique
        // D-Bus path, not the name. A remove-time wipe of one must not match
        // the other's stored secrets (the cross-wipe the finding predicted).
        // Daemon permits duplicate names — verified real-device in S35 T1.
        let path_a = "/net/openvpn/v3/configuration/cfg/1";
        let path_b = "/net/openvpn/v3/configuration/cfg/2";
        let a = search_attrs_for_config(path_a);
        let b = search_attrs_for_config(path_b);
        assert_ne!(
            a.get("config-id"),
            b.get("config-id"),
            "same-named configs MUST have distinct path-keyed queries, or removing one wipes both"
        );
    }

    #[test]
    fn legacy_search_attrs_pins_pre_migration_scheme() {
        // The legacy (pre-0.3.11) scheme keyed by display NAME + key, used
        // only for the one-time read-on-miss migration. Pin its shape so a
        // future refactor can't silently break the upgrade path for existing
        // users: application + config-id(name) + key.
        let attrs = legacy_search_attrs("work-vpn", "Username");
        assert_eq!(attrs.get("application").map(|s| s.as_str()), Some(APP_ID));
        assert_eq!(attrs.get("config-id").map(|s| s.as_str()), Some("work-vpn"));
        assert_eq!(attrs.get("key").map(|s| s.as_str()), Some("Username"));
        assert_eq!(attrs.len(), 3, "legacy query is the full triple");
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
    fn is_locked_error_treats_dismissed_as_locked() {
        // Canceling the unlock prompt the collection itself raised means the
        // keyring stayed locked, so the classifier must return true — the
        // user-facing hint ("keyring locked") is the right message, not a
        // generic one. The prompt only appears because the collection was
        // locked, so Dismissed here implies locked.
        let dismissed: anyhow::Error =
            anyhow::Error::new(oo7::Error::DBus(oo7::dbus::Error::Dismissed));
        assert!(
            is_locked_error(&dismissed),
            "a dismissed unlock prompt means the keyring stayed locked"
        );
    }

    #[test]
    fn is_locked_error_rejects_unrelated_error() {
        // A transport error or a missing item is not a lock condition — the
        // classifier must return false so the UI shows a generic failure.
        let not_found: anyhow::Error =
            anyhow::Error::new(oo7::Error::DBus(oo7::dbus::Error::NotFound("x".into())));
        assert!(!is_locked_error(&not_found));
    }
}
