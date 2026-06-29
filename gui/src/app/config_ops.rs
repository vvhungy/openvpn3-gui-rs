//! Configuration D-Bus operations
//!
//! Testable pure surface: `validate_method_missing` (+ its test).

use tracing::{error, info, warn};
use zbus::proxy::CacheProperties;
use zbus::zvariant::OwnedObjectPath;

use crate::dbus::configuration::{ConfigurationManagerProxy, ConfigurationProxy};
use crate::tray::{ConfigInfo, VpnTray};

/// The D-Bus error names that mean "the method does not exist on this
/// interface" — i.e. the daemon predates v22 and has no `Validate()`.
const MISSING_METHOD_ERROR_NAMES: &[&str] = &[
    "org.freedesktop.DBus.Error.UnknownMethod",
    "org.freedesktop.DBus.Error.NoReply",
];

/// True when `name` is one of the D-Bus error names signalling a missing
/// method (a pre-v22 daemon with no `Validate()`).
///
/// Pure (testable) half of [`validate_method_missing`].
fn is_missing_method_error_name(name: &str) -> bool {
    MISSING_METHOD_ERROR_NAMES.contains(&name)
}

/// True when a `Validate()` error means the daemon is too old to expose the
/// method (pre-v22), so import should skip validation rather than reject.
///
/// Match the D-Bus error *name*, never the human message: a real parse
/// failure ("file does not exist", "No such interface option") can carry the
/// same substrings and must not be mis-classified as a missing method.
fn validate_method_missing(err: &zbus::Error) -> bool {
    match err {
        zbus::Error::MethodError(name, _, _) => is_missing_method_error_name(name.as_str()),
        // Other variants (Timeout, UnknownInterface on the proxy path, etc.)
        // are never a "missing method" — treat as a real failure.
        _ => false,
    }
}

/// Refresh the config list in the tray
pub(crate) async fn refresh_configs(
    dbus: &zbus::Connection,
    tray: &ksni::blocking::Handle<VpnTray>,
) {
    match ConfigurationManagerProxy::builder(dbus)
        .cache_properties(CacheProperties::No)
        .build()
        .await
    {
        Ok(config_manager) => {
            if let Ok(paths) = config_manager.FetchAvailableConfigs().await {
                let mut configs = Vec::new();
                for path in &paths {
                    let builder = match ConfigurationProxy::builder(dbus).path(path.clone()) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("Invalid config path {}: {}", path, e);
                            continue;
                        }
                    };
                    if let Ok(config) = builder.build().await
                        && let Ok(name) = config.name().await
                    {
                        configs.push(ConfigInfo {
                            path: path.as_str().to_string(),
                            name,
                        });
                    }
                }
                tray.update(move |t| {
                    t.configs = configs;
                });
                info!("Config list refreshed");
            }
        }
        Err(e) => error!("Failed to refresh configs: {}", e),
    }
}

/// Import a configuration file
///
/// openvpn3's `Import()` stores the raw blob **without parsing it** — a
/// malformed file is accepted and silently shows up in the profile list. To
/// reject junk configs at import time we call `Validate()` (daemon v22+)
/// immediately after Import; on failure we remove the just-added config and
/// surface the daemon's error so the caller's result dialog shows it. A daemon
/// too old to expose `Validate()` is skipped (warn-only) so import keeps
/// working on legacy installs.
pub(crate) async fn import_config(
    dbus: &zbus::Connection,
    name: &str,
    path: &std::path::Path,
) -> anyhow::Result<()> {
    let config_content = std::fs::read_to_string(path)?;
    let config_manager = ConfigurationManagerProxy::builder(dbus)
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    let config_path = config_manager
        .Import(name, &config_content, false, true)
        .await?;
    info!("Configuration imported: {}", config_path);

    let config = ConfigurationProxy::builder(dbus)
        .path(config_path.clone())?
        .build()
        .await?;
    match config.Validate().await {
        Ok(()) => info!("Configuration validated: {}", config_path),
        Err(e) => {
            // Pre-v22 daemons lack the Validate() method — skip rather than
            // reject on legacy installs. Match the D-Bus error *name*, not a
            // substring of the message: a genuine parse failure's human text
            // (e.g. "referenced file does not exist") can contain "not exist"
            // / "No such interface" and would otherwise be mis-classified as
            // "legacy daemon", leaving the malformed config stored as success.
            if validate_method_missing(&e) {
                warn!("Validate() unsupported by daemon, skipping: {}", e);
            } else {
                warn!("Config '{}' failed validation: {}", config_path, e);
                // Remove the junk config we just added so it doesn't linger.
                // Surface a Remove() failure in the bail message too, so a
                // lingering junk config isn't hidden behind a clean error.
                if let Err(rm_err) = config.Remove().await {
                    warn!(
                        "Failed to remove invalid config {}: {}",
                        config_path, rm_err
                    );
                    anyhow::bail!(
                        "configuration failed validation: {e} \
                         (and removing the rejected config failed: {rm_err})"
                    );
                } else {
                    anyhow::bail!("configuration failed validation: {}", e);
                }
            }
        }
    }

    crate::dialogs::show_info_notification(
        "Import Successful",
        &format!("Configuration '{}' has been imported", name),
    );
    Ok(())
}

/// Remove a configuration, then best-effort wipe its stored credentials.
///
/// `config_path_str` is the unique D-Bus object path — and, post-#2, the
/// keyring key. The credential wipe scopes by the PATH, not the display name:
/// two configs may share a name (verified real-device, S35 T1), so keying the
/// remove-time wipe by name would cross-wipe a same-named sibling. `config_name`
/// is kept only for the log message.
///
/// A keyring failure here must NOT block removal: the config is already gone
/// from openvpn3, so leftover secrets are at worst stale, not dangerous. Log +
/// continue.
pub(crate) async fn remove_config(
    dbus: &zbus::Connection,
    config_path_str: &str,
    config_name: &str,
) -> anyhow::Result<()> {
    let config_path = OwnedObjectPath::try_from(config_path_str)?;
    let config = ConfigurationProxy::builder(dbus)
        .path(config_path)?
        .build()
        .await?;
    config.Remove().await?;
    info!("Configuration removed: {}", config_path_str);

    // Best-effort credential cleanup scoped by the unique config PATH — don't
    // let a keyring hiccup fail a removal that already succeeded on the
    // openvpn3 side. Keying by path ensures a same-named sibling is untouched.
    let store = crate::credentials::CredentialStore::default();
    match store.delete_for_config_async(config_path_str).await {
        Ok(n) if n > 0 => {
            info!("Wiped {n} stored credential(s) for '{config_name}' ({config_path_str})")
        }
        Ok(_) => info!("No stored credentials to wipe for '{config_name}' ({config_path_str})"),
        Err(e) => warn!(
            "Config '{config_name}' ({config_path_str}) removed, but credential cleanup failed: {e}"
        ),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_method_name_matches_unknown_method_only() {
        // Missing method on a pre-v22 daemon → skip validation.
        assert!(is_missing_method_error_name(
            "org.freedesktop.DBus.Error.UnknownMethod"
        ));
        assert!(is_missing_method_error_name(
            "org.freedesktop.DBus.Error.NoReply"
        ));

        // A genuine openvpn3 parse/validation failure carries a domain error
        // name — even though its human text says "does not exist", the NAME
        // is what matters and must NOT be treated as a missing method.
        assert!(!is_missing_method_error_name(
            "net.openvpn.v3.error.ConfigError"
        ));
        assert!(!is_missing_method_error_name(
            "net.openvpn.v3.configuration.Error"
        ));
        // No name at all → never a missing method.
        assert!(!is_missing_method_error_name(""));
    }
}
