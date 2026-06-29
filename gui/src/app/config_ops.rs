//! Configuration D-Bus operations
//!
//! No testable pure surface — async D-Bus wrappers only.

use tracing::{error, info, warn};
use zbus::proxy::CacheProperties;
use zbus::zvariant::OwnedObjectPath;

use crate::dbus::configuration::{ConfigurationManagerProxy, ConfigurationProxy};
use crate::tray::{ConfigInfo, VpnTray};

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
            let err_str = e.to_string();
            // Pre-v22 daemons lack Validate() — don't reject on legacy installs.
            if err_str.contains("UnknownMethod")
                || err_str.contains("NoSuchMethod")
                || err_str.contains("not exist")
                || err_str.contains("No such interface")
            {
                warn!("Validate() unsupported by daemon, skipping: {}", e);
            } else {
                warn!("Config '{}' failed validation: {}", config_path, e);
                // Remove the junk config we just added so it doesn't linger.
                if let Err(rm_err) = config.Remove().await {
                    warn!(
                        "Failed to remove invalid config {}: {}",
                        config_path, rm_err
                    );
                }
                anyhow::bail!("configuration failed validation: {}", e);
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
