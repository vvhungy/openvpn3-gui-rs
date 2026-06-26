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
    crate::dialogs::show_info_notification(
        "Import Successful",
        &format!("Configuration '{}' has been imported", name),
    );
    Ok(())
}

/// Remove a configuration, then best-effort wipe its stored credentials.
///
/// `config_name` is the keyring key (the name shown in the confirm dialog) —
/// passed in rather than re-resolved so the credential cleanup matches the
/// identity the user confirmed. A keyring failure here must NOT block removal:
/// the config is already gone from openvpn3, so leftover secrets are at worst
/// stale, not dangerous. Log + continue.
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

    // Best-effort credential cleanup — don't let a keyring hiccup fail a
    // removal that already succeeded on the openvpn3 side.
    let store = crate::credentials::CredentialStore::default();
    match store.delete_for_config_async(config_name).await {
        Ok(n) if n > 0 => info!("Wiped {n} stored credential(s) for '{config_name}'"),
        Ok(_) => info!("No stored credentials to wipe for '{config_name}'"),
        Err(e) => warn!("Config '{config_name}' removed, but credential cleanup failed: {e}"),
    }

    Ok(())
}
