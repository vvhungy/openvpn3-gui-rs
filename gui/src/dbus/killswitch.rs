//! D-Bus proxy for the privileged kill-switch helper.
//!
//! The helper runs as a system D-Bus service (`net.openvpn.v3.killswitch`)
//! and applies/removes nftables rules on behalf of the GUI. This module
//! exposes thin async wrappers that the GUI calls on the connect/disconnect
//! lifecycle and on user actions in the unexpected-disconnect notification.
//!
//! When the helper package is not installed the bus name is not
//! activatable — the wrappers log a single warning and return without
//! an error so the GUI keeps working without firewall enforcement.
//!
//! A persistent system-bus connection is kept alive for the GUI process
//! lifetime so the helper's watcher does not auto-clean rules prematurely.

use tokio::sync::OnceCell;
use tracing::{info, warn};
use zbus::fdo;
use zbus::proxy::CacheProperties;

const BUS_NAME: &str = "net.openvpn.v3.killswitch";
const OBJECT_PATH: &str = "/net/openvpn/v3/killswitch";

/// Persistent system-bus connection shared across all kill-switch calls.
/// Kept alive for the GUI process lifetime so the helper's watcher sees
/// our sender name persist until `RemoveRules` is called or the GUI exits.
static SYSTEM_BUS: OnceCell<Option<zbus::Connection>> = OnceCell::const_new();

async fn system_bus() -> Option<&'static zbus::Connection> {
    SYSTEM_BUS
        .get_or_init(|| async {
            match zbus::Connection::system().await {
                Ok(c) => Some(c),
                Err(e) => {
                    warn!("kill-switch: cannot connect to system bus: {}", e);
                    None
                }
            }
        })
        .await
        .as_ref()
}

#[zbus::proxy(
    interface = "net.openvpn.v3.killswitch",
    default_service = "net.openvpn.v3.killswitch",
    default_path = "/net/openvpn/v3/killswitch"
)]
pub trait KillSwitch {
    fn AddRules(
        &self,
        interface: &str,
        vpn_server_ips: Vec<String>,
        allow_lan: bool,
    ) -> zbus::Result<()>;

    fn RemoveRules(&self) -> zbus::Result<()>;
}

async fn build_proxy(conn: &zbus::Connection) -> zbus::Result<KillSwitchProxy<'_>> {
    KillSwitchProxy::builder(conn)
        .destination(BUS_NAME)?
        .path(OBJECT_PATH)?
        .cache_properties(CacheProperties::No)
        .build()
        .await
}

/// True when dbus-daemon knows how to start the helper — i.e. a
/// `.service` file is installed for `BUS_NAME`. We deliberately use
/// `ListActivatableNames` rather than `NameHasOwner` because the helper
/// is auto-activated on demand and is not running before the first call.
async fn helper_present(conn: &zbus::Connection) -> bool {
    let Ok(dbus) = fdo::DBusProxy::new(conn).await else {
        return false;
    };
    match dbus.list_activatable_names().await {
        Ok(names) => names.iter().any(|n| n.as_str() == BUS_NAME),
        Err(_) => false,
    }
}

/// Ask the helper to apply kill-switch rules for the given tunnel interface
/// and the resolved VPN server IP(s). Idempotent — the helper replaces any
/// existing rules from a previous invocation.
pub async fn add_rules(interface: &str, vpn_server_ips: Vec<String>, allow_lan: bool) {
    let Some(conn) = system_bus().await else {
        return;
    };
    if !helper_present(conn).await {
        warn!(
            "kill-switch: helper not installed (bus name '{}' is not activatable; \
             check that the helper package is installed and `systemctl reload dbus` \
             has been run) — rules NOT applied",
            BUS_NAME
        );
        return;
    }
    let proxy = match build_proxy(conn).await {
        Ok(p) => p,
        Err(e) => {
            warn!("kill-switch: proxy build failed: {}", e);
            return;
        }
    };
    match proxy.AddRules(interface, vpn_server_ips, allow_lan).await {
        Ok(()) => info!(interface = %interface, "kill-switch: rules applied"),
        Err(e) => warn!("kill-switch: AddRules failed: {}", e),
    }
}

/// Ask the helper to tear down kill-switch rules. Idempotent — safe to call
/// even if no rules are currently in place. No-op when the helper isn't
/// installed.
pub async fn remove_rules() {
    let Some(conn) = system_bus().await else {
        return;
    };
    if !helper_present(conn).await {
        return;
    }
    let proxy = match build_proxy(conn).await {
        Ok(p) => p,
        Err(e) => {
            warn!("kill-switch: proxy build failed: {}", e);
            return;
        }
    };
    match proxy.RemoveRules().await {
        Ok(()) => info!("kill-switch: rules removed"),
        Err(e) => warn!("kill-switch: RemoveRules failed: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time sanity: const strings match the helper's published interface.
    /// (Helper-side definitions live in helper/src/main.rs.)
    #[test]
    fn bus_name_and_path_match_helper() {
        assert_eq!(BUS_NAME, "net.openvpn.v3.killswitch");
        assert_eq!(OBJECT_PATH, "/net/openvpn/v3/killswitch");
    }
}
