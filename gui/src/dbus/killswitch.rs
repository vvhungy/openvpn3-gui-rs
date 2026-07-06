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
///
/// `get_or_try_init` is used (not `get_or_init`) deliberately: it caches
/// only the `Ok` connection and leaves the cell empty on `Err`, so a
/// transient bus outage at the first call (boot race, dbus restart) is
/// retried on the next call rather than permanently caching "absent" and
/// silently disabling kill-switch enforcement until the GUI restarts.
static SYSTEM_BUS: OnceCell<zbus::Connection> = OnceCell::const_new();

async fn system_bus() -> Option<&'static zbus::Connection> {
    match SYSTEM_BUS
        .get_or_try_init(|| async { zbus::Connection::system().await })
        .await
    {
        Ok(conn) => Some(conn),
        Err(e) => {
            warn!("kill-switch: cannot connect to system bus: {}", e);
            None
        }
    }
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

    fn SetBypassCidrs(&self, cidrs: Vec<String>) -> zbus::Result<()>;

    fn ClearBypassCidrs(&self) -> zbus::Result<()>;

    fn ValidateBypassCidrs(&self, cidrs: Vec<String>) -> zbus::Result<Vec<String>>;

    #[allow(clippy::type_complexity)]
    fn ApplyBypassRoutes(&self) -> zbus::Result<(Vec<String>, Vec<(String, String)>)>;

    fn RemoveBypassRoutes(&self) -> zbus::Result<()>;

    #[allow(clippy::type_complexity)]
    fn VerifyBypassSet(
        &self,
        desired_v4: Vec<String>,
        desired_v6: Vec<String>,
    ) -> zbus::Result<(Vec<String>, Vec<String>, Vec<String>)>;

    #[zbus(property)]
    fn version(&self) -> zbus::Result<String>;
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
pub async fn helper_present(conn: &zbus::Connection) -> bool {
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
///
/// Returns `false` when the helper package is not installed (bus name not
/// activatable). Returns `true` in all other cases (rules applied, or a
/// D-Bus call was attempted and the outcome is logged).
pub async fn add_rules(interface: &str, vpn_server_ips: Vec<String>, allow_lan: bool) -> bool {
    let Some(conn) = system_bus().await else {
        return true;
    };
    if !helper_present(conn).await {
        warn!(
            "kill-switch: helper not installed (bus name '{}' is not activatable; \
             check that the helper package is installed and `systemctl reload dbus` \
             has been run) — rules NOT applied",
            BUS_NAME
        );
        return false;
    }
    let proxy = match build_proxy(conn).await {
        Ok(p) => p,
        Err(e) => {
            warn!("kill-switch: proxy build failed: {}", e);
            return true;
        }
    };
    match proxy.AddRules(interface, vpn_server_ips, allow_lan).await {
        Ok(()) => info!(interface = %interface, "kill-switch: rules applied"),
        Err(e) => warn!("kill-switch: AddRules failed: {}", e),
    }
    true
}

/// Probe the helper's `Version` property. Returns `None` when the helper
/// is not installed (bus name not activatable) or the property fetch
/// fails. Informational — never blocks GUI startup.
pub async fn probe_version() -> Option<String> {
    let conn = system_bus().await?;
    if !helper_present(conn).await {
        return None;
    }
    let proxy = build_proxy(conn).await.ok()?;
    proxy.version().await.ok()
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

/// Ask the helper to replace its bypass CIDR list with `cidrs` (replace-all
/// semantics per S22 T4 D3). The helper canonicalises and validates each
/// entry at the trust boundary — invalid entries cause the whole call to
/// fail with `InvalidArgs` and the prior list is preserved.
///
/// Returns `false` when the helper package is not installed or the call
/// fails; `true` when the helper accepted the list.
pub async fn set_bypass_cidrs(cidrs: Vec<String>) -> bool {
    let Some(conn) = system_bus().await else {
        return false;
    };
    if !helper_present(conn).await {
        warn!("kill-switch: helper not installed — bypass CIDR list NOT applied");
        return false;
    }
    let proxy = match build_proxy(conn).await {
        Ok(p) => p,
        Err(e) => {
            warn!("kill-switch: proxy build failed: {}", e);
            return false;
        }
    };
    match proxy.SetBypassCidrs(cidrs).await {
        Ok(()) => {
            info!("kill-switch: bypass CIDR list set");
            true
        }
        Err(e) => {
            warn!("kill-switch: SetBypassCidrs failed: {}", e);
            false
        }
    }
}

/// Ask the helper to dry-run validate `cidrs` — same rules `SetBypassCidrs`
/// applies (loopback / multicast / link-local / unspecified / `/0`
/// rejection, host-bit masking, dedup after canonicalization, max-count
/// ceiling) but with NO state mutation. The helper's canonical form (or
/// helper-side rejection message) is what the GUI shows the user before
/// they commit the list via Save.
///
/// Returns `Ok(canonical_list)` on accept, `Err(diagnostic)` on reject.
/// When the helper package is not installed, returns
/// `Err("helper not installed")` — the GUI's "Helper not installed" hint
/// label is the user-facing surface for that state; this string is just
/// a fallback so live validation does not silently accept invalid input
/// when helper validation cannot run.
pub async fn validate_bypass_cidrs(cidrs: Vec<String>) -> Result<Vec<String>, String> {
    let Some(conn) = system_bus().await else {
        return Err("system bus unavailable".to_string());
    };
    if !helper_present(conn).await {
        return Err("helper not installed".to_string());
    }
    let proxy = build_proxy(conn)
        .await
        .map_err(|e| format!("proxy build failed: {e}"))?;
    proxy
        .ValidateBypassCidrs(cidrs)
        .await
        .map_err(|e| extract_diagnostic(&e))
}

/// Strip zbus's "InvalidArgs: " prefix from helper's diagnostic message
/// so the UI shows the same text the helper logs would show on a real
/// `SetBypassCidrs` reject. Falls back to the raw zbus Display on any
/// other error kind.
fn extract_diagnostic(err: &zbus::Error) -> String {
    let raw = err.to_string();
    raw.strip_prefix("InvalidArgs: ")
        .map(str::to_string)
        .unwrap_or(raw)
}

/// Ask the helper to clear its bypass CIDR list. Idempotent — safe to call
/// even if the list is already empty. No-op when the helper isn't installed.
#[allow(dead_code)] // T3 ships plumbing; first call site lands in T4 (Preferences).
pub async fn clear_bypass_cidrs() {
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
    match proxy.ClearBypassCidrs().await {
        Ok(()) => info!("kill-switch: bypass CIDR list cleared"),
        Err(e) => warn!("kill-switch: ClearBypassCidrs failed: {}", e),
    }
}

/// Per-CIDR outcome of an `ApplyBypassRoutes` call. `applied` lists CIDRs
/// for which `ip rule add` succeeded; `failed` carries `(cidr, reason)` for
/// ones that did not. System-wide apply failures (helper missing, gateway
/// capture, rp_filter, table populate) surface as `None` from the wrapper —
/// the caller renders those as `BypassState::Failed`.
#[derive(Debug, Clone)]
pub struct BypassApplyOutcome {
    pub applied: Vec<String>,
    pub failed: Vec<(String, String)>,
}

/// Ask the helper to install bypass routing (ip rules + secondary table +
/// conntrack flush). The helper captures the pre-VPN gateway at apply-time
/// (ephemeral, network-bound TTL). Must be preceded by `set_bypass_cidrs`
/// so the helper has a CIDR list to route.
///
/// Returns `None` when the helper is absent, the proxy fails, or the call
/// fails entirely (system-wide apply error). Returns `Some` with per-CIDR
/// granularity for partial-success cases.
pub async fn apply_bypass_routes() -> Option<BypassApplyOutcome> {
    let conn = system_bus().await?;
    if !helper_present(conn).await {
        warn!("kill-switch: helper not installed — bypass routes NOT applied");
        return None;
    }
    let proxy = match build_proxy(conn).await {
        Ok(p) => p,
        Err(e) => {
            warn!("kill-switch: proxy build failed: {}", e);
            return None;
        }
    };
    match proxy.ApplyBypassRoutes().await {
        Ok((applied, failed)) => {
            info!(
                applied = applied.len(),
                failed = failed.len(),
                "kill-switch: bypass routes applied"
            );
            Some(BypassApplyOutcome { applied, failed })
        }
        Err(e) => {
            warn!("kill-switch: ApplyBypassRoutes failed: {}", e);
            None
        }
    }
}

/// Drift between the desired bypass CIDR list and the live nft sets, as
/// reported by `VerifyBypassSet`. `v4_missing`/`v6_missing` = desired-but-
/// not-live (the leak); `extra` = live-but-not-desired (tamper-add). Empty
/// vectors across the board means the live sets match exactly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BypassDriftReport {
    pub v4_missing: Vec<String>,
    pub v6_missing: Vec<String>,
    pub extra: Vec<String>,
}

impl BypassDriftReport {
    /// True when no leak and no tamper — the live sets match the desired list.
    pub fn is_clean(&self) -> bool {
        self.v4_missing.is_empty() && self.v6_missing.is_empty() && self.extra.is_empty()
    }
}

/// Ask the helper to diff the live nft bypass sets against the desired lists
/// and return the drift. Read-only — does not re-apply or mutate state.
///
/// Returns `None` when the helper is absent, the proxy fails, or the call
/// errors (treated as "verify unavailable this cycle — skip, don't alarm").
/// The GUI polls this periodically while connected + bypass-on; a `Some`
/// report with `missing_count() > 0` surfaces drift to the tray + a
/// persistent notification. Old helpers pre-S38 lack the method → the call
/// errors → we log once and stop polling for the session (graceful no-op).
pub async fn verify_bypass_set(
    desired_v4: Vec<String>,
    desired_v6: Vec<String>,
) -> Option<BypassDriftReport> {
    let conn = system_bus().await?;
    if !helper_present(conn).await {
        return None;
    }
    let proxy = build_proxy(conn).await.ok()?;
    match proxy.VerifyBypassSet(desired_v4, desired_v6).await {
        Ok((v4_missing, v6_missing, extra)) => {
            let report = BypassDriftReport {
                v4_missing,
                v6_missing,
                extra,
            };
            if !report.is_clean() {
                info!(
                    v4_missing = report.v4_missing.len(),
                    v6_missing = report.v6_missing.len(),
                    extra = report.extra.len(),
                    "kill-switch: bypass-set drift detected"
                );
            }
            Some(report)
        }
        Err(e) => {
            warn!("kill-switch: VerifyBypassSet failed: {}", e);
            None
        }
    }
}

/// Ask the helper to tear down bypass routing (ip rules + secondary table).
/// Idempotent — safe to call even if no routes are installed. No-op when
/// the helper isn't installed.
pub async fn remove_bypass_routes() {
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
    match proxy.RemoveBypassRoutes().await {
        Ok(()) => info!("kill-switch: bypass routes removed"),
        Err(e) => warn!("kill-switch: RemoveBypassRoutes failed: {}", e),
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
