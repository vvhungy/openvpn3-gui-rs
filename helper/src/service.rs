//! D-Bus interface implementation. Exposes the `net.openvpn.v3.killswitch`
//! interface (rule application, bypass list, routing-layer orchestration)
//! and shells out to `nft -f -` to apply rule scripts. Spawns a watcher
//! task per active client; if the client disappears, rules are auto-
//! removed so the user is never locked out.
//!
//! Input validation lives in [`crate::validation`]; this module is async
//! D-Bus glue with no unit-testable pure surface.

use anyhow::{Context, Result, bail};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use zbus::Connection;
use zbus::fdo;
use zbus::interface;

use crate::validation::{split_ips, validate_bypass_cidrs, validate_interface};
use crate::{bypass, nft, watcher};

const NFT_BIN: &str = "nft";

#[derive(Default)]
struct State {
    sender: Option<String>,
    watcher: Option<JoinHandle<()>>,
    /// Canonicalized bypass CIDR list (replace-all semantics per T4 D3).
    /// Populated by `SetBypassCidrs`, cleared by `ClearBypassCidrs`.
    bypass_cidrs: Vec<String>,
    /// T2: true between a successful `ApplyBypassRoutes` and the matching
    /// `RemoveBypassRoutes` (or shutdown). Drives shutdown cleanup —
    /// only tear down routing state we actually installed.
    bypass_routes_applied: bool,
    /// T2: (iface, original rp_filter value) captured at apply-time.
    /// `RemoveBypassRoutes` takes this back so we can restore the iface's
    /// rp_filter to its pre-apply value. `None` when routing not applied.
    rp_filter_original: Option<(String, String)>,
}

#[derive(Default)]
pub struct KillSwitch {
    state: Arc<Mutex<State>>,
}

#[interface(name = "net.openvpn.v3.killswitch")]
impl KillSwitch {
    /// Helper crate version, exposed as the `Version` D-Bus property.
    /// GUI reads this on cold-start to log a compat warning if the
    /// installed helper predates the GUI's minimum supported version.
    #[zbus(property)]
    async fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// Apply kill-switch nftables rules. Replace semantics — any existing
    /// rules from a previous client are torn down first.
    async fn add_rules(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &Connection,
        interface: &str,
        vpn_server_ips: Vec<String>,
        allow_lan: bool,
    ) -> fdo::Result<()> {
        validate_interface(interface).map_err(|e| fdo::Error::InvalidArgs(e.to_string()))?;
        let (v4, v6) =
            split_ips(&vpn_server_ips).map_err(|e| fdo::Error::InvalidArgs(e.to_string()))?;
        let v4_refs: Vec<&str> = v4.iter().map(String::as_str).collect();
        let v6_refs: Vec<&str> = v6.iter().map(String::as_str).collect();

        // Snapshot the bypass list outside the await window so we don't hold
        // the std::sync::Mutex across tokio::process::Command::output().
        let bypass_cidrs = {
            let state = self.state.lock().expect("state mutex poisoned");
            state.bypass_cidrs.clone()
        };
        let (bypass_v4, bypass_v6) = bypass::split_by_family(&bypass_cidrs)
            .map_err(|e| fdo::Error::Failed(format!("bypass split: {e}")))?;
        let bypass_v4_refs: Vec<&str> = bypass_v4.iter().map(String::as_str).collect();
        let bypass_v6_refs: Vec<&str> = bypass_v6.iter().map(String::as_str).collect();

        let script = nft::add_rules_script(
            interface,
            &v4_refs,
            &v6_refs,
            allow_lan,
            &bypass_v4_refs,
            &bypass_v6_refs,
        );

        // Replace any existing rules; ignore "no such table" on first run.
        let _ = run_nft(nft::remove_rules_script()).await;
        run_nft(&script)
            .await
            .map_err(|e| fdo::Error::Failed(format!("nft add: {e}")))?;

        let sender = hdr
            .sender()
            .ok_or_else(|| fdo::Error::Failed("missing sender on AddRules".into()))?
            .to_string();

        let prev_watcher = {
            let mut state = self.state.lock().expect("state mutex poisoned");
            let prev = state.watcher.take();
            state.sender = Some(sender.clone());
            prev
        };
        if let Some(h) = prev_watcher {
            h.abort();
        }

        let conn_clone = conn.clone();
        let sender_clone = sender.clone();
        let state_arc = Arc::clone(&self.state);
        let handle = tokio::spawn(async move {
            match watcher::wait_for_disappearance(&conn_clone, &sender_clone).await {
                Ok(()) => {
                    warn!(sender = %sender_clone, "GUI vanished — removing rules");
                    if let Err(e) = run_nft(nft::remove_rules_script()).await {
                        error!(err = ?e, "auto-cleanup nft failed");
                    }
                    let mut state = state_arc.lock().expect("state mutex poisoned");
                    state.sender = None;
                    state.watcher = None;
                }
                Err(e) => error!(err = ?e, "watcher errored"),
            }
        });

        self.state.lock().expect("state mutex poisoned").watcher = Some(handle);

        info!(
            interface = %interface,
            ipv4_count = v4.len(),
            ipv6_count = v6.len(),
            allow_lan,
            "kill-switch rules applied"
        );
        Ok(())
    }

    /// Remove kill-switch nftables rules. Idempotent.
    async fn remove_rules(&self) -> fdo::Result<()> {
        let prev_watcher = {
            let mut state = self.state.lock().expect("state mutex poisoned");
            state.sender = None;
            state.watcher.take()
        };
        if let Some(h) = prev_watcher {
            h.abort();
        }
        if let Err(e) = run_nft(nft::remove_rules_script()).await {
            warn!(err = ?e, "remove_rules nft (often expected if no table)");
        }
        info!("kill-switch rules removed");
        Ok(())
    }

    /// Set the bypass CIDR list. Replace-all semantics per T4 D3.
    /// Validates input at the trust boundary; rejects loopback, multicast,
    /// link-local, unspecified, and `/0` prefixes. Stores only — actual rule
    /// installation lands in Sprint 23 T2.
    async fn set_bypass_cidrs(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        cidrs: Vec<String>,
    ) -> fdo::Result<()> {
        let canonical =
            validate_bypass_cidrs(&cidrs).map_err(|e| fdo::Error::InvalidArgs(e.to_string()))?;
        let count = canonical.len();
        {
            let mut state = self.state.lock().expect("state mutex poisoned");
            state.bypass_cidrs = canonical;
        }
        info!(count, caller = ?hdr.sender(), "bypass CIDR list set");
        Ok(())
    }

    /// Clear the bypass CIDR list. Idempotent. Fail-closed cleanup per T4 D3.
    async fn clear_bypass_cidrs(&self) -> fdo::Result<()> {
        let prior = {
            let mut state = self.state.lock().expect("state mutex poisoned");
            let prior = state.bypass_cidrs.len();
            state.bypass_cidrs.clear();
            prior
        };
        info!(removed = prior, "bypass CIDR list cleared");
        Ok(())
    }

    /// Dry-run validation — applies the same canonicalization and rejection
    /// rules as `SetBypassCidrs` but does NOT mutate state. Returns the
    /// canonical list on success (host bits masked, duplicates removed) so
    /// the GUI can show the user what would be stored, or `InvalidArgs`
    /// carrying the same diagnostic message `SetBypassCidrs` would emit.
    async fn validate_bypass_cidrs(&self, cidrs: Vec<String>) -> fdo::Result<Vec<String>> {
        validate_bypass_cidrs(&cidrs).map_err(|e| fdo::Error::InvalidArgs(e.to_string()))
    }

    /// Apply the routing-layer split-tunnel: priority-100 ip-rule per CIDR
    /// (symmetric v4+v6), secondary table 100 pointing at the captured
    /// pre-VPN gateway, rp_filter set to loose on the physical iface, and a
    /// scoped conntrack flush per bypass CIDR. Independent of kill-switch
    /// state per S22 D4. Replace-all semantics per D3 — any prior routing
    /// state is torn down first. No-op success when bypass list is empty.
    ///
    /// Returns `(applied, failed)` where `applied` is the CIDRs whose
    /// `ip rule add` succeeded and `failed` carries `(cidr, reason)` for ones
    /// that did not. System-wide steps (gateway capture, rp_filter, table)
    /// still fail fast — only per-CIDR failures are collected (S28 T3).
    async fn apply_bypass_routes(&self) -> fdo::Result<(Vec<String>, Vec<(String, String)>)> {
        let cidrs = {
            let state = self.state.lock().expect("state mutex poisoned");
            state.bypass_cidrs.clone()
        };
        if cidrs.is_empty() {
            // D3: clearing is via ClearBypassCidrs + RemoveBypassRoutes.
            // Calling Apply with an empty list is a benign no-op.
            info!("ApplyBypassRoutes: bypass list empty — no routing changes");
            return Ok((Vec::new(), Vec::new()));
        }

        // D3 replace-all: tear down any prior state first. Best-effort —
        // a clean system returns errors we ignore inside teardown_routing.
        bypass::teardown_routing()
            .await
            .map_err(|e| fdo::Error::Failed(format!("bypass teardown: {e}")))?;
        bypass::ensure_rt_tables_entry()
            .await
            .map_err(|e| fdo::Error::Failed(format!("rt_tables register: {e}")))?;
        // Re-capture at apply-time per CLAUDE.md "network-bound state has
        // implicit TTL". Same call site handles D5 (Resume re-capture).
        let net = bypass::capture_default_gateway()
            .await
            .map_err(|e| fdo::Error::Failed(format!("gateway capture: {e}")))?;
        let original_rpf = bypass::set_rp_filter_loose(&net.iface)
            .await
            .map_err(|e| fdo::Error::Failed(format!("rp_filter set: {e}")))?;
        let (applied, failed) = bypass::install_rules(&cidrs).await;
        // From here rp_filter is loose (2). `populate_table` is the only step
        // after `set_rp_filter_loose` that can return Err, so it is the lone
        // mid-chain failure point. Fail-closed (S32 T1): restore rp_filter
        // AND tear down any partial ip-rules before surfacing the error, so a
        // failed apply never leaves the iface stuck loose or orphan rules
        // behind. `teardown_routing` + `restore_rp_filter` are both idempotent.
        if let Err(e) = bypass::populate_table(&net).await {
            if let Err(te) = bypass::teardown_routing().await {
                warn!(err = ?te, "teardown after apply failure failed");
            }
            if let Err(re) = bypass::restore_rp_filter(&net.iface, &original_rpf).await {
                warn!(iface = %net.iface, err = ?re, "rp_filter restore after apply failure failed (iface gone?)");
            }
            return Err(fdo::Error::Failed(format!("populate table: {e}")));
        }
        // conntrack flush is defence-in-depth — return value intentionally
        // discarded (failure logged inside flush_conntrack_scoped). Use
        // `applied` so we don't burn cycles on CIDRs that never got a rule.
        bypass::flush_conntrack_scoped(&applied).await;

        {
            let mut state = self.state.lock().expect("state mutex poisoned");
            state.bypass_routes_applied = true;
            state.rp_filter_original = Some((net.iface.clone(), original_rpf));
        }
        info!(
            applied = applied.len(),
            failed = failed.len(),
            iface = %net.iface,
            "bypass routes applied"
        );
        Ok((applied, failed))
    }

    /// Tear down the routing-layer split-tunnel: delete every ip-rule at our
    /// priority (both families), flush table 100, restore rp_filter. Idempotent
    /// — safe to call when nothing is applied. Does NOT touch nft state per
    /// D4 (the firewall layer is the responsibility of `remove_rules`).
    async fn remove_bypass_routes(&self) -> fdo::Result<()> {
        let rpf = {
            let mut state = self.state.lock().expect("state mutex poisoned");
            state.bypass_routes_applied = false;
            state.rp_filter_original.take()
        };
        if let Some((iface, value)) = rpf {
            // Best-effort restore — iface may have disappeared (e.g. user
            // unplugged WiFi). Log and continue with rule/table teardown.
            if let Err(e) = bypass::restore_rp_filter(&iface, &value).await {
                warn!(iface = %iface, err = ?e, "rp_filter restore failed (iface gone?)");
            }
        }
        bypass::teardown_routing()
            .await
            .map_err(|e| fdo::Error::Failed(format!("bypass teardown: {e}")))?;
        info!("bypass routes removed");
        Ok(())
    }
}

/// Best-effort cleanup of both firewall *and* routing state, called from
/// the SIGTERM/SIGINT handler in main. Per D4 the watcher and explicit
/// `remove_rules` deliberately do NOT touch routing — only shutdown clears
/// everything (the helper is going away, no one will clean up otherwise).
pub async fn cleanup_rules() {
    if let Err(e) = run_nft(nft::remove_rules_script()).await {
        warn!(err = ?e, "shutdown cleanup nft failed (often expected)");
    }
    if let Err(e) = bypass::teardown_routing().await {
        warn!(err = ?e, "shutdown cleanup bypass routing failed");
    }
}

async fn run_nft(script: &str) -> Result<()> {
    let mut child = Command::new(NFT_BIN)
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {NFT_BIN}"))?;

    {
        let mut stdin = child
            .stdin
            .take()
            .context("nft stdin closed unexpectedly")?;
        stdin
            .write_all(script.as_bytes())
            .await
            .context("write nft stdin")?;
    }

    let output = child.wait_with_output().await.context("wait for nft")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nft exit {}: {}", output.status, stderr.trim());
    }
    Ok(())
}
