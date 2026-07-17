//! D-Bus interface implementation. Exposes the `net.openvpn.v3.killswitch`
//! interface (rule application, bypass list, routing-layer orchestration)
//! and shells out to `nft -f -` to apply rule scripts. Spawns a watcher
//! task per active client; if the client disappears, rules are auto-
//! removed so the user is never locked out.
//!
//! Input validation lives in [`crate::validation`]; this module is async
//! D-Bus glue with no unit-testable pure surface.

use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use zbus::Connection;
use zbus::fdo;
use zbus::interface;

use crate::validation::{split_ips, validate_bypass_cidrs, validate_interface};
use crate::{bypass, nft, watcher};

// Absolute path — a root system service must not trust ambient `PATH`.
// `/usr/sbin/nft` is the install location on all target distros (Debian,
// Fedora/RPM, Arch); `/sbin` is a symlink to `/usr/sbin` under usr-merge.
const NFT_BIN: &str = "/usr/sbin/nft";

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
    /// One entry per *touched* iface: the iface's pre-apply rp_filter value.
    /// `RemoveBypassRoutes` / shutdown / vanish-teardown each drain this and
    /// restore every recorded iface. Empty when routing is not applied.
    /// Keyed by iface (not a single slot) so a physical switch mid-VPN
    /// (wlan0→eth0) preserves BOTH originals instead of dropping the new
    /// iface's true value on re-apply (G1: stale-iface). Per-iface first-seen
    /// wins: a re-apply on the same iface reads the "2" we wrote, so only the
    /// first capture per iface is kept.
    rp_filter_original: HashMap<String, String>,
}

#[derive(Default)]
pub struct KillSwitch {
    state: Arc<Mutex<State>>,
}

/// Process-wide handle to the service's state, so the SIGTERM/SIGINT handler
/// in `main` can reach the bypass-routing state the service recorded. zbus
/// owns the `KillSwitch` instance after `serve_at`, so `main` has no direct
/// reference; `SHARED_STATE` hands the shutdown path the same `Arc` the live
/// service mutates. Set once at startup.
static SHARED_STATE: OnceLock<Arc<Mutex<State>>> = OnceLock::new();

impl KillSwitch {
    /// Construct the service and register its state in `SHARED_STATE` so the
    /// shutdown handler can restore bypass-routing state. `main` must use this
    /// instead of `KillSwitch::default()` — otherwise `SHARED_STATE` stays empty
    /// and `cleanup_rules` can't reach the recorded `rp_filter_original`.
    pub fn new() -> Self {
        let state = Arc::new(Mutex::new(State::default()));
        // `new` is called exactly once at startup; a set failure means a
        // second construction, which is a programming error — surface it.
        if SHARED_STATE.set(Arc::clone(&state)).is_err() {
            warn!("SHARED_STATE already set — KillSwitch::new called twice?");
        }
        Self { state }
    }
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

        // Atomic replace: the script itself tears down any prior table and
        // rebuilds in one nft transaction (no no-enforcement window). On
        // first apply the embedded teardown is a no-op (ensure-exists guard).
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

        let handle = tokio::spawn(watch_and_cleanup(
            conn.clone(),
            sender.clone(),
            Arc::clone(&self.state),
        ));

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

    /// Verify the live nft bypass sets against the caller-supplied desired
    /// lists and return the drift. S38 T2 — read-only detection of external
    /// tamper / partial teardown between applies. Returns `(v4_missing,
    /// v6_missing, extra)`:
    ///   - `*_missing` = desired-but-not-live → the leak (bypassed traffic to
    ///     those CIDRs hits `policy drop` instead of escaping).
    ///   - `extra` = live-but-not-desired → tamper-add (visibility only).
    ///
    /// The caller (GUI) owns the desired list in GSettings; the helper stays
    /// stateless here to avoid a second source of truth that could itself
    /// drift from `state.bypass_cidrs`. Input is validated at the trust
    /// boundary (`validate_bypass_cidrs`) so untrusted CIDR strings never
    /// reach the comparison.
    ///
    /// A missing/unparseable table is reported as "everything missing"
    /// (absent table ⇒ no live sets ⇒ every desired CIDR is missing). The GUI
    /// poller only runs this while the kill-switch is already `Active`/
    /// `Drifted`, so it never reaches the table-gone branch through normal
    /// polling — and it treats any non-clean report as drift unconditionally
    /// (no "all-missing ⇒ kill-switch-off" special case). A torn-down table
    /// surfacing here would read as drift, but that path is not exercised in
    /// practice because the poll is gated on a live kill-switch state.
    async fn verify_bypass_set(
        &self,
        desired_v4: Vec<String>,
        desired_v6: Vec<String>,
    ) -> fdo::Result<(Vec<String>, Vec<String>, Vec<String>)> {
        // Canonicalize so the comparison uses the same string form the live
        // sets were built from (host bits masked). Reject on invalid input.
        let desired_v4 = validate_bypass_cidrs(&desired_v4)
            .map_err(|e| fdo::Error::InvalidArgs(e.to_string()))?;
        let desired_v6 = validate_bypass_cidrs(&desired_v6)
            .map_err(|e| fdo::Error::InvalidArgs(e.to_string()))?;
        let dv4: Vec<&str> = desired_v4.iter().map(|s| s.as_str()).collect();
        let dv6: Vec<&str> = desired_v6.iter().map(|s| s.as_str()).collect();

        let live_json = run_nft_list()
            .await
            .map_err(|e| fdo::Error::Failed(format!("nft list: {e}")))?;
        let report = nft::diff_bypass_set((dv4.as_slice(), dv6.as_slice()), &live_json);
        Ok((report.v4_missing, report.v6_missing, report.extra))
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
            // First-seen-per-iface wins: a re-apply on the SAME iface reads
            // the value we wrote ("2"), so only record an iface's true original
            // the first time we touch it. Keyed by iface so a physical switch
            // mid-VPN (wlan0→eth0) preserves BOTH originals — the old iface's
            // value is restored at teardown even though it was captured on a
            // prior apply, instead of being dropped on the floor (G1).
            state
                .rp_filter_original
                .entry(net.iface.clone())
                .or_insert(original_rpf);
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
            state.rp_filter_original.drain().collect::<Vec<_>>()
        };
        // Best-effort restore per touched iface — an iface may have
        // disappeared (e.g. user unplugged WiFi). restore_rp_filter_all logs
        // and skips gone ifaces; routing teardown below runs regardless.
        bypass::restore_rp_filter_all(rpf).await;
        bypass::teardown_routing()
            .await
            .map_err(|e| fdo::Error::Failed(format!("bypass teardown: {e}")))?;
        info!("bypass routes removed");
        Ok(())
    }
}

/// Best-effort cleanup of firewall *and* routing state, called from the
/// SIGTERM/SIGINT handler in `main`. Mirrors `remove_bypass_routes`: restore
/// `rp_filter` from the value captured at apply time (best-effort — the iface
/// may have vanished), then tear down the ip-rules + table 100, then drop the
/// nft table. zbus owns the live `KillSwitch`, so this reaches the recorded
/// state via `SHARED_STATE`; if `KillSwitch::new` wasn't used (or no bypass
/// routing was ever applied) there is nothing to restore and only the nft +
/// routing teardown runs.
pub async fn cleanup_rules() {
    // rp_filter restore must run before routing teardown — `teardown_routing`
    // only deletes ip-rules and flushes table 100, it never writes rp_filter.
    // Without this the physical iface stays at loose (2) until reboot.
    let rpf = match SHARED_STATE.get() {
        Some(state) => state
            .lock()
            .expect("state mutex poisoned")
            .rp_filter_original
            .drain()
            .collect::<Vec<_>>(),
        None => Vec::new(),
    };
    if let Err(e) = run_nft(nft::remove_rules_script()).await {
        warn!(err = ?e, "shutdown cleanup nft failed (often expected)");
    }
    // Restore rp_filter then tear down routing via the shared sequence (D6).
    // Empty when no bypass routing was ever applied (both steps no-op).
    if let Err(e) = bypass::teardown_bypass_state(rpf).await {
        warn!(err = ?e, "shutdown cleanup bypass routing failed");
    }
}

/// Spawned per active client from `add_rules`: block until the client's D-Bus
/// name disappears, then tear down firewall + routing state so a GUI crash
/// never leaves the user locked out. Extracted from `add_rules` to keep that
/// method under the complexity gate — pure structural move, no behaviour change.
async fn watch_and_cleanup(conn: Connection, sender: String, state_arc: Arc<Mutex<State>>) {
    match watcher::wait_for_disappearance(&conn, &sender).await {
        Ok(()) => {
            warn!(sender = %sender, "GUI vanished — removing rules");
            if let Err(e) = run_nft(nft::remove_rules_script()).await {
                error!(err = ?e, "auto-cleanup nft failed");
            }
            teardown_bypass_on_vanish(&state_arc).await;
        }
        Err(e) => error!(err = ?e, "watcher errored"),
    }
}

/// Restore rp_filter and tear down routing state recorded for a vanished
/// client. No-op when bypass routing was never applied. Split from
/// `watch_and_cleanup` so that fn stays flat under the complexity gate.
async fn teardown_bypass_on_vanish(state_arc: &Arc<Mutex<State>>) {
    // Firewall down before routing down (apply order reversed).
    // If bypass routing was applied, tear it down too — otherwise
    // table 100, the priority-100 ip-rules, and loose rp_filter
    // survive the GUI crash and the user is left in a degraded
    // forwarding state. Restore rp_filter first, then teardown.
    let rpf = {
        let mut state = state_arc.lock().expect("state mutex poisoned");
        let rpf = if state.bypass_routes_applied {
            state.bypass_routes_applied = false;
            state.rp_filter_original.drain().collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        state.sender = None;
        state.watcher = None;
        rpf
    };
    if let Err(e) = bypass::teardown_bypass_state(rpf).await {
        error!(err = ?e, "auto-cleanup bypass routing failed");
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

/// Capture the live kill-switch nft table as JSON (`nft -j list table inet
/// openvpn3_killswitch`). Used by `VerifyBypassSet` to diff against the desired
/// bypass list. Empty stdout (exit 0) means the table is absent — the caller
/// treats that as kill-switch-off, not drift. A non-zero exit (e.g. table
/// deleted between the check and the list) is surfaced as an error so the GUI
/// skips this poll rather than reporting a false clean.
async fn run_nft_list() -> Result<String> {
    let output = Command::new(NFT_BIN)
        .args(["-j", "list", "table", "inet", nft::TABLE])
        .output()
        .await
        .with_context(|| format!("spawn {NFT_BIN}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nft list exit {}: {}", output.status, stderr.trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
