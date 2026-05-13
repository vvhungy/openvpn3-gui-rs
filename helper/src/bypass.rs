//! Split-tunnel routing layer. Owns all `ip`/`sysctl`/`conntrack` shell-outs
//! for bypass CIDR routing (priority 100 rule + secondary table 100).
//!
//! Per Sprint 22 T4 D2 the routing layer is independent from the kill-switch
//! firewall layer — this module ships symmetric v4+v6 rule install (closing
//! the T5 PoC IPv6-leak finding), atomic teardown that matches on structural
//! identifiers (table number) per CLAUDE.md, and `rp_filter` toggling with
//! restore.
//!
//! All commands are spawned via `tokio::process::Command`. No public function
//! holds the caller's `std::sync::Mutex<State>` lock across `.await` — that
//! is the caller's responsibility.

use anyhow::{Context, Result, bail};
use std::net::IpAddr;
use std::process::Stdio;
use tokio::process::Command;
use tracing::{info, warn};

pub const TABLE_ID: u32 = 100;
pub const TABLE_NAME: &str = "openvpn3-bypass";
pub const RULE_PRIORITY: u32 = 100;
pub const RT_TABLES_FILE: &str = "/etc/iproute2/rt_tables.d/openvpn3-bypass.conf";

/// Captured pre-VPN network attachment. v6 fields are optional — many
/// networks are v4-only, in which case `gateway_v6` is `None` and the v6
/// default route in table 100 is skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedNet {
    pub gateway_v4: Option<String>,
    pub gateway_v6: Option<String>,
    pub iface: String,
}

/// Idempotently register `<TABLE_ID> <TABLE_NAME>` in rt_tables.d so the
/// table name resolves in `ip route ... table <name>`. Helper runs as root,
/// so the write is allowed.
pub async fn ensure_rt_tables_entry() -> Result<()> {
    let want = format!("{TABLE_ID} {TABLE_NAME}\n");
    match tokio::fs::read_to_string(RT_TABLES_FILE).await {
        Ok(existing) if existing == want => return Ok(()),
        Ok(_) | Err(_) => {}
    }
    if let Some(parent) = std::path::Path::new(RT_TABLES_FILE).parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create_dir_all {}", parent.display()))?;
    }
    tokio::fs::write(RT_TABLES_FILE, want)
        .await
        .with_context(|| format!("write {RT_TABLES_FILE}"))?;
    info!("registered routing table '{TABLE_NAME}' (id {TABLE_ID})");
    Ok(())
}

/// Capture the current default gateway + outgoing interface for both
/// families. Parses `ip -j route show default` JSON. The v4 default is
/// required; v6 is optional (returns `None` when absent).
pub async fn capture_default_gateway() -> Result<CapturedNet> {
    let (gw4, iface) = capture_default_one_family(false)
        .await
        .context("capture v4 default route")?
        .ok_or_else(|| anyhow::anyhow!("no IPv4 default route on this system"))?;

    let v6 = capture_default_one_family(true)
        .await
        .context("capture v6 default route")?;
    let gateway_v6 = v6.map(|(gw, _)| gw);

    Ok(CapturedNet {
        gateway_v4: Some(gw4),
        gateway_v6,
        iface,
    })
}

async fn capture_default_one_family(v6: bool) -> Result<Option<(String, String)>> {
    let mut cmd = Command::new("ip");
    if v6 {
        cmd.arg("-6");
    }
    cmd.args(["-j", "route", "show", "default"]);
    let output = cmd.output().await.context("spawn ip route show default")?;
    if !output.status.success() {
        // ip prints to stderr only when the syntax is wrong; an empty
        // default-route set returns success with `[]` stdout.
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("ip route show default failed: {}", stderr.trim());
    }
    let routes: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("parse ip -j route show default JSON")?;
    let first = match routes.as_array().and_then(|a| a.first()) {
        Some(r) => r,
        None => return Ok(None),
    };
    let gateway = first
        .get("gateway")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("default route missing 'gateway' field"))?
        .to_string();
    let dev = first
        .get("dev")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("default route missing 'dev' field"))?
        .to_string();
    Ok(Some((gateway, dev)))
}

/// Read current rp_filter for the iface, switch to "2" (loose), return the
/// original value so the caller can restore on teardown. Loose mode is
/// required because bypass return traffic arrives on the physical iface
/// while a rule routes the outgoing leg through the same iface — strict
/// mode (1) drops the asymmetric replies as martians (D2 failure mode #3).
pub async fn set_rp_filter_loose(iface: &str) -> Result<String> {
    let path = rp_filter_path(iface);
    let original = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("read {path}"))?
        .trim()
        .to_string();
    if original != "2" {
        tokio::fs::write(&path, "2\n")
            .await
            .with_context(|| format!("write {path}"))?;
        info!(iface, original = %original, "rp_filter switched to loose (2)");
    }
    Ok(original)
}

pub async fn restore_rp_filter(iface: &str, original: &str) -> Result<()> {
    let path = rp_filter_path(iface);
    tokio::fs::write(&path, format!("{}\n", original))
        .await
        .with_context(|| format!("write {path}"))?;
    info!(iface, restored = %original, "rp_filter restored");
    Ok(())
}

fn rp_filter_path(iface: &str) -> String {
    format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter")
}

/// Install `ip rule` entries for every CIDR — v4 CIDRs get `ip rule`, v6 get
/// `ip -6 rule`. Both fire `lookup <TABLE_ID> priority <RULE_PRIORITY>`.
///
/// Closes the T5 IPv6 leak: a v6 CIDR now actually installs an `ip -6 rule`,
/// where the PoC silently dropped it.
pub async fn install_rules(cidrs: &[String]) -> Result<()> {
    for cidr in cidrs {
        let v6 = cidr_is_v6(cidr)?;
        ip_rule_add(cidr, v6).await?;
    }
    Ok(())
}

async fn ip_rule_add(cidr: &str, v6: bool) -> Result<()> {
    let mut cmd = Command::new("ip");
    if v6 {
        cmd.arg("-6");
    }
    cmd.args([
        "rule",
        "add",
        "to",
        cidr,
        "lookup",
        &TABLE_ID.to_string(),
        "priority",
        &RULE_PRIORITY.to_string(),
    ]);
    run_ip(cmd, &format!("ip rule add to {cidr}")).await
}

/// Populate table `<TABLE_ID>` with default routes for both families,
/// pointing at the captured pre-VPN gateway. v6 default is added only when
/// `net.gateway_v6` is `Some` — many networks are v4-only.
pub async fn populate_table(net: &CapturedNet) -> Result<()> {
    if let Some(gw) = &net.gateway_v4 {
        let mut cmd = Command::new("ip");
        cmd.args([
            "route",
            "add",
            "default",
            "via",
            gw,
            "dev",
            &net.iface,
            "table",
            &TABLE_ID.to_string(),
        ]);
        run_ip(cmd, "ip route add default v4").await?;
    }
    if let Some(gw) = &net.gateway_v6 {
        let mut cmd = Command::new("ip");
        cmd.args([
            "-6",
            "route",
            "add",
            "default",
            "via",
            gw,
            "dev",
            &net.iface,
            "table",
            &TABLE_ID.to_string(),
        ]);
        run_ip(cmd, "ip route add default v6").await?;
    }
    Ok(())
}

/// Scoped conntrack flush per D2 failure mode #4. We call `conntrack -D -d
/// <cidr>` once per entry; the tool prints "0 flow entries have been
/// deleted" on a no-op, which is fine. We swallow non-zero exit because
/// conntrack may be unavailable on minimal systems — defence-in-depth
/// failure here should not block route apply.
pub async fn flush_conntrack_scoped(cidrs: &[String]) {
    for cidr in cidrs {
        let mut cmd = Command::new("conntrack");
        cmd.args(["-D", "-d", cidr]);
        match cmd.output().await {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                if !stderr.contains("0 flow entries") {
                    warn!(cidr, stderr = %stderr.trim(), "conntrack -D non-zero exit");
                }
            }
            Err(e) => warn!(cidr, err = %e, "conntrack spawn failed (tool missing?)"),
        }
    }
}

/// Idempotent teardown. Delete every rule at our priority then flush table.
/// We match on `priority <RULE_PRIORITY>` + `lookup <TABLE_ID>` (structural
/// identifiers) rather than the CIDR text, per CLAUDE.md — `ip rule show`
/// strips `/32` on v4 host routes which would break string matching.
pub async fn teardown_routing() -> Result<()> {
    for v6 in [false, true] {
        // Repeated `ip rule del` removes one rule at a time; loop until exit
        // status is non-zero ("No such rule"). Cap at MAX_BYPASS_CIDRS*2 so
        // we don't spin forever if `ip` ever changes its semantics.
        for _ in 0..256 {
            let mut cmd = Command::new("ip");
            if v6 {
                cmd.arg("-6");
            }
            cmd.args([
                "rule",
                "del",
                "priority",
                &RULE_PRIORITY.to_string(),
                "lookup",
                &TABLE_ID.to_string(),
            ]);
            let output = cmd.output().await.context("spawn ip rule del")?;
            if !output.status.success() {
                break;
            }
        }
    }
    // Flush both families' default routes from table 100. Errors here are
    // expected on a clean system (table already empty).
    for v6 in [false, true] {
        let mut cmd = Command::new("ip");
        if v6 {
            cmd.arg("-6");
        }
        cmd.args(["route", "flush", "table", &TABLE_ID.to_string()]);
        let _ = cmd.output().await;
    }
    Ok(())
}

/// Classify a canonical CIDR by family. Reuses parsing logic equivalent to
/// service::canonicalize_cidr — kept local to avoid a cross-module dep loop.
fn cidr_is_v6(cidr: &str) -> Result<bool> {
    let (addr_str, _) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("CIDR missing '/' — '{cidr}'"))?;
    let addr: IpAddr = addr_str
        .parse()
        .with_context(|| format!("invalid IP in '{cidr}'"))?;
    Ok(matches!(addr, IpAddr::V6(_)))
}

/// Partition a canonical CIDR list by address family. Used by the kill-switch
/// nft script builder to emit the v4 and v6 bypass named sets separately.
pub fn split_by_family(cidrs: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for c in cidrs {
        if cidr_is_v6(c)? {
            v6.push(c.clone());
        } else {
            v4.push(c.clone());
        }
    }
    Ok((v4, v6))
}

async fn run_ip(mut cmd: Command, ctx: &str) -> Result<()> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = cmd.output().await.with_context(|| format!("spawn {ctx}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{ctx} failed ({}): {}", output.status, stderr.trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_by_family_partitions_v4_and_v6() {
        let cidrs = vec![
            "10.0.0.0/8".to_string(),
            "2001:db8::/32".to_string(),
            "192.168.1.0/24".to_string(),
            "fd00::/8".to_string(),
        ];
        let (v4, v6) = split_by_family(&cidrs).unwrap();
        assert_eq!(v4, vec!["10.0.0.0/8", "192.168.1.0/24"]);
        assert_eq!(v6, vec!["2001:db8::/32", "fd00::/8"]);
    }

    #[test]
    fn split_by_family_empty_input() {
        let (v4, v6) = split_by_family(&[]).unwrap();
        assert!(v4.is_empty());
        assert!(v6.is_empty());
    }

    #[test]
    fn split_by_family_v4_only() {
        let cidrs = vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()];
        let (v4, v6) = split_by_family(&cidrs).unwrap();
        assert_eq!(v4.len(), 2);
        assert!(v6.is_empty());
    }

    #[test]
    fn split_by_family_v6_only() {
        let cidrs = vec!["2001:db8::/32".to_string()];
        let (v4, v6) = split_by_family(&cidrs).unwrap();
        assert!(v4.is_empty());
        assert_eq!(v6.len(), 1);
    }

    #[test]
    fn split_by_family_rejects_malformed() {
        let cidrs = vec!["not-a-cidr".to_string()];
        assert!(split_by_family(&cidrs).is_err());
    }

    #[test]
    fn cidr_is_v6_classifies_v4() {
        assert!(!cidr_is_v6("10.0.0.0/8").unwrap());
    }

    #[test]
    fn cidr_is_v6_classifies_v6() {
        assert!(cidr_is_v6("2001:db8::/32").unwrap());
    }

    #[test]
    fn rp_filter_path_format() {
        assert_eq!(
            rp_filter_path("wlan0"),
            "/proc/sys/net/ipv4/conf/wlan0/rp_filter"
        );
    }

    #[test]
    fn captured_net_structure() {
        let n = CapturedNet {
            gateway_v4: Some("192.168.1.1".into()),
            gateway_v6: Some("fe80::1".into()),
            iface: "wlan0".into(),
        };
        assert_eq!(n.gateway_v4.unwrap(), "192.168.1.1");
        assert_eq!(n.iface, "wlan0");
    }

    #[test]
    fn captured_net_v4_only_network() {
        let n = CapturedNet {
            gateway_v4: Some("10.0.0.1".into()),
            gateway_v6: None,
            iface: "eth0".into(),
        };
        assert!(n.gateway_v6.is_none());
    }

    #[test]
    fn constants_match_poc() {
        assert_eq!(TABLE_ID, 100);
        assert_eq!(RULE_PRIORITY, 100);
        assert_eq!(TABLE_NAME, "openvpn3-bypass");
    }
}
