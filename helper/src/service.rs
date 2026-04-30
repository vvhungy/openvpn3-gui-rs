//! D-Bus interface implementation. Exposes `AddRules`/`RemoveRules` to
//! the GUI and shells out to `nft -f -` to apply rule scripts. Spawns
//! a watcher task per active client; if the client disappears, rules
//! are auto-removed so the user is never locked out.
//!
//! D-Bus async glue is untested (requires real bus + `nft` + root); the
//! testable surface is [`validate_interface`] and [`split_ips`].

use anyhow::{Context, Result, bail};
use std::net::IpAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use zbus::Connection;
use zbus::fdo;
use zbus::interface;

use crate::{nft, watcher};

const NFT_BIN: &str = "nft";
const IFNAMSIZ_MAX: usize = 15; // Linux IFNAMSIZ - 1 (NUL terminator)

#[derive(Default)]
struct State {
    sender: Option<String>,
    watcher: Option<JoinHandle<()>>,
}

#[derive(Default)]
pub struct KillSwitch {
    state: Arc<Mutex<State>>,
}

#[interface(name = "net.openvpn.v3.killswitch")]
impl KillSwitch {
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
        let script = nft::add_rules_script(interface, &v4_refs, &v6_refs, allow_lan);

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
}

/// Best-effort rule cleanup, called from the SIGTERM/SIGINT handler in main.
pub async fn cleanup_rules() {
    if let Err(e) = run_nft(nft::remove_rules_script()).await {
        warn!(err = ?e, "shutdown cleanup nft failed (often expected)");
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

fn validate_interface(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("interface name empty");
    }
    if name.len() > IFNAMSIZ_MAX {
        bail!("interface name too long ({} > {IFNAMSIZ_MAX})", name.len());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
    {
        bail!("interface name contains invalid characters");
    }
    Ok(())
}

fn split_ips(ips: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for ip in ips {
        let parsed: IpAddr = ip.parse().with_context(|| format!("invalid IP '{ip}'"))?;
        match parsed {
            IpAddr::V4(_) => v4.push(ip.clone()),
            IpAddr::V6(_) => v6.push(ip.clone()),
        }
    }
    Ok((v4, v6))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_simple_tunnel_name() {
        assert!(validate_interface("tun0").is_ok());
    }

    #[test]
    fn validate_accepts_dash_underscore_dot_colon() {
        // 11 chars, exercises all 4 allowed special characters (- _ . :)
        assert!(validate_interface("vpn-1_a.b:c").is_ok());
    }

    #[test]
    fn validate_rejects_empty() {
        assert!(validate_interface("").is_err());
    }

    #[test]
    fn validate_rejects_too_long() {
        // 16 chars exceeds IFNAMSIZ-1
        assert!(validate_interface("aaaaaaaaaaaaaaaa").is_err());
    }

    #[test]
    fn validate_rejects_shell_injection_attempt() {
        assert!(validate_interface("tun0; rm -rf /").is_err());
        assert!(validate_interface("tun0\"; nft drop").is_err());
        assert!(validate_interface("tun 0").is_err()); // space
    }

    #[test]
    fn split_ips_v4_only() {
        let (v4, v6) = split_ips(&["1.2.3.4".into()]).unwrap();
        assert_eq!(v4, vec!["1.2.3.4"]);
        assert!(v6.is_empty());
    }

    #[test]
    fn split_ips_v6_only() {
        let (v4, v6) = split_ips(&["2001:db8::1".into()]).unwrap();
        assert!(v4.is_empty());
        assert_eq!(v6, vec!["2001:db8::1"]);
    }

    #[test]
    fn split_ips_preserves_order_within_family() {
        let (v4, v6) = split_ips(&[
            "1.2.3.4".into(),
            "2001:db8::1".into(),
            "5.6.7.8".into(),
            "2001:db8::2".into(),
        ])
        .unwrap();
        assert_eq!(v4, vec!["1.2.3.4", "5.6.7.8"]);
        assert_eq!(v6, vec!["2001:db8::1", "2001:db8::2"]);
    }

    #[test]
    fn split_ips_rejects_malformed() {
        assert!(split_ips(&["not-an-ip".into()]).is_err());
        assert!(split_ips(&["1.2.3.4".into(), "garbage".into()]).is_err());
        assert!(split_ips(&["256.0.0.1".into()]).is_err()); // out-of-range octet
    }
}
