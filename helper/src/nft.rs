//! nftables rule generation. Pure functions — the unit-testable surface.
//! See `docs/kill-switch.md` for the locked rule set design.

use std::fmt::Write as _;

const TABLE: &str = "openvpn3_killswitch";
const RFC1918: &str = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16";

/// Build the nft script that creates the kill-switch table.
///
/// Writes to a String never fails, so the `writeln!` results are discarded.
/// Caller is expected to validate `interface` and IP literals before calling
/// — this function performs no sanitisation.
pub fn add_rules_script(
    interface: &str,
    ipv4_servers: &[&str],
    ipv6_servers: &[&str],
    allow_lan: bool,
) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "table inet {TABLE} {{");
    s.push_str("    chain output {\n");
    s.push_str("        type filter hook output priority 0; policy drop;\n");
    s.push_str("        oifname \"lo\" accept\n");
    s.push_str("        ct state established,related accept\n");

    if !ipv4_servers.is_empty() {
        let _ = writeln!(
            s,
            "        ip daddr {{ {} }} accept",
            ipv4_servers.join(", ")
        );
    }
    if !ipv6_servers.is_empty() {
        let _ = writeln!(
            s,
            "        ip6 daddr {{ {} }} accept",
            ipv6_servers.join(", ")
        );
    }
    if allow_lan {
        let _ = writeln!(s, "        ip daddr {{ {RFC1918} }} accept");
    }
    let _ = writeln!(s, "        oifname \"{interface}\" accept");

    s.push_str("    }\n");
    s.push_str("}\n");
    s
}

/// nft script that removes the kill-switch table. Idempotent at the helper
/// layer (helper swallows "no such table" errors from `nft`).
pub const fn remove_rules_script() -> &'static str {
    "delete table inet openvpn3_killswitch\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_script_is_table_delete() {
        assert_eq!(
            remove_rules_script(),
            "delete table inet openvpn3_killswitch\n"
        );
    }

    #[test]
    fn add_script_includes_base_rules() {
        let s = add_rules_script("tun0", &[], &[], false);
        assert!(s.contains("table inet openvpn3_killswitch"));
        assert!(s.contains("type filter hook output priority 0; policy drop;"));
        assert!(s.contains("oifname \"lo\" accept"));
        assert!(s.contains("ct state established,related accept"));
        assert!(s.contains("oifname \"tun0\" accept"));
    }

    #[test]
    fn add_script_omits_ipv4_section_when_empty() {
        let s = add_rules_script("tun0", &[], &[], false);
        assert!(!s.contains("ip daddr"));
    }

    #[test]
    fn add_script_includes_ipv4_servers_comma_separated() {
        let s = add_rules_script("tun0", &["1.2.3.4", "5.6.7.8"], &[], false);
        assert!(s.contains("ip daddr { 1.2.3.4, 5.6.7.8 } accept"));
    }

    #[test]
    fn add_script_omits_ipv6_section_when_empty() {
        let s = add_rules_script("tun0", &["1.2.3.4"], &[], false);
        assert!(!s.contains("ip6 daddr"));
    }

    #[test]
    fn add_script_includes_ipv6_servers() {
        let s = add_rules_script("tun0", &[], &["2001:db8::1", "2001:db8::2"], false);
        assert!(s.contains("ip6 daddr { 2001:db8::1, 2001:db8::2 } accept"));
    }

    #[test]
    fn add_script_includes_lan_ranges_when_allowed() {
        let s = add_rules_script("tun0", &[], &[], true);
        assert!(s.contains("ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept"));
    }

    #[test]
    fn add_script_omits_lan_ranges_when_disallowed() {
        let s = add_rules_script("tun0", &[], &[], false);
        assert!(!s.contains("10.0.0.0/8"));
    }

    #[test]
    fn add_script_uses_provided_interface_name() {
        let s = add_rules_script("vpn-corp", &[], &[], false);
        assert!(s.contains("oifname \"vpn-corp\" accept"));
        assert!(!s.contains("oifname \"tun0\""));
    }
}
