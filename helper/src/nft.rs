//! nftables rule generation. Pure functions — the unit-testable surface.
//! See `docs/kill-switch.md` for the locked rule set design.
//!
//! Sprint 23 T2 added the bypass-set + MSS-clamp branch — when bypass CIDR
//! slices are non-empty, named sets `bypass_set` (v4) / `bypass_set_v6` (v6)
//! are declared in the table preamble and `accept` rules match against
//! them in the chain. The MSS-clamp line is emitted unconditionally:
//! harmless on tunnel TCP (rt mtu == tun MTU) and corrects bypass-path TCP
//! MSS when the bypass path MTU differs from the tunnel MTU. Per D4 the
//! firewall layer gates on routing already being applied — the caller in
//! `service.rs::add_rules` is responsible for passing the current bypass
//! CIDR snapshot.

use std::fmt::Write as _;

const TABLE: &str = "openvpn3_killswitch";
const RFC1918: &str = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16";

/// Build the nft script that creates the kill-switch table.
///
/// Writes to a String never fails, so the `writeln!` results are discarded.
/// Caller is expected to validate `interface` and IP literals before calling
/// — this function performs no sanitisation. Bypass CIDRs MUST be canonical
/// (host bits masked) per `service::canonicalize_cidr` — they are inlined
/// into named-set element lists verbatim.
pub fn add_rules_script(
    interface: &str,
    ipv4_servers: &[&str],
    ipv6_servers: &[&str],
    allow_lan: bool,
    bypass_cidrs_v4: &[&str],
    bypass_cidrs_v6: &[&str],
) -> String {
    let mut s = String::new();
    // Atomic replace: nft applies a whole `-f` script as one transaction, so
    // emitting the teardown + rebuild in a single script eliminates the
    // no-enforcement window that a separate remove-then-add call pair leaves.
    // `add table` is an idempotent ensure-exists, so the following `delete`
    // never fails on first apply (no prior table) — then the table (with all
    // its sets/chains) is rebuilt fresh. The whole thing commits or rolls back
    // as a unit; there is no instant where the table is absent.
    let _ = writeln!(s, "add table inet {TABLE}");
    let _ = writeln!(s, "delete table inet {TABLE}");
    let _ = writeln!(s, "table inet {TABLE} {{");

    // Bypass named-set declarations live in the table preamble. `flags
    // interval` is required because elements include /N CIDRs, not single
    // host addrs. Each family gets its own typed set — nft type system
    // forbids mixing ipv4_addr and ipv6_addr in one set.
    if !bypass_cidrs_v4.is_empty() {
        s.push_str("    set bypass_set {\n");
        s.push_str("        type ipv4_addr\n");
        s.push_str("        flags interval\n");
        let _ = writeln!(s, "        elements = {{ {} }}", bypass_cidrs_v4.join(", "));
        s.push_str("    }\n");
    }
    if !bypass_cidrs_v6.is_empty() {
        s.push_str("    set bypass_set_v6 {\n");
        s.push_str("        type ipv6_addr\n");
        s.push_str("        flags interval\n");
        let _ = writeln!(s, "        elements = {{ {} }}", bypass_cidrs_v6.join(", "));
        s.push_str("    }\n");
    }

    s.push_str("    chain output {\n");
    s.push_str("        type filter hook output priority 0; policy drop;\n");
    s.push_str("        oifname \"lo\" accept\n");
    s.push_str("        ct state established,related accept\n");

    // MSS clamping (defence-in-depth per docs/split-tunneling.md). Harmless
    // on tunnel TCP — rt mtu equals the tun MTU; for bypass TCP, it sizes
    // SYN MSS to the physical-iface path MTU instead of the tun's smaller
    // MTU. Placed before any `accept` so it applies to every TCP SYN
    // crossing this chain regardless of bypass/tunnel destination.
    s.push_str("        tcp flags syn tcp option maxseg size set rt mtu\n");

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
    // Bypass accept rules — sit between LAN exemption and the tunnel-iface
    // accept so bypass-destined traffic on the *physical* iface escapes the
    // policy drop. The routing layer ensures bypass packets actually leave
    // via the physical iface (table 100), so without this line they would
    // be dropped by `policy drop` since they never hit `oifname tun*`.
    if !bypass_cidrs_v4.is_empty() {
        s.push_str("        ip daddr @bypass_set accept\n");
    }
    if !bypass_cidrs_v6.is_empty() {
        s.push_str("        ip6 daddr @bypass_set_v6 accept\n");
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
    fn add_script_is_self_contained_atomic_replace() {
        // The script must tear down any prior table and rebuild within one
        // nft transaction — no dependency on a prior remove_rules call, so
        // re-apply has no no-enforcement window. Ensure-exists `add table`
        // precedes the `delete table` so first-apply (no prior table) works.
        let s = add_rules_script("tun0", &["1.2.3.4"], &[], false, &[], &[]);
        let add_pos = s.find("add table inet openvpn3_killswitch").unwrap();
        let del_pos = s.find("delete table inet openvpn3_killswitch").unwrap();
        let build_pos = s.find("table inet openvpn3_killswitch {").unwrap();
        assert!(add_pos < del_pos, "ensure-exists must precede delete");
        assert!(del_pos < build_pos, "delete must precede rebuild");
    }

    #[test]
    fn add_script_includes_base_rules() {
        let s = add_rules_script("tun0", &[], &[], false, &[], &[]);
        assert!(s.contains("table inet openvpn3_killswitch"));
        assert!(s.contains("type filter hook output priority 0; policy drop;"));
        assert!(s.contains("oifname \"lo\" accept"));
        assert!(s.contains("ct state established,related accept"));
        assert!(s.contains("oifname \"tun0\" accept"));
    }

    #[test]
    fn add_script_omits_ipv4_section_when_empty() {
        let s = add_rules_script("tun0", &[], &[], false, &[], &[]);
        // No server ipv4 `daddr` AND no bypass set declaration.
        assert!(!s.contains("ip daddr"));
        assert!(!s.contains("bypass_set"));
    }

    #[test]
    fn add_script_includes_ipv4_servers_comma_separated() {
        let s = add_rules_script("tun0", &["1.2.3.4", "5.6.7.8"], &[], false, &[], &[]);
        assert!(s.contains("ip daddr { 1.2.3.4, 5.6.7.8 } accept"));
    }

    #[test]
    fn add_script_omits_ipv6_section_when_empty() {
        let s = add_rules_script("tun0", &["1.2.3.4"], &[], false, &[], &[]);
        assert!(!s.contains("ip6 daddr"));
    }

    #[test]
    fn add_script_includes_ipv6_servers() {
        let s = add_rules_script(
            "tun0",
            &[],
            &["2001:db8::1", "2001:db8::2"],
            false,
            &[],
            &[],
        );
        assert!(s.contains("ip6 daddr { 2001:db8::1, 2001:db8::2 } accept"));
    }

    #[test]
    fn add_script_includes_lan_ranges_when_allowed() {
        let s = add_rules_script("tun0", &[], &[], true, &[], &[]);
        assert!(s.contains("ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept"));
    }

    #[test]
    fn add_script_omits_lan_ranges_when_disallowed() {
        let s = add_rules_script("tun0", &[], &[], false, &[], &[]);
        assert!(!s.contains("10.0.0.0/8"));
    }

    #[test]
    fn add_script_uses_provided_interface_name() {
        let s = add_rules_script("vpn-corp", &[], &[], false, &[], &[]);
        assert!(s.contains("oifname \"vpn-corp\" accept"));
        assert!(!s.contains("oifname \"tun0\""));
    }

    // === S23 T2: bypass-set + MSS-clamp tests ===

    #[test]
    fn add_script_emits_mss_clamp_unconditionally() {
        let s = add_rules_script("tun0", &[], &[], false, &[], &[]);
        assert!(s.contains("tcp flags syn tcp option maxseg size set rt mtu"));
    }

    #[test]
    fn add_script_emits_bypass_set_v4_when_non_empty() {
        let s = add_rules_script(
            "tun0",
            &[],
            &[],
            false,
            &["10.0.0.0/8", "192.168.1.0/24"],
            &[],
        );
        assert!(s.contains("set bypass_set {"));
        assert!(s.contains("type ipv4_addr"));
        assert!(s.contains("flags interval"));
        assert!(s.contains("elements = { 10.0.0.0/8, 192.168.1.0/24 }"));
        assert!(s.contains("ip daddr @bypass_set accept"));
    }

    #[test]
    fn add_script_emits_bypass_set_v6_when_non_empty() {
        let s = add_rules_script("tun0", &[], &[], false, &[], &["2001:db8::/32"]);
        assert!(s.contains("set bypass_set_v6 {"));
        assert!(s.contains("type ipv6_addr"));
        assert!(s.contains("elements = { 2001:db8::/32 }"));
        assert!(s.contains("ip6 daddr @bypass_set_v6 accept"));
    }

    #[test]
    fn add_script_emits_both_bypass_sets_independently() {
        let s = add_rules_script("tun0", &[], &[], false, &["10.0.0.0/8"], &["2001:db8::/32"]);
        assert!(s.contains("set bypass_set {"));
        assert!(s.contains("set bypass_set_v6 {"));
        assert!(s.contains("ip daddr @bypass_set accept"));
        assert!(s.contains("ip6 daddr @bypass_set_v6 accept"));
    }

    #[test]
    fn add_script_omits_bypass_set_when_only_other_family() {
        // v4-only bypass list must NOT emit the v6 set or v6 accept rule.
        let s = add_rules_script("tun0", &[], &[], false, &["10.0.0.0/8"], &[]);
        assert!(!s.contains("bypass_set_v6"));
        assert!(!s.contains("ip6 daddr @"));
    }

    #[test]
    fn add_script_bypass_accept_before_tunnel_accept() {
        // Order matters: the bypass accept must come before the tunnel
        // accept so it isn't shadowed (oifname tun* wouldn't match a
        // bypass packet anyway, but the ordering prevents future-rule
        // surprises like adding policy refinements above the tunnel line).
        let s = add_rules_script("tun0", &[], &[], false, &["10.0.0.0/8"], &[]);
        let bypass_pos = s.find("ip daddr @bypass_set accept").unwrap();
        let tunnel_pos = s.find("oifname \"tun0\" accept").unwrap();
        assert!(bypass_pos < tunnel_pos);
    }
}
