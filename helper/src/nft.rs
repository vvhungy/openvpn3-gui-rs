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

pub const TABLE: &str = "openvpn3_killswitch";
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

/// Drift report: the difference between the *desired* bypass CIDR list (what
/// the GUI owns in GSettings and passed to `VerifyBypassSet`) and the *live*
/// nft sets (parsed from `nft -j list table inet openvpn3_killswitch`).
///
/// `missing` = desired-but-not-live → the leak: bypassed traffic to those
/// CIDRs hits `policy drop` instead of escaping, with no signal until the
/// user notices a host stopped working. `extra` = live-but-not-desired →
/// tamper-add (an external actor widened the bypass set); surfaced for
/// visibility but not itself a connectivity hazard. Each vector holds CIDR
/// strings as they appeared in the respective input (not re-canonicalized —
/// the caller already canonicalizes at the GSettings trust boundary).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BypassDriftReport {
    pub v4_missing: Vec<String>,
    pub v6_missing: Vec<String>,
    pub extra: Vec<String>,
}

#[cfg(test)]
impl BypassDriftReport {
    /// True when the live sets match the desired list exactly (no leak, no
    /// tamper). Test-only helper — the GUI gets the three vecs over D-Bus and
    /// does its own emptiness check.
    fn is_clean(&self) -> bool {
        self.v4_missing.is_empty() && self.v6_missing.is_empty() && self.extra.is_empty()
    }
}

/// Compare the desired bypass CIDR list against the live nft sets and return
/// the drift. Pure: takes the already-fetched `nft -j` JSON string (the one
/// impure shell call lives in `service.rs`), so this fn is unit-testable
/// against fixture JSON.
///
/// `desired` semantics: `(v4, v6)` are the CIDRs the GUI believes should be
/// installed. `live_json` is the raw stdout of `nft -j list table inet
/// openvpn3_killswitch`. Sets are matched by name (`bypass_set`, `bypass_set_v6`)
/// — the same names `add_rules_script` emits. `nft` lists set elements as
/// objects with a `prefix` field (`{ "prefix": "10.0.0.0", "len": 8 }`) for
/// `/N` CIDRs under `flags interval`; single hosts appear as bare strings.
/// Both shapes are normalized to the input CIDR's string form for comparison.
///
/// Tolerates a missing table (empty/invalid JSON, or the table absent) by
/// reporting every desired CIDR as missing — the caller distinguishes "table
/// gone" (kill-switch off, not drift) from "table present but drifted" by
/// whether the parse found the table at all. Here we only compute the diff.
pub fn diff_bypass_set(desired: (&[&str], &[&str]), live_json: &str) -> BypassDriftReport {
    let (desired_v4, desired_v6) = desired;
    let parsed = serde_json::from_str::<serde_json::Value>(live_json).ok();

    // `nft -j list table` returns `{"nftables": [ {table}, {set}, {set}, ... ]}`
    // — the table object and each set object are sibling array entries, not
    // nested. A missing/unparseable table → every desired CIDR is "missing".
    let nftables = parsed.as_ref().and_then(|v| v.get("nftables")?.as_array());

    let has_table = nftables
        .map(|arr| {
            arr.iter().any(|obj| {
                obj.get("table")
                    .and_then(|t| t.get("name"))
                    .and_then(|n| n.as_str())
                    == Some(TABLE)
            })
        })
        .unwrap_or(false);

    let live_v4 = if has_table {
        nftables
            .and_then(|arr| live_set_elements(arr, "bypass_set"))
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let live_v6 = if has_table {
        nftables
            .and_then(|arr| live_set_elements(arr, "bypass_set_v6"))
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let v4_missing = desired_v4
        .iter()
        .filter(|c| !live_v4.iter().any(|l| l.as_str() == &***c))
        .map(|c| c.to_string())
        .collect();
    let v6_missing = desired_v6
        .iter()
        .filter(|c| !live_v6.iter().any(|l| l.as_str() == &***c))
        .map(|c| c.to_string())
        .collect();

    // `extra`: live elements that aren't in the desired list (tamper-add).
    // Span both families into one vec — surfaced for visibility, not a hazard.
    let mut extra = Vec::new();
    for el in &live_v4 {
        if !desired_v4.contains(&el.as_str()) {
            extra.push(el.clone());
        }
    }
    for el in &live_v6 {
        if !desired_v6.contains(&el.as_str()) {
            extra.push(el.clone());
        }
    }

    BypassDriftReport {
        v4_missing,
        v6_missing,
        extra,
    }
}

/// Extract the element strings of a named set from the `nftables` sibling
/// array. Handles the two element shapes `nft -j` emits under `flags interval`:
/// bare strings (`"1.2.3.4"`) and prefix objects
/// (`{ "prefix": "10.0.0.0", "len": 8 }` → `"10.0.0.0/8"`). Returns `None`
/// when the set is absent from the array (declared with no elements, or not
/// declared at all because that family had no CIDRs at apply time).
fn live_set_elements(nftables: &[serde_json::Value], set_name: &str) -> Option<Vec<String>> {
    let set = nftables.iter().find_map(|obj| {
        let s = obj.get("set")?;
        let name = s.get("name")?.as_str()?;
        (name == set_name).then_some(s)
    })?;
    let elems = set.get("elem")?.as_array()?;
    Some(
        elems
            .iter()
            .map(|e| match e {
                serde_json::Value::String(s) => s.clone(),
                obj => prefix_element_to_cidr(obj),
            })
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

/// Normalize one set element that is a prefix object to `"addr/len"` CIDR
/// form. `nft -j` emits interval-set prefixes in several shapes across
/// versions; accept all three so drift detection survives whichever the
/// installed nft emits:
/// - nested object: `{ "prefix": { "addr": "10.0.0.0", "len": 8 } }` (modern)
/// - flat:          `{ "prefix": "10.0.0.0", "len": 8 }` (older / libnft docs)
/// - array:         `{ "prefix": ["10.0.0.0", 8] }`
///
/// Returns empty for any other shape; the caller filters empties.
fn prefix_element_to_cidr(obj: &serde_json::Value) -> String {
    let Some(prefix) = obj.get("prefix") else {
        return String::new();
    };
    let (addr, len): (Option<&str>, Option<u64>) = match prefix {
        serde_json::Value::Object(o) => (
            o.get("addr").and_then(|v| v.as_str()),
            o.get("len").and_then(|v| v.as_u64()),
        ),
        serde_json::Value::Array(arr) => (
            arr.first().and_then(|v| v.as_str()),
            arr.get(1).and_then(|v| v.as_u64()),
        ),
        serde_json::Value::String(p) => (Some(p.as_str()), obj.get("len").and_then(|v| v.as_u64())),
        _ => (None, None),
    };
    match (addr, len) {
        (Some(a), Some(n)) => format!("{a}/{n}"),
        _ => String::new(),
    }
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

    // --- diff_bypass_set: drift detection (S38 T2) ---

    /// nft -j table object with one v4 set carrying two CIDRs (one prefix,
    /// one single host) + one v6 prefix. The two element shapes nft emits.
    const CLEAN_TABLE_JSON: &str = r#"{"nftables":[{"table":{"family":"inet","name":"openvpn3_killswitch","handle":12},"set":{"family":"inet","name":"bypass_set","table":"openvpn3_killswitch","handle":5,"type":"ipv4_addr","flags":["interval"],"elem":[{"prefix":"10.0.0.0","len":8},"1.2.3.4"]}},{"set":{"family":"inet","name":"bypass_set_v6","table":"openvpn3_killswitch","handle":6,"type":"ipv6_addr","flags":["interval"],"elem":[{"prefix":"fd00::","len":8}]}}]}"#;

    #[test]
    fn diff_clean_when_live_matches_desired() {
        let report = diff_bypass_set(
            (&["10.0.0.0/8", "1.2.3.4"], &["fd00::/8"]),
            CLEAN_TABLE_JSON,
        );
        assert!(report.is_clean(), "{report:?}");
    }

    #[test]
    fn diff_flags_v4_cidr_missing_from_live() {
        // Desired has an extra v4 CIDR the live set lacks → it's the leak.
        let report = diff_bypass_set(
            (&["10.0.0.0/8", "1.2.3.4", "5.6.7.0/24"], &[]),
            CLEAN_TABLE_JSON,
        );
        assert!(!report.is_clean());
        assert_eq!(report.v4_missing, vec!["5.6.7.0/24"]);
        assert!(report.v6_missing.is_empty());
    }

    #[test]
    fn diff_flags_v6_cidr_missing_from_live() {
        let report = diff_bypass_set((&[], &["fd00::/8", "2001:db8::/32"]), CLEAN_TABLE_JSON);
        assert_eq!(report.v6_missing, vec!["2001:db8::/32"]);
        assert!(report.v4_missing.is_empty());
    }

    #[test]
    fn diff_flags_extra_element_tamper_add() {
        // Live set has an element the desired list doesn't → external widen.
        // Here desired drops 1.2.3.4 but it's still in live → reported as extra.
        let report = diff_bypass_set((&["10.0.0.0/8"], &["fd00::/8"]), CLEAN_TABLE_JSON);
        assert_eq!(report.extra, vec!["1.2.3.4"]);
        assert!(report.v4_missing.is_empty());
    }

    #[test]
    fn diff_no_table_reports_all_desired_missing() {
        // Table absent (empty JSON) → every desired CIDR is missing, no extra.
        let report = diff_bypass_set((&["10.0.0.0/8", "1.2.3.4"], &["fd00::/8"]), "{}");
        assert_eq!(report.v4_missing, vec!["10.0.0.0/8", "1.2.3.4"]);
        assert_eq!(report.v6_missing, vec!["fd00::/8"]);
        assert!(report.extra.is_empty());
    }

    #[test]
    fn diff_empty_everywhere_is_clean() {
        // Zero-data state: no desired AND live sets absent → clean, no false drift.
        // A table with no bypass sets declared (e.g. applied with empty CIDR lists).
        const EMPTY_SETS_JSON: &str = r#"{"nftables":[{"table":{"family":"inet","name":"openvpn3_killswitch","handle":12}}]}"#;
        let report = diff_bypass_set((&[], &[]), EMPTY_SETS_JSON);
        assert!(report.is_clean());
    }

    #[test]
    fn diff_malformed_json_treated_as_no_table() {
        let report = diff_bypass_set((&["10.0.0.0/8"], &[]), "not json at all");
        assert_eq!(report.v4_missing, vec!["10.0.0.0/8"]);
    }

    // nft -j emits interval-set prefixes in multiple shapes across versions.
    // All three must normalize to the same CIDR string or drift fires on a
    // perfectly intact live set (the bug fixed after first real-device test).

    /// Modern nftables: `{ "prefix": { "addr": "10.10.10.0", "len": 24 } }`.
    const NESTED_PREFIX_JSON: &str = r#"{"nftables":[{"table":{"family":"inet","name":"openvpn3_killswitch","handle":12},"set":{"family":"inet","name":"bypass_set","table":"openvpn3_killswitch","handle":5,"type":"ipv4_addr","flags":["interval"],"elem":[{"prefix":{"addr":"10.10.10.0","len":24}}]}}]}"#;

    #[test]
    fn diff_handles_nested_prefix_object() {
        let report = diff_bypass_set((&["10.10.10.0/24"], &[]), NESTED_PREFIX_JSON);
        assert!(report.is_clean(), "{report:?}");
    }

    /// Older / alternate: `{ "prefix": ["10.10.10.0", 24] }`.
    const ARRAY_PREFIX_JSON: &str = r#"{"nftables":[{"table":{"family":"inet","name":"openvpn3_killswitch","handle":12},"set":{"family":"inet","name":"bypass_set","table":"openvpn3_killswitch","handle":5,"type":"ipv4_addr","flags":["interval"],"elem":[{"prefix":["10.10.10.0",24]}]}}]}"#;

    #[test]
    fn diff_handles_array_prefix() {
        let report = diff_bypass_set((&["10.10.10.0/24"], &[]), ARRAY_PREFIX_JSON);
        assert!(report.is_clean(), "{report:?}");
    }

    #[test]
    fn diff_mixed_shapes_in_one_set() {
        // Live: nested prefix + bare host + array prefix; desired = all three.
        const MIXED: &str = r#"{"nftables":[{"table":{"family":"inet","name":"openvpn3_killswitch","handle":1},"set":{"family":"inet","name":"bypass_set","table":"openvpn3_killswitch","handle":1,"type":"ipv4_addr","flags":["interval"],"elem":[{"prefix":{"addr":"10.0.0.0","len":8}},"1.2.3.4",{"prefix":["192.168.1.0",24]}]}}]}"#;
        let report = diff_bypass_set((&["10.0.0.0/8", "1.2.3.4", "192.168.1.0/24"], &[]), MIXED);
        assert!(report.is_clean(), "{report:?}");
    }
}
