//! Settings module

pub mod gsettings;

pub use gsettings::Settings;

/// Filter `all` to entries not present in `disabled`. Preserves order.
/// Used at all 3 push-to-helper sites so disabled bypass CIDRs are skipped.
pub fn enabled_cidrs(all: &[String], disabled: &[String]) -> Vec<String> {
    all.iter()
        .filter(|c| !disabled.iter().any(|d| d == *c))
        .cloned()
        .collect()
}

/// Partition enabled CIDR strings into `(v4, v6)` by parsing the address
/// prefix. Malformed entries (not parseable as `IpAddr`) are dropped — the
/// helper validates at its trust boundary anyway, and drift detection's job
/// is to compare what the GUI *thinks* it installed, not to re-validate.
/// Used by the drift-detection poll so it can pass family-split lists to
/// `VerifyBypassSet`, matching the live nft sets' per-family structure.
///
/// Mirrors `helper/src/bypass.rs::split_by_family` (address-family partition
/// of canonical CIDRs). Keep the two in sync on canonicalization changes — a
/// divergence would split a CIDR into the wrong family here vs. at the helper,
/// and the resulting bypass-set diff would flag a correct set as drifted.
/// Difference: this fn is non-fallible (a malformed CIDR is dropped silently,
/// since the helper re-validates); `split_by_family` returns `Result` and
/// rejects malformed input.
pub fn split_v4_v6(cidrs: &[String]) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for c in cidrs {
        // CIDR form "addr/prefix" — parse the address portion only.
        let addr_str = c.split('/').next().unwrap_or(c);
        match addr_str.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(_)) => v4.push(c.clone()),
            Ok(std::net::IpAddr::V6(_)) => v6.push(c.clone()),
            Err(_) => {}
        }
    }
    (v4, v6)
}

#[cfg(test)]
mod tests {
    use super::{enabled_cidrs, split_v4_v6};

    #[test]
    fn empty_disabled_returns_all() {
        let all = vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()];
        assert_eq!(enabled_cidrs(&all, &[]), all);
    }

    #[test]
    fn all_disabled_returns_empty() {
        let all = vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()];
        assert!(enabled_cidrs(&all, &all).is_empty());
    }

    #[test]
    fn mixed_preserves_order() {
        let all = vec![
            "10.0.0.0/8".to_string(),
            "192.168.1.0/24".to_string(),
            "2001:db8::/32".to_string(),
        ];
        let disabled = vec!["192.168.1.0/24".to_string()];
        assert_eq!(
            enabled_cidrs(&all, &disabled),
            vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()]
        );
    }

    #[test]
    fn orphan_disabled_entries_ignored() {
        let all = vec!["10.0.0.0/8".to_string()];
        let disabled = vec!["172.16.0.0/12".to_string()];
        assert_eq!(enabled_cidrs(&all, &disabled), all);
    }

    // --- split_v4_v6 ---

    #[test]
    fn split_v4_v6_separates_families_preserving_order() {
        let cidrs = vec![
            "10.0.0.0/8".to_string(),
            "2001:db8::/32".to_string(),
            "192.168.1.0/24".to_string(),
            "::1/128".to_string(),
        ];
        let (v4, v6) = split_v4_v6(&cidrs);
        assert_eq!(
            v4,
            vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()]
        );
        assert_eq!(v6, vec!["2001:db8::/32".to_string(), "::1/128".to_string()]);
    }

    #[test]
    fn split_v4_v6_drops_malformed() {
        let cidrs = vec![
            "10.0.0.0/8".to_string(),
            "not-a-cidr".to_string(),
            "999.999.999.999/24".to_string(),
        ];
        let (v4, v6) = split_v4_v6(&cidrs);
        assert_eq!(v4, vec!["10.0.0.0/8".to_string()]);
        assert!(v6.is_empty());
    }

    #[test]
    fn split_v4_v6_empty_input() {
        let (v4, v6) = split_v4_v6(&[]);
        assert!(v4.is_empty());
        assert!(v6.is_empty());
    }
}
