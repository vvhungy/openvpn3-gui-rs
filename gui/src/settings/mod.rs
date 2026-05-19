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

#[cfg(test)]
mod tests {
    use super::enabled_cidrs;

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
}
