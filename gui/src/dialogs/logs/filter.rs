//! Pure filtering logic for the log viewer tabs.
//!
//! Extracted from `mod.rs` so the search/level filter rules are unit-testable
//! in isolation from the GTK widget builder + async D-Bus stream wiring. These
//! functions hold the correctness-critical branchy logic; `rebuild_buffer`
//! stays in `mod.rs` because it mutates a `gtk4::TextBuffer`.

use crate::app::log_buffer::LogEntry;

/// Returns true if any entry in `entries` passes the current filter.
pub(super) fn any_passes_filter(entries: &[LogEntry], search: &str, level_min: u32) -> bool {
    entries.iter().any(|e| passes_filter(e, search, level_min))
}

/// Returns true if the entry passes the current filter pair (substring
/// match on message, case-insensitive; category >= level_min).
pub(super) fn passes_filter(entry: &LogEntry, search: &str, level_min: u32) -> bool {
    if entry.category < level_min {
        return false;
    }
    if !search.is_empty()
        && !entry
            .message
            .to_lowercase()
            .contains(&search.to_lowercase())
    {
        return false;
    }
    true
}

/// Map DropDown selected index to the min category threshold.
pub(super) fn level_index_to_min(idx: u32) -> u32 {
    match idx {
        1 => 5,
        2 => 6,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::log_buffer::LogEntry;

    /// Build a LogEntry with the given category and message (other fields defaulted).
    fn entry(category: u32, message: &str) -> LogEntry {
        LogEntry {
            timestamp: chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
            session_path: String::new(),
            config_name: String::new(),
            category,
            message: message.to_string(),
        }
    }

    // --- level_index_to_min: every combo-index variant asserted ---

    #[test]
    fn level_index_to_min_maps_all_variants() {
        assert_eq!(level_index_to_min(0), 0, "index 0 = All");
        assert_eq!(level_index_to_min(1), 5, "index 1 = Warn+");
        assert_eq!(level_index_to_min(2), 6, "index 2 = Error");
    }

    #[test]
    fn level_index_to_min_clamps_out_of_range_to_all() {
        // No enum bound on the DropDown index; out-of-range must not panic.
        assert_eq!(level_index_to_min(3), 0);
        assert_eq!(level_index_to_min(u32::MAX), 0);
    }

    // --- passes_filter: substring + level gate, independently and together ---

    #[test]
    fn passes_filter_empty_search_matches_all_at_or_above_level() {
        assert!(passes_filter(&entry(6, "anything"), "", 0));
        assert!(passes_filter(&entry(5, "warn text"), "", 5));
        assert!(passes_filter(&entry(6, "err"), "", 6));
    }

    #[test]
    fn passes_filter_rejects_below_level_regardless_of_search() {
        assert!(!passes_filter(&entry(3, "match"), "", 5));
        assert!(!passes_filter(&entry(3, "match"), "match", 5));
    }

    #[test]
    fn passes_filter_substring_match_is_case_insensitive() {
        assert!(passes_filter(&entry(0, "Connection Refused"), "refused", 0));
        assert!(passes_filter(&entry(0, "connection refused"), "REFUSED", 0));
        assert!(passes_filter(&entry(0, "REFUSED"), "fus", 0));
    }

    #[test]
    fn passes_filter_rejects_when_search_present_but_not_in_message() {
        assert!(!passes_filter(&entry(6, "unrelated"), "missing", 0));
    }

    #[test]
    fn passes_filter_both_gates_apply_simultaneously() {
        // Passes level but fails substring.
        assert!(!passes_filter(&entry(6, "nope"), "match", 0));
        // Passes substring but fails level.
        assert!(!passes_filter(&entry(3, "match"), "match", 5));
        // Passes both.
        assert!(passes_filter(&entry(6, "match"), "match", 5));
    }

    // --- any_passes_filter: zero-data state + aggregation ---

    #[test]
    fn any_passes_filter_false_on_empty_slice() {
        assert!(!any_passes_filter(&[], "", 0));
        assert!(!any_passes_filter(&[], "anything", 6));
    }

    #[test]
    fn any_passes_filter_true_iff_at_least_one_passes() {
        let entries = vec![
            entry(3, "below level"), // filtered out by level_min=5
            entry(6, "no match"),    // filtered out by search
            entry(6, "target hit"),  // passes both
        ];
        assert!(any_passes_filter(&entries, "target", 5));
    }

    #[test]
    fn any_passes_filter_false_when_all_filtered_out() {
        let entries = vec![entry(3, "below"), entry(6, "wrong")];
        assert!(!any_passes_filter(&entries, "target", 5));
    }
}
