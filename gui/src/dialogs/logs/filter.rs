//! Pure filtering logic for the log viewer tabs.
//!
//! Extracted from `mod.rs` so the search/level filter rules are unit-testable
//! in isolation from the GTK widget builder + async D-Bus stream wiring. These
//! functions hold the correctness-critical branchy logic; `rebuild_buffer`
//! stays in `mod.rs` because it mutates a `gtk4::TextBuffer`.

use crate::app::log_buffer::LogEntry;

/// Returns true if any entry in `entries` passes the current filter.
///
/// `search` is lowercased once here before the loop, so the per-entry
/// `passes_filter` never re-allocates the search term.
pub(super) fn any_passes_filter(entries: &[LogEntry], search: &str, level_min: u32) -> bool {
    let search_lower = search.to_lowercase();
    entries
        .iter()
        .any(|e| passes_filter(e, &search_lower, level_min))
}

/// Returns true if the entry passes the current filter pair (substring
/// match on message, case-insensitive; category >= level_min).
///
/// `search_lower` MUST already be lowercased — the hot call sites
/// (`rebuild_buffer`, the export `.filter`) lower the search term once per
/// loop rather than once per entry, and this fn runs once per entry. An
/// empty `search_lower` matches all messages.
pub(super) fn passes_filter(entry: &LogEntry, search_lower: &str, level_min: u32) -> bool {
    if entry.category < level_min {
        return false;
    }
    if !search_lower.is_empty() && !entry.message.to_lowercase().contains(search_lower) {
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
    // Callers pass a pre-lowered search term; the test helper does the same.

    /// `passes_filter` with the search pre-lowered (as every real call site does).
    fn pf(entry: &LogEntry, search: &str, level_min: u32) -> bool {
        passes_filter(entry, &search.to_lowercase(), level_min)
    }

    #[test]
    fn passes_filter_empty_search_matches_all_at_or_above_level() {
        assert!(pf(&entry(6, "anything"), "", 0));
        assert!(pf(&entry(5, "warn text"), "", 5));
        assert!(pf(&entry(6, "err"), "", 6));
    }

    #[test]
    fn passes_filter_rejects_below_level_regardless_of_search() {
        assert!(!pf(&entry(3, "match"), "", 5));
        assert!(!pf(&entry(3, "match"), "match", 5));
    }

    #[test]
    fn passes_filter_substring_match_is_case_insensitive() {
        assert!(pf(&entry(0, "Connection Refused"), "refused", 0));
        assert!(pf(&entry(0, "connection refused"), "REFUSED", 0));
        assert!(pf(&entry(0, "REFUSED"), "fus", 0));
    }

    #[test]
    fn passes_filter_rejects_when_search_present_but_not_in_message() {
        assert!(!pf(&entry(6, "unrelated"), "missing", 0));
    }

    #[test]
    fn passes_filter_both_gates_apply_simultaneously() {
        // Passes level but fails substring.
        assert!(!pf(&entry(6, "nope"), "match", 0));
        // Passes substring but fails level.
        assert!(!pf(&entry(3, "match"), "match", 5));
        // Passes both.
        assert!(pf(&entry(6, "match"), "match", 5));
    }

    #[test]
    fn passes_filter_consumes_pre_lowered_search_verbatim() {
        // Pins the new contract: the fn does NOT lower the search itself.
        // A mixed-case message + already-lowered "refused" must still match.
        assert!(passes_filter(&entry(0, "Connection Refused"), "refused", 0));
        // A search term that is NOT lowercased would miss uppercase message
        // text — documenting that the caller, not this fn, owns lowering.
        assert!(!passes_filter(&entry(0, "REFUSED"), "REFUSED", 0));
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
