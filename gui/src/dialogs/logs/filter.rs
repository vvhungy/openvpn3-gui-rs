//! Pure filtering logic for the log viewer tabs.
//!
//! Extracted from `mod.rs` so the search/level filter rules are unit-testable
//! in isolation from the GTK widget builder + async D-Bus stream wiring. These
//! functions hold the correctness-critical branchy logic; `rebuild_buffer`
//! stays in `mod.rs` because it mutates a `gtk4::TextBuffer`.

use crate::app::log_buffer::LogEntry;

/// A search term that is guaranteed to be lowercased.
///
/// `passes_filter` requires a pre-lowered search so it can run once per entry
/// without re-allocating the term inside the loop. Making the lowered form a
/// distinct type means "forgot to lower" is unrepresentable at the call site:
/// the only way to obtain a `LoweredQuery` is `LoweredQuery::new`, which lowers
/// exactly once. An empty query matches all messages.
pub(super) struct LoweredQuery(String);

impl LoweredQuery {
    /// Lower the search term once. Call once per rebuild, before the loop.
    pub(super) fn new(search: &str) -> Self {
        LoweredQuery(search.to_lowercase())
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// Returns true if any entry in `entries` passes the current filter.
///
/// `search` is lowered once here before the loop, so the per-entry
/// `passes_filter` never re-allocates the search term.
pub(super) fn any_passes_filter(entries: &[LogEntry], search: &str, level_min: u32) -> bool {
    let query = LoweredQuery::new(search);
    entries.iter().any(|e| passes_filter(e, &query, level_min))
}

/// Returns true if the entry passes the current filter pair (substring
/// match on message, case-insensitive; category >= level_min).
///
/// Takes a `LoweredQuery` so the search term is lowered once per loop (in the
/// constructor) rather than once per entry, and "forgot to lower" cannot
/// happen — the type has no other constructor.
pub(super) fn passes_filter(entry: &LogEntry, query: &LoweredQuery, level_min: u32) -> bool {
    if entry.category < level_min {
        return false;
    }
    if !query.is_empty() && !entry.message.to_lowercase().contains(query.as_str()) {
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

    /// `passes_filter` via the `LoweredQuery` newtype (as every real call site does).
    fn pf(entry: &LogEntry, search: &str, level_min: u32) -> bool {
        passes_filter(entry, &LoweredQuery::new(search), level_min)
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
    fn lowered_query_lowers_once_and_matches_case_insensitively() {
        // The newtype is the only way to build a search term, and it lowers on
        // construction — so an uppercase query still matches lowercase message
        // text. This is what the old doc-only "caller must lower" contract
        // asserted, now enforced by the type instead of by discipline.
        let q = LoweredQuery::new("REFUSED");
        assert!(passes_filter(&entry(0, "connection refused"), &q, 0));
        assert!(passes_filter(&entry(0, "Connection REFUSED"), &q, 0));
        // Empty query matches all.
        assert!(passes_filter(
            &entry(0, "anything"),
            &LoweredQuery::new(""),
            0
        ));
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
