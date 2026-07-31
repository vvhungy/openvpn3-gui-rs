//! Notification ID dedup map.
//!
//! Tracks the last freedesktop notification ID per key so that subsequent
//! notifications can replace the previous toast (via `replaces_id`) instead
//! of stacking new ones on the user's screen.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

/// Tracks the last notification ID per config name so status updates replace
/// the previous toast instead of stacking new ones.
pub(super) static NOTIFICATION_IDS: LazyLock<Mutex<HashMap<String, u32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Maximum entries before the dedup map is pruned. Keys are config names, so a
/// real workload stays well under this; the cap only bounds pathological growth
/// (#2, T4). On overflow the whole map is dropped — the only consequence is
/// that the *next* notification for a key no longer replaces its predecessor
/// (one extra toast), which is benign and self-heals as new IDs are recorded.
const MAX_NOTIFICATION_IDS: usize = 256;

/// Record a `replaces_id` for `key`, evicting the whole map if it has grown past
/// `MAX_NOTIFICATION_IDS`. Centralised so every insert site inherits the cap
/// without each caller repeating the bounds check.
pub(super) fn record(key: &str, id: u32) {
    if let Ok(mut map) = NOTIFICATION_IDS.lock() {
        if needs_prune(map.len()) {
            map.clear();
        }
        map.insert(key.to_string(), id);
    }
}

/// Pure: would an insert into a map of this length trigger a pre-insert prune?
/// Extracted from [`record`] so the cap threshold is unit-assertable without
/// polluting the shared static map.
fn needs_prune(len: usize) -> bool {
    len >= MAX_NOTIFICATION_IDS
}

/// Drop every tracked notification ID. Called when the sessions service
/// vanishes permanently — all toasts it tracked are stale, so keeping them
/// only risks replacing a toast that no longer exists (#2, T4).
pub(crate) fn clear_all() {
    if let Ok(mut map) = NOTIFICATION_IDS.lock() {
        map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique key prefix to avoid collisions with other test runs in the
    /// shared static map.
    const TEST_PREFIX: &str = "__notif_test__";

    fn test_key(suffix: &str) -> String {
        format!("{}{}", TEST_PREFIX, suffix)
    }

    fn cleanup(key: &str) {
        if let Ok(mut m) = NOTIFICATION_IDS.lock() {
            m.remove(key);
        }
    }

    #[test]
    fn test_notification_ids_lock_is_accessible() {
        // Verify the static mutex can be locked without deadlock
        let _guard = NOTIFICATION_IDS.lock().unwrap();
    }

    #[test]
    fn test_notification_ids_insert_and_retrieve() {
        let key = test_key("insert");
        {
            let mut m = NOTIFICATION_IDS.lock().unwrap();
            m.insert(key.clone(), 99u32);
        }
        let stored = NOTIFICATION_IDS
            .lock()
            .map(|m| *m.get(&key).unwrap_or(&0))
            .unwrap_or(0);
        assert_eq!(stored, 99);
        cleanup(&key);
    }

    #[test]
    fn test_notification_ids_missing_key_returns_zero() {
        let key = test_key("missing");
        // Ensure it's not in the map
        cleanup(&key);
        let stored = NOTIFICATION_IDS
            .lock()
            .map(|m| *m.get(&key).unwrap_or(&0))
            .unwrap_or(0);
        assert_eq!(stored, 0);
    }

    #[test]
    fn test_notification_ids_overwrite() {
        let key = test_key("overwrite");
        {
            let mut m = NOTIFICATION_IDS.lock().unwrap();
            m.insert(key.clone(), 1u32);
            m.insert(key.clone(), 2u32);
        }
        let stored = NOTIFICATION_IDS
            .lock()
            .map(|m| *m.get(&key).unwrap_or(&0))
            .unwrap_or(0);
        assert_eq!(stored, 2);
        cleanup(&key);
    }

    #[test]
    fn test_notification_ids_remove() {
        let key = test_key("remove");
        {
            let mut m = NOTIFICATION_IDS.lock().unwrap();
            m.insert(key.clone(), 5u32);
        }
        cleanup(&key);
        let stored = NOTIFICATION_IDS
            .lock()
            .map(|m| *m.get(&key).unwrap_or(&0))
            .unwrap_or(0);
        assert_eq!(stored, 0);
    }

    // --- cap (T4 #2) ---

    #[test]
    fn needs_prune_only_at_or_above_cap() {
        // The map is pruned before an insert that would reach the cap, so a
        // real workload (keys = config names, dozens at most) never triggers it.
        assert!(!needs_prune(0));
        assert!(!needs_prune(1));
        assert!(!needs_prune(MAX_NOTIFICATION_IDS - 1));
        assert!(
            needs_prune(MAX_NOTIFICATION_IDS),
            "inserting once the cap is reached must prune first"
        );
        assert!(needs_prune(MAX_NOTIFICATION_IDS + 100));
    }

    #[test]
    fn record_stores_and_is_retrievable() {
        let key = test_key("record_store");
        cleanup(&key);
        record(&key, 777);
        let stored = NOTIFICATION_IDS
            .lock()
            .ok()
            .and_then(|m| m.get(&key).copied())
            .unwrap_or(0);
        assert_eq!(stored, 777);
        cleanup(&key);
    }
}
