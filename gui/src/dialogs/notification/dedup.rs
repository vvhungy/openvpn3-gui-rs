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
}
