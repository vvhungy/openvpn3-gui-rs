//! Auth-retry bookkeeping: the running counter of consecutive auth failures
//! per config, with a stale-failure window. Pure over an injected map/state
//! so the window-reset branch is unit-testable without sleeping.
//!
//! Split out of the async credential-request flow so the pure surface and its
//! tests live alone. Re-exported from [`super`] so existing
//! `credential_handler::next_attempt` / `CREDENTIAL_ATTEMPTS` /
//! `MAX_CREDENTIAL_ATTEMPTS` call paths stay valid.

use std::collections::HashMap;

pub(crate) const MAX_CREDENTIAL_ATTEMPTS: u32 = 3;

/// Auth failures older than this are considered stale and the counter resets.
pub(crate) const AUTH_RETRY_WINDOW_SECS: u64 = 300; // 5 minutes

pub(crate) struct AuthAttempt {
    pub(crate) count: u32,
    pub(crate) last_failure: std::time::Instant,
}

pub(crate) static CREDENTIAL_ATTEMPTS: std::sync::LazyLock<
    std::sync::Mutex<HashMap<String, AuthAttempt>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// Record one auth failure for `config_id` and return the running attempt count.
///
/// `config_id` is the unique D-Bus config object **path**, never the display
/// name: two configs can share a name (`LookupConfigName -> Vec<...>`,
/// `dbus/configuration.rs:28`), so keying the retry budget on the name makes
/// wrong-password attempts on one same-named config burn the other's cap. The
/// caller (`status_handler`) threads the path and keeps the name only for
/// human-readable notification text. An empty path must never reach here — the
/// caller gates retry on `!config_path.is_empty()`, and an empty key would
/// become a shared bucket across all un-keyed failures.
///
/// Pure bookkeeping over the supplied `state` map, with `now` injected so the
/// window-reset branch is unit-testable without sleeping. Behaviour:
/// - a brand-new config starts at count 1;
/// - a repeat failure within `AUTH_RETRY_WINDOW_SECS` increments;
/// - a failure more than the window after the previous one resets to 1.
///
/// The returned count is **not** capped here — callers compare it against
/// [`MAX_CREDENTIAL_ATTEMPTS`] to decide whether to retry or disconnect. The
/// cap lives at the call site, not in this function.
pub(crate) fn next_attempt(
    state: &mut HashMap<String, AuthAttempt>,
    now: std::time::Instant,
    config_id: &str,
) -> u32 {
    debug_assert!(
        !config_id.is_empty(),
        "next_attempt key must be a non-empty config path, never empty"
    );
    let entry = state.entry(config_id.to_string()).or_insert(AuthAttempt {
        count: 0,
        last_failure: now,
    });
    // Reset counter if the previous failure was too long ago.
    if now.saturating_duration_since(entry.last_failure).as_secs() > AUTH_RETRY_WINDOW_SECS {
        entry.count = 0;
    }
    entry.count += 1;
    entry.last_failure = now;
    entry.count
}

/// Pure retry decision for an auth failure: retry while under the attempt cap
/// and a config path exists to reconnect to.
///
/// Extracted from `handle_auth_failed` (which previously inlined this as
/// `attempt < MAX_CREDENTIAL_ATTEMPTS && !config_path.is_empty()`) so the gate
/// is single-source and unit-testable in isolation. Two ways it answers false:
/// - `attempt >= MAX_CREDENTIAL_ATTEMPTS` — the per-config budget is spent;
/// - `config_path` is empty — the session already left the tray, so there is
///   nothing to reconnect to. A first failure with no path must still
///   disconnect (the empty-path branch of the status-handler glue returns
///   [`MAX_CREDENTIAL_ATTEMPTS`], so this is belt-and-braces, not load-bearing).
pub(crate) fn should_retry_auth(attempt: u32, config_path: &str) -> bool {
    attempt < MAX_CREDENTIAL_ATTEMPTS && !config_path.is_empty()
}

#[cfg(test)]
mod tests {
    use super::{
        AUTH_RETRY_WINDOW_SECS, AuthAttempt, MAX_CREDENTIAL_ATTEMPTS, next_attempt,
        should_retry_auth,
    };
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    #[test]
    fn fresh_config_starts_at_one() {
        let mut state: HashMap<String, AuthAttempt> = HashMap::new();
        let now = Instant::now();
        assert_eq!(next_attempt(&mut state, now, "vpn-a"), 1);
    }

    #[test]
    fn repeated_failures_within_window_increment() {
        let mut state: HashMap<String, AuthAttempt> = HashMap::new();
        let t0 = Instant::now();
        assert_eq!(next_attempt(&mut state, t0, "vpn-a"), 1);
        // 10s later — well inside the window.
        let t1 = t0 + Duration::from_secs(10);
        assert_eq!(next_attempt(&mut state, t1, "vpn-a"), 2);
        let t2 = t1 + Duration::from_secs(10);
        assert_eq!(next_attempt(&mut state, t2, "vpn-a"), 3);
    }

    #[test]
    fn counter_keeps_climbing_past_cap_gate_lives_in_caller() {
        // next_attempt itself does NOT cap — it keeps incrementing. The
        // MAX_CREDENTIAL_ATTEMPTS gate is the caller's job. This pins that
        // contract so a future "helpful" cap inside next_attempt is caught.
        let mut state: HashMap<String, AuthAttempt> = HashMap::new();
        let mut t = Instant::now();
        for expected in 1..=(MAX_CREDENTIAL_ATTEMPTS + 1) {
            assert_eq!(next_attempt(&mut state, t, "vpn-a"), expected);
            t += Duration::from_secs(5);
        }
    }

    #[test]
    fn failure_after_window_resets_to_one() {
        let mut state: HashMap<String, AuthAttempt> = HashMap::new();
        let t0 = Instant::now();
        assert_eq!(next_attempt(&mut state, t0, "vpn-a"), 1);
        assert_eq!(
            next_attempt(&mut state, t0 + Duration::from_secs(10), "vpn-a"),
            2
        );
        // One second past the window since the last failure → reset.
        let stale = t0 + Duration::from_secs(10 + AUTH_RETRY_WINDOW_SECS + 1);
        assert_eq!(next_attempt(&mut state, stale, "vpn-a"), 1);
    }

    #[test]
    fn exactly_at_window_boundary_does_not_reset() {
        // Reset is strict `>`, so a failure exactly AUTH_RETRY_WINDOW_SECS after
        // the previous one still counts as within the window and increments.
        let mut state: HashMap<String, AuthAttempt> = HashMap::new();
        let t0 = Instant::now();
        assert_eq!(next_attempt(&mut state, t0, "vpn-a"), 1);
        let boundary = t0 + Duration::from_secs(AUTH_RETRY_WINDOW_SECS);
        assert_eq!(next_attempt(&mut state, boundary, "vpn-a"), 2);
    }

    #[test]
    fn distinct_configs_count_independently() {
        let mut state: HashMap<String, AuthAttempt> = HashMap::new();
        let t = Instant::now();
        assert_eq!(next_attempt(&mut state, t, "vpn-a"), 1);
        assert_eq!(next_attempt(&mut state, t, "vpn-b"), 1);
        assert_eq!(next_attempt(&mut state, t, "vpn-a"), 2);
        assert_eq!(next_attempt(&mut state, t, "vpn-b"), 2);
    }

    // Regression guard for the dup-name bug (#2 class): two configs can share
    // a display NAME but have distinct object PATHS. The caller now threads the
    // path as `config_id`, so failures on one same-named config must NOT burn
    // the other's retry budget. This test would fail under the old name-keyed
    // scheme only if it modelled the names colliding; here it pins the contract
    // by using distinct path-shaped keys that a shared name could not tell apart.
    #[test]
    fn same_name_different_path_budgets_isolate() {
        let mut state: HashMap<String, AuthAttempt> = HashMap::new();
        let t = Instant::now();
        // Two configs both displayed as "vpn-a" but distinct paths:
        let path_a = "/net/openvpn/v3/configuration/a1";
        let path_b = "/net/openvpn/v3/configuration/b2";
        assert_eq!(next_attempt(&mut state, t, path_a), 1);
        assert_eq!(next_attempt(&mut state, t, path_a), 2);
        // Failure on the sibling must start fresh — name-collision must not leak.
        assert_eq!(next_attempt(&mut state, t, path_b), 1);
        assert_eq!(next_attempt(&mut state, t, path_a), 3);
    }

    // S37-T2: a manual Disconnect (or Remove) clears the config's budget entry,
    // so a reconnect within the 5-min window starts fresh at 1, not at the
    // count the abandoned session reached. Models the clear sites in
    // actions.rs (Disconnect, RemoveConfig) and status_handler (lockout,
    // connect-success) — all do `state.remove(&config_path)`.
    #[test]
    fn remove_key_resets_budget_within_window() {
        let mut state: HashMap<String, AuthAttempt> = HashMap::new();
        let t0 = Instant::now();
        // Two failures, 10s apart — well inside the window.
        assert_eq!(
            next_attempt(&mut state, t0, "/net/openvpn/v3/configuration/a1"),
            1
        );
        assert_eq!(
            next_attempt(
                &mut state,
                t0 + Duration::from_secs(10),
                "/net/openvpn/v3/configuration/a1"
            ),
            2
        );
        // User disconnects → clear (as actions.rs does). Without this, a
        // reconnect 20s in would hit attempt 3 (instant lockout).
        state.remove("/net/openvpn/v3/configuration/a1");
        // Reconnect 20s after the second failure — still inside the window, but
        // the entry is gone, so next_attempt sees a brand-new config (count 1).
        assert_eq!(
            next_attempt(
                &mut state,
                t0 + Duration::from_secs(30),
                "/net/openvpn/v3/configuration/a1"
            ),
            1
        );
    }

    #[test]
    fn retry_while_under_cap_with_a_path() {
        // The happy retry case: first/second failure with a known config path.
        assert!(should_retry_auth(0, "/net/openvpn/v3/configuration/a1"));
        assert!(should_retry_auth(1, "/net/openvpn/v3/configuration/a1"));
        // MAX_CREDENTIAL_ATTEMPTS-1 is the last retryable attempt (count is
        // 1-based; next_attempt returns MAX at the third failure, which must
        // NOT retry).
        assert!(should_retry_auth(
            MAX_CREDENTIAL_ATTEMPTS - 1,
            "/net/openvpn/v3/configuration/a1"
        ));
    }

    #[test]
    fn no_retry_once_cap_reached() {
        // At and over the cap → disconnect, even with a valid path. Pins the
        // boundary so an off-by-one (using <=) would fail here.
        assert!(!should_retry_auth(
            MAX_CREDENTIAL_ATTEMPTS,
            "/net/openvpn/v3/configuration/a1"
        ));
        assert!(!should_retry_auth(
            MAX_CREDENTIAL_ATTEMPTS + 5,
            "/net/openvpn/v3/configuration/a1"
        ));
    }

    #[test]
    fn no_retry_without_a_config_path() {
        // Empty path → nothing to reconnect to. Even a first failure (attempt
        // 1, well under cap) must disconnect: the session already left the
        // tray, so connect_to_config has no target.
        assert!(!should_retry_auth(1, ""));
        assert!(!should_retry_auth(0, ""));
    }

    #[test]
    fn retry_decision_ignores_display_name_collisions() {
        // The decision keys off the path, not the name — but should_retry_auth
        // itself only checks emptiness, so two distinct paths both retry
        // independently. (Name-vs-path keying is enforced inside next_attempt;
        // this test pins that the gate doesn't second-guess it.)
        assert!(should_retry_auth(1, "/net/openvpn/v3/configuration/a1"));
        assert!(should_retry_auth(1, "/net/openvpn/v3/configuration/a2"));
    }
}
