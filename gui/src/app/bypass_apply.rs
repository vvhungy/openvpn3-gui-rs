//! Shared post-apply tray + notification handling for `apply_bypass_routes`.
//!
//! Three sites call the helper to install bypass routes (cold-start re-apply,
//! mid-session preferences toggle, status-change connect glue). Each must:
//!   1. translate the `Option<BypassApplyOutcome>` to a `BypassState`,
//!   2. update the tray,
//!   3. fire the matching notification (success / partial / system-fail).
//!
//! Centralising the mapping keeps tray label, notification, and log line in
//! sync across call sites.

use tracing::{info, warn};

use crate::dbus::killswitch::BypassApplyOutcome;
use crate::tray::{BypassState, VpnTray};

/// Map a bypass-apply outcome to the tray state.
///
/// Pure mapping extracted so the three-state logic (`None` ⇒ system-wide
/// failure; all-applied ⇒ `Active` with zero failures; partial ⇒ `Active`
/// with the failure count) is unit-testable without a tray/notification
/// harness. The applied/failed counts flow from the same `BypassApplyOutcome`
/// the impure wrapper uses for its notification, so the tray label and the
/// notification can't drift apart.
fn outcome_to_state(outcome: &Option<BypassApplyOutcome>) -> BypassState {
    match outcome {
        None => BypassState::Failed,
        Some(out) if out.failed.is_empty() => BypassState::Active {
            applied: out.applied.len(),
            failed: 0,
        },
        Some(out) => BypassState::Active {
            applied: out.applied.len(),
            failed: out.failed.len(),
        },
    }
}

/// Update tray + send the matching notification for a bypass-apply outcome.
///
/// `context` is a short string logged on failure paths so the journal shows
/// which call site reported (e.g. "startup re-apply", "preferences toggle").
pub(crate) fn apply_bypass_outcome_to_tray(
    tray: &ksni::blocking::Handle<VpnTray>,
    outcome: Option<BypassApplyOutcome>,
    context: &str,
) {
    // Compute the tray state once via the pure mapping; the match below only
    // owns the side effects (notification + log line).
    let state = outcome_to_state(&outcome);
    match outcome {
        Some(out) if out.failed.is_empty() => {
            let applied = out.applied.len();
            tray.update(move |t| {
                t.bypass_state = state;
            });
            info!(applied, context, "bypass routing: all applied");
            crate::dialogs::show_bypass_active_notification(applied);
        }
        Some(out) => {
            let applied = out.applied.len();
            let failed_count = out.failed.len();
            tray.update(move |t| {
                t.bypass_state = state;
            });
            warn!(
                applied,
                failed = failed_count,
                context,
                "bypass routing: partial apply"
            );
            crate::dialogs::show_bypass_partial_notification(applied, out.failed);
        }
        None => {
            tray.update(move |t| t.bypass_state = state);
            warn!(context, "bypass routing: system-wide apply failed");
            crate::dialogs::show_bypass_failed_notification();
        }
    }
}

/// Push `cidrs` to the helper and install bypass routing, then reflect the
/// outcome on the tray + fire the matching notification. Consolidates the
/// set→apply→outcome sequence that was copy-pasted across the apply sites
/// (cold-start re-apply, preferences toggle, session-connect glue) — D1.
///
/// `context` labels the failure log/notification so the source call site is
/// identifiable. No-op when `cidrs` is empty: a toggle-OFF (preferences) does
/// its own remove+clear and must not route through here.
pub(crate) async fn apply_bypass(
    tray: &ksni::blocking::Handle<VpnTray>,
    cidrs: Vec<String>,
    context: &str,
) {
    if cidrs.is_empty() {
        return;
    }
    // Gate ApplyBypassRoutes on SetBypassCidrs success — if validation rejects
    // the list the helper retains its prior state and applying would install
    // routes for the wrong CIDRs.
    let set_ok = crate::dbus::killswitch::set_bypass_cidrs(cidrs).await;
    let outcome = if set_ok {
        crate::dbus::killswitch::apply_bypass_routes().await
    } else {
        None
    };
    apply_bypass_outcome_to_tray(tray, outcome, context);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(applied: &[&str], failed: &[&[&str; 2]]) -> BypassApplyOutcome {
        BypassApplyOutcome {
            applied: applied.iter().map(|s| s.to_string()).collect(),
            failed: failed
                .iter()
                .map(|pair| (pair[0].to_string(), pair[1].to_string()))
                .collect(),
        }
    }

    #[test]
    fn none_outcome_maps_to_failed_state() {
        assert!(matches!(outcome_to_state(&None), BypassState::Failed));
    }

    #[test]
    fn all_applied_maps_to_active_with_zero_failed() {
        let out = outcome(&["10.0.0.0/8", "192.168.1.0/24"], &[]);
        match outcome_to_state(&Some(out)) {
            BypassState::Active { applied, failed } => {
                assert_eq!(applied, 2);
                assert_eq!(failed, 0);
            }
            other => panic!("expected Active, got {other:?}"),
        }
    }

    #[test]
    fn partial_maps_to_active_with_failure_count() {
        let out = outcome(&["10.0.0.0/8"], &[&["fe80::/64", "rt-table unreachable"]]);
        match outcome_to_state(&Some(out)) {
            BypassState::Active { applied, failed } => {
                assert_eq!(applied, 1);
                assert_eq!(failed, 1);
            }
            other => panic!("expected Active, got {other:?}"),
        }
    }

    #[test]
    fn partial_with_multiple_failures_preserves_exact_count() {
        // Guards against a future coercion (e.g. capping at 1) on the failure
        // count the tray label surfaces.
        let out = outcome(
            &["10.0.0.0/8"],
            &[
                &["fe80::/64", "rt-table unreachable"],
                &["2001:db8::/32", "permission denied"],
            ],
        );
        match outcome_to_state(&Some(out)) {
            BypassState::Active { applied, failed } => {
                assert_eq!(applied, 1);
                assert_eq!(failed, 2);
            }
            other => panic!("expected Active, got {other:?}"),
        }
    }

    #[test]
    fn empty_applied_with_no_failures_still_active_zero() {
        // Edge: helper returned applied=∅, failed=∅ (e.g. nothing to apply).
        let out = outcome(&[], &[]);
        assert!(matches!(
            outcome_to_state(&Some(out)),
            BypassState::Active {
                applied: 0,
                failed: 0
            }
        ));
    }
}
