//! Bypass drift state machine: pure transitions for the stats poller.
//!
//! Once per stats cycle the poller verifies the live nft bypass sets still
//! hold the desired CIDR list. These pure helpers decide the resulting
//! `BypassState`; the tray mutation stays at the call site in `mod.rs`.

/// True when bypass is in a live, verifiable state (`Active` or `Drifted`).
/// Drift detection and recovery run only while live — `Off`/`Failed` have no
/// nft set to reconcile. Extracted so the gate is unit-testable.
pub(super) fn bypass_is_live(state: &crate::tray::BypassState) -> bool {
    matches!(
        state,
        crate::tray::BypassState::Active { .. } | crate::tray::BypassState::Drifted { .. }
    )
}

/// Recovery transition: a `Drifted` state whose live sets now match the desired
/// set restores the pre-drift apply counts as `Active` (not a fabricated
/// full-success Active — drift verifies set membership, a different measure than
/// route apply-outcome). Returns the restored `Active` state, or `None` if not
/// currently `Drifted`. Pure; the tray mutation stays at the call site.
pub(super) fn recover_from_drift(
    state: &crate::tray::BypassState,
) -> Option<crate::tray::BypassState> {
    use crate::tray::BypassState;
    if let BypassState::Drifted {
        prev_applied,
        prev_failed,
        ..
    } = state
    {
        Some(BypassState::Active {
            applied: *prev_applied,
            failed: *prev_failed,
        })
    } else {
        None
    }
}

/// Drift transition from a live state into `Drifted` with the current
/// missing/extra counts, preserving pre-drift apply counts for faithful
/// recovery. Returns `Some((new_state, should_notify))`:
/// - `Active` → `Drifted` (new drift): notify.
/// - `Drifted` → `Drifted`: re-notify only if missing/extra changed since the
///   last poll (a persistent drift must not re-fire the toast every ~30s).
/// - `Off`/`Failed`: `None` — the captured `bypass_live` gate is stale (a
///   disconnect/split-tunnel toggle during the verify await moved bypass off the
///   live path); drop the report so we never resurrect a torn-down kill-switch.
///
/// Pure; the tray mutation stays at the call site.
pub(super) fn drift_transition(
    state: &crate::tray::BypassState,
    missing: usize,
    extra: usize,
) -> Option<(crate::tray::BypassState, bool)> {
    use crate::tray::BypassState;
    match state {
        BypassState::Active { applied, failed } => Some((
            BypassState::Drifted {
                missing,
                extra,
                prev_applied: *applied,
                prev_failed: *failed,
            },
            true,
        )),
        BypassState::Drifted {
            missing: prev_missing,
            extra: prev_extra,
            prev_applied,
            prev_failed,
        } => {
            let changed = *prev_missing != missing || *prev_extra != extra;
            Some((
                BypassState::Drifted {
                    missing,
                    extra,
                    prev_applied: *prev_applied,
                    prev_failed: *prev_failed,
                },
                changed,
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bypass_is_live_true_for_active_and_drifted() {
        use crate::tray::BypassState;
        assert!(bypass_is_live(&BypassState::Active {
            applied: 3,
            failed: 1
        }));
        assert!(bypass_is_live(&BypassState::Drifted {
            missing: 1,
            extra: 0,
            prev_applied: 3,
            prev_failed: 1
        }));
    }

    #[test]
    fn bypass_is_live_false_for_off_and_failed() {
        use crate::tray::BypassState;
        assert!(!bypass_is_live(&BypassState::Off));
        assert!(!bypass_is_live(&BypassState::Failed));
    }

    #[test]
    fn recover_from_drift_restores_prev_counts_as_active() {
        use crate::tray::BypassState;
        let d = BypassState::Drifted {
            missing: 2,
            extra: 1,
            prev_applied: 5,
            prev_failed: 2,
        };
        assert!(matches!(
            recover_from_drift(&d),
            Some(BypassState::Active {
                applied: 5,
                failed: 2
            })
        ));
    }

    #[test]
    fn recover_from_drift_none_when_not_drifted() {
        use crate::tray::BypassState;
        assert!(
            recover_from_drift(&BypassState::Active {
                applied: 1,
                failed: 0
            })
            .is_none()
        );
        assert!(recover_from_drift(&BypassState::Off).is_none());
    }

    #[test]
    fn drift_transition_active_to_drifted_notifies() {
        use crate::tray::BypassState;
        let active = BypassState::Active {
            applied: 4,
            failed: 1,
        };
        let (new, notify) = drift_transition(&active, 2, 0).unwrap();
        assert!(matches!(
            new,
            BypassState::Drifted {
                missing: 2,
                extra: 0,
                prev_applied: 4,
                prev_failed: 1
            }
        ));
        assert!(notify, "first drift must notify");
    }

    #[test]
    fn drift_transition_drifted_unchanged_dims_no_notify() {
        use crate::tray::BypassState;
        let drifted = BypassState::Drifted {
            missing: 2,
            extra: 0,
            prev_applied: 4,
            prev_failed: 1,
        };
        let (new, notify) = drift_transition(&drifted, 2, 0).unwrap();
        assert!(matches!(
            new,
            BypassState::Drifted {
                missing: 2,
                extra: 0,
                prev_applied: 4,
                prev_failed: 1
            }
        ));
        assert!(!notify, "unchanged drift dims must not re-notify");
    }

    #[test]
    fn drift_transition_drifted_changed_dims_notifies() {
        use crate::tray::BypassState;
        let drifted = BypassState::Drifted {
            missing: 2,
            extra: 0,
            prev_applied: 4,
            prev_failed: 1,
        };
        let (new, notify) = drift_transition(&drifted, 3, 1).unwrap();
        assert!(matches!(
            new,
            BypassState::Drifted {
                missing: 3,
                extra: 1,
                prev_applied: 4,
                prev_failed: 1
            }
        ));
        assert!(notify);
    }

    #[test]
    fn drift_transition_off_is_stale_gate() {
        use crate::tray::BypassState;
        assert!(drift_transition(&BypassState::Off, 1, 0).is_none());
        assert!(drift_transition(&BypassState::Failed, 1, 0).is_none());
    }
}
