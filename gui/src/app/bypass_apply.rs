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

/// Update tray + send the matching notification for a bypass-apply outcome.
///
/// `context` is a short string logged on failure paths so the journal shows
/// which call site reported (e.g. "startup re-apply", "preferences toggle").
pub(crate) fn apply_bypass_outcome_to_tray(
    tray: &ksni::blocking::Handle<VpnTray>,
    outcome: Option<BypassApplyOutcome>,
    context: &str,
) {
    match outcome {
        Some(out) if out.failed.is_empty() => {
            let applied = out.applied.len();
            tray.update(move |t| {
                t.bypass_state = BypassState::Active { applied, failed: 0 };
            });
            info!(applied, context, "bypass routing: all applied");
            crate::dialogs::show_bypass_active_notification(applied);
        }
        Some(out) => {
            let applied = out.applied.len();
            let failed_count = out.failed.len();
            tray.update(move |t| {
                t.bypass_state = BypassState::Active {
                    applied,
                    failed: failed_count,
                };
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
            tray.update(|t| t.bypass_state = BypassState::Failed);
            warn!(context, "bypass routing: system-wide apply failed");
            crate::dialogs::show_bypass_failed_notification();
        }
    }
}
