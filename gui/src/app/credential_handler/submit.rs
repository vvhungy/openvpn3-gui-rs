//! Credential submit path — push values to the D-Bus input queue, then act on
//! the outcome.
//!
//! Split out of `mod` so the dialog-construction side stays separate from the
//! submit/outcome side. [`submit_credentials`] is the D-Bus write;
//! [`handle_submit_outcome`] is the three-way branch on its result (persist /
//! re-show prefilled / re-dispatch or notify), which loops back into
//! [`super::show_credentials_with_slots`] on the partial-input path.

use std::collections::HashMap;
use std::rc::Rc;

use tracing::{error, info};
use zbus::zvariant::OwnedObjectPath;

use crate::dbus::session::SessionProxy;

use super::keyring::{delete_remembered_credentials, save_remembered_credentials};
use super::show_credentials_with_slots;

/// Resources captured by the credentials-dialog submit callback, bundled so the
/// outcome handler receives them as one value (and stays under the argument-count
/// lint). All owned; moved into whichever submit branch consumes them.
pub(super) struct SubmitContext {
    pub(super) dbus: zbus::Connection,
    pub(super) session_path: String,
    pub(super) config_path: String,
    pub(super) config_name: String,
    pub(super) cred_key: String,
    pub(super) slots: Vec<(u32, u32, u32, String, bool)>,
    pub(super) prev_snapshot: Rc<HashMap<String, String>>,
}

/// Act on the outcome of submitting credentials to D-Bus.
///
/// Extracted from the credentials-dialog submit callback so its three-way
/// `match` — all-provided (persist) / partial (re-show prefilled) / error
/// (re-dispatch or notify) — is isolated from the callback's value-capture
/// plumbing, which reduced the callback to a single delegated call. Impure
/// async glue — no unit surface.
pub(super) async fn handle_submit_outcome(
    outcome: anyhow::Result<bool>,
    values: Vec<(String, String)>,
    remember: bool,
    ctx: SubmitContext,
) {
    match outcome {
        Ok(true) => {
            // All slots provided and Connect() sent — counter is cleared by
            // status_handler when is_connected() fires. Persist only storable
            // credentials (username/password, not OTP).
            let store = crate::credentials::CredentialStore::default();
            if remember {
                save_remembered_credentials(&values, &ctx.slots, &ctx.cred_key, &store).await;
            } else {
                delete_remembered_credentials(&values, &ctx.slots, &ctx.cred_key, &store).await;
            }
        }
        Ok(false) => {
            // Some fields left empty — no slots were consumed, so re-show the
            // same dialog with pre-filled values.
            let merged: HashMap<String, String> = (*ctx.prev_snapshot)
                .clone()
                .into_iter()
                .chain(values.into_iter().filter(|(_, v)| !v.is_empty()))
                .collect();

            show_credentials_with_slots(
                ctx.dbus,
                ctx.session_path,
                ctx.config_path,
                ctx.config_name,
                &ctx.slots,
                &merged,
            );
        }
        Err(e) => {
            let err_str = format!("{}", e);
            if err_str.contains("User input not required") {
                info!(
                    "Session '{}' queue reset, re-dispatching credentials",
                    ctx.config_name
                );
                super::request_credentials(
                    &ctx.dbus,
                    &ctx.session_path,
                    &ctx.config_path,
                    &ctx.config_name,
                    Default::default(),
                )
                .await;
            } else {
                error!("Failed to submit credentials: {}", e);
                crate::dialogs::show_error_notification(
                    "Authentication Failed",
                    &format!("Server rejected credentials for '{}'.", ctx.config_name),
                );
            }
        }
    }
}

/// Replace control characters in a peer-controlled string before logging it
/// (#10 / T7, defense-in-depth). Slot labels and error messages come from the
/// D-Bus queue / daemon reply; a `\n`-bearing label would otherwise forge a
/// fresh log line. C0 controls → `?`; tabs/spaces kept verbatim so the value
/// stays readable.
fn sanitize_for_log(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() && c != ' ' { '?' } else { c })
        .collect()
}

/// Submit credentials to all input slots by matching labels, then call Ready() + Connect().
/// Returns `Ok(true)` if all slots were provided and connection started.
/// Returns `Ok(false)` if some slots were skipped (empty values) — caller should re-show dialog.
pub(super) async fn submit_credentials(
    dbus: &zbus::Connection,
    session_path: &str,
    slots: &[(u32, u32, u32, String, bool)],
    values: &[(String, String)],
) -> anyhow::Result<bool> {
    let session_path_obj = OwnedObjectPath::try_from(session_path)?;
    let session = SessionProxy::builder(dbus)
        .path(session_path_obj)?
        .build()
        .await?;

    // Check if all fields are filled before consuming any slots.
    // If any field is empty, return early — no slots are consumed,
    // so the dialog can safely re-show with the same (still-valid) slots.
    let any_skipped = slots.iter().any(|(_, _, _, label, _)| {
        values
            .iter()
            .find(|(l, _)| l == label)
            .map(|(_, v)| v.is_empty())
            .unwrap_or(true)
    });
    if any_skipped {
        return Ok(false);
    }

    // All fields filled — provide values to each slot.
    for (att_type, group, id, label, _mask) in slots {
        let value = values
            .iter()
            .find(|(l, _)| l == label)
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        match session
            .UserInputProvide(*att_type, *group, *id, value)
            .await
        {
            Ok(()) => {
                info!(
                    "Provided input for slot '{}' on session {}",
                    sanitize_for_log(label),
                    session_path
                );
            }
            Err(e) => {
                // Match on the structured D-Bus error, not a re-formatted Display
                // (#10 / T7): formatting the whole error and substring-matching it
                // could swallow an unrelated error whose Display happens to contain
                // the phrase. Only genuine `MethodError`s from the daemon are
                // inspected, and we read the structured `detail` arg. Anything else
                // is a real failure → propagate.
                if let zbus::Error::MethodError(_name, detail, _reply) = &e {
                    let d = detail.as_deref().unwrap_or("");
                    if d.contains("already-provided") {
                        info!(
                            "Slot '{}' already provided, skipping",
                            sanitize_for_log(label)
                        );
                        continue;
                    } else if d.contains("User input not required") {
                        info!(
                            "Slot '{}' — session queue reset, aborting",
                            sanitize_for_log(label)
                        );
                        anyhow::bail!("User input not required");
                    }
                }
                return Err(e.into());
            }
        }
    }

    if any_skipped {
        // Not all slots filled — caller should re-show dialog for remaining slots
        return Ok(false);
    }

    // All slots provided — try to connect
    match session.Ready().await {
        Ok(()) => {
            session.Connect().await?;
            info!("Session connected after credentials: {}", session_path);
            Ok(true)
        }
        Err(e) => {
            // May need dynamic challenge — the StatusChange handler will dispatch
            info!(
                "Session still not ready after credentials (may need more input): {}",
                e
            );
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_for_log;

    #[test]
    fn sanitize_for_log_strips_newlines_and_controls() {
        // A peer-controlled label bearing a newline must not forge a log line.
        assert_eq!(
            sanitize_for_log("username\r\n[ERROR] forged"),
            "username??[ERROR] forged"
        );
        assert_eq!(sanitize_for_log("a\tb"), "a?b");
        assert_eq!(sanitize_for_log("normal label"), "normal label");
        // Non-control, non-ASCII stays readable.
        assert_eq!(sanitize_for_log("café"), "café");
    }
}
