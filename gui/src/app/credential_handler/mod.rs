//! Username / password credential request flow
//!
//! Orchestration + dialog construction. The pure auth-failure counter and its
//! unit tests live in [`retry`], re-exported here so existing
//! `credential_handler::next_attempt` / `CREDENTIAL_ATTEMPTS` /
//! `MAX_CREDENTIAL_ATTEMPTS` call paths stay valid. Label-mapping /
//! storability helpers live in `crate::credentials::policy` with their own
//! unit tests.
//!
//! Sibling modules own the two halves this one dispatches to:
//! - [`keyring`] — open/unlock, read-back, persist (secret-store side).
//! - [`submit`] — push values to the D-Bus input queue and act on the outcome.

mod keyring;
mod retry;
mod slots;
mod submit;

pub(crate) use retry::{
    CREDENTIAL_ATTEMPTS, MAX_CREDENTIAL_ATTEMPTS, active_attempt_total, next_attempt,
    should_retry_auth, should_retry_auth_globally,
};

use std::collections::HashMap;
use std::rc::Rc;

use glib::object::Cast;
use tracing::{error, info, warn};
use zbus::zvariant::OwnedObjectPath;

use crate::credentials::policy::{display_label_for, is_storable_field};
use crate::dbus::session::SessionProxy;
use crate::dbus::types::ClientAttentionType;

use keyring::{open_and_unlock_keyring, resolve_keyring_values};
use submit::{SubmitContext, handle_submit_outcome, submit_credentials};

// Pure label/slot logic (STANDARD_FIELDS, build_labels_to_try, slot_mask,
// label_matches_category, keyring_label_variants) + its unit tests live in the
// `slots` sibling module.
use slots::{STANDARD_FIELDS, build_labels_to_try, label_matches_category};

/// Fetch credential input slots from D-Bus and show the credentials dialog.
///
/// This queries the D-Bus queue **once** to discover slots, then delegates to
/// `show_credentials_with_slots` for the dialog loop (which never re-queries).
///
/// `prefilled` carries previously entered values (e.g. after an `invalid-input`
/// retry) so the user doesn't have to re-type everything.
pub(crate) async fn request_credentials(
    dbus: &zbus::Connection,
    session_path: &str,
    config_path: &str,
    config_name: &str,
    prefilled: HashMap<String, String>,
) {
    let dbus = dbus.clone();
    let session_path = session_path.to_string();
    let config_path = config_path.to_string();
    let config_name = config_name.to_string();

    let Some(session) = build_session_proxy(&dbus, &session_path).await else {
        return;
    };

    // Fetch credential slots from the session — ONLY done once here
    let type_groups = match session.UserInputQueueGetTypeGroup().await {
        Ok(tg) => tg,
        Err(e) => {
            error!("Failed to get input type groups: {}", e);
            return;
        }
    };

    // Collect all credential slots: (type, group, id, label, mask)
    let slots = collect_credential_slots(&session, &type_groups).await;

    if slots.is_empty() {
        warn!(
            "No credential slots found for session {} — showing standard fields",
            session_path
        );
    }

    info!(
        "Found {} credential slots for session {}",
        slots.len(),
        session_path,
    );

    // Resolve keyring values in async context before entering the sync dialog loop.
    // Prefilled values (from a previous attempt) take priority over keyring values.
    // Resolve for actual queue slots, standard field labels, AND common label
    // variants (OpenVPN3 servers use varying labels like "Username" vs
    // "Enter username" — all map to the same keyring attribute).
    //
    // Key the store on the unique config PATH (#2 fix) — not the display name,
    // which two configs may share. config_name is passed to get_with_keyring
    // solely as the legacy key for the read-on-miss migration.
    let cred_key = config_path.clone();
    let cred_store = crate::credentials::CredentialStore::default();
    let mut resolved = prefilled;
    let labels_to_try = build_labels_to_try(&slots);

    // Open ONE keyring handle for the whole resolution and unlock it once.
    // Previously each get_async opened its own Keyring::new() — N labels meant
    // N opens, and none shared unlock state, so a locked collection left every
    // field blank with no signal. Unlock before the loop so the system prompt
    // fires before our dialog, not under it.
    let keyring = open_and_unlock_keyring().await;

    // Read against the single unlocked handle. Classify the outcome instead
    // of the old `.ok().flatten()`, which conflated *locked/error* with
    // *absent* and silently blanked fields.
    resolve_keyring_values(
        &labels_to_try,
        &slots,
        keyring.as_ref(),
        &cred_store,
        &cred_key,
        &config_name,
        &mut resolved,
    )
    .await;

    // Delegate to the dialog loop — never re-queries D-Bus or keyring
    show_credentials_with_slots(
        dbus,
        session_path,
        config_path,
        config_name,
        &slots,
        &resolved,
    );
}

/// Build the session proxy for `session_path`, logging and returning `None`
/// on any of the three setup failures (bad path, path-set, build).
///
/// Extracted from `request_credentials` so the nested error-guards reduce to a
/// single `let-else` at the call site. Flattens the two-level `path`/`build`
/// match into independent steps. Impure async glue — no unit surface.
async fn build_session_proxy<'a>(
    dbus: &'a zbus::Connection,
    session_path: &str,
) -> Option<SessionProxy<'a>> {
    let path_obj = match OwnedObjectPath::try_from(session_path) {
        Ok(p) => p,
        Err(e) => {
            error!("Invalid session path: {}", e);
            return None;
        }
    };
    match SessionProxy::builder(dbus).path(path_obj) {
        Ok(builder) => match builder.build().await {
            Ok(s) => Some(s),
            Err(e) => {
                error!("Failed to create session proxy: {}", e);
                None
            }
        },
        Err(e) => {
            error!("Failed to set session path: {}", e);
            None
        }
    }
}

/// Collect credential-type slots `(type, group, id, label, mask)` from the
/// D-Bus input queue.
///
/// Extracted from `request_credentials`'s nested loop. Only the `Credentials`
/// attention type is fetched; non-credential types and fetch errors are skipped
/// (they have no field to show). Impure async glue — no unit surface.
async fn collect_credential_slots(
    session: &SessionProxy<'_>,
    type_groups: &[(u32, u32)],
) -> Vec<(u32, u32, u32, String, bool)> {
    let mut slots: Vec<(u32, u32, u32, String, bool)> = Vec::new();
    for (att_type, group) in type_groups {
        if *att_type != ClientAttentionType::Credentials as u32 {
            continue;
        }
        let Ok(ids) = session.UserInputQueueCheck(*att_type, *group).await else {
            continue;
        };
        for id in ids {
            if let Ok((_t, _g, _i, label, _desc, mask)) =
                session.UserInputQueueFetch(*att_type, *group, id).await
            {
                slots.push((*att_type, *group, id, label, mask));
            }
        }
    }
    slots
}

/// Show the credentials dialog with a **pre-built** slot list.
///
/// On `Ok(false)` (some fields left empty), re-shows the same dialog with
/// pre-filled values. Safe because `submit_credentials` returns `Ok(false)`
/// *before* consuming any slots.
fn show_credentials_with_slots(
    dbus: zbus::Connection,
    session_path: String,
    config_path: String,
    config_name: String,
    slots: &[(u32, u32, u32, String, bool)],
    prefilled: &HashMap<String, String>,
) {
    // Key the credential store on the config's unique D-Bus PATH, not its
    // display name: two configs may share a name (verified real-device, S35
    // T1), and keying by name would cross-wipe. `config_name` is kept as the
    // legacy key for the read-on-miss migration from pre-0.3.11 stores.
    let cred_key = config_path.clone();

    // Build dialog fields: always show all 3 standard fields so the user
    // sees a consistent UI regardless of which slots are currently in the
    // D-Bus queue. Fields that have a matching queue slot will be submitted;
    // others are silently ignored.
    let mut fields = Vec::new();
    for (standard_label, standard_mask) in &STANDARD_FIELDS {
        // Check if a real queue slot exists whose label matches this category
        let matching_slot = slots.iter().find(|(_, _, _, label, _)| {
            let lower = label.to_lowercase();
            match *standard_label {
                "Username" => lower.contains("username"),
                "Password" => lower.contains("password"),
                _ => !lower.contains("username") && !lower.contains("password"),
            }
        });
        let (label, mask, key) = match matching_slot {
            Some((_att_type, _group, _id, slot_label, slot_mask)) => {
                (slot_label.clone(), *slot_mask, slot_label.clone())
            }
            None => (
                standard_label.to_string(),
                *standard_mask,
                standard_label.to_string(),
            ),
        };
        let saved = prefilled.get(&key).cloned().or_else(|| {
            // Fallback: keyring may have stored under a different label
            // variant that still matches this field category (e.g.
            // "Enter username" → Username field).
            prefilled
                .iter()
                .find(|(k, _)| label_matches_category(k, standard_label))
                .map(|(_, v)| v.clone())
        });
        fields.push(crate::dialogs::CredentialField {
            key,
            label: display_label_for(&label),
            masked: mask,
            can_store: is_storable_field(&label, mask),
            saved_value: saved,
        });
    }

    // Build cancel handler — disconnects session
    let cancel_dbus = dbus.clone();
    let cancel_sp = session_path.clone();
    let cancel_cn = config_name.clone();
    let on_cancel = move || {
        let dbus = cancel_dbus.clone();
        let sp = cancel_sp.clone();
        let cn = cancel_cn.clone();
        glib::spawn_future_local(async move {
            super::session_ops::disconnect_with_message(
                &dbus,
                &sp,
                "Connection Cancelled",
                &format!(
                    "Authentication cancelled for '{}'. Session disconnected.",
                    cn
                ),
            )
            .await;
        });
    };

    let parent = super::dialog_parent();
    crate::dialogs::show_credentials_dialog(
        parent.as_ref().map(|w| w.upcast_ref()),
        &session_path,
        &config_name,
        &fields,
        {
            let dbus = dbus.clone();
            let sp = session_path.clone();
            let cp = config_path.clone();
            let cn = config_name.clone();
            let slots = slots.to_vec();
            let ck = cred_key.clone();
            let prefilled = Rc::new(prefilled.clone());

            move |values, remember| {
                let dbus = dbus.clone();
                let sp = sp.clone();
                let cp = cp.clone();
                let cn = cn.clone();
                let slots = slots.clone();
                let ck = ck.clone();
                let prev_snapshot = prefilled.clone();

                glib::spawn_future_local(async move {
                    let outcome = submit_credentials(&dbus, &sp, &slots, &values).await;
                    handle_submit_outcome(
                        outcome,
                        values,
                        remember,
                        SubmitContext {
                            dbus,
                            session_path: sp,
                            config_path: cp,
                            config_name: cn,
                            cred_key: ck,
                            slots,
                            prev_snapshot,
                        },
                    )
                    .await;
                });
            }
        },
        on_cancel,
    );
}
