//! Username / password credential request flow
//!
//! Async D-Bus dispatch + retry orchestration. The pure auth-failure counter
//! and its unit tests live in [`retry`], re-exported here so existing
//! `credential_handler::next_attempt` / `CREDENTIAL_ATTEMPTS` /
//! `MAX_CREDENTIAL_ATTEMPTS` call paths stay valid. Label-mapping /
//! storability helpers live in `crate::credentials::policy` with their own
//! unit tests.

mod retry;

pub(crate) use retry::{
    CREDENTIAL_ATTEMPTS, MAX_CREDENTIAL_ATTEMPTS, next_attempt, should_retry_auth,
};

use std::collections::HashMap;
use std::rc::Rc;

use glib::object::Cast;
use tracing::{error, info, warn};
use zbus::zvariant::OwnedObjectPath;

use crate::credentials::policy::{display_label_for, is_storable_field};
use crate::dbus::session::SessionProxy;
use crate::dbus::types::ClientAttentionType;

/// Standard credential field labels — dialog always shows all 3 regardless
/// of which slots the D-Bus queue currently holds. Extra dialog fields with
/// no matching queue slot are silently ignored on submit.
const STANDARD_FIELDS: [(&str, bool); 3] = [
    ("Username", false),
    ("Password", true),
    ("One-Time Code", true),
];

/// Common D-Bus label variants seen from different OpenVPN3 servers.
/// Used to probe the keyring when the actual queue slot label doesn't
/// match the standard field label.
fn keyring_label_variants(standard_label: &str) -> &'static [&'static str] {
    match standard_label {
        "Username" => &["username", "Enter Username", "Enter username"],
        "Password" => &[
            "password",
            "Enter Password",
            "Enter password",
            "Your password",
        ],
        "One-Time Code" => &["one-time code", "Authenticator Code", "One Time Password"],
        _ => &[],
    }
}

/// Check whether a D-Bus label belongs to a standard field category.
fn label_matches_category(label: &str, standard_label: &str) -> bool {
    let lower = label.to_lowercase();
    match standard_label {
        "Username" => lower.contains("username"),
        "Password" => lower.contains("password"),
        // OTP / challenge: anything that isn't username or password
        _ => !lower.contains("username") && !lower.contains("password"),
    }
}

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

    let session_path_obj = match OwnedObjectPath::try_from(session_path.as_str()) {
        Ok(p) => p,
        Err(e) => {
            error!("Invalid session path: {}", e);
            return;
        }
    };
    let session = match SessionProxy::builder(&dbus).path(session_path_obj) {
        Ok(builder) => match builder.build().await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to create session proxy: {}", e);
                return;
            }
        },
        Err(e) => {
            error!("Failed to set session path: {}", e);
            return;
        }
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
    let mut slots: Vec<(u32, u32, u32, String, bool)> = Vec::new();
    for (att_type, group) in &type_groups {
        // Only handle credential type (1)
        if *att_type != ClientAttentionType::Credentials as u32 {
            continue;
        }
        if let Ok(ids) = session.UserInputQueueCheck(*att_type, *group).await {
            for id in ids {
                if let Ok((_t, _g, _i, label, _desc, mask)) =
                    session.UserInputQueueFetch(*att_type, *group, id).await
                {
                    slots.push((*att_type, *group, id, label, mask));
                }
            }
        }
    }

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
    let mut labels_to_try: Vec<String> = slots.iter().map(|(_, _, _, l, _)| l.clone()).collect();
    for (standard_label, _) in &STANDARD_FIELDS {
        labels_to_try.push(standard_label.to_string());
        // Common D-Bus label variants seen from different OpenVPN3 servers
        for variant in keyring_label_variants(standard_label) {
            labels_to_try.push(variant.to_string());
        }
    }

    // Open ONE keyring handle for the whole resolution and unlock it once.
    // Previously each get_async opened its own Keyring::new() — N labels meant
    // N opens, and none shared unlock state, so a locked collection left every
    // field blank with no signal. Unlock before the loop so the system prompt
    // fires before our dialog, not under it.
    let mut keyring = match oo7::Keyring::new().await {
        Ok(k) => Some(k),
        Err(e) => {
            warn!("Failed to open keyring — saved credentials unavailable: {e}");
            crate::dialogs::show_error_notification(
                "Saved Credentials Unavailable",
                "Could not open the keyring. Enter credentials manually.",
            );
            None
        }
    };
    if let Some(k) = &keyring
        && let Err(e) = crate::credentials::store::ensure_unlocked(k).await
    {
        warn!("Failed to unlock keyring — pre-fill disabled: {e}");
        let hint = if crate::credentials::store::is_locked_error(&e) {
            "Keyring is locked. Enter credentials manually."
        } else {
            "Could not unlock the keyring. Enter credentials manually."
        };
        crate::dialogs::show_error_notification("Saved Credentials Unavailable", hint);
        // Drop the handle so the read loop below short-circuits. Otherwise it
        // stays `Some` and every label logs its own read-failure `warn!` (N
        // near-identical lines for one root cause). One notification + one log
        // line above is enough; pre-fill is simply blank.
        keyring = None;
    }

    for label in labels_to_try {
        if resolved.contains_key(&label) {
            continue;
        }
        if !is_storable_field(&label, true) {
            continue;
        }
        // Read against the single unlocked handle. Classify the outcome instead
        // of the old `.ok().flatten()`, which conflated *locked/error* with
        // *absent* and silently blanked fields.
        if let Some(k) = keyring.as_ref() {
            match cred_store
                .get_with_keyring(k, &cred_key, &config_name, &label)
                .await
            {
                Ok(Some(val)) => {
                    resolved.insert(label, val);
                }
                Ok(None) => {} // genuinely absent — leave blank
                Err(e) => warn!("Failed to read saved credential '{label}': {e}"),
            }
            // No keyring — already notified above; leave field blank.
        }
    }

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
                    match submit_credentials(&dbus, &sp, &slots, &values).await {
                        Ok(true) => {
                            // All slots provided and Connect() sent — counter is
                            // cleared by status_handler when is_connected() fires.
                            // Save only storable credentials (username/password, not OTP)
                            let store = crate::credentials::CredentialStore::default();
                            // Fire the "save failed" notification at most once per submit:
                            // a locked keyring fails every label, but the user only needs
                            // one toast for the single root cause.
                            let mut save_failure_notified = false;
                            for (label, value) in &values {
                                let mask = slots
                                    .iter()
                                    .find(|(_, _, _, l, _)| l == label)
                                    .map(|(_, _, _, _, m)| *m)
                                    .unwrap_or(false);
                                if !is_storable_field(label, mask) {
                                    continue;
                                }
                                if remember {
                                    if let Err(e) = store.set_async(&ck, label, value).await {
                                        // A failed "remember" must not be silent —
                                        // the user believes credentials were saved
                                        // when they weren't. classify so the message
                                        // distinguishes "locked" from a generic keyring
                                        // failure.
                                        warn!(
                                            "Failed to save credential '{}' to keyring: {}",
                                            label, e
                                        );
                                        if !save_failure_notified {
                                            save_failure_notified = true;
                                            let hint = if crate::credentials::store::is_locked_error(
                                                &e,
                                            ) {
                                                "Keyring is locked — credentials could not be saved."
                                            } else {
                                                "Could not save credentials to the keyring."
                                            };
                                            crate::dialogs::show_error_notification(
                                                "Credential Save Failed",
                                                hint,
                                            );
                                        }
                                    }
                                } else {
                                    if let Err(e) = store.delete_async(&ck, label).await {
                                        warn!(
                                            "Failed to delete credential '{}' from keyring: {}",
                                            label, e
                                        );
                                        // Delete failure is lower-stakes than save
                                        // failure (worst case: a stale entry), so a
                                        // bare warn suffices — no notification.
                                    }
                                }
                            }
                        }
                        Ok(false) => {
                            // Some fields left empty — no slots were consumed, so
                            // re-show the same dialog with pre-filled values.
                            let merged: HashMap<String, String> = (*prev_snapshot)
                                .clone()
                                .into_iter()
                                .chain(values.into_iter().filter(|(_, v)| !v.is_empty()))
                                .collect();

                            show_credentials_with_slots(dbus, sp, cp, cn, &slots, &merged);
                        }
                        Err(e) => {
                            let err_str = format!("{}", e);
                            if err_str.contains("User input not required") {
                                info!("Session '{}' queue reset, re-dispatching credentials", cn);
                                super::credential_handler::request_credentials(
                                    &dbus,
                                    &sp,
                                    &cp,
                                    &cn,
                                    Default::default(),
                                )
                                .await;
                            } else {
                                error!("Failed to submit credentials: {}", e);
                                crate::dialogs::show_error_notification(
                                    "Authentication Failed",
                                    &format!("Server rejected credentials for '{}'.", cn),
                                );
                            }
                        }
                    }
                });
            }
        },
        on_cancel,
    );
}

/// Submit credentials to all input slots by matching labels, then call Ready() + Connect().
/// Returns `Ok(true)` if all slots were provided and connection started.
/// Returns `Ok(false)` if some slots were skipped (empty values) — caller should re-show dialog.
async fn submit_credentials(
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
                    label, session_path
                );
            }
            Err(e) => {
                let err_str = format!("{}", e);
                if err_str.contains("already-provided") {
                    info!("Slot '{}' already provided, skipping", label);
                } else if err_str.contains("User input not required") {
                    info!("Slot '{}' — session queue reset, aborting", label);
                    anyhow::bail!("User input not required");
                } else {
                    return Err(e.into());
                }
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
