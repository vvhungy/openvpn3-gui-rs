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

/// Build the ordered list of keyring labels to probe for a given set of slots.
///
/// Pure: the queue-slot labels first (as the server named them), then the three
/// standard labels, then the per-standard common D-Bus label variants.
/// Extracted from `request_credentials` so the label-accumulation is testable.
fn build_labels_to_try(slots: &[(u32, u32, u32, String, bool)]) -> Vec<String> {
    let mut labels: Vec<String> = slots.iter().map(|(_, _, _, l, _)| l.clone()).collect();
    for (standard_label, _) in &STANDARD_FIELDS {
        labels.push(standard_label.to_string());
        for variant in keyring_label_variants(standard_label) {
            labels.push(variant.to_string());
        }
    }
    labels
}

/// Open the default keyring and unlock it once, returning a usable handle or
/// `None` (after a single user-facing notification) if either step fails.
///
/// Extracted from `request_credentials`. Dropping the handle on unlock failure
/// keeps the read loop below from logging N near-identical `warn!` lines.
/// Impure async glue — no unit surface.
async fn open_and_unlock_keyring() -> Option<oo7::Keyring> {
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
        crate::dialogs::show_error_notification(
            "Saved Credentials Unavailable",
            keyring_unlock_hint(crate::credentials::store::is_locked_error(&e)),
        );
        // Drop the handle so the read loop short-circuits. Otherwise it stays
        // `Some` and every label logs its own read-failure `warn!` (N
        // near-identical lines for one root cause). One notification + one log
        // line above is enough; pre-fill is simply blank.
        keyring = None;
    }
    keyring
}

/// Human-readable hint for a keyring *unlock* failure, given whether the
/// underlying error was a lock/refusal.
///
/// Pure (bool -> message) so the locked-vs-generic branch is unit-testable; the
/// impure error classification ([`is_locked_error`]) stays at the call site.
fn keyring_unlock_hint(locked: bool) -> &'static str {
    if locked {
        "Keyring is locked. Enter credentials manually."
    } else {
        "Could not unlock the keyring. Enter credentials manually."
    }
}

/// Resolve keyring values into `resolved`, keyed by label.
///
/// Prefilled entries already in `resolved` win and are skipped; non-storable
/// labels (e.g. OTP) are skipped. Outcome is classified so a *locked/error*
/// read never reads as *absent*. Extracted from `request_credentials`'s read
/// loop. Impure async glue — no unit surface.
async fn resolve_keyring_values(
    labels: &[String],
    keyring: Option<&oo7::Keyring>,
    cred_store: &crate::credentials::CredentialStore,
    cred_key: &str,
    config_name: &str,
    resolved: &mut HashMap<String, String>,
) {
    let Some(k) = keyring else {
        return;
    };
    for label in labels {
        if resolved.contains_key(label) {
            continue;
        }
        if !is_storable_field(label, true) {
            continue;
        }
        match cred_store
            .get_with_keyring(k, cred_key, config_name, label)
            .await
        {
            Ok(Some(val)) => {
                resolved.insert(label.clone(), val);
            }
            Ok(None) => {} // genuinely absent — leave blank
            Err(e) => warn!("Failed to read saved credential '{label}': {e}"),
        }
    }
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

/// Look up the `mask` flag for a credential label among the D-Bus queue
/// slots, or `false` when no slot carries that label.
///
/// Pure extraction of the per-label `.find().map().unwrap_or(false)` lookup so
/// it is unit-testable in isolation.
fn slot_mask(label: &str, slots: &[(u32, u32, u32, String, bool)]) -> bool {
    slots
        .iter()
        .find(|(_, _, _, l, _)| l == label)
        .map(|(_, _, _, _, m)| *m)
        .unwrap_or(false)
}

/// User-facing hint for a credential *save* failure, given whether the
/// underlying keyring error was a lock/refusal.
///
/// Pure (bool -> message) so the locked-vs-generic branch is unit-testable; the
/// impure error classification ([`is_locked_error`]) stays at the call site.
fn save_failure_hint(locked: bool) -> &'static str {
    if locked {
        "Keyring is locked — credentials could not be saved."
    } else {
        "Could not save credentials to the keyring."
    }
}

/// Persist submitted "remembered" credentials to the keyring, one label at a
/// time.
///
/// Extracted from the dialog submit callback's `Ok(true)` arm. Only storable
/// fields (username/password, not OTP) are written; the "save failed"
/// notification fires at most once per submit (a locked keyring fails every
/// label but the user needs one toast for the single root cause). Impure async
/// glue — no unit surface.
async fn save_remembered_credentials(
    values: &[(String, String)],
    slots: &[(u32, u32, u32, String, bool)],
    cred_key: &str,
    store: &crate::credentials::CredentialStore,
) {
    let mut save_failure_notified = false;
    for (label, value) in values {
        if !is_storable_field(label, slot_mask(label, slots)) {
            continue;
        }
        if let Err(e) = store.set_async(cred_key, label, value).await {
            // A failed "remember" must not be silent — the user believes
            // credentials were saved when they weren't.
            warn!("Failed to save credential '{}' to keyring: {}", label, e);
            if !save_failure_notified {
                save_failure_notified = true;
                crate::dialogs::show_error_notification(
                    "Credential Save Failed",
                    save_failure_hint(crate::credentials::store::is_locked_error(&e)),
                );
            }
        }
    }
}

/// Delete submitted credentials from the keyring when "remember" was unticked.
///
/// Extracted from the dialog submit callback's `Ok(true)` arm. Delete failure
/// is lower-stakes than save failure (worst case: a stale entry), so it only
/// logs. Impure async glue — no unit surface.
async fn delete_remembered_credentials(
    values: &[(String, String)],
    slots: &[(u32, u32, u32, String, bool)],
    cred_key: &str,
    store: &crate::credentials::CredentialStore,
) {
    for (label, _value) in values {
        if !is_storable_field(label, slot_mask(label, slots)) {
            continue;
        }
        if let Err(e) = store.delete_async(cred_key, label).await {
            warn!(
                "Failed to delete credential '{}' from keyring: {}",
                label, e
            );
        }
    }
}

/// Resources captured by the credentials-dialog submit callback, bundled so the
/// outcome handler receives them as one value (and stays under the argument-count
/// lint). All owned; moved into whichever submit branch consumes them.
struct SubmitContext {
    dbus: zbus::Connection,
    session_path: String,
    config_path: String,
    config_name: String,
    cred_key: String,
    slots: Vec<(u32, u32, u32, String, bool)>,
    prev_snapshot: Rc<HashMap<String, String>>,
}

/// Act on the outcome of submitting credentials to D-Bus.
///
/// Extracted from the credentials-dialog submit callback so its three-way
/// `match` — all-provided (persist) / partial (re-show prefilled) / error
/// (re-dispatch or notify) — is isolated from the callback's value-capture
/// plumbing, which reduced the callback to a single delegated call. Impure
/// async glue — no unit surface.
async fn handle_submit_outcome(
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
                super::credential_handler::request_credentials(
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

#[cfg(test)]
mod tests {
    use super::{build_labels_to_try, keyring_unlock_hint, save_failure_hint, slot_mask};

    #[test]
    fn build_labels_starts_with_slot_labels() {
        // Queue-slot labels are probed before the standard field names so the
        // server's actual label wins when it matches a keyring attribute.
        let slots = vec![(1, 0, 0, "Server User".to_string(), false)];
        let labels = build_labels_to_try(&slots);
        assert_eq!(labels.first().map(String::as_str), Some("Server User"));
        assert!(labels.contains(&"Username".to_string()));
        assert!(labels.contains(&"Password".to_string()));
        assert!(labels.contains(&"One-Time Code".to_string()));
    }

    #[test]
    fn build_labels_includes_common_variants() {
        // Different OpenVPN3 servers emit varying label prose for the same
        // field; all known variants are appended so the keyring is probed once
        // per spelling.
        let labels = build_labels_to_try(&[]);
        assert!(labels.contains(&"Enter Password".to_string()));
        assert!(labels.contains(&"Your password".to_string()));
        assert!(labels.contains(&"one-time code".to_string()));
    }

    #[test]
    fn slot_mask_finds_masked_label() {
        let slots = vec![(1, 0, 0, "Password".to_string(), true)];
        assert!(slot_mask("Password", &slots));
    }

    #[test]
    fn slot_mask_unmasked_slot_is_false() {
        let slots = vec![(1, 0, 0, "Username".to_string(), false)];
        assert!(!slot_mask("Username", &slots));
    }

    #[test]
    fn slot_mask_missing_label_is_false() {
        let slots = vec![(1, 0, 0, "Password".to_string(), true)];
        assert!(!slot_mask("Username", &slots));
    }

    #[test]
    fn save_failure_hint_distinguishes_locked() {
        assert_eq!(
            save_failure_hint(true),
            "Keyring is locked — credentials could not be saved."
        );
        assert_eq!(
            save_failure_hint(false),
            "Could not save credentials to the keyring."
        );
    }

    #[test]
    fn keyring_unlock_hint_distinguishes_locked() {
        assert_eq!(
            keyring_unlock_hint(true),
            "Keyring is locked. Enter credentials manually."
        );
        assert_eq!(
            keyring_unlock_hint(false),
            "Could not unlock the keyring. Enter credentials manually."
        );
    }
}
