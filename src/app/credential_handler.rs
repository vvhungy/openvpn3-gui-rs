//! Username / password credential request flow

use std::collections::HashMap;

use glib::object::Cast;
use tracing::{error, info, warn};
use zbus::zvariant::OwnedObjectPath;

use crate::dbus::session::SessionProxy;
use crate::dbus::types::ClientAttentionType;

pub(crate) const MAX_CREDENTIAL_ATTEMPTS: u32 = 3;

pub(crate) static CREDENTIAL_ATTEMPTS: std::sync::LazyLock<std::sync::Mutex<HashMap<String, u32>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// Fetch credential input slots and show the credentials dialog
pub(crate) async fn request_credentials(
    dbus: &zbus::Connection,
    session_path: &str,
    config_name: &str,
) {
    let dbus = dbus.clone();
    let session_path = session_path.to_string();
    let config_name = config_name.to_string();

    // Check attempt count
    let attempt = {
        let mut attempts = CREDENTIAL_ATTEMPTS.lock().unwrap();
        let count = attempts.entry(session_path.clone()).or_insert(0);
        *count += 1;
        *count
    };

    if attempt > MAX_CREDENTIAL_ATTEMPTS {
        warn!(
            "Max credential attempts ({}) reached for {}",
            MAX_CREDENTIAL_ATTEMPTS, session_path
        );
        super::session_ops::disconnect_with_message(
            &dbus,
            &session_path,
            "Authentication Failed",
            &format!(
                "Too many failed attempts for '{}'. Session disconnected.",
                config_name
            ),
        )
        .await;
        return;
    }

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

    // Fetch credential slots from the session
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
        warn!("No credential slots found for session {}", session_path);
        return;
    }

    info!(
        "Found {} credential slots for session {} (attempt {}/{})",
        slots.len(),
        session_path,
        attempt,
        MAX_CREDENTIAL_ATTEMPTS
    );

    // Use config_name as credential store key (stable across sessions)
    let cred_key = config_name.clone();
    let cred_store = crate::credentials::CredentialStore::default();

    // Build dynamic fields from the credential slots, loading saved values.
    // Only username/password-like fields (masked) are storable; OTP/auth codes are not.
    let mut fields = Vec::new();
    for (_att_type, _group, _id, label, mask) in &slots {
        let label_lower = label.to_lowercase();
        let is_storable =
            label_lower.contains("username") || label_lower.contains("password") || *mask;
        let saved = if is_storable {
            cred_store.get_async(&cred_key, label).await.ok().flatten()
        } else {
            None
        };
        // Map D-Bus labels to user-friendly display labels
        let display_label = if label_lower.contains("username") {
            "Auth Username".to_string()
        } else if label_lower.contains("password") {
            "Auth Password".to_string()
        } else {
            "Authentication Code".to_string()
        };
        fields.push(crate::dialogs::CredentialField {
            key: label.clone(),
            label: display_label,
            masked: *mask,
            can_store: is_storable,
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
        &config_name,
        &fields,
        move |values, remember| {
            let dbus = dbus.clone();
            let sp = session_path.clone();
            let slots = slots.clone();
            let ck = cred_key.clone();
            glib::spawn_future_local(async move {
                match submit_credentials(&dbus, &sp, &slots, &values).await {
                    Ok(()) => {
                        // Clear attempt counter on success
                        if let Ok(mut attempts) = CREDENTIAL_ATTEMPTS.lock() {
                            attempts.remove(&sp);
                        }
                        // Save only storable credentials (username/password, not OTP)
                        let store = crate::credentials::CredentialStore::default();
                        for (label, value) in &values {
                            let ll = label.to_lowercase();
                            let is_storable = ll.contains("username")
                                || ll.contains("password")
                                || slots.iter().any(|(_, _, _, l, m)| l == label && *m);
                            if !is_storable {
                                continue;
                            }
                            if remember {
                                if let Err(e) = store.set_async(&ck, label, value).await {
                                    warn!(
                                        "Failed to save credential '{}' to keyring: {}",
                                        label, e
                                    );
                                }
                            } else {
                                if let Err(e) = store.delete_async(&ck, label).await {
                                    warn!(
                                        "Failed to delete credential '{}' from keyring: {}",
                                        label, e
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to submit credentials: {}", e);
                    }
                }
            });
        },
        on_cancel,
    );
}

/// Submit credentials to all input slots by matching labels, then retry Ready() + Connect()
async fn submit_credentials(
    dbus: &zbus::Connection,
    session_path: &str,
    slots: &[(u32, u32, u32, String, bool)],
    values: &[(String, String)],
) -> anyhow::Result<()> {
    let session_path_obj = OwnedObjectPath::try_from(session_path)?;
    let session = SessionProxy::builder(dbus)
        .path(session_path_obj)?
        .build()
        .await?;

    // Provide values to each slot, matched by label
    for (att_type, group, id, label, _mask) in slots {
        let value = values
            .iter()
            .find(|(l, _)| l == label)
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        session
            .UserInputProvide(*att_type, *group, *id, value)
            .await?;
        info!(
            "Provided input for slot '{}' on session {}",
            label, session_path
        );
    }

    // Retry Ready() + Connect()
    match session.Ready().await {
        Ok(()) => {
            session.Connect().await?;
            info!("Session connected after credentials: {}", session_path);
        }
        Err(e) => {
            // Not ready yet — may trigger another CFG_REQUIRE_USER for
            // additional credentials (e.g. OTP after password).
            // The StatusChange handler will call request_credentials again.
            info!(
                "Session still not ready after credentials (may need more input): {}",
                e
            );
        }
    }

    Ok(())
}
