//! Challenge / OTP request flow

use glib::object::Cast;
use tracing::{error, info, warn};
use zbus::zvariant::OwnedObjectPath;

use crate::dbus::session::SessionProxy;

/// Fetch challenge prompt and show the challenge/response dialog
pub(crate) async fn request_challenge(
    dbus: &zbus::Connection,
    session_path: &str,
    config_name: &str,
) {
    let dbus = dbus.clone();
    let session_path = session_path.to_string();
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

    // Fetch all type/group pairs
    let type_groups = match session.UserInputQueueGetTypeGroup().await {
        Ok(tg) => tg,
        Err(e) => {
            error!("Failed to get input type groups for challenge: {}", e);
            return;
        }
    };

    // Collect challenge slots: (type, group, id)
    let mut challenge_text = String::from("Enter your authentication response");
    let mut slots: Vec<(u32, u32, u32)> = Vec::new();

    for (att_type, group) in &type_groups {
        if let Ok(ids) = session.UserInputQueueCheck(*att_type, *group).await {
            for id in ids {
                if let Ok((_t, _g, _i, label, desc, _mask)) =
                    session.UserInputQueueFetch(*att_type, *group, id).await
                {
                    // Use description as challenge text if non-empty, else label
                    if !desc.is_empty() {
                        challenge_text = desc;
                    } else if !label.is_empty() {
                        challenge_text = label;
                    }
                    slots.push((*att_type, *group, id));
                }
            }
        }
    }

    if slots.is_empty() {
        warn!("No challenge slots found for session {}", session_path);
        return;
    }

    info!("Challenge for session {}: {}", session_path, challenge_text);

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
                &cn,
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
    crate::dialogs::show_challenge_dialog(
        parent.as_ref().map(|w| w.upcast_ref()),
        &config_name.clone(),
        &challenge_text,
        move |response_text| {
            let dbus = dbus.clone();
            let sp = session_path.clone();
            let cn = config_name.clone();
            let slots = slots.clone();
            glib::spawn_future_local(async move {
                match submit_challenge(&dbus, &sp, &slots, &response_text).await {
                    Ok(true) => {
                        // Server needs another round of input
                        info!("Challenge accepted, server requires additional input");
                        request_challenge(&dbus, &sp, &cn).await;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        let err_str = format!("{}", e);
                        if err_str.contains("invalid-input") {
                            warn!("Server rejected empty challenge response");
                            crate::dialogs::show_error_notification(
                                "Challenge Required",
                                &format!("A response is required for '{}'.", cn),
                            );
                            request_challenge(&dbus, &sp, &cn).await;
                        } else {
                            error!("Failed to submit challenge response: {}", e);
                        }
                    }
                }
            });
        },
        on_cancel,
    );
}

/// Submit challenge response to all pending slots, then retry Ready() + Connect().
/// Returns `Ok(true)` if the server requires another round of input, `Ok(false)` otherwise.
async fn submit_challenge(
    dbus: &zbus::Connection,
    session_path: &str,
    slots: &[(u32, u32, u32)],
    response: &str,
) -> anyhow::Result<bool> {
    let session_path_obj = OwnedObjectPath::try_from(session_path)?;
    let session = SessionProxy::builder(dbus)
        .path(session_path_obj)?
        .build()
        .await?;

    for (att_type, group, id) in slots {
        session
            .UserInputProvide(*att_type, *group, *id, response)
            .await?;
        info!(
            "Provided challenge response for slot on session {}",
            session_path
        );
    }

    match session.Ready().await {
        Ok(()) => {
            session.Connect().await?;
            info!("Session connected after challenge: {}", session_path);
            Ok(false)
        }
        Err(e) => {
            info!(
                "Session not ready after challenge (checking for pending input): {}",
                e
            );
            // Actively re-check — server may not re-emit StatusChange for a second round.
            let pending = session
                .UserInputQueueGetTypeGroup()
                .await
                .unwrap_or_default();
            Ok(!pending.is_empty())
        }
    }
}
