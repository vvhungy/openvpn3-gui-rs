//! Session log viewer dialog
//!
//! Opens a live-tail window that subscribes to `Log` signals for a specific
//! session path and appends each line to a scrollable text view.  Cancels
//! cleanly (removes the D-Bus match rule) when the user closes the dialog.

use std::cell::RefCell;
use std::rc::Rc;

use futures::channel::oneshot;
use futures::{FutureExt, StreamExt};
use gtk4::prelude::*;
use gtk4::{Dialog, ResponseType, ScrolledWindow, TextView};
use tracing::warn;
use zbus::MessageStream;
use zbus::message::Type as MessageType;

fn log_category_label(category: u32) -> &'static str {
    match category {
        1 => "DEBUG",
        2 => "VERB2",
        3 => "VERB1",
        4 => "INFO",
        5 => "WARN",
        6 => "ERROR",
        7 => "CRIT",
        8 => "FATAL",
        _ => "LOG",
    }
}

/// Show a live-tail log viewer dialog for the given VPN session.
///
/// Subscribes to `net.openvpn.v3.backends::Log` signals for `session_path`
/// and streams them into a scrollable monospace text view.  The D-Bus match
/// rule is removed when the dialog is closed.
pub fn show_session_log_dialog(
    parent: Option<&gtk4::Window>,
    config_name: &str,
    session_path: &str,
    dbus: &zbus::Connection,
) {
    let dialog = Dialog::builder()
        .title(format!("Session Logs — {}", config_name))
        .modal(false)
        .default_width(700)
        .default_height(450)
        .build();

    dialog.add_button("Close", ResponseType::Close);

    let buffer = gtk4::TextBuffer::new(None);
    buffer.set_text(&format!(
        "Listening for log messages from '{}'...\n",
        config_name
    ));

    let text_view = TextView::builder()
        .buffer(&buffer)
        .editable(false)
        .cursor_visible(false)
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::WordChar)
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(8)
        .margin_end(8)
        .build();

    let scrolled = ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .child(&text_view)
        .build();

    dialog.content_area().append(&scrolled);

    if let Some(p) = parent {
        dialog.set_transient_for(Some(p));
    }

    // Cancellation: fired via oneshot when user closes the dialog
    let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
    let cancel_tx = Rc::new(RefCell::new(Some(cancel_tx)));
    let cancel_tx_for_response = cancel_tx.clone();

    dialog.connect_response(move |dialog, _| {
        if let Some(tx) = cancel_tx_for_response.borrow_mut().take() {
            let _ = tx.send(());
        }
        dialog.close();
    });

    dialog.present();

    // Right-gravity mark auto-tracks end of buffer as text is appended
    let end_mark = buffer.create_mark(Some("log-end"), &buffer.end_iter(), false);

    let dbus = dbus.clone();
    let session_path = session_path.to_string();

    glib::spawn_future_local(async move {
        let match_rule = format!(
            "type='signal',interface='net.openvpn.v3.backends',member='Log',path='{}'",
            session_path
        );

        let subscribed = dbus
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "AddMatch",
                &match_rule.as_str(),
            )
            .await
            .is_ok();

        if !subscribed {
            let mut end = buffer.end_iter();
            buffer.insert(&mut end, "[Error: could not subscribe to session logs]\n");
            return;
        }

        let mut stream = MessageStream::from(&dbus).fuse();
        let mut cancel = cancel_rx.fuse();

        loop {
            futures::select! {
                msg_result = stream.next() => {
                    let msg = match msg_result {
                        Some(Ok(m)) => m,
                        Some(Err(e)) => {
                            warn!("Log stream error: {}", e);
                            continue;
                        }
                        None => break,
                    };

                    if msg.message_type() != MessageType::Signal {
                        continue;
                    }

                    let header = msg.header();
                    if header.interface().map(|i| i.as_str())
                        != Some("net.openvpn.v3.backends")
                    {
                        continue;
                    }
                    if header.member().map(|m| m.as_str()) != Some("Log") {
                        continue;
                    }
                    let path = header
                        .path()
                        .map(|p| p.as_str().to_string())
                        .unwrap_or_default();
                    if path != session_path {
                        continue;
                    }

                    match msg.body().deserialize::<(u32, u32, &str)>() {
                        Ok((_group, category, message)) => {
                            let label = log_category_label(category);
                            let line = format!("[{}] {}\n", label, message);
                            let mut end_iter = buffer.end_iter();
                            buffer.insert(&mut end_iter, &line);
                            text_view.scroll_mark_onscreen(&end_mark);
                        }
                        Err(e) => {
                            warn!("Failed to parse Log signal: {}", e);
                        }
                    }
                }
                _ = cancel => break,
            }
        }

        // Clean up match rule so it doesn't accumulate across multiple opens
        let _ = dbus
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "RemoveMatch",
                &match_rule.as_str(),
            )
            .await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_category_label_known_values() {
        assert_eq!(log_category_label(1), "DEBUG");
        assert_eq!(log_category_label(4), "INFO");
        assert_eq!(log_category_label(5), "WARN");
        assert_eq!(log_category_label(6), "ERROR");
        assert_eq!(log_category_label(7), "CRIT");
        assert_eq!(log_category_label(8), "FATAL");
    }

    #[test]
    fn test_log_category_label_unknown_falls_back() {
        assert_eq!(log_category_label(0), "LOG");
        assert_eq!(log_category_label(99), "LOG");
    }
}
