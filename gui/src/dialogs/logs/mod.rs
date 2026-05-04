//! Tabbed VPN log viewer window
//!
//! One "View Logs" entry opens a window with one tab per VPN profile.
//! Multiple session attempts for the same profile all feed into the same tab.
//! Logs are populated from the global `LogBuffer` (history) and then live-
//! tailed via a D-Bus `Log` signal subscription.
//!
//! No testable pure surface here — pure formatting (`format_log_line`) lives
//! in the `format` submodule with its own unit tests. This file is GTK widget
//! builder + async D-Bus stream wiring.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use futures::channel::oneshot;
use futures::{FutureExt, StreamExt};
use gtk4::prelude::*;
use gtk4::{Notebook, ScrolledWindow, TextView, Window};
use tracing::warn;
use zbus::MessageStream;
use zbus::message::Type as MessageType;

use crate::app::log_buffer;

mod format;

use format::format_log_line;

/// State for a single tab: its text buffer and end-mark for auto-scroll.
struct TabState {
    buffer: gtk4::TextBuffer,
    end_mark: gtk4::TextMark,
    text_view: TextView,
    scrolled: ScrolledWindow,
}

/// Show the tabbed log viewer window.
///
/// One tab per config name. All sessions for the same profile feed into
/// the same tab. History comes from `LogBuffer`, then live-tails new entries.
pub fn show_log_viewer(
    parent: Option<&gtk4::Window>,
    tray: &ksni::blocking::Handle<crate::tray::VpnTray>,
    dbus: &zbus::Connection,
) {
    let window = Window::builder()
        .title("VPN Logs")
        .modal(false)
        .default_width(750)
        .default_height(500)
        .build();

    if let Some(p) = parent {
        window.set_transient_for(Some(p));
    }

    let notebook = Notebook::builder().vexpand(true).hexpand(true).build();

    // Build a set of config names from both active sessions and buffered logs
    let active_names: Vec<String> = tray
        .update(|t| {
            let mut names: Vec<String> =
                t.sessions.values().map(|s| s.config_name.clone()).collect();
            names.sort();
            names.dedup();
            names
        })
        .unwrap_or_default();

    let buffered_names: Vec<String> = {
        let buffered = log_buffer::sessions_with_logs();
        let mut names: Vec<String> = buffered.iter().map(|(_, cn)| cn.clone()).collect();
        names.sort();
        names.dedup();
        names
    };

    // Merge and deduplicate
    let mut all_names: Vec<String> = active_names;
    all_names.extend(buffered_names);
    all_names.sort();
    all_names.dedup();

    // session_path → config_name reverse lookup for live-tail routing
    let path_to_name: Rc<RefCell<HashMap<String, String>>> = Rc::new(RefCell::new(HashMap::new()));

    // Populate reverse lookup from tray and buffer
    let tray_names = tray
        .update(|t| {
            t.sessions
                .values()
                .map(|s| (s.session_path.clone(), s.config_name.clone()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for (sp, cn) in &tray_names {
        path_to_name.borrow_mut().insert(sp.clone(), cn.clone());
    }
    for (sp, cn) in &log_buffer::sessions_with_logs() {
        path_to_name.borrow_mut().insert(sp.clone(), cn.clone());
    }

    // Tabs keyed by config_name
    let tabs: Rc<RefCell<HashMap<String, TabState>>> = Rc::new(RefCell::new(HashMap::new()));

    let placeholder_page: Rc<RefCell<Option<u32>>> = Rc::new(RefCell::new(None));

    if all_names.is_empty() {
        let label = gtk4::Label::new(Some("No VPN sessions to show logs for."));
        label.set_margin_top(24);
        label.set_margin_bottom(24);
        let page_num = notebook.append_page(&label, Some(&gtk4::Label::new(Some("No Sessions"))));
        *placeholder_page.borrow_mut() = Some(page_num);
    } else {
        for config_name in &all_names {
            let tab = create_tab_for_config(config_name);
            notebook.append_page(&tab.scrolled, Some(&gtk4::Label::new(Some(config_name))));
            tabs.borrow_mut().insert(config_name.clone(), tab);
        }
    }

    // Main layout: notebook + close button
    let vbox = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    vbox.append(&notebook);

    let notif_note = gtk4::Label::new(Some(
        "Opening this window may suppress notifications on some desktop environments.",
    ));
    notif_note.add_css_class("dim-label");
    let notif_icon = gtk4::Image::from_icon_name("dialog-information-symbolic");
    let notif_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
    notif_box.set_margin_top(4);
    notif_box.set_margin_start(8);
    notif_box.set_halign(gtk4::Align::Start);
    notif_box.append(&notif_icon);
    notif_box.append(&notif_note);
    vbox.append(&notif_box);

    let close_btn = gtk4::Button::with_label("Close");
    let btn_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 0);
    btn_box.set_halign(gtk4::Align::End);
    btn_box.set_margin_top(8);
    btn_box.set_margin_bottom(8);
    btn_box.set_margin_end(8);
    btn_box.append(&close_btn);
    vbox.append(&btn_box);

    window.set_child(Some(&vbox));

    // Cancellation
    let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
    let cancel_tx = Rc::new(RefCell::new(Some(cancel_tx)));

    let cancel_for_btn = cancel_tx.clone();
    let win_for_btn = window.clone();
    close_btn.connect_clicked(move |_| {
        if let Some(tx) = cancel_for_btn.borrow_mut().take() {
            let _ = tx.send(());
        }
        win_for_btn.close();
    });

    let cancel_for_close = cancel_tx;
    window.connect_close_request(move |_| {
        if let Some(tx) = cancel_for_close.borrow_mut().take() {
            let _ = tx.send(());
        }
        glib::Propagation::Proceed
    });

    window.present();

    // Live-tail subscription
    let dbus = dbus.clone();
    let tray = tray.clone();
    let placeholder_page = placeholder_page.clone();
    let notebook_rc = notebook;
    glib::spawn_future_local(async move {
        let match_rule = "type='signal',interface='net.openvpn.v3.backends',member='Log'";
        let subscribed = dbus
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "AddMatch",
                &match_rule,
            )
            .await
            .is_ok();

        if !subscribed {
            warn!("Log viewer: could not subscribe to Log signals");
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
                            warn!("Log viewer stream error: {}", e);
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

                    let session_path = header
                        .path()
                        .map(|p| p.as_str().to_string())
                        .unwrap_or_default();

                    if let Ok((_group, category, message)) =
                        msg.body().deserialize::<(u32, u32, &str)>()
                    {
                        let timestamp = chrono::Local::now().time();
                        let line = format_log_line(&timestamp, category, message);

                        // Resolve config_name from session_path
                        let config_name = {
                            // Check reverse lookup cache first
                            if let Some(cn) = path_to_name.borrow().get(&session_path) {
                                cn.clone()
                            } else {
                                // Look up from tray
                                let cn = tray
                                    .update(|t| {
                                        t.sessions
                                            .get(&session_path)
                                            .map(|s| s.config_name.clone())
                                    })
                                    .flatten()
                                    .unwrap_or_else(|| "VPN".to_string());
                                path_to_name
                                    .borrow_mut()
                                    .insert(session_path.clone(), cn.clone());
                                cn
                            }
                        };

                        // Find or create tab by config_name
                        let mut tabs_map = tabs.borrow_mut();
                        if !tabs_map.contains_key(&config_name) {
                            if let Some(page_num) = placeholder_page.borrow_mut().take() {
                                notebook_rc.remove_page(Some(page_num));
                            }
                            let tab = create_tab_for_config(&config_name);
                            notebook_rc.append_page(
                                &tab.scrolled,
                                Some(&gtk4::Label::new(Some(&config_name))),
                            );
                            tabs_map.insert(config_name.clone(), tab);
                        }

                        if let Some(tab) = tabs_map.get(&config_name) {
                            let mut end_iter = tab.buffer.end_iter();
                            tab.buffer.insert(&mut end_iter, &line);
                            tab.text_view.scroll_mark_onscreen(&tab.end_mark);
                        }
                    }
                }
                _ = cancel => break,
            }
        }

        // Clean up match rule
        let _ = dbus
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "RemoveMatch",
                &match_rule,
            )
            .await;
    });
}

/// Create a tab for a config name, populated with all buffered history
/// across all session paths for that config.
fn create_tab_for_config(config_name: &str) -> TabState {
    let buffer = gtk4::TextBuffer::new(None);

    // Collect all entries across all sessions for this config name
    let buffered_sessions = log_buffer::sessions_with_logs();
    let relevant_paths: Vec<&str> = buffered_sessions
        .iter()
        .filter(|(_, cn)| cn == config_name)
        .map(|(sp, _)| sp.as_str())
        .collect();

    let mut all_entries: Vec<log_buffer::LogEntry> = Vec::new();
    for path in &relevant_paths {
        all_entries.extend(log_buffer::entries_for_session(path));
    }
    // Sort by timestamp (entries from different sessions interleave)
    all_entries.sort_by_key(|e| e.timestamp);

    if all_entries.is_empty() {
        let header = format!("Listening for log messages from '{}'...\n", config_name);
        buffer.set_text(&header);
    } else {
        let mut text = String::new();
        for entry in &all_entries {
            text.push_str(&format_log_line(
                &entry.timestamp,
                entry.category,
                &entry.message,
            ));
        }
        buffer.set_text(&text);
    }

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

    let end_mark = buffer.create_mark(Some("log-end"), &buffer.end_iter(), false);

    let scrolled = ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .child(&text_view)
        .build();

    text_view.scroll_mark_onscreen(&end_mark);

    TabState {
        buffer,
        end_mark,
        text_view,
        scrolled,
    }
}
