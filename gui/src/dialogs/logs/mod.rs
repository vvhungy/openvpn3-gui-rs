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
use crate::settings::Settings;

mod format;

use format::{format_export, format_log_line};

/// Per-tab state. Holds the full unfiltered entry vec so search/level
/// changes can rebuild the visible buffer without re-fetching from the
/// global log buffer. `level_min` is 0 (all), 5 (warn+), or 6 (error).
struct TabState {
    buffer: gtk4::TextBuffer,
    end_mark: gtk4::TextMark,
    text_view: TextView,
    page: gtk4::Box,
    entries: Rc<RefCell<Vec<log_buffer::LogEntry>>>,
    search_text: Rc<RefCell<String>>,
    level_min: Rc<RefCell<u32>>,
    export_btn: gtk4::Button,
}

/// Returns true if any entry in `entries` passes the current filter.
fn any_passes_filter(entries: &[log_buffer::LogEntry], search: &str, level_min: u32) -> bool {
    entries.iter().any(|e| passes_filter(e, search, level_min))
}

/// Returns true if the entry passes the current filter pair (substring
/// match on message, case-insensitive; category >= level_min).
fn passes_filter(entry: &log_buffer::LogEntry, search: &str, level_min: u32) -> bool {
    if entry.category < level_min {
        return false;
    }
    if !search.is_empty()
        && !entry
            .message
            .to_lowercase()
            .contains(&search.to_lowercase())
    {
        return false;
    }
    true
}

/// Rebuild the visible TextBuffer from the unfiltered entries vec by
/// re-applying the current filter. Called on search/level change.
fn rebuild_buffer(
    buffer: &gtk4::TextBuffer,
    entries: &[log_buffer::LogEntry],
    search: &str,
    level_min: u32,
) {
    let mut text = String::new();
    for e in entries {
        if passes_filter(e, search, level_min) {
            text.push_str(&format_log_line(&e.timestamp, e.category, &e.message));
        }
    }
    buffer.set_text(&text);
}

/// Map DropDown selected index to the min category threshold.
fn level_index_to_min(idx: u32) -> u32 {
    match idx {
        1 => 5,
        2 => 6,
        _ => 0,
    }
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
    let parent = parent.cloned();
    let tray = tray.clone();
    let dbus = dbus.clone();
    crate::dialogs::singleton::present_global("log_viewer", move || {
        build_log_viewer(parent.as_ref(), &tray, &dbus)
    });
}

fn build_log_viewer(
    parent: Option<&gtk4::Window>,
    tray: &ksni::blocking::Handle<crate::tray::VpnTray>,
    dbus: &zbus::Connection,
) -> gtk4::Window {
    let settings = Settings::new();
    let window = Window::builder()
        .title("VPN Logs")
        .modal(false)
        .default_width(settings.logs_window_width())
        .default_height(settings.logs_window_height())
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
            notebook.append_page(&tab.page, Some(&gtk4::Label::new(Some(config_name))));
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
    let settings_for_close = settings.clone();
    window.connect_close_request(move |w| {
        if let Some(tx) = cancel_for_close.borrow_mut().take() {
            let _ = tx.send(());
        }
        let (width, height) = (w.width(), w.height());
        if width > 0 && height > 0 {
            settings_for_close.set_logs_window_width(width);
            settings_for_close.set_logs_window_height(height);
        }
        glib::Propagation::Proceed
    });

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
                                &tab.page,
                                Some(&gtk4::Label::new(Some(&config_name))),
                            );
                            tabs_map.insert(config_name.clone(), tab);
                        }

                        if let Some(tab) = tabs_map.get(&config_name) {
                            let entry = log_buffer::LogEntry {
                                timestamp,
                                session_path: session_path.clone(),
                                config_name: config_name.clone(),
                                category,
                                message: message.to_string(),
                            };
                            tab.entries.borrow_mut().push(entry.clone());
                            let search = tab.search_text.borrow().clone();
                            let level_min = *tab.level_min.borrow();
                            if passes_filter(&entry, &search, level_min) {
                                let mut end_iter = tab.buffer.end_iter();
                                tab.buffer.insert(&mut end_iter, &line);
                                tab.text_view.scroll_mark_onscreen(&tab.end_mark);
                                tab.export_btn.set_sensitive(true);
                            }
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

    window
}

/// Create a tab for a config name, populated with all buffered history
/// across all session paths for that config. Tab layout is a vertical
/// box: filter strip on top (search + level dropdown + copy button),
/// scrolled log area below. Filter state is per-tab and independent.
fn create_tab_for_config(config_name: &str) -> TabState {
    let buffer = gtk4::TextBuffer::new(None);

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
    all_entries.sort_by_key(|e| e.timestamp);

    let entries = Rc::new(RefCell::new(all_entries));
    let search_text = Rc::new(RefCell::new(String::new()));
    let level_min = Rc::new(RefCell::new(0u32));

    // Initial buffer paint — empty filter shows everything; if no history
    // yet, show a listener hint so the tab isn't blank on first open.
    if entries.borrow().is_empty() {
        let header = format!("Listening for log messages from '{}'...\n", config_name);
        buffer.set_text(&header);
    } else {
        rebuild_buffer(&buffer, &entries.borrow(), "", 0);
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

    // --- Filter strip widgets ---
    let search_entry = gtk4::Entry::builder()
        .placeholder_text("Search log…")
        .hexpand(true)
        .build();

    let level_model = gtk4::StringList::new(&["All levels", "Warn and above", "Error only"]);
    let level_dropdown = gtk4::DropDown::builder().model(&level_model).build();

    let copy_btn = gtk4::Button::builder()
        .label("Copy")
        .tooltip_text("Copy visible (filtered) log to clipboard")
        .build();

    let export_btn = gtk4::Button::builder()
        .label("Export…")
        .tooltip_text("Save visible (filtered) log entries to a file")
        .sensitive(!entries.borrow().is_empty())
        .build();

    let strip = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
    strip.set_margin_top(6);
    strip.set_margin_bottom(6);
    strip.set_margin_start(8);
    strip.set_margin_end(8);
    strip.append(&search_entry);
    strip.append(&level_dropdown);
    strip.append(&copy_btn);
    strip.append(&export_btn);

    // --- Wire filter signals ---
    {
        let entries = Rc::clone(&entries);
        let search_text = Rc::clone(&search_text);
        let level_min = Rc::clone(&level_min);
        let buffer = buffer.clone();
        let text_view = text_view.clone();
        let end_mark = end_mark.clone();
        let export_btn = export_btn.clone();
        search_entry.connect_changed(move |e| {
            *search_text.borrow_mut() = e.text().to_string();
            rebuild_buffer(
                &buffer,
                &entries.borrow(),
                &search_text.borrow(),
                *level_min.borrow(),
            );
            text_view.scroll_mark_onscreen(&end_mark);
            export_btn.set_sensitive(any_passes_filter(
                &entries.borrow(),
                &search_text.borrow(),
                *level_min.borrow(),
            ));
        });
    }

    {
        let entries = Rc::clone(&entries);
        let search_text = Rc::clone(&search_text);
        let level_min = Rc::clone(&level_min);
        let buffer = buffer.clone();
        let text_view = text_view.clone();
        let end_mark = end_mark.clone();
        let export_btn = export_btn.clone();
        level_dropdown.connect_selected_notify(move |dd| {
            *level_min.borrow_mut() = level_index_to_min(dd.selected());
            rebuild_buffer(
                &buffer,
                &entries.borrow(),
                &search_text.borrow(),
                *level_min.borrow(),
            );
            text_view.scroll_mark_onscreen(&end_mark);
            export_btn.set_sensitive(any_passes_filter(
                &entries.borrow(),
                &search_text.borrow(),
                *level_min.borrow(),
            ));
        });
    }

    {
        let buffer = buffer.clone();
        let text_view = text_view.clone();
        copy_btn.connect_clicked(move |_| {
            let text = buffer.text(&buffer.start_iter(), &buffer.end_iter(), false);
            text_view.clipboard().set_text(&text);
        });
    }

    {
        let entries = Rc::clone(&entries);
        let search_text = Rc::clone(&search_text);
        let level_min = Rc::clone(&level_min);
        let config_name_owned = config_name.to_string();
        export_btn.connect_clicked(move |btn| {
            let parent = btn.root().and_then(|r| r.downcast::<gtk4::Window>().ok());
            let visible: Vec<log_buffer::LogEntry> = entries
                .borrow()
                .iter()
                .filter(|e| passes_filter(e, &search_text.borrow(), *level_min.borrow()))
                .cloned()
                .collect();
            if visible.is_empty() {
                return;
            }
            show_export_dialog(parent.as_ref(), config_name_owned.clone(), visible);
        });
    }

    let page = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    page.append(&strip);
    page.append(&scrolled);

    TabState {
        buffer,
        end_mark,
        text_view,
        page,
        entries,
        search_text,
        level_min,
        export_btn,
    }
}

/// Open a Save-As file chooser and write the export to the selected path.
fn show_export_dialog(
    parent: Option<&gtk4::Window>,
    config_name: String,
    entries: Vec<log_buffer::LogEntry>,
) {
    use gtk4::{FileChooserAction, FileChooserDialog, ResponseType};

    let dialog = FileChooserDialog::builder()
        .title("Export Logs")
        .action(FileChooserAction::Save)
        .modal(true)
        .build();
    dialog.add_button("Cancel", ResponseType::Cancel);
    dialog.add_button("Save", ResponseType::Accept);

    let default_name = format!(
        "openvpn3-gui-{}-{}.log",
        sanitize_filename(&config_name),
        chrono::Local::now().format("%Y%m%d-%H%M%S"),
    );
    dialog.set_current_name(&default_name);

    if let Some(p) = parent {
        dialog.set_transient_for(Some(p));
    }

    dialog.connect_response(move |dlg, resp| {
        if resp == ResponseType::Accept
            && let Some(file) = dlg.file()
            && let Some(path) = file.path()
        {
            let text = format_export(&entries, &config_name, chrono::Local::now());
            match std::fs::write(&path, text) {
                Ok(()) => tracing::info!("Exported logs to {:?}", path),
                Err(e) => {
                    tracing::warn!("Log export to {:?} failed: {}", path, e);
                    crate::dialogs::show_error_notification(
                        "Log Export Failed",
                        &format!("Could not write to {}: {}", path.display(), e),
                    );
                }
            }
        }
        dlg.close();
    });

    dialog.show();
}

/// Strip filesystem-unfriendly characters from a config name for use in a
/// default export filename. Keeps alphanumerics, dash, underscore; replaces
/// anything else with `_`.
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
