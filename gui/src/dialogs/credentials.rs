//! Credentials dialog
//!
//! Dynamic dialog for collecting VPN credentials from the user.
//! Supports any combination of fields: username, password, OTP, etc.
//!
//! No testable pure surface — GTK widget builder.

use std::cell::Cell;
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{Box as GtkBox, CheckButton, Entry, Grid, Label, Orientation, PasswordEntry};

use super::layout::{CONTENT_MARGIN, GRID_SPACING, make_button_row};

/// A credential field descriptor
#[derive(Debug, Clone)]
pub struct CredentialField {
    /// Original D-Bus label used for slot matching and credential storage
    pub key: String,
    /// Display label shown in the UI (e.g. "Auth Username", "Auth Password")
    pub label: String,
    /// Whether the input should be masked (password-style)
    pub masked: bool,
    /// Whether this field can be stored in the credential store
    pub can_store: bool,
    /// Pre-filled value from credential store (if any)
    pub saved_value: Option<String>,
}

/// Show a dynamic credentials dialog based on the fields required by the VPN.
///
/// `on_submit` receives the list of (label, value, can_store) tuples and the remember flag.
/// `on_cancel` is called if the user cancels.
pub fn show_credentials_dialog<F, C>(
    parent: Option<&gtk4::Window>,
    config_name: &str,
    fields: &[CredentialField],
    on_submit: F,
    on_cancel: C,
) where
    F: Fn(Vec<(String, String)>, bool) + 'static,
    C: Fn() + 'static,
{
    let window = gtk4::Window::builder()
        .title("VPN Credentials")
        .modal(true)
        .resizable(false)
        .build();

    if let Some(p) = parent {
        window.set_transient_for(Some(p));
    }

    let vbox = GtkBox::new(Orientation::Vertical, 0);

    let grid = Grid::builder()
        .margin_top(CONTENT_MARGIN)
        .margin_bottom(CONTENT_MARGIN)
        .margin_start(CONTENT_MARGIN)
        .margin_end(CONTENT_MARGIN)
        .row_spacing(GRID_SPACING)
        .column_spacing(GRID_SPACING)
        .build();

    // Config name label
    let config_label = Label::builder()
        .label(format!("Configuration: {}", config_name))
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    grid.attach(&config_label, 0, 0, 2, 1);

    // Dynamically create entry fields for each credential slot
    let mut entry_getters: Vec<(String, Box<dyn Fn() -> String>)> = Vec::new();
    let mut first_empty_entry: Option<gtk4::Widget> = None;
    let has_storable = fields.iter().any(|f| f.can_store);

    for (i, field) in fields.iter().enumerate() {
        let row = (i + 1) as i32;

        let label = Label::builder()
            .label(format!("{}:", field.label))
            .halign(gtk4::Align::Start)
            .build();
        grid.attach(&label, 0, row, 1, 1);

        let field_key = field.key.clone();

        if field.masked {
            let entry = PasswordEntry::builder()
                .hexpand(true)
                .placeholder_text(format!("Enter {}", field.label.to_lowercase()))
                .show_peek_icon(true)
                .build();
            if let Some(ref val) = field.saved_value {
                entry.set_text(val);
            }
            if first_empty_entry.is_none() && field.saved_value.is_none() {
                first_empty_entry = Some(entry.clone().upcast());
            }
            grid.attach(&entry, 1, row, 1, 1);
            let entry_clone = entry.clone();
            entry_getters.push((field_key, Box::new(move || entry_clone.text().to_string())));
        } else {
            let entry = Entry::builder()
                .hexpand(true)
                .placeholder_text(format!("Enter {}", field.label.to_lowercase()))
                .build();
            if let Some(ref val) = field.saved_value {
                entry.set_text(val);
            }
            if first_empty_entry.is_none() && field.saved_value.is_none() {
                first_empty_entry = Some(entry.clone().upcast());
            }
            grid.attach(&entry, 1, row, 1, 1);
            let entry_clone = entry.clone();
            entry_getters.push((field_key, Box::new(move || entry_clone.text().to_string())));
        }
    }

    // Remember checkbox (only if any field supports storage)
    let remember_row = (fields.len() + 1) as i32;
    let remember_check = CheckButton::builder()
        .label("Remember credentials")
        .active(has_storable && fields.iter().any(|f| f.saved_value.is_some()))
        .visible(has_storable)
        .build();
    grid.attach(&remember_check, 0, remember_row, 2, 1);

    vbox.append(&grid);

    // Guard against double-fire
    let handled = Rc::new(Cell::new(false));
    let entry_getters = Rc::new(entry_getters);

    vbox.append(&make_button_row(
        "Cancel",
        "Connect",
        {
            let window = window.clone();
            let handled = handled.clone();
            move || {
                if handled.get() {
                    return;
                }
                handled.set(true);
                on_cancel();
                window.close();
            }
        },
        {
            let window = window.clone();
            move || {
                if handled.get() {
                    return;
                }
                handled.set(true);
                let values: Vec<(String, String)> = entry_getters
                    .iter()
                    .map(|(label, getter)| (label.clone(), getter()))
                    .collect();
                let remember = remember_check.is_active();
                on_submit(values, remember);
                window.close();
            }
        },
    ));

    // Focus first empty field, or first field
    if let Some(entry) = first_empty_entry {
        entry.grab_focus();
    }

    window.set_child(Some(&vbox));
    window.present();
}

/// Show a challenge/response dialog for OTP or challenge-based authentication.
///
/// `on_cancel` is called if the user cancels the dialog.
pub fn show_challenge_dialog<F, C>(
    parent: Option<&gtk4::Window>,
    config_name: &str,
    challenge: &str,
    on_response: F,
    on_cancel: C,
) where
    F: Fn(String) + 'static,
    C: Fn() + 'static,
{
    let window = gtk4::Window::builder()
        .title("VPN Authentication Challenge")
        .modal(true)
        .resizable(false)
        .build();

    if let Some(p) = parent {
        window.set_transient_for(Some(p));
    }

    let vbox = GtkBox::new(Orientation::Vertical, 0);

    let grid = Grid::builder()
        .margin_top(CONTENT_MARGIN)
        .margin_bottom(CONTENT_MARGIN)
        .margin_start(CONTENT_MARGIN)
        .margin_end(CONTENT_MARGIN)
        .row_spacing(GRID_SPACING)
        .column_spacing(GRID_SPACING)
        .build();

    // Config name
    let config_label = Label::builder()
        .label(format!("Configuration: {}", config_name))
        .halign(gtk4::Align::Start)
        .build();
    grid.attach(&config_label, 0, 0, 2, 1);

    // Challenge text
    let challenge_label = Label::builder()
        .label(challenge)
        .halign(gtk4::Align::Start)
        .wrap(true)
        .margin_top(GRID_SPACING)
        .margin_bottom(GRID_SPACING)
        .build();
    grid.attach(&challenge_label, 0, 1, 2, 1);

    // Response entry
    let response_label = Label::builder()
        .label("Response:")
        .halign(gtk4::Align::Start)
        .build();
    grid.attach(&response_label, 0, 2, 1, 1);

    let response_entry = Entry::builder()
        .hexpand(true)
        .placeholder_text("Enter response")
        .build();
    grid.attach(&response_entry, 1, 2, 1, 1);

    vbox.append(&grid);

    // Guard against double-fire
    let handled = Rc::new(Cell::new(false));

    let response_clone = response_entry.clone();
    vbox.append(&make_button_row(
        "Cancel",
        "Submit",
        {
            let window = window.clone();
            let handled = handled.clone();
            move || {
                if handled.get() {
                    return;
                }
                handled.set(true);
                on_cancel();
                window.close();
            }
        },
        {
            let window = window.clone();
            move || {
                if handled.get() {
                    return;
                }
                handled.set(true);
                let response_text = response_clone.text().to_string();
                if !response_text.is_empty() {
                    on_response(response_text);
                }
                window.close();
            }
        },
    ));

    response_entry.grab_focus();

    window.set_child(Some(&vbox));
    window.present();
}
