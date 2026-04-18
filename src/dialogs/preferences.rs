//! Preferences dialog

use gtk4::prelude::*;
use gtk4::{
    Box as GtkBox, Button, CheckButton, ComboBoxText, IconSize, Image, Label, Orientation,
    Separator, SpinButton,
};

use super::layout::{CONTENT_MARGIN, INDENT, SECTION_SPACING, make_button_row};
use crate::settings::Settings;
use crate::tray::ConfigInfo;

/// Show the preferences dialog.
///
/// Reads current settings and writes them back on Save.
pub fn show_preferences_dialog(
    parent: Option<&gtk4::Window>,
    settings: &Settings,
    configs: Vec<ConfigInfo>,
) {
    let window = gtk4::Window::builder()
        .title("Preferences")
        .modal(true)
        .resizable(false)
        .build();

    if let Some(p) = parent {
        window.set_transient_for(Some(p));
    }

    let outer = GtkBox::new(Orientation::Vertical, 0);

    let content = GtkBox::new(Orientation::Vertical, SECTION_SPACING);
    content.set_margin_top(CONTENT_MARGIN);
    content.set_margin_bottom(0);
    content.set_margin_start(CONTENT_MARGIN);
    content.set_margin_end(CONTENT_MARGIN);

    // --- Startup behavior ---
    let startup_label = Label::builder()
        .label("<b>Startup Behavior</b>")
        .use_markup(true)
        .halign(gtk4::Align::Start)
        .build();
    content.append(&startup_label);

    let current_action = settings.startup_action();
    let current_specific = settings.specific_config_path();

    let radio_none = CheckButton::builder().label("Do nothing").build();
    let radio_recent = CheckButton::builder()
        .label("Connect most recent")
        .group(&radio_none)
        .build();
    let radio_specific = CheckButton::builder()
        .label("Connect specific config:")
        .group(&radio_none)
        .build();

    match current_action.as_str() {
        "connect-recent" => radio_recent.set_active(true),
        "connect-specific" => radio_specific.set_active(true),
        _ => radio_none.set_active(true),
    }

    content.append(&radio_none);
    content.append(&radio_recent);
    content.append(&radio_specific);

    // Combo box for specific config (indented under the radio)
    let config_combo = ComboBoxText::new();
    for config in &configs {
        config_combo.append(Some(&config.path), &config.name);
    }
    if !current_specific.is_empty() {
        config_combo.set_active_id(Some(&current_specific));
    } else if !configs.is_empty() {
        config_combo.set_active(Some(0));
    }
    config_combo.set_sensitive(current_action == "connect-specific");
    config_combo.set_margin_start(INDENT);
    content.append(&config_combo);

    // Wire radio toggle → combo sensitivity
    {
        let combo = config_combo.clone();
        radio_specific.connect_toggled(move |btn| {
            combo.set_sensitive(btn.is_active());
        });
    }

    // --- Separator ---
    content.append(&Separator::new(Orientation::Horizontal));

    // --- Notifications ---
    let notif_check = CheckButton::builder()
        .label("Show desktop notifications")
        .active(settings.show_notifications())
        .build();
    content.append(&notif_check);

    // --- Tooltip refresh interval ---
    let interval_row = GtkBox::new(Orientation::Horizontal, 8);
    let interval_label = Label::builder()
        .label("Tooltip refresh interval (seconds):")
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    let interval_spin = SpinButton::with_range(10.0, 300.0, 10.0);
    interval_spin.set_value(settings.tooltip_refresh_interval() as f64);
    interval_row.append(&interval_label);
    interval_row.append(&interval_spin);
    content.append(&interval_row);

    // --- Security ---
    content.append(&Separator::new(Orientation::Horizontal));

    let security_label = Label::builder()
        .label("<b>Security</b>")
        .use_markup(true)
        .halign(gtk4::Align::Start)
        .build();
    content.append(&security_label);

    let clear_btn = Button::builder()
        .label("Clear Saved Credentials...")
        .halign(gtk4::Align::Start)
        .build();
    clear_btn.add_css_class("destructive-action");
    content.append(&clear_btn);

    let window_for_clear = window.clone();
    clear_btn.connect_clicked(move |_| {
        show_clear_credentials_confirm(&window_for_clear);
    });

    outer.append(&content);

    // --- Button row ---
    let settings_clone = settings.clone();
    outer.append(&make_button_row(
        "Cancel",
        "Save",
        {
            let window = window.clone();
            move || window.close()
        },
        {
            let window = window.clone();
            move || {
                let action = if radio_specific.is_active() {
                    if let Some(id) = config_combo.active_id() {
                        settings_clone.set_specific_config_path(&id);
                        let name = config_combo
                            .active_text()
                            .map(|t| t.to_string())
                            .unwrap_or_default();
                        settings_clone.set_most_recent_config(&id, &name);
                    }
                    "connect-specific"
                } else if radio_recent.is_active() {
                    "connect-recent"
                } else {
                    "none"
                };
                settings_clone.set_startup_action(action);
                settings_clone.set_show_notifications(notif_check.is_active());
                settings_clone.set_tooltip_refresh_interval(interval_spin.value() as u32);
                window.close();
            }
        },
    ));

    window.set_child(Some(&outer));
    window.present();
}

/// Show the "Clear all saved credentials?" confirmation dialog.
fn show_clear_credentials_confirm(parent: &gtk4::Window) {
    let window = gtk4::Window::builder()
        .transient_for(parent)
        .modal(true)
        .resizable(false)
        .build();

    let outer = GtkBox::new(Orientation::Vertical, 0);

    // --- Icon + text row ---
    let hbox = GtkBox::new(Orientation::Horizontal, 16);
    hbox.set_margin_top(CONTENT_MARGIN);
    hbox.set_margin_bottom(16);
    hbox.set_margin_start(CONTENT_MARGIN);
    hbox.set_margin_end(CONTENT_MARGIN);

    let icon = Image::from_icon_name("dialog-warning");
    icon.set_icon_size(IconSize::Large);
    icon.set_pixel_size(48);
    hbox.append(&icon);

    let text_box = GtkBox::new(Orientation::Vertical, SECTION_SPACING);
    text_box.set_valign(gtk4::Align::Center);
    let title = Label::builder()
        .label("<b>Clear all saved credentials?</b>")
        .use_markup(true)
        .halign(gtk4::Align::Start)
        .wrap(true)
        .build();
    let body = Label::builder()
        .label("This will delete all saved usernames and passwords.\nThis cannot be undone.")
        .halign(gtk4::Align::Start)
        .wrap(true)
        .build();
    text_box.append(&title);
    text_box.append(&body);
    hbox.append(&text_box);
    outer.append(&hbox);

    outer.append(&Separator::new(Orientation::Horizontal));

    outer.append(&make_button_row(
        "Cancel",
        "Clear",
        {
            let window = window.clone();
            move || window.close()
        },
        {
            let window = window.clone();
            move || {
                window.close();
                glib::spawn_future_local(async move {
                    match crate::credentials::CredentialStore::default()
                        .clear_all_async()
                        .await
                    {
                        Ok(0) => crate::dialogs::show_info_notification(
                            "Credentials Cleared",
                            "No saved credentials found.",
                        ),
                        Ok(n) => crate::dialogs::show_info_notification(
                            "Credentials Cleared",
                            &format!("{} saved credential(s) removed.", n),
                        ),
                        Err(e) => crate::dialogs::show_error_notification(
                            "Clear Failed",
                            &format!("Could not clear credentials: {}", e),
                        ),
                    }
                });
            }
        },
    ));

    window.set_child(Some(&outer));
    window.present();
}
