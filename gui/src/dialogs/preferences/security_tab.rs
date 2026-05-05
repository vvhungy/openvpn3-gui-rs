use gtk4::prelude::*;
use gtk4::{Box as GtkBox, Button, CheckButton, Image, Label, Orientation, Separator};

use crate::dialogs::layout::{CONTENT_MARGIN, INDENT, SECTION_SPACING, make_button_row};
use crate::settings::Settings;

pub(super) struct SecurityWidgets {
    pub enable_killswitch_check: CheckButton,
    pub allow_lan_check: CheckButton,
    pub block_during_pause_check: CheckButton,
    pub warn_disconnect_check: CheckButton,
}

pub(super) fn build(settings: &Settings, window: &gtk4::Window) -> (GtkBox, SecurityWidgets, bool) {
    let security = GtkBox::new(Orientation::Vertical, SECTION_SPACING);
    security.set_margin_top(CONTENT_MARGIN);
    security.set_margin_bottom(CONTENT_MARGIN);
    security.set_margin_start(CONTENT_MARGIN);
    security.set_margin_end(CONTENT_MARGIN);

    let enable_killswitch_check = CheckButton::builder()
        .label("Enable kill-switch (block traffic outside VPN)")
        .active(settings.enable_kill_switch())
        .build();
    security.append(&enable_killswitch_check);

    let allow_lan_check = CheckButton::builder()
        .label("Allow LAN access (printer, NAS, local devices)")
        .active(settings.kill_switch_allow_lan())
        .margin_start(INDENT)
        .sensitive(settings.enable_kill_switch())
        .build();
    security.append(&allow_lan_check);

    let block_during_pause_check = CheckButton::builder()
        .label("Block traffic when VPN is paused")
        .active(settings.kill_switch_block_during_pause())
        .margin_start(INDENT)
        .sensitive(settings.enable_kill_switch())
        .build();
    security.append(&block_during_pause_check);

    let warn_disconnect_check = CheckButton::builder()
        .label("Warn on unexpected disconnect")
        .active(settings.warn_on_unexpected_disconnect())
        .margin_start(INDENT)
        .sensitive(!settings.enable_kill_switch())
        .build();
    if settings.enable_kill_switch() {
        warn_disconnect_check.set_active(true);
    }
    security.append(&warn_disconnect_check);

    let helper_hint = Label::builder()
        .label("⚠ Helper not installed — install openvpn3-killswitch-helper")
        .margin_start(INDENT)
        .halign(gtk4::Align::Start)
        .visible(false)
        .build();
    helper_hint.add_css_class("dim-label");
    security.append(&helper_hint);

    {
        let allow_lan_check = allow_lan_check.clone();
        let block_during_pause_check = block_during_pause_check.clone();
        let warn_disconnect_check = warn_disconnect_check.clone();
        let helper_hint = helper_hint.clone();
        enable_killswitch_check.connect_toggled(move |btn| {
            let on = btn.is_active();
            allow_lan_check.set_sensitive(on);
            block_during_pause_check.set_sensitive(on);
            warn_disconnect_check.set_sensitive(!on);
            if on {
                warn_disconnect_check.set_active(true);
            }
            if !on {
                helper_hint.set_visible(false);
            }
        });
    }

    if settings.enable_kill_switch() {
        let helper_hint = helper_hint.clone();
        glib::spawn_future_local(async move {
            let system_bus = zbus::Connection::system().await.ok();
            let present = match system_bus {
                Some(ref conn) => crate::dbus::killswitch::helper_present(conn).await,
                None => false,
            };
            if !present {
                helper_hint.set_visible(true);
            }
        });
    }

    let was_killswitch_on = settings.enable_kill_switch();

    security.append(&Separator::new(Orientation::Horizontal));

    let clear_btn = Button::builder()
        .label("Clear Saved Credentials...")
        .halign(gtk4::Align::Start)
        .build();
    clear_btn.add_css_class("destructive-action");
    security.append(&clear_btn);
    {
        let window_for_clear = window.clone();
        clear_btn.connect_clicked(move |_| {
            show_clear_credentials_confirm(&window_for_clear);
        });
    }

    let widgets = SecurityWidgets {
        enable_killswitch_check,
        allow_lan_check,
        block_during_pause_check,
        warn_disconnect_check,
    };

    (security, widgets, was_killswitch_on)
}

fn show_clear_credentials_confirm(parent: &gtk4::Window) {
    let window = gtk4::Window::builder()
        .transient_for(parent)
        .modal(true)
        .resizable(false)
        .build();

    let outer = GtkBox::new(Orientation::Vertical, 0);

    let hbox = GtkBox::new(Orientation::Horizontal, 16);
    hbox.set_margin_top(CONTENT_MARGIN);
    hbox.set_margin_bottom(16);
    hbox.set_margin_start(CONTENT_MARGIN);
    hbox.set_margin_end(CONTENT_MARGIN);

    let icon = Image::from_icon_name("dialog-warning");
    icon.set_icon_size(gtk4::IconSize::Large);
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
        .label("This will delete all saved username and passwords.\nThis cannot be undone.")
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
