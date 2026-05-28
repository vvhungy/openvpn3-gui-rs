use gtk4::prelude::*;
use gtk4::{Box as GtkBox, CheckButton, ComboBoxText, Label, Orientation, Separator, SpinButton};

use crate::autostart;
use crate::dialogs::layout::{CONTENT_MARGIN, INDENT, SECTION_SPACING};
use crate::settings::Settings;
use crate::tray::ConfigInfo;

pub(super) struct GeneralWidgets {
    pub radio_specific: CheckButton,
    pub radio_recent: CheckButton,
    pub config_combo: ComboBoxText,
    pub notif_check: CheckButton,
    pub first_run_check: CheckButton,
    pub interval_spin: SpinButton,
    pub timeout_spin: SpinButton,
    pub stall_check: CheckButton,
    pub stall_spin: SpinButton,
    pub auto_reconnect_check: CheckButton,
    pub auto_reconnect_spin: SpinButton,
}

pub(super) fn build(settings: &Settings, configs: &[ConfigInfo]) -> (GtkBox, GeneralWidgets) {
    let general = GtkBox::new(Orientation::Vertical, SECTION_SPACING);
    general.set_margin_top(CONTENT_MARGIN);
    general.set_margin_bottom(CONTENT_MARGIN);
    general.set_margin_start(CONTENT_MARGIN);
    general.set_margin_end(CONTENT_MARGIN);

    let startup_label = Label::builder()
        .label("<b>Startup Behavior</b>")
        .use_markup(true)
        .halign(gtk4::Align::Start)
        .build();
    general.append(&startup_label);

    let launch_on_login_check = CheckButton::builder()
        .label("Launch on login")
        .active(autostart::is_enabled())
        .build();
    {
        let settings_for_toggle = settings.clone();
        launch_on_login_check.connect_toggled(move |btn| {
            let want = btn.is_active();
            let res = if want {
                autostart::enable()
            } else {
                autostart::disable()
            };
            match res {
                Ok(()) => settings_for_toggle.set_launch_on_login(want),
                Err(e) => {
                    tracing::error!(
                        "autostart {} failed: {}",
                        if want { "enable" } else { "disable" },
                        e
                    );
                    crate::dialogs::show_error_notification(
                        "Launch on Login Failed",
                        &format!("Could not update autostart entry: {}", e),
                    );
                }
            }
        });
    }
    general.append(&launch_on_login_check);

    general.append(&Separator::new(Orientation::Horizontal));

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

    general.append(&radio_none);
    general.append(&radio_recent);
    general.append(&radio_specific);

    let config_combo = ComboBoxText::new();
    for config in configs {
        config_combo.append(Some(&config.path), &config.name);
    }
    if !current_specific.is_empty() {
        config_combo.set_active_id(Some(&current_specific));
    } else if !configs.is_empty() {
        config_combo.set_active(Some(0));
    }
    config_combo.set_sensitive(current_action == "connect-specific");
    config_combo.set_margin_start(INDENT);
    general.append(&config_combo);

    {
        let combo = config_combo.clone();
        radio_specific.connect_toggled(move |btn| {
            combo.set_sensitive(btn.is_active());
        });
    }

    general.append(&Separator::new(Orientation::Horizontal));

    let notif_check = CheckButton::builder()
        .label("Show desktop notifications")
        .active(settings.show_notifications())
        .build();
    general.append(&notif_check);

    let first_run_check = CheckButton::builder()
        .label("Show first-run service help")
        .active(settings.show_first_run_help())
        .margin_start(INDENT)
        .build();
    general.append(&first_run_check);

    let interval_row = GtkBox::new(Orientation::Horizontal, 8);
    let interval_label = Label::builder()
        .label("Menu update interval (seconds):")
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    let interval_spin = SpinButton::with_range(10.0, 300.0, 10.0);
    interval_spin.set_value(settings.stats_refresh_interval() as f64);
    interval_row.append(&interval_label);
    interval_row.append(&interval_spin);
    general.append(&interval_row);

    let timeout_row = GtkBox::new(Orientation::Horizontal, 8);
    let timeout_label = Label::builder()
        .label("Connection timeout (seconds):")
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    let timeout_spin = SpinButton::with_range(5.0, 300.0, 5.0);
    timeout_spin.set_value(settings.connection_timeout() as f64);
    timeout_row.append(&timeout_label);
    timeout_row.append(&timeout_spin);
    general.append(&timeout_row);

    let current_stall = settings.health_check_stall_seconds();
    let stall_check = CheckButton::builder()
        .label("Detect stalled connections")
        .active(current_stall > 0)
        .build();
    general.append(&stall_check);

    let stall_row = GtkBox::new(Orientation::Horizontal, 8);
    stall_row.set_margin_start(INDENT);
    let stall_label = Label::builder()
        .label("Stall threshold (seconds):")
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    let stall_spin = SpinButton::with_range(10.0, 600.0, 10.0);
    let initial_stall = if current_stall > 0 { current_stall } else { 60 };
    stall_spin.set_value(initial_stall as f64);
    stall_spin.set_sensitive(current_stall > 0);
    stall_row.append(&stall_label);
    stall_row.append(&stall_spin);
    general.append(&stall_row);

    {
        let stall_spin = stall_spin.clone();
        stall_check.connect_toggled(move |btn| {
            stall_spin.set_sensitive(btn.is_active());
        });
    }

    let auto_reconnect_check = CheckButton::builder()
        .label("Auto-reconnect after unexpected disconnect")
        .active(settings.auto_reconnect())
        .build();
    general.append(&auto_reconnect_check);

    let auto_reconnect_row = GtkBox::new(Orientation::Horizontal, 8);
    auto_reconnect_row.set_margin_start(INDENT);
    let auto_reconnect_label = Label::builder()
        .label("Reconnect delay (seconds):")
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    let auto_reconnect_spin = SpinButton::with_range(5.0, 300.0, 5.0);
    auto_reconnect_spin.set_value(settings.auto_reconnect_delay_seconds() as f64);
    auto_reconnect_spin.set_sensitive(settings.auto_reconnect());
    auto_reconnect_row.append(&auto_reconnect_label);
    auto_reconnect_row.append(&auto_reconnect_spin);
    general.append(&auto_reconnect_row);

    {
        let spin = auto_reconnect_spin.clone();
        auto_reconnect_check.connect_toggled(move |btn| {
            spin.set_sensitive(btn.is_active());
        });
    }

    let widgets = GeneralWidgets {
        radio_specific,
        radio_recent,
        config_combo,
        notif_check,
        first_run_check,
        interval_spin,
        timeout_spin,
        stall_check,
        stall_spin,
        auto_reconnect_check,
        auto_reconnect_spin,
    };

    (general, widgets)
}
