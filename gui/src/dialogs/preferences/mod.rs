//! Preferences dialog — notebook shell delegating to tab modules.
//!
//! No testable pure surface — GTK widget builder.

mod general_tab;
mod routing_tab;
mod security_tab;

use gtk4::prelude::*;
use gtk4::{Box as GtkBox, Label, Notebook, Orientation};

use super::layout::make_button_row;
use crate::settings::Settings;
use crate::tray::ConfigInfo;

/// Show the preferences dialog.
///
/// Reads current settings and writes them back on Save.
pub fn show_preferences_dialog(
    parent: Option<&gtk4::Window>,
    settings: &Settings,
    configs: Vec<ConfigInfo>,
    tray: ksni::blocking::Handle<crate::tray::VpnTray>,
    dbus: zbus::Connection,
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

    let (general, gw) = general_tab::build(settings, &configs);
    let (security, sw, was_killswitch_on) = security_tab::build(settings, &window);
    let (routing, rw) = routing_tab::build(settings);

    let notebook = Notebook::builder().hexpand(true).vexpand(true).build();
    let general_tab_label = Label::new(Some("General"));
    let security_tab_label = Label::new(Some("Security"));
    let routing_tab_label = Label::new(Some("Routing"));
    notebook.append_page(&general, Some(&general_tab_label));
    notebook.append_page(&security, Some(&security_tab_label));
    notebook.append_page(&routing, Some(&routing_tab_label));
    outer.append(&notebook);

    let settings_clone = settings.clone();
    let tray_for_save = tray.clone();
    let dbus_for_save = dbus.clone();
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
                let action = if gw.radio_specific.is_active() {
                    if let Some(id) = gw.config_combo.active_id() {
                        settings_clone.set_specific_config_path(&id);
                        let name = gw
                            .config_combo
                            .active_text()
                            .map(|t| t.to_string())
                            .unwrap_or_default();
                        settings_clone.set_most_recent_config(&id, &name);
                    }
                    "connect-specific"
                } else if gw.radio_recent.is_active() {
                    "connect-recent"
                } else {
                    "none"
                };
                settings_clone.set_startup_action(action);
                settings_clone.set_show_notifications(gw.notif_check.is_active());
                settings_clone.set_show_first_run_help(gw.first_run_check.is_active());
                settings_clone.set_stats_refresh_interval(gw.interval_spin.value() as u32);
                settings_clone.set_connection_timeout(gw.timeout_spin.value() as u32);
                settings_clone.set_health_check_stall_seconds(if gw.stall_check.is_active() {
                    gw.stall_spin.value() as u32
                } else {
                    0
                });
                settings_clone
                    .set_warn_on_unexpected_disconnect(sw.warn_disconnect_check.is_active());
                settings_clone.set_enable_kill_switch(sw.enable_killswitch_check.is_active());
                settings_clone.set_kill_switch_allow_lan(sw.allow_lan_check.is_active());
                settings_clone
                    .set_kill_switch_block_during_pause(sw.block_during_pause_check.is_active());
                let ks_on = sw.enable_killswitch_check.is_active();
                tray_for_save.update(move |t| {
                    t.kill_switch_enabled = ks_on;
                });
                let killswitch_now_on =
                    !was_killswitch_on && sw.enable_killswitch_check.is_active();
                let killswitch_now_off =
                    was_killswitch_on && !sw.enable_killswitch_check.is_active();
                if killswitch_now_on {
                    let allow_lan = sw.allow_lan_check.is_active();
                    let dbus = dbus_for_save.clone();
                    let paths: Vec<String> = tray_for_save
                        .update(|t| {
                            t.sessions
                                .iter()
                                .filter(|(_, s)| s.status.is_connected())
                                .map(|(p, _)| p.clone())
                                .collect()
                        })
                        .unwrap_or_default();
                    if !paths.is_empty() {
                        let tray_apply = tray_for_save.clone();
                        glib::spawn_future_local(async move {
                            for path in paths {
                                match crate::app::apply_kill_switch(&dbus, &path, allow_lan).await {
                                    Ok(true) => {
                                        let p = path.clone();
                                        tray_apply.update(move |t| {
                                            if let Some(s) = t.sessions.get_mut(&p) {
                                                s.kill_switch_active = true;
                                            }
                                        });
                                        crate::dialogs::show_killswitch_active_notification();
                                    }
                                    Ok(false) => {}
                                    Err(e) => tracing::warn!(
                                        "kill-switch mid-session apply failed: {}",
                                        e
                                    ),
                                }
                            }
                        });
                    }
                } else if killswitch_now_off {
                    let tray_clear = tray_for_save.clone();
                    glib::spawn_future_local(async move {
                        crate::dbus::killswitch::remove_rules().await;
                        tray_clear.update(|t| {
                            for s in t.sessions.values_mut() {
                                s.kill_switch_active = false;
                            }
                        });
                        crate::dialogs::show_killswitch_inactive_notification();
                    });
                }

                // Bypass CIDR list: persist to GSettings, and if any session
                // is currently connected push the new list to the helper so
                // the change takes effect immediately (cold-start re-apply in
                // dbus_init covers the no-session-connected case on next
                // connect). Independent of kill-switch state per D4.
                let new_cidrs = rw.entries.borrow().clone();
                let new_disabled = rw.disabled.borrow().clone();
                let cidrs_changed = new_cidrs != rw.initial;
                let disabled_changed = new_disabled != rw.initial_disabled;
                if cidrs_changed || disabled_changed {
                    if cidrs_changed {
                        settings_clone.set_bypass_cidrs(&new_cidrs);
                    }
                    if disabled_changed {
                        settings_clone.set_bypass_cidrs_disabled(&new_disabled);
                    }
                    // Helper push uses the enabled-only subset — disabled
                    // entries are GUI-side state and never reach the helper.
                    let enabled = crate::settings::enabled_cidrs(&new_cidrs, &new_disabled);
                    let any_connected = tray_for_save
                        .update(|t| t.sessions.values().any(|s| s.status.is_connected()))
                        .unwrap_or(false);
                    if any_connected {
                        let tray_for_bypass = tray_for_save.clone();
                        glib::spawn_future_local(async move {
                            if enabled.is_empty() {
                                crate::dbus::killswitch::remove_bypass_routes().await;
                                crate::dbus::killswitch::clear_bypass_cidrs().await;
                                tray_for_bypass
                                    .update(|t| t.bypass_state = crate::tray::BypassState::Off);
                            } else {
                                let count = enabled.len();
                                let set_ok =
                                    crate::dbus::killswitch::set_bypass_cidrs(enabled).await;
                                let apply_ok =
                                    set_ok && crate::dbus::killswitch::apply_bypass_routes().await;
                                if apply_ok {
                                    tray_for_bypass.update(move |t| {
                                        t.bypass_state = crate::tray::BypassState::Active(count)
                                    });
                                    crate::dialogs::show_bypass_active_notification(count);
                                } else {
                                    tray_for_bypass.update(|t| {
                                        t.bypass_state = crate::tray::BypassState::Failed
                                    });
                                    crate::dialogs::show_bypass_failed_notification();
                                }
                            }
                        });
                    }
                }

                window.close();
            }
        },
    ));

    window.set_child(Some(&outer));
    window.present();
}
