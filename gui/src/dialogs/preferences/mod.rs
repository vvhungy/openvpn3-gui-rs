//! Preferences dialog — notebook shell delegating to tab modules.
//!
//! The Save flow is decomposed into focused helpers (CLAUDE.md:63): the only
//! pure surface — startup-action radio selection — is unit-tested; the rest is
//! impure GTK/settings glue and live kill-switch / bypass re-apply, each in its
//! own small gateway function orchestrated by the Save closure.

mod general_tab;
mod routing_tab;
mod security_tab;

use gtk4::prelude::*;
use gtk4::{Box as GtkBox, Label, Notebook, Orientation};

use super::layout::make_button_row;
use crate::settings::Settings;
use crate::tray::ConfigInfo;

use general_tab::GeneralWidgets;
use routing_tab::RoutingWidgets;
use security_tab::SecurityWidgets;

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
    let parent = parent.cloned();
    let settings = settings.clone();
    super::singleton::present_global("preferences", move || {
        build_preferences_window(parent.as_ref(), &settings, configs, tray, dbus)
    });
}

fn build_preferences_window(
    parent: Option<&gtk4::Window>,
    settings: &Settings,
    configs: Vec<ConfigInfo>,
    tray: ksni::blocking::Handle<crate::tray::VpnTray>,
    dbus: zbus::Connection,
) -> gtk4::Window {
    // Non-modal: leaves tray and other surfaces interactable while user
    // configures — fixes the race where modal Preferences hides incoming
    // connection notifications.
    let window = gtk4::Window::builder()
        .title("Preferences")
        .modal(false)
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
                persist_preferences(&settings_clone, &gw, &sw, &tray_for_save);
                apply_kill_switch_transition(
                    &sw,
                    was_killswitch_on,
                    &tray_for_save,
                    &dbus_for_save,
                );
                apply_bypass_changes(&settings_clone, &rw, &tray_for_save);
                window.close();
            }
        },
    ));

    window.set_child(Some(&outer));
    window
}

/// Pure: select the startup action from the General-tab radio state.
///
/// Order mirrors the original `if radio_specific / else if radio_recent / else`
/// chain — "specific" wins when both read active (the radios are grouped, so
/// that case is defensive only).
fn resolve_startup_action(radio_specific: bool, radio_recent: bool) -> &'static str {
    if radio_specific {
        "connect-specific"
    } else if radio_recent {
        "connect-recent"
    } else {
        "none"
    }
}

/// Remember the chosen specific config when the "specific" startup action is
/// selected. Reads combo state, writes Settings — impure GTK glue, no unit
/// surface.
fn remember_specific_config(settings: &Settings, gw: &GeneralWidgets) {
    if gw.radio_specific.is_active()
        && let Some(id) = gw.config_combo.active_id()
    {
        settings.set_specific_config_path(&id);
        let name = gw
            .config_combo
            .active_text()
            .map(|t| t.to_string())
            .unwrap_or_default();
        settings.set_most_recent_config(&id, &name);
    }
}

/// Persist every General + Security tab value to Settings and mirror the
/// kill-switch flag onto the tray handle. Impure GTK glue — no unit surface.
fn persist_preferences(
    settings: &Settings,
    gw: &GeneralWidgets,
    sw: &SecurityWidgets,
    tray: &ksni::blocking::Handle<crate::tray::VpnTray>,
) {
    remember_specific_config(settings, gw);
    settings.set_startup_action(resolve_startup_action(
        gw.radio_specific.is_active(),
        gw.radio_recent.is_active(),
    ));
    settings.set_show_notifications(gw.notif_check.is_active());
    settings.set_show_first_run_help(gw.first_run_check.is_active());
    settings.set_stats_refresh_interval(gw.interval_spin.value() as u32);
    settings.set_connection_timeout(gw.timeout_spin.value() as u32);
    settings.set_health_check_stall_seconds(if gw.stall_check.is_active() {
        gw.stall_spin.value() as u32
    } else {
        0
    });
    settings.set_auto_reconnect(gw.auto_reconnect_check.is_active());
    settings.set_auto_reconnect_delay_seconds(gw.auto_reconnect_spin.value() as u32);
    settings.set_warn_on_unexpected_disconnect(sw.warn_disconnect_check.is_active());
    settings.set_enable_kill_switch(sw.enable_killswitch_check.is_active());
    settings.set_kill_switch_allow_lan(sw.allow_lan_check.is_active());
    settings.set_kill_switch_block_during_pause(sw.block_during_pause_check.is_active());
    let ks_on = sw.enable_killswitch_check.is_active();
    tray.update(move |t| {
        t.kill_switch_enabled = ks_on;
    });
}

/// Apply the kill switch to already-connected sessions mid-session when the
/// user just toggled it on. One `apply` per connected path.
async fn apply_kill_switch_to_sessions(
    dbus: zbus::Connection,
    paths: Vec<String>,
    allow_lan: bool,
    tray: ksni::blocking::Handle<crate::tray::VpnTray>,
) {
    for path in paths {
        match crate::app::apply_kill_switch(&dbus, &path, allow_lan).await {
            Ok(true) => {
                let p = path.clone();
                tray.update(move |t| {
                    if let Some(s) = t.sessions.get_mut(&p) {
                        s.kill_switch_active = true;
                    }
                });
                crate::dialogs::show_killswitch_active_notification();
            }
            Ok(false) => {}
            Err(e) => tracing::warn!("kill-switch mid-session apply failed: {}", e),
        }
    }
}

/// Strip kill-switch rules tray-wide when the user just toggled it off.
async fn clear_kill_switch_rules(tray: ksni::blocking::Handle<crate::tray::VpnTray>) {
    crate::dbus::killswitch::remove_rules().await;
    tray.update(|t| {
        for s in t.sessions.values_mut() {
            s.kill_switch_active = false;
        }
    });
    crate::dialogs::show_killswitch_inactive_notification();
}

/// React to a kill-switch toggle made in the dialog: apply mid-session rules on
/// enable, clear them on disable. No-op when the setting didn't change.
fn apply_kill_switch_transition(
    sw: &SecurityWidgets,
    was_killswitch_on: bool,
    tray: &ksni::blocking::Handle<crate::tray::VpnTray>,
    dbus: &zbus::Connection,
) {
    let now_on = !was_killswitch_on && sw.enable_killswitch_check.is_active();
    let now_off = was_killswitch_on && !sw.enable_killswitch_check.is_active();
    if now_on {
        let allow_lan = sw.allow_lan_check.is_active();
        let dbus = dbus.clone();
        let paths: Vec<String> = tray
            .update(|t| {
                t.sessions
                    .iter()
                    .filter(|(_, s)| s.status.is_connected())
                    .map(|(p, _)| p.clone())
                    .collect()
            })
            .unwrap_or_default();
        if !paths.is_empty() {
            glib::spawn_future_local(apply_kill_switch_to_sessions(
                dbus,
                paths,
                allow_lan,
                tray.clone(),
            ));
        }
    } else if now_off {
        glib::spawn_future_local(clear_kill_switch_rules(tray.clone()));
    }
}

/// Push the new bypass CIDR set to the helper for currently-connected sessions
/// so a Routing-tab change takes effect immediately.
async fn apply_bypass_live(
    tray: ksni::blocking::Handle<crate::tray::VpnTray>,
    enabled: Vec<String>,
) {
    if enabled.is_empty() {
        crate::dbus::killswitch::remove_bypass_routes().await;
        crate::dbus::killswitch::clear_bypass_cidrs().await;
        tray.update(|t| t.bypass_state = crate::tray::BypassState::Off);
    } else {
        let set_ok = crate::dbus::killswitch::set_bypass_cidrs(enabled).await;
        let outcome = if set_ok {
            crate::dbus::killswitch::apply_bypass_routes().await
        } else {
            None
        };
        crate::app::bypass_apply::apply_bypass_outcome_to_tray(&tray, outcome, "preferences save");
    }
}

/// Persist the Routing tab's bypass CIDR list when it changed, and push the
/// enabled subset to the helper live if any session is connected (cold-start
/// re-apply in dbus_init covers the no-session case on next connect;
/// independent of kill-switch state per D4).
fn apply_bypass_changes(
    settings: &Settings,
    rw: &RoutingWidgets,
    tray: &ksni::blocking::Handle<crate::tray::VpnTray>,
) {
    let new_cidrs = rw.entries.borrow().clone();
    let new_disabled = rw.disabled.borrow().clone();
    let cidrs_changed = new_cidrs != rw.initial;
    let disabled_changed = new_disabled != rw.initial_disabled;
    if cidrs_changed || disabled_changed {
        if cidrs_changed {
            settings.set_bypass_cidrs(&new_cidrs);
        }
        if disabled_changed {
            settings.set_bypass_cidrs_disabled(&new_disabled);
        }
        // Helper push uses the enabled-only subset — disabled entries are
        // GUI-side state and never reach the helper.
        let enabled = crate::settings::enabled_cidrs(&new_cidrs, &new_disabled);
        let any_connected = tray
            .update(|t| t.sessions.values().any(|s| s.status.is_connected()))
            .unwrap_or(false);
        if any_connected {
            glib::spawn_future_local(apply_bypass_live(tray.clone(), enabled));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_startup_action;

    #[test]
    fn specific_radio_yields_connect_specific() {
        assert_eq!(resolve_startup_action(true, false), "connect-specific");
    }

    #[test]
    fn specific_takes_precedence_over_recent() {
        // Both active shouldn't happen (radios are grouped), but the original
        // if/else-if order checked specific first — pin that precedence.
        assert_eq!(resolve_startup_action(true, true), "connect-specific");
    }

    #[test]
    fn recent_radio_yields_connect_recent() {
        assert_eq!(resolve_startup_action(false, true), "connect-recent");
    }

    #[test]
    fn neither_radio_yields_none() {
        assert_eq!(resolve_startup_action(false, false), "none");
    }
}
