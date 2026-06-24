//! Unit tests for `super::Settings`.
//!
//! Extracted from `gsettings.rs` so the getter/setter module stays under
//! the size threshold. Pure move — tests exercise the same `new_empty()`
//! constructor and public API as before; no logic changed.

use super::Settings;

// --- Fallback behaviour when GSettings schema is absent ---

#[test]
fn test_startup_action_default() {
    assert_eq!(Settings::new_empty().startup_action(), "");
}

#[test]
fn test_show_notifications_default() {
    assert!(Settings::new_empty().show_notifications());
}

#[test]
fn test_most_recent_config_default() {
    let s = Settings::new_empty();
    assert_eq!(s.get_most_recent_config(), ("".into(), "".into()));
}

#[test]
fn test_specific_config_path_default() {
    assert_eq!(Settings::new_empty().specific_config_path(), "");
}

// --- Setters do not panic when schema is absent ---

#[test]
fn test_set_startup_action_no_panic() {
    Settings::new_empty().set_startup_action("connect-recent");
}

#[test]
fn test_set_most_recent_config_no_panic() {
    Settings::new_empty().set_most_recent_config("/some/path", "My VPN");
}

#[test]
fn test_set_show_notifications_no_panic() {
    Settings::new_empty().set_show_notifications(false);
}

#[test]
fn test_stats_refresh_interval_default() {
    assert_eq!(Settings::new_empty().stats_refresh_interval(), 30);
}

#[test]
fn test_set_stats_refresh_interval_no_panic() {
    Settings::new_empty().set_stats_refresh_interval(60);
}

#[test]
fn test_connection_timeout_default() {
    assert_eq!(Settings::new_empty().connection_timeout(), 30);
}

#[test]
fn test_set_connection_timeout_no_panic() {
    Settings::new_empty().set_connection_timeout(60);
}

#[test]
fn test_health_check_stall_seconds_default() {
    assert_eq!(Settings::new_empty().health_check_stall_seconds(), 60);
}

#[test]
fn test_set_health_check_stall_seconds_no_panic() {
    Settings::new_empty().set_health_check_stall_seconds(120);
}

#[test]
fn test_warn_on_unexpected_disconnect_default() {
    assert!(Settings::new_empty().warn_on_unexpected_disconnect());
}

#[test]
fn test_set_warn_on_unexpected_disconnect_no_panic() {
    Settings::new_empty().set_warn_on_unexpected_disconnect(false);
}

#[test]
fn test_auto_reconnect_default_false() {
    assert!(!Settings::new_empty().auto_reconnect());
}

#[test]
fn test_set_auto_reconnect_no_panic() {
    Settings::new_empty().set_auto_reconnect(true);
}

#[test]
fn test_auto_reconnect_delay_default() {
    assert_eq!(Settings::new_empty().auto_reconnect_delay_seconds(), 30);
}

#[test]
fn test_set_auto_reconnect_delay_no_panic() {
    Settings::new_empty().set_auto_reconnect_delay_seconds(60);
}

#[test]
fn test_enable_kill_switch_default_false() {
    assert!(!Settings::new_empty().enable_kill_switch());
}

#[test]
fn test_set_enable_kill_switch_no_panic() {
    Settings::new_empty().set_enable_kill_switch(true);
}

#[test]
fn test_kill_switch_allow_lan_default_true() {
    assert!(Settings::new_empty().kill_switch_allow_lan());
}

#[test]
fn test_set_kill_switch_allow_lan_no_panic() {
    Settings::new_empty().set_kill_switch_allow_lan(false);
}

#[test]
fn test_show_first_run_help_default_true() {
    assert!(Settings::new_empty().show_first_run_help());
}

#[test]
fn test_set_show_first_run_help_no_panic() {
    Settings::new_empty().set_show_first_run_help(false);
}

#[test]
fn test_launch_on_login_default_false() {
    assert!(!Settings::new_empty().launch_on_login());
}

#[test]
fn test_set_launch_on_login_no_panic() {
    Settings::new_empty().set_launch_on_login(true);
}

#[test]
fn test_kill_switch_block_during_pause_default_false() {
    assert!(!Settings::new_empty().kill_switch_block_during_pause());
}

#[test]
fn test_set_kill_switch_block_during_pause_no_panic() {
    Settings::new_empty().set_kill_switch_block_during_pause(true);
}

#[test]
fn test_bypass_cidrs_default_empty() {
    assert!(Settings::new_empty().bypass_cidrs().is_empty());
}

#[test]
fn test_set_bypass_cidrs_no_panic() {
    Settings::new_empty().set_bypass_cidrs(&["10.0.0.0/8".to_string()]);
}

#[test]
fn test_bypass_cidrs_disabled_default_empty() {
    assert!(Settings::new_empty().bypass_cidrs_disabled().is_empty());
}

#[test]
fn test_set_bypass_cidrs_disabled_no_panic() {
    Settings::new_empty().set_bypass_cidrs_disabled(&["10.0.0.0/8".to_string()]);
}

#[test]
fn test_bypass_cidrs_max_count_default() {
    assert_eq!(Settings::new_empty().bypass_cidrs_max_count(), 32);
}

#[test]
fn test_logs_window_width_default() {
    assert_eq!(Settings::new_empty().logs_window_width(), 800);
}

#[test]
fn test_set_logs_window_width_no_panic() {
    Settings::new_empty().set_logs_window_width(1024);
}

#[test]
fn test_logs_window_height_default() {
    assert_eq!(Settings::new_empty().logs_window_height(), 600);
}

#[test]
fn test_set_logs_window_height_no_panic() {
    Settings::new_empty().set_logs_window_height(768);
}
