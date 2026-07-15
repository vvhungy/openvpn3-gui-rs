//! Per-session connection statistics dialog.
//!
//! Live-refreshing read-only window: config name + status, connected-since
//! timestamp, duration, tunnel interface name (via `SessionProxy.device_name`),
//! bytes in/out. Refresh interval mirrors the tray stats poller.
//!
//! Per-session singleton (keyed by `session_path`). Auto-closes when the
//! session disappears from the tray.

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::tray::VpnTray;

/// Format byte counts with 1-decimal precision (B/KB/MB/GB).
pub(crate) fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Format an elapsed duration as "Hh Mm Ss" (omitting zero-leading units).
pub(crate) fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m {}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    }
}

/// Open the stats dialog for `session_path`. Singleton per session_path.
pub fn show_stats_dialog(
    parent: Option<&gtk4::Window>,
    dbus: &zbus::Connection,
    tray: &ksni::blocking::Handle<VpnTray>,
    session_path: &str,
) {
    let parent_cloned = parent.cloned();
    let dbus = dbus.clone();
    let tray = tray.clone();
    let session_path = session_path.to_string();
    let key = format!("stats:{session_path}");

    super::singleton::present_keyed(&key, move || {
        build_stats_window(parent_cloned, dbus, tray, session_path)
    });
}

fn build_stats_window(
    parent: Option<gtk4::Window>,
    dbus: zbus::Connection,
    tray: ksni::blocking::Handle<VpnTray>,
    session_path: String,
) -> gtk4::Window {
    let initial = tray
        .update(|t| t.sessions.get(&session_path).cloned())
        .flatten();

    let config_name = initial
        .as_ref()
        .map(|s| s.config_name.clone())
        .unwrap_or_else(|| crate::tray::FALLBACK_NAME.to_string());

    let window = gtk4::Window::builder()
        .title(format!("Statistics — {config_name}"))
        .default_width(420)
        .default_height(320)
        .resizable(false)
        .modal(false)
        .build();

    if let Some(p) = parent.as_ref() {
        window.set_transient_for(Some(p));
    }

    let outer = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    outer.set_margin_top(12);
    outer.set_margin_bottom(12);
    outer.set_margin_start(12);
    outer.set_margin_end(12);

    let group = adw::PreferencesGroup::builder().title("Session").build();

    let status_row = adw::ActionRow::builder().title("Status").build();
    status_row.add_css_class("property");
    let connected_row = adw::ActionRow::builder().title("Connected since").build();
    connected_row.add_css_class("property");
    let duration_row = adw::ActionRow::builder().title("Duration").build();
    duration_row.add_css_class("property");
    let interface_row = adw::ActionRow::builder().title("Interface").build();
    interface_row.add_css_class("property");
    let bytes_in_row = adw::ActionRow::builder().title("Bytes received").build();
    bytes_in_row.add_css_class("property");
    let bytes_out_row = adw::ActionRow::builder().title("Bytes sent").build();
    bytes_out_row.add_css_class("property");

    group.add(&status_row);
    group.add(&connected_row);
    group.add(&duration_row);
    group.add(&interface_row);
    group.add(&bytes_in_row);
    group.add(&bytes_out_row);

    outer.append(&group);

    let close_btn = gtk4::Button::with_label("Close");
    close_btn.set_halign(gtk4::Align::End);
    let win_for_close = window.clone();
    close_btn.connect_clicked(move |_| {
        win_for_close.close();
    });
    outer.append(&close_btn);

    window.set_child(Some(&outer));

    // Initial population with tray data; device_name resolved async on first tick.
    refresh_rows(
        &status_row,
        &connected_row,
        &duration_row,
        &interface_row,
        &bytes_in_row,
        &bytes_out_row,
        initial.as_ref(),
        None,
    );

    let tray_for_timer = tray.clone();
    let session_path_for_timer = session_path.clone();
    let dbus_for_timer = dbus.clone();
    let window_weak = window.downgrade();
    let status_row_w = status_row.clone();
    let connected_row_w = connected_row.clone();
    let duration_row_w = duration_row.clone();
    let interface_row_w = interface_row.clone();
    let bytes_in_row_w = bytes_in_row.clone();
    let bytes_out_row_w = bytes_out_row.clone();

    // Poll the tray's session cache every 1s. Read is a HashMap lookup (no
    // D-Bus cost), so this is cheap and avoids stacking lag on top of the
    // tray poller's own interval (which already gates upstream freshness).
    glib::spawn_future_local(async move {
        let mut dev_name: Option<String> = None;
        loop {
            glib::timeout_future_seconds(1).await;

            let Some(_win) = window_weak.upgrade() else {
                break;
            };

            let current = tray_for_timer
                .update(|t| t.sessions.get(&session_path_for_timer).cloned())
                .flatten();

            // Close when session reaches terminal state. HashMap-removal-based
            // close fires ~3s later (status_handler delays removal so notification
            // chain completes with correct profile name) — checking status here
            // gives the user prompt close without waiting on that delay.
            let terminal = match current.as_ref() {
                None => true,
                Some(s) => s.status.is_disconnected() || s.status.is_error(),
            };
            if terminal {
                if let Some(win) = window_weak.upgrade() {
                    win.close();
                }
                break;
            }

            // Resolve device_name once (per-session property; doesn't change).
            if dev_name.is_none()
                && let Ok(obj_path) =
                    zbus::zvariant::OwnedObjectPath::try_from(session_path_for_timer.as_str())
                && let Ok(builder) =
                    crate::dbus::session::SessionProxy::builder(&dbus_for_timer).path(obj_path)
                && let Ok(proxy) = builder.build().await
                && let Some(s) = proxy.device_name().await.ok()
                && !s.is_empty()
            {
                dev_name = Some(s);
            }

            refresh_rows(
                &status_row_w,
                &connected_row_w,
                &duration_row_w,
                &interface_row_w,
                &bytes_in_row_w,
                &bytes_out_row_w,
                current.as_ref(),
                dev_name.as_deref(),
            );
        }
    });

    window.upcast::<gtk4::Window>()
}

#[allow(clippy::too_many_arguments)]
fn refresh_rows(
    status_row: &adw::ActionRow,
    connected_row: &adw::ActionRow,
    duration_row: &adw::ActionRow,
    interface_row: &adw::ActionRow,
    bytes_in_row: &adw::ActionRow,
    bytes_out_row: &adw::ActionRow,
    session: Option<&crate::tray::SessionInfo>,
    device_name: Option<&str>,
) {
    let (status_txt, since_txt, duration_txt, bi, bo) = match session {
        Some(s) => {
            let status =
                crate::status::get_status_description(s.status.major, s.status.minor).to_string();
            let (since, dur) = match s.connected_at {
                Some(t) => {
                    let dur = format_duration(t.elapsed().as_secs());
                    let since = format_since(t);
                    (since, dur)
                }
                None => ("—".to_string(), "—".to_string()),
            };
            (status, since, dur, s.bytes_in, s.bytes_out)
        }
        None => (
            "Unknown".to_string(),
            "—".to_string(),
            "—".to_string(),
            0u64,
            0u64,
        ),
    };

    status_row.set_subtitle(&status_txt);
    connected_row.set_subtitle(&since_txt);
    duration_row.set_subtitle(&duration_txt);
    interface_row.set_subtitle(device_name.unwrap_or("—"));
    bytes_in_row.set_subtitle(&format_bytes(bi));
    bytes_out_row.set_subtitle(&format_bytes(bo));
}

/// Render `connected_at` as a local wall-clock timestamp.
///
/// `Instant` has no calendar mapping, so we anchor it by computing the
/// offset from now and applying it to `Local::now()`. Drift is bounded by
/// the elapsed monotonic time, not by wall-clock changes after capture.
fn format_since(connected_at: std::time::Instant) -> String {
    let elapsed = connected_at.elapsed();
    let now = chrono::Local::now();
    match chrono::Duration::from_std(elapsed) {
        Ok(d) => (now - d).format("%Y-%m-%d %H:%M:%S").to_string(),
        Err(_) => "—".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.0 KB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    #[test]
    fn test_format_duration_sub_minute() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(45), "45s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(60), "1m 0s");
        assert_eq!(format_duration(125), "2m 5s");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(3600), "1h 0m 0s");
        assert_eq!(format_duration(3725), "1h 2m 5s");
    }
}
