//! Periodic session statistics poller.
//!
//! Polls `BYTES_IN/OUT` from each connected session's D-Bus `statistics`
//! property and updates the tray. Doubles as the tooltip-refresh tick — the
//! ksni tray re-reads tooltip text whenever we call `tray.update(|_| {})`.

use crate::settings::Settings;
use crate::tray::VpnTray;

/// Spawn the stats polling loop on the GTK main loop.
///
/// Interval is re-read from settings each tick so preference changes take
/// effect on the next iteration.
pub(super) fn setup_stats_poller(dbus: &zbus::Connection, tray: &ksni::blocking::Handle<VpnTray>) {
    let tray_for_timer = tray.clone();
    let dbus_for_stats = dbus.clone();
    glib::spawn_future_local(async move {
        loop {
            let secs = Settings::new().tooltip_refresh_interval();
            glib::timeout_future_seconds(secs).await;

            let session_paths: Vec<(String, bool)> = tray_for_timer
                .update(|t| {
                    t.sessions
                        .iter()
                        .map(|(path, s)| (path.clone(), s.status.is_connected()))
                        .collect()
                })
                .unwrap_or_default();

            for (path, connected) in session_paths {
                if !connected {
                    continue;
                }
                if let Ok(obj_path) = zbus::zvariant::OwnedObjectPath::try_from(path.as_str())
                    && let Ok(builder) =
                        crate::dbus::session::SessionProxy::builder(&dbus_for_stats).path(obj_path)
                    && let Ok(session) = builder.build().await
                    && let Ok(stats) = session.statistics().await
                {
                    let bi = stats.get("BYTES_IN").copied().unwrap_or(0) as u64;
                    let bo = stats.get("BYTES_OUT").copied().unwrap_or(0) as u64;
                    let p = path.clone();
                    tray_for_timer.update(move |t| {
                        if let Some(s) = t.sessions.get_mut(&p) {
                            s.bytes_in = bi;
                            s.bytes_out = bo;
                        }
                    });
                }
            }

            tray_for_timer.update(|_| {});
        }
    });
}
