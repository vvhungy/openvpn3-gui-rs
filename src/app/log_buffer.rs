//! Global in-memory log buffer
//!
//! Captures `net.openvpn.v3.backends::Log` signals from app startup so the
//! log viewer dialog can show history, not just live-tail.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use futures::StreamExt;
use tracing::{info, warn};
use zbus::MessageStream;
use zbus::message::Type as MessageType;

/// Maximum number of log entries to keep in memory.
const MAX_LOG_ENTRIES: usize = 5000;

/// A single log entry captured from a D-Bus Log signal.
#[derive(Debug, Clone)]
pub(crate) struct LogEntry {
    /// Wall-clock time the entry was received
    pub timestamp: chrono::NaiveTime,
    /// D-Bus session path that emitted the signal
    pub session_path: String,
    /// Human-readable config name (resolved at capture time)
    pub config_name: String,
    /// Log category (1=DEBUG .. 8=FATAL)
    pub category: u32,
    /// Log message text
    pub message: String,
}

/// Thread-safe global log buffer.
static LOG_BUFFER: LazyLock<Mutex<Vec<LogEntry>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Append an entry to the global buffer, evicting oldest entries if full.
fn push_entry(entry: LogEntry) {
    if let Ok(mut buf) = LOG_BUFFER.lock() {
        if buf.len() >= MAX_LOG_ENTRIES {
            // Remove oldest 10% to avoid evicting on every insert
            let drain_count = MAX_LOG_ENTRIES / 10;
            buf.drain(..drain_count);
        }
        buf.push(entry);
    }
}

/// Get all entries for a specific session path.
pub(crate) fn entries_for_session(session_path: &str) -> Vec<LogEntry> {
    LOG_BUFFER
        .lock()
        .map(|buf| {
            buf.iter()
                .filter(|e| e.session_path == session_path)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Get all distinct session paths that have log entries, with their config names.
pub(crate) fn sessions_with_logs() -> Vec<(String, String)> {
    LOG_BUFFER
        .lock()
        .map(|buf| {
            let mut seen = HashMap::new();
            for entry in buf.iter().rev() {
                seen.entry(entry.session_path.clone())
                    .or_insert_with(|| entry.config_name.clone());
            }
            seen.into_iter().collect()
        })
        .unwrap_or_default()
}

/// Subscribe to all `net.openvpn.v3.backends::Log` signals and buffer them.
///
/// Call once at app startup. The spawned task runs for the lifetime of the app.
pub(crate) async fn subscribe(
    dbus: &zbus::Connection,
    tray: &ksni::blocking::Handle<crate::tray::VpnTray>,
) {
    let match_rule = "type='signal',interface='net.openvpn.v3.backends',member='Log'";
    if let Err(e) = dbus
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "AddMatch",
            &match_rule,
        )
        .await
    {
        warn!("Failed to subscribe to Log signals for buffer: {}", e);
        return;
    }
    info!("Log buffer: subscribed to all Log signals");

    let conn = dbus.clone();
    let tray = tray.clone();
    glib::spawn_future_local(async move {
        let mut stream = MessageStream::from(&conn);

        while let Some(msg_result) = stream.next().await {
            let msg = match msg_result {
                Ok(m) => m,
                Err(e) => {
                    warn!("Log buffer stream error: {}", e);
                    continue;
                }
            };

            if msg.message_type() != MessageType::Signal {
                continue;
            }

            let header = msg.header();
            if header.interface().map(|i| i.as_str()) != Some("net.openvpn.v3.backends") {
                continue;
            }
            if header.member().map(|m| m.as_str()) != Some("Log") {
                continue;
            }

            let session_path = header
                .path()
                .map(|p| p.as_str().to_string())
                .unwrap_or_default();

            let config_name = tray
                .update(|t| t.sessions.get(&session_path).map(|s| s.config_name.clone()))
                .flatten()
                .unwrap_or_else(|| "VPN".to_string());

            if let Ok((_group, category, message)) = msg.body().deserialize::<(u32, u32, &str)>() {
                push_entry(LogEntry {
                    timestamp: chrono::Local::now().time(),
                    session_path,
                    config_name,
                    category,
                    message: message.to_string(),
                });
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize tests that share the global LOG_BUFFER
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn make_entry(session: &str, config: &str, cat: u32, msg: &str) -> LogEntry {
        LogEntry {
            timestamp: chrono::NaiveTime::from_hms_opt(12, 0, 0).unwrap(),
            session_path: session.to_string(),
            config_name: config.to_string(),
            category: cat,
            message: msg.to_string(),
        }
    }

    #[test]
    fn test_push_and_query() {
        let _guard = TEST_LOCK.lock().unwrap();
        LOG_BUFFER.lock().unwrap().clear();

        push_entry(make_entry("/sess/1", "Work", 4, "hello"));
        push_entry(make_entry("/sess/2", "Home", 5, "warning"));
        push_entry(make_entry("/sess/1", "Work", 4, "world"));

        let s1 = entries_for_session("/sess/1");
        assert_eq!(s1.len(), 2);
        assert_eq!(s1[0].message, "hello");
        assert_eq!(s1[1].message, "world");

        let s2 = entries_for_session("/sess/2");
        assert_eq!(s2.len(), 1);
        assert_eq!(s2[0].message, "warning");

        LOG_BUFFER.lock().unwrap().clear();
    }

    #[test]
    fn test_sessions_with_logs() {
        let _guard = TEST_LOCK.lock().unwrap();
        LOG_BUFFER.lock().unwrap().clear();

        push_entry(make_entry("/sess/1", "Work", 4, "a"));
        push_entry(make_entry("/sess/2", "Home", 4, "b"));

        let sessions = sessions_with_logs();
        assert_eq!(sessions.len(), 2);

        let names: Vec<&str> = sessions.iter().map(|(_, n)| n.as_str()).collect();
        assert!(names.contains(&"Work"));
        assert!(names.contains(&"Home"));

        LOG_BUFFER.lock().unwrap().clear();
    }

    #[test]
    fn test_eviction() {
        let _guard = TEST_LOCK.lock().unwrap();
        LOG_BUFFER.lock().unwrap().clear();

        // Fill past MAX_LOG_ENTRIES
        for i in 0..MAX_LOG_ENTRIES + 100 {
            push_entry(make_entry("/sess/1", "Work", 4, &format!("msg-{}", i)));
        }

        let buf = LOG_BUFFER.lock().unwrap();
        assert!(buf.len() <= MAX_LOG_ENTRIES);
        // Oldest entries should have been evicted
        assert!(!buf[0].message.starts_with("msg-0"));

        drop(buf);
        LOG_BUFFER.lock().unwrap().clear();
    }
}
