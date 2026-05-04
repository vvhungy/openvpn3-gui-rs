//! Pure log-line formatting for the tabbed log viewer.
//!
//! Separated from the GTK dialog plumbing in `super` so the rules for
//! "what does a log line look like" can be unit-tested without spinning up
//! a TextBuffer or D-Bus connection.

fn log_category_label(category: u32) -> &'static str {
    match category {
        1 => "DEBUG",
        2 => "VERB2",
        3 => "VERB1",
        4 => "INFO",
        5 => "WARN",
        6 => "ERROR",
        7 => "CRIT",
        8 => "FATAL",
        _ => "LOG",
    }
}

/// Format a log line with timestamp and category.
pub(super) fn format_log_line(
    timestamp: &chrono::NaiveTime,
    category: u32,
    message: &str,
) -> String {
    format!(
        "{} [{}] {}\n",
        timestamp.format("%H:%M:%S"),
        log_category_label(category),
        message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_category_label_known_values() {
        assert_eq!(log_category_label(1), "DEBUG");
        assert_eq!(log_category_label(4), "INFO");
        assert_eq!(log_category_label(5), "WARN");
        assert_eq!(log_category_label(6), "ERROR");
        assert_eq!(log_category_label(7), "CRIT");
        assert_eq!(log_category_label(8), "FATAL");
    }

    #[test]
    fn test_log_category_label_unknown_falls_back() {
        assert_eq!(log_category_label(0), "LOG");
        assert_eq!(log_category_label(99), "LOG");
    }

    #[test]
    fn test_format_log_line() {
        let ts = chrono::NaiveTime::from_hms_opt(14, 32, 1).unwrap();
        let line = format_log_line(&ts, 4, "Connecting to server...");
        assert_eq!(line, "14:32:01 [INFO] Connecting to server...\n");
    }

    #[test]
    fn test_format_log_line_error() {
        let ts = chrono::NaiveTime::from_hms_opt(9, 5, 30).unwrap();
        let line = format_log_line(&ts, 6, "Connection refused");
        assert_eq!(line, "09:05:30 [ERROR] Connection refused\n");
    }
}
