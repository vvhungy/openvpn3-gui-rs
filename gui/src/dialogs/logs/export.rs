//! Log-export file-chooser dialog.
//!
//! Extracted from `super` so the GTK viewer builder stays focused on tab
//! construction. Self-contained: depends only on the pure `format_export`
//! formatter in `format` and `crate::app::log_buffer::LogEntry`.

use gtk4::prelude::*;
use gtk4::{FileChooserAction, FileChooserDialog, ResponseType};

use super::format::format_export;
use crate::app::log_buffer;

/// Open a Save file chooser and write the given (already filtered) entries
/// to the chosen path as plain text via `format_export`. One line per entry
/// with a header/footer. Errors are surfaced as a notification, not a panic.
pub(super) fn show_export_dialog(
    parent: Option<&gtk4::Window>,
    config_name: String,
    entries: Vec<log_buffer::LogEntry>,
) {
    let dialog = FileChooserDialog::builder()
        .title("Export Logs")
        .action(FileChooserAction::Save)
        .modal(true)
        .build();
    dialog.add_button("Cancel", ResponseType::Cancel);
    dialog.add_button("Save", ResponseType::Accept);

    let default_name = format!(
        "openvpn3-gui-{}-{}.log",
        sanitize_filename(&config_name),
        chrono::Local::now().format("%Y%m%d-%H%M%S"),
    );
    dialog.set_current_name(&default_name);

    if let Some(p) = parent {
        dialog.set_transient_for(Some(p));
    }

    dialog.connect_response(move |dlg, resp| {
        if resp == ResponseType::Accept
            && let Some(file) = dlg.file()
            && let Some(path) = file.path()
        {
            let text = format_export(&entries, &config_name, chrono::Local::now());
            match std::fs::write(&path, text) {
                Ok(()) => tracing::info!("Exported logs to {:?}", path),
                Err(e) => {
                    tracing::warn!("Log export to {:?} failed: {}", path, e);
                    crate::dialogs::show_error_notification(
                        "Log Export Failed",
                        &format!("Could not write to {}: {}", path.display(), e),
                    );
                }
            }
        }
        dlg.close();
    });

    dialog.show();
}

/// Strip filesystem-unfriendly characters from a config name for use in a
/// default export filename. Keeps alphanumerics, dash, underscore; replaces
/// anything else with `_`.
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
