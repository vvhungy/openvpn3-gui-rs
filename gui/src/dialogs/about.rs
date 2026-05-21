//! About dialog
//!
//! No testable pure surface — GTK widget builder.

use gtk4::prelude::*;
use libadwaita::AboutWindow;

use crate::config::{APPLICATION_TITLE, APPLICATION_VERSION};

fn system_info() -> String {
    let gtk_ver = format!(
        "GTK: {}.{}.{}",
        gtk4::major_version(),
        gtk4::minor_version(),
        gtk4::micro_version(),
    );

    let os = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("PRETTY_NAME=")).map(|l| {
                l.trim_start_matches("PRETTY_NAME=")
                    .trim_matches('"')
                    .to_string()
            })
        })
        .unwrap_or_else(|| std::env::consts::OS.to_string());

    format!("A Rust OpenVPN3 GUI for Linux\n\n{gtk_ver}\nOS: {os}")
}

/// Show the about dialog
pub fn show_about_dialog(parent: Option<&gtk4::Window>) {
    let parent = parent.cloned();
    super::singleton::present_global("about", move || {
        let dialog = AboutWindow::builder()
            .application_name(APPLICATION_TITLE)
            .version(APPLICATION_VERSION)
            .comments(system_info().as_str())
            .license_type(gtk4::License::Gpl30)
            .website("https://github.com/vvhungy/openvpn3-gui-rs")
            .application_icon("openvpn3-gui-rs")
            .build();

        if let Some(p) = parent.as_ref() {
            dialog.set_transient_for(Some(p));
        }

        dialog.upcast::<gtk4::Window>()
    });
}
