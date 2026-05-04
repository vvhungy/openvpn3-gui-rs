//! About dialog
//!
//! No testable pure surface — GTK widget builder.

use gtk4::prelude::*;
use gtk4::{AboutDialog, License};

use crate::config::{APPLICATION_NAME, APPLICATION_TITLE, APPLICATION_VERSION};

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
    let dialog = AboutDialog::builder()
        .program_name(APPLICATION_TITLE)
        .logo_icon_name(APPLICATION_NAME)
        .version(APPLICATION_VERSION)
        .comments(system_info().as_str())
        .license_type(License::Gpl30)
        .website("https://github.com/vvhungy/openvpn3-gui-rs")
        .website_label("GitHub")
        .build();

    if let Some(p) = parent {
        dialog.set_transient_for(Some(p));
    }

    dialog.present();
}
