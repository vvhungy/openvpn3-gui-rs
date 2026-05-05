//! About dialog
//!
//! No testable pure surface — GTK widget builder.

use gtk4::gdk::Texture;
use gtk4::gdk_pixbuf::Pixbuf;
use gtk4::gio::{Cancellable, MemoryInputStream};
use gtk4::glib::Bytes;
use gtk4::prelude::*;
use gtk4::{AboutDialog, License};

use crate::config::{APPLICATION_TITLE, APPLICATION_VERSION};

const APP_ICON_SVG: &[u8] =
    include_bytes!("../../../data/icons/hicolor/scalable/apps/openvpn3-gui-rs.svg");

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
        .version(APPLICATION_VERSION)
        .comments(system_info().as_str())
        .license_type(License::Gpl30)
        .website("https://github.com/vvhungy/openvpn3-gui-rs")
        .website_label("GitHub")
        .build();

    let stream = MemoryInputStream::from_bytes(&Bytes::from_owned(APP_ICON_SVG.to_vec()));
    if let Ok(pixbuf) = Pixbuf::from_stream_at_scale(&stream, 128, 128, true, None::<&Cancellable>)
    {
        dialog.set_logo(Some(&Texture::for_pixbuf(&pixbuf)));
    }

    if let Some(p) = parent {
        dialog.set_transient_for(Some(p));
    }

    dialog.present();
}
