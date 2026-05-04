//! Configuration dialogs
//!
//! No testable pure surface — GTK widget builders.

use gtk4::prelude::*;
use gtk4::{Entry, FileChooserAction, FileChooserDialog, Grid, Label, ResponseType};
use tracing::info;

use super::layout::{CONTENT_MARGIN, GRID_SPACING, make_button_row};

/// Show file chooser dialog for selecting an OpenVPN configuration file
pub fn show_config_select_dialog<F>(parent: Option<&gtk4::Window>, on_select: F)
where
    F: Fn(std::path::PathBuf) + 'static,
{
    let dialog = FileChooserDialog::builder()
        .title("Select OpenVPN Configuration")
        .action(FileChooserAction::Open)
        .modal(true)
        .build();

    dialog.add_button("Cancel", ResponseType::Cancel);
    dialog.add_button("Open", ResponseType::Accept);

    let filter = gtk4::FileFilter::new();
    filter.set_name(Some("OpenVPN Configuration (*.ovpn, *.conf)"));
    filter.add_pattern("*.ovpn");
    filter.add_pattern("*.conf");
    dialog.add_filter(&filter);

    let all_filter = gtk4::FileFilter::new();
    all_filter.set_name(Some("All Files"));
    all_filter.add_pattern("*");
    dialog.add_filter(&all_filter);

    if let Some(p) = parent {
        dialog.set_transient_for(Some(p));
    }

    dialog.connect_response(move |dialog, response| {
        if response == ResponseType::Accept
            && let Some(file) = dialog.file()
            && let Some(path) = file.path()
        {
            info!("Selected file: {:?}", path);
            on_select(path);
        }
        dialog.close();
    });

    dialog.present();
}

/// Show configuration import dialog to set a name for the imported config
pub fn show_config_import_dialog<F>(
    parent: Option<&gtk4::Window>,
    path: std::path::PathBuf,
    on_import: F,
) where
    F: Fn(String, std::path::PathBuf) + 'static,
{
    let window = gtk4::Window::builder()
        .title("Import Configuration")
        .modal(true)
        .default_width(400)
        .resizable(false)
        .build();

    if let Some(p) = parent {
        window.set_transient_for(Some(p));
    }

    let vbox = gtk4::Box::new(gtk4::Orientation::Vertical, 0);

    let grid = Grid::builder()
        .margin_top(CONTENT_MARGIN)
        .margin_bottom(CONTENT_MARGIN)
        .margin_start(CONTENT_MARGIN)
        .margin_end(CONTENT_MARGIN)
        .row_spacing(GRID_SPACING)
        .column_spacing(GRID_SPACING)
        .build();

    let name_label = Label::builder()
        .label("Configuration Name:")
        .halign(gtk4::Align::Start)
        .build();
    grid.attach(&name_label, 0, 0, 1, 1);

    let default_name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("VPN")
        .to_string();

    let name_entry = Entry::builder().text(&default_name).hexpand(true).build();
    grid.attach(&name_entry, 1, 0, 1, 1);

    let file_label = Label::builder()
        .label("File:")
        .halign(gtk4::Align::Start)
        .build();
    grid.attach(&file_label, 0, 1, 1, 1);

    let file_value = Label::builder()
        .label(path.to_str().unwrap_or(""))
        .halign(gtk4::Align::Start)
        .ellipsize(gtk4::pango::EllipsizeMode::Start)
        .build();
    grid.attach(&file_value, 1, 1, 1, 1);

    vbox.append(&grid);
    vbox.append(&make_button_row(
        "Cancel",
        "Import",
        {
            let window = window.clone();
            move || window.close()
        },
        {
            let window = window.clone();
            move || {
                let name = name_entry.text().to_string();
                if !name.is_empty() {
                    info!("Importing config '{}' from {:?}", name, path);
                    on_import(name, path.clone());
                }
                window.close();
            }
        },
    ));

    window.set_child(Some(&vbox));
    window.present();
}

/// Show configuration removal confirmation dialog
pub fn show_config_remove_dialog<F>(parent: Option<&gtk4::Window>, name: &str, on_remove: F)
where
    F: Fn() + 'static,
{
    let window = gtk4::Window::builder()
        .title("Remove Configuration")
        .modal(true)
        .default_width(350)
        .resizable(false)
        .build();

    if let Some(p) = parent {
        window.set_transient_for(Some(p));
    }

    let vbox = gtk4::Box::new(gtk4::Orientation::Vertical, 0);

    let label = Label::builder()
        .label(format!(
            "Remove configuration '{}'?\n\nThis action cannot be undone.",
            name
        ))
        .margin_top(CONTENT_MARGIN)
        .margin_bottom(CONTENT_MARGIN)
        .margin_start(CONTENT_MARGIN)
        .margin_end(CONTENT_MARGIN)
        .wrap(true)
        .build();
    vbox.append(&label);

    vbox.append(&make_button_row(
        "Cancel",
        "Remove",
        {
            let window = window.clone();
            move || window.close()
        },
        {
            let window = window.clone();
            move || {
                on_remove();
                window.close();
            }
        },
    ));

    window.set_child(Some(&vbox));
    window.present();
}
