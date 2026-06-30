//! Configuration dialogs
//!
//! No testable pure surface — GTK widget builders.

use gtk4::prelude::*;
use gtk4::{Application as GtkApplication, IconSize, Image};
use gtk4::{Box as GtkBox, Orientation, Separator};
use gtk4::{Entry, FileChooserAction, FileChooserDialog, Grid, Label, ResponseType};
use tracing::info;

use super::layout::{
    BTN_MIN_WIDTH, CONTENT_MARGIN, GRID_SPACING, make_button_row, make_destructive_button_row,
};

/// Show file chooser dialog for selecting an OpenVPN configuration file
pub fn show_config_select_dialog<F>(parent: Option<&gtk4::Window>, on_select: F)
where
    F: Fn(std::path::PathBuf) + 'static,
{
    let parent = parent.cloned();
    super::singleton::present_global("config_select", move || {
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

        if let Some(p) = parent.as_ref() {
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

        dialog.upcast::<gtk4::Window>()
    });
}

/// Show configuration import dialog to set a name for the imported config.
///
/// Singleton per file path: a second invocation for the *same* path focuses
/// the existing window instead of spawning a second one (two Import windows
/// for the same file racing on the config write would double-import).
/// Different paths still open concurrently — legitimate multi-import is not
/// blocked. Routed through `present_keyed` like every other dialog per the
/// module's lifecycle invariant.
pub fn show_config_import_dialog<F>(
    parent: Option<&gtk4::Window>,
    path: std::path::PathBuf,
    on_import: F,
) where
    F: Fn(String, std::path::PathBuf) + 'static,
{
    let parent = parent.cloned();
    let key = format!("config_import:{}", path.display());
    // Bypass the modal-funnel: this fires from the FileChooser response
    // callback, where the chooser is still mapped (its close is deferred).
    // `present_keyed` would route to that chooser and never build the
    // name-entry window — wizard step 2 must always surface.
    super::singleton::present_keyed_system(&key, move || {
        build_config_import_window(parent.as_ref(), path, on_import)
    });
}

fn build_config_import_window<F>(
    parent: Option<&gtk4::Window>,
    path: std::path::PathBuf,
    on_import: F,
) -> gtk4::Window
where
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
    window
}

/// Show configuration removal confirmation dialog
pub fn show_config_remove_dialog<F>(
    parent: Option<&gtk4::Window>,
    key: &str,
    name: &str,
    on_remove: F,
) where
    F: Fn() + 'static,
{
    let parent = parent.cloned();
    let name = name.to_string();
    super::singleton::present_keyed(key, move || {
        build_config_remove_window(parent.as_ref(), &name, on_remove)
    });
}

/// Show "forget saved credentials" confirmation for one config.
///
/// Distinct singleton key from remove (`forget-<path>` vs remove) so a user
/// can open both against the same config without one no-showing the other.
/// Tray-triggered (not chained from another dialog) so plain `present_keyed`
/// is correct — no modal-funnel suppression to bypass here.
pub fn show_config_forget_dialog<F>(
    parent: Option<&gtk4::Window>,
    key: &str,
    name: &str,
    on_forget: F,
) where
    F: Fn() + 'static,
{
    let parent = parent.cloned();
    let name = name.to_string();
    super::singleton::present_keyed(key, move || {
        build_config_forget_window(parent.as_ref(), &name, on_forget)
    });
}

fn build_config_forget_window<F>(
    parent: Option<&gtk4::Window>,
    name: &str,
    on_forget: F,
) -> gtk4::Window
where
    F: Fn() + 'static,
{
    let window = gtk4::Window::builder()
        .title("Forget Credentials")
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
            "Forget saved credentials for '{}'?\n\
             \nRemoves the saved username and password for this configuration. \
             The configuration itself is kept.\n\
             \nThis action cannot be undone.",
            name
        ))
        .margin_top(CONTENT_MARGIN)
        .margin_bottom(CONTENT_MARGIN)
        .margin_start(CONTENT_MARGIN)
        .margin_end(CONTENT_MARGIN)
        .wrap(true)
        .build();
    vbox.append(&label);

    vbox.append(&make_destructive_button_row(
        "Cancel",
        "Forget",
        {
            let window = window.clone();
            move || window.close()
        },
        {
            let window = window.clone();
            move || {
                on_forget();
                window.close();
            }
        },
    ));

    window.set_child(Some(&vbox));
    window
}

fn build_config_remove_window<F>(
    parent: Option<&gtk4::Window>,
    name: &str,
    on_remove: F,
) -> gtk4::Window
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

    vbox.append(&make_destructive_button_row(
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
    window
}

/// Show the import result modal — always-shown confirmation of an import's
/// outcome, independent of the desktop-notification setting (which gates only
/// the success toast). `success` picks the title/body; `detail` carries the
/// daemon error on failure. Single OK dismisses.
///
/// Keyed on a fixed key so a second import before the first window is
/// dismissed reuses/raises the existing window rather than stacking. Note
/// this does NOT refresh the body (unlike the desktop notification, which
/// replaces its text) — the first window's result stays visible. A second
/// import's outcome is still conveyed by its toast + the log line.
pub fn show_import_result_dialog(
    parent: Option<&gtk4::Window>,
    success: bool,
    name: &str,
    detail: Option<&str>,
) {
    let parent = parent.cloned();
    let (title, body) = if success {
        (
            "Import Successful",
            format!("Configuration '{}' has been imported.", name),
        )
    } else {
        (
            "Import Failed",
            match detail {
                Some(d) => format!("Could not import configuration '{}':\n{}", name, d),
                None => format!("Could not import configuration '{}'.", name),
            },
        )
    };
    // Bypass the modal-funnel: the result dialog must always surface even
    // if the (closing) import window or another modal is still mapped when
    // this fires. `present_global` would route to that modal and never build.
    super::singleton::present_keyed_system("import_result", move || {
        build_import_result_window(parent.as_ref(), title, &body)
    });
}

fn build_import_result_window(
    parent: Option<&gtk4::Window>,
    title: &str,
    body: &str,
) -> gtk4::Window {
    let window = gtk4::Window::builder()
        .title(title)
        .modal(true)
        .default_width(360)
        .resizable(false)
        .build();

    if let Some(p) = parent {
        window.set_transient_for(Some(p));
    }

    let vbox = GtkBox::new(Orientation::Vertical, 0);

    let label = Label::builder()
        .label(body)
        .margin_top(CONTENT_MARGIN)
        .margin_bottom(CONTENT_MARGIN)
        .margin_start(CONTENT_MARGIN)
        .margin_end(CONTENT_MARGIN)
        .wrap(true)
        .build();
    vbox.append(&label);

    // Single OK button (no cancel). Match make_button_row's right-aligned,
    // margin-padded row so the result dialog is visually consistent with the
    // other config dialogs.
    let btn_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .halign(gtk4::Align::End)
        .margin_top(8)
        .margin_bottom(12)
        .margin_start(CONTENT_MARGIN)
        .margin_end(CONTENT_MARGIN)
        .build();
    let ok_btn = gtk4::Button::with_label("OK");
    ok_btn.set_width_request(BTN_MIN_WIDTH);
    ok_btn.add_css_class("suggested-action");
    {
        let window = window.clone();
        ok_btn.connect_clicked(move |_| window.close());
    }
    btn_box.append(&ok_btn);
    vbox.append(&btn_box);

    window.set_child(Some(&vbox));
    window
}

/// Show quit-while-kill-switch-active confirmation dialog.
pub fn show_quit_confirmation_dialog(parent: Option<&gtk4::Window>, gtk_app: GtkApplication) {
    let parent = parent.cloned();
    super::singleton::present_global("quit_confirmation", move || {
        let window = gtk4::Window::builder()
            .title("Quit with kill-switch active?")
            .modal(true)
            .resizable(false)
            .build();

        if let Some(p) = parent.as_ref() {
            window.set_transient_for(Some(p));
        }

        let outer = GtkBox::new(Orientation::Vertical, 0);
        let hbox = GtkBox::new(Orientation::Horizontal, 16);
        hbox.set_margin_top(CONTENT_MARGIN);
        hbox.set_margin_bottom(CONTENT_MARGIN);
        hbox.set_margin_start(CONTENT_MARGIN);
        hbox.set_margin_end(CONTENT_MARGIN);

        let icon = Image::from_icon_name("dialog-warning");
        icon.set_icon_size(IconSize::Large);
        icon.set_pixel_size(48);
        hbox.append(&icon);

        let body = Label::builder()
            .label("Quitting will remove the kill-switch firewall rules.\nYour VPN session will stay connected, but traffic will\nno longer be blocked if the tunnel drops.")
            .halign(gtk4::Align::Start)
            .valign(gtk4::Align::Center)
            .wrap(true)
            .build();
        hbox.append(&body);

        outer.append(&hbox);
        outer.append(&Separator::new(Orientation::Horizontal));
        outer.append(&make_destructive_button_row(
            "Cancel",
            "Quit anyway",
            {
                let window = window.clone();
                move || window.close()
            },
            {
                let window = window.clone();
                move || {
                    window.close();
                    gtk_app.quit();
                }
            },
        ));

        window.set_child(Some(&outer));
        window
    });
}
