//! Shared dialog layout constants and helpers.
//!
//! No testable pure surface — GTK constants + a thin builder helper.

use gtk4::prelude::*;
use gtk4::{Box as GtkBox, Orientation};

pub const CONTENT_MARGIN: i32 = 20;
pub const GRID_SPACING: i32 = 10;
pub const SECTION_SPACING: i32 = 6;
pub const INDENT: i32 = 24;
pub const BTN_MIN_WIDTH: i32 = 100;

/// Build a consistent button row with equal-width Cancel/Action buttons.
pub fn make_button_row<C, A>(
    cancel_label: &str,
    action_label: &str,
    on_cancel: C,
    on_action: A,
) -> gtk4::Box
where
    C: Fn() + 'static,
    A: Fn() + 'static,
{
    let btn_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .halign(gtk4::Align::End)
        .margin_top(8)
        .margin_bottom(12)
        .margin_start(CONTENT_MARGIN)
        .margin_end(CONTENT_MARGIN)
        .homogeneous(true)
        .build();

    let cancel_btn = gtk4::Button::with_label(cancel_label);
    cancel_btn.set_width_request(BTN_MIN_WIDTH);
    cancel_btn.connect_clicked(move |_| on_cancel());

    let action_btn = gtk4::Button::with_label(action_label);
    action_btn.set_width_request(BTN_MIN_WIDTH);
    action_btn.add_css_class("suggested-action");
    action_btn.connect_clicked(move |_| on_action());

    btn_box.append(&cancel_btn);
    btn_box.append(&action_btn);

    btn_box
}
