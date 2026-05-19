//! Preferences "Routing" tab — split-tunnel bypass CIDR editor.
//!
//! Two-tier validation per Sprint 23 T4 locked design (Option X):
//!   1. Live syntax check on every keystroke — cheap, in-process. Enables
//!      Add/Update button and shows inline hint. Catches typos, missing
//!      prefix, out-of-range prefix length.
//!   2. Full helper validation on Add/Update click — calls the helper's
//!      `ValidateBypassCidrs` dry-run method which applies the same
//!      rejection rules `SetBypassCidrs` would (loopback, multicast,
//!      link-local, unspecified, `/0`, duplicates after canonicalization,
//!      max-count ceiling). Authoritative; the helper canonical form is
//!      what lands in the list.
//!
//! No Test button: helper validation is automatic on every commit, so
//! a separate explicit-test action would be redundant. Save flow only
//! pushes to the live helper when at least one session is connected
//! (cold-start re-apply on next reconnect handles the disconnected case).

use std::cell::RefCell;
use std::net::IpAddr;
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{
    Box as GtkBox, Button, CheckButton, Entry, Frame, Label, ListBox, ListBoxRow, Orientation,
    ScrolledWindow,
};

use crate::dialogs::layout::{CONTENT_MARGIN, SECTION_SPACING};
use crate::settings::Settings;

pub(super) struct RoutingWidgets {
    /// Live CIDR list — mutated by the tab's own widgets, read by the
    /// outer Save closure for diff vs. `initial` and write-back.
    pub entries: Rc<RefCell<Vec<String>>>,
    /// Live disabled-CIDR list — checkbox-driven subset of `entries` that
    /// is skipped on apply. Mutated on toggle, read by the Save closure.
    pub disabled: Rc<RefCell<Vec<String>>>,
    /// Snapshot at build-time so the Save closure can detect "did the
    /// user actually change the list?" without re-reading GSettings.
    pub initial: Vec<String>,
    /// Snapshot of disabled-list for the same diff-detection purpose.
    pub initial_disabled: Vec<String>,
}

pub(super) fn build(settings: &Settings) -> (GtkBox, RoutingWidgets) {
    let max_count = settings.bypass_cidrs_max_count() as usize;
    let initial = settings.bypass_cidrs();
    let initial_disabled = settings.bypass_cidrs_disabled();
    let entries: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(initial.clone()));
    let disabled: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(initial_disabled.clone()));
    let editing: Rc<RefCell<Option<usize>>> = Rc::new(RefCell::new(None));

    let routing = GtkBox::new(Orientation::Vertical, SECTION_SPACING);
    routing.set_margin_top(CONTENT_MARGIN);
    routing.set_margin_bottom(CONTENT_MARGIN);
    routing.set_margin_start(CONTENT_MARGIN);
    routing.set_margin_end(CONTENT_MARGIN);

    let header = Label::builder()
        .label("<b>Bypass Networks (Split Tunneling)</b>")
        .use_markup(true)
        .halign(gtk4::Align::Start)
        .build();
    routing.append(&header);

    let description = Label::builder()
        .label(
            "Traffic to these IP ranges flows outside the VPN tunnel.\n\
             Use CIDR notation, e.g. 10.0.0.0/8 or 2001:db8::/32.\n\
             Uncheck to temporarily disable an entry without removing it.",
        )
        .halign(gtk4::Align::Start)
        .wrap(true)
        .build();
    description.add_css_class("dim-label");
    routing.append(&description);

    let counter = Label::builder().halign(gtk4::Align::End).build();
    counter.add_css_class("dim-label");
    routing.append(&counter);

    let list_frame = Frame::new(None);
    let scrolled = ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vscrollbar_policy(gtk4::PolicyType::Automatic)
        .min_content_height(140)
        .max_content_height(220)
        .build();
    let list_box = ListBox::builder()
        .selection_mode(gtk4::SelectionMode::None)
        .build();
    scrolled.set_child(Some(&list_box));
    list_frame.set_child(Some(&scrolled));
    routing.append(&list_frame);

    let entry_row = GtkBox::new(Orientation::Horizontal, 8);
    entry_row.set_margin_top(6);
    let entry = Entry::builder()
        .placeholder_text("e.g. 10.0.0.0/8")
        .hexpand(true)
        .build();
    entry_row.append(&entry);
    let add_btn = Button::with_label("Add");
    add_btn.set_sensitive(false);
    add_btn.add_css_class("suggested-action");
    entry_row.append(&add_btn);
    let cancel_edit_btn = Button::with_label("Cancel");
    cancel_edit_btn.set_visible(false);
    entry_row.append(&cancel_edit_btn);
    routing.append(&entry_row);

    let validation_label = Label::builder()
        .halign(gtk4::Align::Start)
        .wrap(true)
        .visible(false)
        .build();
    routing.append(&validation_label);

    let helper_hint = Label::builder()
        .label("⚠ Helper not installed — install openvpn3-killswitch-helper for split tunneling")
        .halign(gtk4::Align::Start)
        .visible(false)
        .build();
    helper_hint.add_css_class("dim-label");
    routing.append(&helper_hint);

    // Self-referential renderer: delete and row-click callbacks need to
    // call render() again after mutating `entries`. Standard GTK-Rust
    // pattern — store the closure in an Rc<RefCell<Option<...>>> after
    // it's constructed, then resolve at click-time.
    type Renderer = Rc<dyn Fn()>;
    let render_slot: Rc<RefCell<Option<Renderer>>> = Rc::new(RefCell::new(None));

    let render: Renderer = {
        let list_box = list_box.clone();
        let counter = counter.clone();
        let entries = entries.clone();
        let disabled = disabled.clone();
        let editing = editing.clone();
        let entry = entry.clone();
        let add_btn = add_btn.clone();
        let cancel_edit_btn = cancel_edit_btn.clone();
        let validation_label = validation_label.clone();
        let render_slot = render_slot.clone();
        Rc::new(move || {
            while let Some(child) = list_box.first_child() {
                list_box.remove(&child);
            }
            let cur = entries.borrow().clone();
            counter.set_text(&format!("{} of {} entries", cur.len(), max_count));

            if cur.is_empty() {
                let empty_row = ListBoxRow::new();
                empty_row.set_selectable(false);
                empty_row.set_activatable(false);
                let empty_label = Label::builder()
                    .label("No bypass networks configured.\nAll traffic flows through the VPN.")
                    .halign(gtk4::Align::Center)
                    .justify(gtk4::Justification::Center)
                    .margin_top(20)
                    .margin_bottom(20)
                    .build();
                empty_label.add_css_class("dim-label");
                empty_row.set_child(Some(&empty_label));
                list_box.append(&empty_row);
            }

            for (idx, cidr) in cur.iter().enumerate() {
                let row = ListBoxRow::new();
                row.set_activatable(true);
                let hbox = GtkBox::new(Orientation::Horizontal, 8);
                hbox.set_margin_top(6);
                hbox.set_margin_bottom(6);
                hbox.set_margin_start(8);
                hbox.set_margin_end(8);
                let is_disabled = disabled.borrow().iter().any(|d| d == cidr);
                let enabled_cb = CheckButton::new();
                enabled_cb.set_active(!is_disabled);
                enabled_cb
                    .set_tooltip_text(Some("Uncheck to temporarily disable this entry on Apply"));
                hbox.append(&enabled_cb);
                let lbl = Label::builder()
                    .label(cidr)
                    .halign(gtk4::Align::Start)
                    .hexpand(true)
                    .build();
                if is_disabled {
                    lbl.add_css_class("dim-label");
                }
                hbox.append(&lbl);
                let del_btn = Button::from_icon_name("edit-delete-symbolic");
                del_btn.add_css_class("flat");
                del_btn.set_tooltip_text(Some("Remove this entry"));
                hbox.append(&del_btn);
                row.set_child(Some(&hbox));
                list_box.append(&row);

                // Checkbox toggle → mutate disabled list + re-render so
                // label dimming + tray-row Active(n) preview reflect state.
                {
                    let entries = entries.clone();
                    let disabled = disabled.clone();
                    let render_slot = render_slot.clone();
                    enabled_cb.connect_toggled(move |cb| {
                        let cidr = match entries.borrow().get(idx) {
                            Some(s) => s.clone(),
                            None => return,
                        };
                        let mut d = disabled.borrow_mut();
                        if cb.is_active() {
                            d.retain(|c| c != &cidr);
                        } else if !d.iter().any(|c| c == &cidr) {
                            d.push(cidr);
                        }
                        drop(d);
                        if let Some(r) = render_slot.borrow().as_ref() {
                            r();
                        }
                    });
                }

                // Row-click load-for-edit is wired ONCE on the parent
                // ListBox below (see `list_box.connect_row_activated`),
                // not per-row — `ListBoxRow::activate` only fires for
                // keyboard Enter, missing all mouse clicks.

                // Delete button → mutate + re-render.
                {
                    let entries = entries.clone();
                    let disabled = disabled.clone();
                    let editing = editing.clone();
                    let entry = entry.clone();
                    let add_btn = add_btn.clone();
                    let cancel_edit_btn = cancel_edit_btn.clone();
                    let validation_label = validation_label.clone();
                    let render_slot = render_slot.clone();
                    del_btn.connect_clicked(move |_| {
                        let removed = if idx < entries.borrow().len() {
                            Some(entries.borrow_mut().remove(idx))
                        } else {
                            None
                        };
                        if let Some(c) = removed {
                            disabled.borrow_mut().retain(|d| d != &c);
                        }
                        // If user was editing the deleted row, reset to
                        // "adding fresh" mode.
                        if let Some(editing_idx) = *editing.borrow()
                            && editing_idx == idx
                        {
                            entry.set_text("");
                            editing.replace(None);
                            add_btn.set_label("Add");
                            cancel_edit_btn.set_visible(false);
                            validation_label.set_visible(false);
                        }
                        if let Some(r) = render_slot.borrow().as_ref() {
                            r();
                        }
                    });
                }
            }
        })
    };
    *render_slot.borrow_mut() = Some(render.clone());
    render();

    // Row-click load-for-edit, wired once on the parent ListBox so it
    // survives re-renders (renderer recreates row widgets each call but
    // the ListBox itself persists, so its signal connection persists too).
    // Uses `row.index()` to look up the CIDR in `entries` rather than
    // closing over per-row state.
    {
        let entries = entries.clone();
        let editing = editing.clone();
        let entry = entry.clone();
        let add_btn = add_btn.clone();
        let cancel_edit_btn = cancel_edit_btn.clone();
        let validation_label = validation_label.clone();
        list_box.connect_row_activated(move |_, row| {
            let idx = row.index();
            if idx < 0 {
                return;
            }
            let idx = idx as usize;
            let cidr = match entries.borrow().get(idx) {
                Some(s) => s.clone(),
                None => return,
            };
            entry.set_text(&cidr);
            editing.replace(Some(idx));
            add_btn.set_label("Update");
            cancel_edit_btn.set_visible(true);
            validation_label.set_visible(false);
        });
    }

    // Live syntax check on every keystroke. Gates add_btn sensitivity
    // and updates the inline hint label colour.
    {
        let add_btn = add_btn.clone();
        let validation_label = validation_label.clone();
        let entries = entries.clone();
        let editing = editing.clone();
        entry.connect_changed(move |e| {
            let text = e.text().to_string();
            let trimmed = text.trim();
            if trimmed.is_empty() {
                add_btn.set_sensitive(false);
                validation_label.set_visible(false);
                return;
            }
            match check_syntax(trimmed) {
                Ok(()) => {
                    // Syntax OK — check capacity (only when adding fresh,
                    // not when updating in-place which doesn't grow the list).
                    let is_editing = editing.borrow().is_some();
                    let at_capacity = !is_editing && entries.borrow().len() >= max_count;
                    if at_capacity {
                        add_btn.set_sensitive(false);
                        validation_label.set_label(&format!(
                            "List is full ({} of {} entries). Remove one to add another.",
                            entries.borrow().len(),
                            max_count
                        ));
                        validation_label.remove_css_class("success");
                        validation_label.add_css_class("error");
                        validation_label.set_visible(true);
                    } else {
                        add_btn.set_sensitive(true);
                        validation_label.set_visible(false);
                    }
                }
                Err(msg) => {
                    add_btn.set_sensitive(false);
                    validation_label.set_label(&msg);
                    validation_label.remove_css_class("success");
                    validation_label.add_css_class("error");
                    validation_label.set_visible(true);
                }
            }
        });
    }

    // Cancel-edit button: revert to fresh-add mode without committing.
    // Use the closure's button param (`b`) instead of capturing
    // `cancel_edit_btn` — capture-by-move would conflict with the
    // borrow `connect_clicked` takes on the method receiver.
    {
        let entry = entry.clone();
        let editing = editing.clone();
        let add_btn = add_btn.clone();
        let validation_label = validation_label.clone();
        cancel_edit_btn.connect_clicked(move |b| {
            entry.set_text("");
            editing.replace(None);
            add_btn.set_label("Add");
            b.set_visible(false);
            validation_label.set_visible(false);
        });
    }

    // Add/Update button: build prospective list, send to helper for
    // dry-run validation, then mutate `entries` and re-render on accept.
    {
        let entry = entry.clone();
        let entries = entries.clone();
        let editing = editing.clone();
        let add_btn_for_click = add_btn.clone();
        let cancel_edit_btn = cancel_edit_btn.clone();
        let validation_label = validation_label.clone();
        let render_slot = render_slot.clone();
        add_btn.connect_clicked(move |_| {
            let input = entry.text().to_string().trim().to_string();
            if input.is_empty() {
                return;
            }
            // Build the prospective canonical list the user is asking us
            // to commit. If they are editing, this replaces the entry at
            // `editing_idx`; otherwise it appends.
            let mut prospective: Vec<String> = entries.borrow().clone();
            let editing_idx = *editing.borrow();
            match editing_idx {
                Some(i) if i < prospective.len() => prospective[i] = input.clone(),
                _ => prospective.push(input.clone()),
            }

            // Disable button while async validation is in flight so a
            // fast double-click doesn't fire two validations.
            add_btn_for_click.set_sensitive(false);
            let add_btn = add_btn_for_click.clone();
            let entry = entry.clone();
            let entries = entries.clone();
            let editing = editing.clone();
            let cancel_edit_btn = cancel_edit_btn.clone();
            let validation_label = validation_label.clone();
            let render_slot = render_slot.clone();
            glib::spawn_future_local(async move {
                match crate::dbus::killswitch::validate_bypass_cidrs(prospective).await {
                    Ok(canonical) => {
                        *entries.borrow_mut() = canonical;
                        entry.set_text("");
                        editing.replace(None);
                        add_btn.set_label("Add");
                        cancel_edit_btn.set_visible(false);
                        validation_label.set_visible(false);
                        if let Some(r) = render_slot.borrow().as_ref() {
                            r();
                        }
                    }
                    Err(msg) => {
                        validation_label.set_label(&msg);
                        validation_label.remove_css_class("success");
                        validation_label.add_css_class("error");
                        validation_label.set_visible(true);
                        // Re-enable: user's text is still in the entry and
                        // the syntax handler will gate the button on its
                        // own when the user edits.
                        add_btn.set_sensitive(true);
                    }
                }
            });
        });
    }

    // Helper-not-installed probe at build time. Same pattern as
    // security_tab.rs::build — fires once, only shows the hint when the
    // helper is absent.
    {
        let helper_hint = helper_hint.clone();
        glib::spawn_future_local(async move {
            let system_bus = zbus::Connection::system().await.ok();
            let present = match system_bus {
                Some(ref conn) => crate::dbus::killswitch::helper_present(conn).await,
                None => false,
            };
            if !present {
                helper_hint.set_visible(true);
            }
        });
    }

    let widgets = RoutingWidgets {
        entries,
        disabled,
        initial,
        initial_disabled,
    };
    (routing, widgets)
}

/// Cheap in-process syntax check for the entry field. Mirrors the
/// *parse* portion of `helper/src/service.rs::canonicalize_cidr` —
/// rejects unparseable inputs, prefix-zero, and out-of-range prefixes.
/// Does NOT replicate semantic rejections (loopback / multicast / etc.)
/// — those run helper-side on Add/Update click via `ValidateBypassCidrs`.
///
/// Keeping the syntax check thin keeps the live-keystroke path free of
/// helper-internal knowledge that may drift; semantic rules are owned
/// by the helper and stay authoritative.
fn check_syntax(input: &str) -> Result<(), String> {
    let (addr_str, prefix_str) = input
        .split_once('/')
        .ok_or_else(|| "Missing /prefix (e.g. 10.0.0.0/8)".to_string())?;
    if addr_str.is_empty() || prefix_str.is_empty() {
        return Err("Empty address or prefix".to_string());
    }
    let addr: IpAddr = addr_str
        .parse()
        .map_err(|_| format!("'{addr_str}' is not a valid IP address"))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| format!("'{prefix_str}' is not a valid prefix length"))?;
    let max = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix == 0 {
        return Err("Prefix /0 not allowed (would bypass everything)".to_string());
    }
    if prefix > max {
        return Err(format!(
            "Prefix /{prefix} out of range for {} (max /{max})",
            if matches!(addr, IpAddr::V4(_)) {
                "IPv4"
            } else {
                "IPv6"
            }
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syntax_accepts_ipv4() {
        assert!(check_syntax("10.0.0.0/8").is_ok());
        assert!(check_syntax("192.168.1.0/24").is_ok());
        assert!(check_syntax("1.2.3.4/32").is_ok());
    }

    #[test]
    fn syntax_accepts_ipv6() {
        assert!(check_syntax("2001:db8::/32").is_ok());
        assert!(check_syntax("::1/128").is_ok());
        assert!(check_syntax("fe80::/10").is_ok());
    }

    #[test]
    fn syntax_rejects_missing_prefix() {
        let err = check_syntax("10.0.0.0").unwrap_err();
        assert!(err.contains("Missing /prefix"));
    }

    #[test]
    fn syntax_rejects_empty_address() {
        assert!(check_syntax("/8").is_err());
    }

    #[test]
    fn syntax_rejects_empty_prefix() {
        assert!(check_syntax("10.0.0.0/").is_err());
    }

    #[test]
    fn syntax_rejects_unparseable_address() {
        assert!(check_syntax("not-an-ip/24").is_err());
    }

    #[test]
    fn syntax_rejects_unparseable_prefix() {
        assert!(check_syntax("10.0.0.0/abc").is_err());
    }

    #[test]
    fn syntax_rejects_prefix_zero() {
        let err = check_syntax("1.2.3.4/0").unwrap_err();
        assert!(err.contains("/0"));
    }

    #[test]
    fn syntax_rejects_ipv4_prefix_oversize() {
        let err = check_syntax("10.0.0.0/33").unwrap_err();
        assert!(err.contains("out of range"));
    }

    #[test]
    fn syntax_rejects_ipv6_prefix_oversize() {
        let err = check_syntax("2001:db8::/129").unwrap_err();
        assert!(err.contains("out of range"));
    }

    #[test]
    fn syntax_accepts_canonicalizable_v4() {
        // Live syntax check is permissive — host-bits-set is accepted,
        // helper canonicalizes on commit.
        assert!(check_syntax("10.0.0.1/8").is_ok());
    }
}
