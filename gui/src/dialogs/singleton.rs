//! Dialog singleton registry.
//!
//! Two APIs:
//! - `present_global(key, build)` — at most one window per class (About, Preferences).
//! - `present_keyed(key, build)` — at most one window per dynamic key
//!   (Credentials per session_path, Remove Confirm per config_path).
//!
//! GTK4 widgets are `!Send`/`!Sync`, so the registry is `thread_local!`
//! around the main thread (the only thread that creates dialogs).
//!
//! `WeakRef` lets a closed window drop from the map automatically so the
//! next call rebuilds instead of reusing a destroyed window.

use std::cell::RefCell;
use std::collections::HashMap;

use glib::object::{Cast, ObjectExt};
use gtk4::prelude::{GtkWindowExt, WidgetExt};

thread_local! {
    static REGISTRY: RefCell<HashMap<String, glib::WeakRef<gtk4::Window>>> =
        RefCell::new(HashMap::new());
}

/// Present the global-singleton window for `key`. If an instance is already
/// alive, raises it; otherwise calls `build`, stores a weak ref, presents.
pub(crate) fn present_global<F: FnOnce() -> gtk4::Window>(key: &'static str, build: F) {
    present_inner(key.to_string(), build, true);
}

/// Present the per-key-singleton window. Same behaviour as `present_global`
/// but keyed on caller-supplied dynamic value (e.g. session_path).
///
/// Funnels through any active modal — use for **user-triggered** dialogs
/// (Config Remove). For D-Bus / system-triggered dialogs that must always
/// surface, use `present_keyed_system`.
pub(crate) fn present_keyed<F: FnOnce() -> gtk4::Window>(key: &str, build: F) {
    present_inner(key.to_string(), build, true);
}

/// Like `present_keyed` but bypasses the modal-funnel. Use for dialogs
/// triggered by external events (D-Bus credential / challenge requests)
/// that must always reach the user, even when another modal is open.
pub(crate) fn present_keyed_system<F: FnOnce() -> gtk4::Window>(key: &str, build: F) {
    present_inner(key.to_string(), build, false);
}

fn present_inner<F: FnOnce() -> gtk4::Window>(key: String, build: F, funnel_modal: bool) {
    // For user-triggered calls: if any modal window is open, route the
    // present request to it. Prevents dead-lock where user opens a modal
    // child (e.g. Clear Credentials confirm), clicks tray to switch to
    // another window, and the modal grab makes the original parent
    // unreachable. System-triggered calls (credentials/challenge from
    // D-Bus) must bypass this — they have to surface regardless.
    if funnel_modal && let Some(modal) = find_active_modal() {
        modal.present();
        return;
    }
    if let Some(existing) = upgrade(&key)
        && !existing.in_destruction()
    {
        // Hide + present cycle forces compositor to re-activate the window;
        // bare .present() is a no-op on Wayland when window already mapped
        // (focus-stealing prevention drops the activation request).
        // set_visible(false) triggers connect_hide which clears the registry
        // entry — re-insert it after present so subsequent clicks still hit
        // the same window.
        let weak = existing.downgrade();
        existing.set_visible(false);
        existing.present();
        REGISTRY.with(|r| {
            r.borrow_mut().insert(key, weak);
        });
        return;
    }
    let win = build();
    let weak = win.downgrade();
    REGISTRY.with(|r| {
        r.borrow_mut().insert(key.clone(), weak);
    });
    // Drop registry entry on close/hide so a closed-but-not-yet-dropped
    // window is never re-presented (GTK warns "shown after destroyed").
    let close_key = key.clone();
    win.connect_close_request(move |_| {
        REGISTRY.with(|r| {
            r.borrow_mut().remove(&close_key);
        });
        glib::Propagation::Proceed
    });
    let hide_key = key;
    win.connect_hide(move |_| {
        REGISTRY.with(|r| {
            r.borrow_mut().remove(&hide_key);
        });
    });
    win.present();
}

fn upgrade(key: &str) -> Option<gtk4::Window> {
    REGISTRY.with(|r| r.borrow().get(key).and_then(|w| w.upgrade()))
}

/// Find any currently-visible modal toplevel. Used to funnel tray actions
/// to a blocking dialog instead of leaving the user stranded behind it.
fn find_active_modal() -> Option<gtk4::Window> {
    for widget in gtk4::Window::list_toplevels() {
        if let Ok(win) = widget.downcast::<gtk4::Window>()
            && win.is_modal()
            && win.is_visible()
            && !win.in_destruction()
        {
            return Some(win);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PREFIX: &str = "__singleton_test__";

    fn test_key(suffix: &str) -> String {
        format!("{}{}", TEST_PREFIX, suffix)
    }

    fn cleanup(key: &str) {
        REGISTRY.with(|r| {
            r.borrow_mut().remove(key);
        });
    }

    #[test]
    fn test_registry_accessible() {
        REGISTRY.with(|r| {
            let _ = r.borrow();
        });
    }

    #[test]
    fn test_weak_ref_absent_returns_none() {
        let key = test_key("absent");
        cleanup(&key);
        assert!(upgrade(&key).is_none());
    }

    #[test]
    fn test_weak_ref_after_drop_returns_none() {
        // Simulate a window that was registered then destroyed: insert a
        // WeakRef whose strong referent is dropped. Upgrade must yield None
        // so the next present_* call rebuilds.
        let key = test_key("dropped");
        cleanup(&key);
        {
            let weak: glib::WeakRef<gtk4::Window> = glib::WeakRef::new();
            REGISTRY.with(|r| {
                r.borrow_mut().insert(key.clone(), weak);
            });
        }
        assert!(upgrade(&key).is_none());
        cleanup(&key);
    }

    #[test]
    fn test_distinct_keys_isolated() {
        let k1 = test_key("iso1");
        let k2 = test_key("iso2");
        cleanup(&k1);
        cleanup(&k2);
        REGISTRY.with(|r| {
            r.borrow_mut().insert(k1.clone(), glib::WeakRef::new());
        });
        REGISTRY.with(|r| {
            assert!(r.borrow().contains_key(&k1));
            assert!(!r.borrow().contains_key(&k2));
        });
        cleanup(&k1);
    }
}
