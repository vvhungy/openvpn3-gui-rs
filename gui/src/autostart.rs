//! XDG autostart entry management.
//!
//! Writes/removes `$XDG_CONFIG_HOME/autostart/<APPLICATION_ID>.desktop`. The
//! filesystem entry is the source of truth — GSettings mirrors it and is
//! re-synced from disk on every startup (see `sync_gsettings_from_fs`).

use std::fs;
use std::io;
use std::path::PathBuf;

use crate::config::APPLICATION_ID;
use crate::settings::Settings;

/// Returns `$XDG_CONFIG_HOME/autostart/<APPLICATION_ID>.desktop`,
/// falling back to `$HOME/.config/autostart/...` when XDG_CONFIG_HOME is unset.
pub fn autostart_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(
        base.join("autostart")
            .join(format!("{APPLICATION_ID}.desktop")),
    )
}

/// True when the autostart entry exists on disk.
pub fn is_enabled() -> bool {
    autostart_path().map(|p| p.exists()).unwrap_or(false)
}

/// Write the autostart entry (idempotent: overwrites if present).
pub fn enable() -> io::Result<()> {
    let path =
        autostart_path().ok_or_else(|| io::Error::other("XDG_CONFIG_HOME and HOME both unset"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, desktop_entry())
}

/// Remove the autostart entry. Missing file is not an error.
pub fn disable() -> io::Result<()> {
    let Some(path) = autostart_path() else {
        return Ok(());
    };
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Re-sync the GSettings key from filesystem state. Call once at startup so
/// the toggle reflects reality even if the user removed the file out-of-band.
pub fn sync_gsettings_from_fs(settings: &Settings) {
    let fs_state = is_enabled();
    if settings.launch_on_login() != fs_state {
        settings.set_launch_on_login(fs_state);
    }
}

fn desktop_entry() -> &'static str {
    "[Desktop Entry]\n\
     Type=Application\n\
     Name=OpenVPN3 GUI\n\
     Comment=A Rust OpenVPN3 GUI for Linux\n\
     Exec=openvpn3-gui-rs\n\
     Icon=openvpn3-gui-rs-idle\n\
     Terminal=false\n\
     Categories=Network;VPN;Security;\n\
     StartupNotify=false\n\
     X-GNOME-Autostart-enabled=true\n\
     X-KDE-autostart-phase=2\n\
     Hidden=false\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autostart_path_uses_xdg_config_home_when_set() {
        // Save and override env; this test runs single-threaded by virtue of
        // touching process env, so don't add #[serial] without the crate dep.
        let prev = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", "/tmp/xdg-test");
        }
        let p = autostart_path().expect("path");
        assert!(p.starts_with("/tmp/xdg-test/autostart/"));
        assert!(p.to_string_lossy().ends_with(".desktop"));
        unsafe {
            match prev {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
    }

    #[test]
    fn desktop_entry_contains_required_keys() {
        let body = desktop_entry();
        assert!(body.contains("[Desktop Entry]"));
        assert!(body.contains("Type=Application"));
        assert!(body.contains("Exec=openvpn3-gui-rs"));
        assert!(body.contains("X-GNOME-Autostart-enabled=true"));
    }
}
