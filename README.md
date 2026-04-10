# openvpn3-gui-rs

A system tray GUI for [OpenVPN3 Linux](https://github.com/OpenVPN/openvpn3-linux), written in Rust with GTK4.

## Features

- System tray icon showing aggregate connection status
- Connect / disconnect / pause / resume / restart sessions from the tray menu
- Import VPN profiles from `.ovpn` files via a file chooser
- Username/password, OTP/challenge, and browser-redirect authentication dialogs
- Saved credentials via the system keyring (libsecret) — per-connection, optional
- Auto-connect on startup: most-recent session, a specific profile, or disabled
- Desktop notifications on status changes (grouped per connection, no duplicates)
- Auto-reconnect prompt when a session drops unexpectedly
- Automatic recovery when the OpenVPN3 service restarts
- Session log viewer — live tail of OpenVPN3 backend log messages
- Preferences dialog with startup behaviour, notification toggle, and credential management
- DEB, RPM, and AUR packaging

## Requirements

- **OpenVPN3 Linux** — the D-Bus services must be installed and running
- **GTK4** — `libgtk-4-dev` / `gtk4-devel`
- **libsecret** — `libsecret-1-dev` / `libsecret-devel`
- **libdbus** — `libdbus-1-dev` / `dbus-devel`
- **Rust** — 1.85 or later (`rustup.rs`)

## Build from source

```bash
git clone https://github.com/vvhungy/openvpn3-gui-rs.git
cd openvpn3-gui-rs
cargo build --release
```

## Install

```bash
# System-wide (requires sudo)
sudo make install

# Current user only
make install-user
```

This installs the binary, icons, desktop entry, GSettings schema, and metainfo.

## Packaging

```bash
make deb   # Debian/Ubuntu — requires cargo-deb
make rpm   # Fedora/RHEL  — requires cargo-generate-rpm
```

AUR `PKGBUILD` is in `pkg/aur/`.

## Usage

Launch `openvpn3-gui-rs` from your application menu or run it directly. It
appears in the system tray. Left- or right-click the tray icon to open the
menu.

**Per-session submenu** (shown when a session is active):

| Action | Available when |
|--------|---------------|
| Pause | Connected |
| Resume | Paused |
| Restart | Connected or Paused |
| Disconnect | Always |
| View Logs | Always — streams live backend log messages |

**Top-level menu:**

- **Import Config...** — pick a `.ovpn` file to import into OpenVPN3
- **Preferences...** — startup behaviour, notifications, credential storage
- **About** / **Quit**

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
