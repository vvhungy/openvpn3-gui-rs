# openvpn3-gui-rs

A system tray GUI for [OpenVPN3 Linux](https://github.com/OpenVPN/openvpn3-linux), written in Rust with GTK4.

## Features

- System tray icon showing aggregate connection status
- Connect / disconnect / pause / resume / restart / reconnect sessions from the tray menu
- Import and remove VPN profiles from `.ovpn` files via a file chooser
- Username/password, OTP/challenge, and browser-redirect authentication dialogs
- Saved credentials via the system keyring (Secret Service) — per-connection, optional
- Auto-connect on startup: most-recent session, a specific profile, or disabled
- Desktop notifications on status changes (grouped per connection, deduplicated)
- Auto-reconnect prompt when a session drops unexpectedly
- Automatic recovery when the OpenVPN3 service restarts
- Tabbed session log viewer — live tail of OpenVPN3 backend log messages, one tab per profile
- Preferences dialog: startup behaviour, notification toggle, tooltip interval, connection timeout, credential management
- DEB, RPM, and AUR packaging

## Requirements

- **OpenVPN3 Linux** — the D-Bus services must be installed and running
- **GTK4** — `libgtk-4-dev` / `gtk4-devel`
- **Rust** — 1.85 or later (`rustup.rs`)

> **Note:** The project uses pure-Rust D-Bus and Secret Service crates (`zbus`, `oo7`).
> Your package manager may pull in `libdbus-1-dev` and `libsecret-1-dev` as transitive
> dependencies depending on the platform and Cargo feature flags.

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
make install-local
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
| Reconnect | Disconnected or error state |

**Per-config submenu** (shown when no active session for that config):

| Action | Description |
|--------|-------------|
| Connect | Start a new VPN session |
| Remove | Delete the imported configuration |

**Top-level menu:**

- **View Logs** — tabbed log viewer, one tab per VPN profile (always visible)
- **Import Config...** — pick a `.ovpn` file to import into OpenVPN3
- **Preferences...** — startup behaviour, notifications, tooltip interval, connection timeout, credential storage
- **About** / **Quit**

## Command-line options

```
openvpn3-gui-rs [OPTIONS]

Options:
  -v, --verbose               Show more info (stackable, e.g. -vv)
  -d, --debug                 Show debug-level log output
  -s, --silent                Only show errors
  -c, --clear-secret-storage  Remove all stored credentials on startup
```

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
