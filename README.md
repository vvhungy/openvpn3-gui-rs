# openvpn3-gui-rs

A system tray GUI for [OpenVPN3 Linux](https://github.com/OpenVPN/openvpn3-linux), written in Rust with GTK4.

## Features

- System tray icon showing connection status
- Connect/disconnect from imported VPN profiles
- Username/password and challenge/OTP authentication dialogs
- Credential storage via the system keyring (libsecret)
- Auto-connect on startup (most-recent, specific, or restore)
- Desktop notifications on status changes
- DEB, RPM, and AUR packaging

## Requirements

- **OpenVPN3 Linux** — the D-Bus services must be installed and running
- **GTK4** — `libgtk-4-dev` / `gtk4-devel`
- **libsecret** — `libsecret-1-dev` / `libsecret-devel`
- **libdbus** — `libdbus-1-dev` / `dbus-devel`
- **Rust** — 1.75 or later (`rustup.rs`)

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

Launch `openvpn3-gui-rs` from your application menu or run it directly. It appears in the system tray. Right-click the tray icon to:

- Connect to a VPN profile
- Disconnect the active session
- Clear saved credentials
- Open preferences

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
