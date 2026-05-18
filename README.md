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
- Connection-stall detection — flags an idle tunnel in the tray menu and icon when traffic stops flowing
- Kill-switch — block all non-VPN traffic via nftables when a tunnel drops (requires the `openvpn3-killswitch-helper` package); always-visible state row (🔒/🔓) in the tray menu; lock indicator (🔒) in the session menu label when active; notifications on rule apply (persistent) and removal; notification and Preferences hint when the helper is not installed; quit confirmation warns before removing rules
- Split tunneling — exempt specific networks from the VPN tunnel so they route over the local connection (requires the `openvpn3-killswitch-helper` package); configure bypass CIDRs in the Preferences Routing tab; always-visible state row (🌐) in the tray menu showing active count or apply-failure; notifications on route apply and failure; symmetric IPv4/IPv6 routing with MSS clamping
- First-run help notification when the OpenVPN3 backend cannot be reached
- Automatic recovery when the OpenVPN3 service restarts
- Tabbed session log viewer — live tail of OpenVPN3 backend log messages, one tab per profile; per-tab search (case-insensitive substring), log-level filter (All / Warn+ / Error only), copy-to-clipboard (filter-aware), persistent window size
- Tabbed Preferences dialog (General / Security / Routing): startup behaviour, notifications, menu update interval, connection timeout, stall threshold, kill-switch with nested warn-on-disconnect, split-tunneling bypass CIDR editor, credential management
- DEB, RPM, and AUR packaging (separate `openvpn3-killswitch-helper` package for the privileged firewall helper)

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

- **🔒/🔓 Kill-switch: On/Off** — always-visible state row (insensitive; toggle in Preferences)
- **🌐 Split tunnel: Off / N networks / Apply failed** — always-visible state row (insensitive; configure in Preferences → Routing)
- **View Logs** — tabbed log viewer with per-tab search, level filter, and copy (always visible)
- **Import Config...** — pick a `.ovpn` file to import into OpenVPN3
- **Preferences...** — tabbed dialog (General: startup, notifications, intervals, stall detection; Security: kill-switch, warn-on-disconnect, credentials; Routing: split-tunneling bypass CIDR editor)
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
