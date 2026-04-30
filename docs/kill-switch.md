# Kill-Switch

Two-layer system for protecting user traffic when a VPN tunnel drops:

1. **Notification layer** (Sprint 15) — persistent critical notification on
   unexpected disconnect with Reconnect/Dismiss actions.
2. **Firewall enforcement layer** (Sprint 16) — nftables rules managed by a
   privileged D-Bus helper that block all non-VPN traffic.

## Architecture

```
┌─────────┐   system D-Bus   ┌──────────────────────┐   nft   ┌─────────┐
│   GUI    │ ──────────────►  │  helper (root)        │ ──────► │ kernel  │
│ (user)   │  AddRules /      │  net.openvpn.v3.      │         │ nftables │
│          │  RemoveRules     │  killswitch           │         │         │
└─────────┘                  └──────────────────────┘         └─────────┘
     │                               │
     │  D-Bus name watcher           │  auto-cleanup on
     │  (watcher.rs)                 │  GUI crash
     └───────────────────────────────┘
```

### Helper (`helper/`)

A system D-Bus service running as root, activated on first call.

- **`service.rs`** — D-Bus interface with `AddRules` and `RemoveRules`
  methods. Validates all inputs before generating nft rules.
- **`nft.rs`** — Pure nft rule generator. Produces nft scripts for a
  dedicated `inet openvpn3_killswitch` table.
- **`watcher.rs`** — Monitors the GUI's D-Bus bus name. Auto-removes rules
  if the GUI disappears (crash, force-kill).

### GUI proxy (`gui/src/dbus/killswitch.rs`)

zbus proxy with `CacheProperties::No`. Maintains a persistent system-bus
connection via `OnceCell` (ephemeral connections would trigger the helper's
name-watcher cleanup).

Graceful degradation: if the helper is not installed, proxy calls log a
single `warn!` and return `Ok(())` — no user-facing error.

## Firewall rules

A dedicated `inet` table — `openvpn3_killswitch` — holds all rules. This
isolates them from ufw/firewalld and means cleanup is a single
`nft delete table` command.

**`AddRules(interface, vpn_server_ips, allow_lan)` emits:**

```nft
table inet openvpn3_killswitch {
    chain output {
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        ct state established,related accept
        ip  daddr { <ipv4 server ips> } accept
        ip6 daddr { <ipv6 server ips> } accept    # only if list non-empty
        ip  daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept    # if allow-lan
        oifname "<interface>" accept
    }
}
```

**`RemoveRules()` emits:**

```nft
delete table inet openvpn3_killswitch
```

(idempotent — helper swallows "no such table" errors)

### Why each base rule

| Rule | Reason |
|------|--------|
| `oifname lo accept` | Local resolver stubs, dbus, X11 — break without this |
| `ct state established,related accept` | Keeps the existing tunnel flow alive across rule apply; otherwise we kill the connection we're protecting |
| `ip daddr { server_ips }` | Lets reconnect attempts reach the gateway after a drop |
| `oifname "<interface>"` | The actual tunneled traffic |

## Settings

| Key | Type | Default | Purpose |
|-----|------|---------|---------|
| `enable-kill-switch` | bool | `false` | Master toggle. When true, firewall rules are applied on connect. |
| `kill-switch-allow-lan` | bool | `true` | Allow RFC1918 LAN traffic through the firewall. |
| `kill-switch-block-during-pause` | bool | `false` | Keep rules applied during Pause. `false` = remove on pause, re-apply on resume. |
| `warn-on-unexpected-disconnect` | bool | `true` | Show persistent notification on unexpected tunnel drop. |

Enabling the kill-switch forces `warn-on-unexpected-disconnect=true` and
greys out that checkbox (the notification is the user's escape hatch when
rules are applied and the tunnel drops).

## Preferences UI

```
Security
─────────────────────────────────────
☑ Warn on unexpected disconnect       (greyed out if kill-switch on)
☑ Enable kill-switch
   ☐ Allow LAN connections during VPN
   ☐ Block traffic when VPN is paused
[Clear Saved Credentials...]
```

## Behaviour

### On connect

When `enable-kill-switch=true` and a session transitions to `ConnConnected`:

1. Query `Session.device_name` and `Session.connected_to` via D-Bus.
2. Call `killswitch::add_rules(device_name, [server_ip], allow_lan)`.
3. Helper has replace semantics — re-firing on Reconnect is safe.

### On expected disconnect (user clicks Disconnect)

1. Session path added to `USER_DISCONNECTED` set before `Disconnect()` D-Bus call.
2. `SessDestroyed` handler calls `killswitch::remove_rules()`.
3. Table deleted, internet restored.

### On unexpected drop

1. Rules stay applied — internet blocked.
2. Persistent critical notification fires with Reconnect and Dismiss actions.
3. **Reconnect** — new tunnel establishes, `add_rules` re-fires on connect,
   helper replaces existing rules.
4. **Dismiss** — calls `killswitch::remove_rules()`, internet restored.

### On pause

Controlled by `kill-switch-block-during-pause`:

- **`false` (default — user-friendly):** Rules are removed on Pause.
  Internet works normally while the VPN is paused. This creates a
  deliberate leak window during the pause — the user's traffic is not
  tunnelled and not blocked. Resume re-applies rules.
- **`true` (strict):** Rules stay applied during Pause. Internet remains
  blocked. The user must resume the VPN to restore connectivity.

### On resume

No explicit code needed. Resume transitions the session back to
`ConnConnected`, which triggers the existing `is_connected` branch in
`status_handler.rs` → `apply_kill_switch` re-fires. Helper's replace
semantics make this idempotent.

### Mid-session toggle

Flipping the kill-switch checkbox in Preferences takes immediate effect:

- **ON** → rules applied for all currently-connected sessions.
- **OFF** → rules removed immediately.

### Cold start

If the GUI starts while a session is already connected:
`dbus_init.rs` re-fires the `is_connected` check, which applies rules if
the kill-switch setting is enabled. No gap after GUI restart.

### Helper not installed

Proxy catches `ServiceUnknown` / `NameHasNoOwner` errors, logs a single
`warn!`, returns `Ok(())`. Normal VPN operation continues — just no
firewall enforcement.

## Failure modes

| Mode | Symptom | Detection |
|------|---------|-----------|
| `openvpn3-service` crashed | `SessDestroyed` signal, no prior `StatusChange` | `SessDestroyed` handler |
| Backend process killed (OOM, signal) | `StatusChange` → `ProcStopped`/`ProcKilled` then `SessDestroyed` | `status_handler.rs` error path → `disconnect_with_message()` |
| D-Bus service restart | Name owner changed on bus, all sessions destroyed | `watch_service_restart()` in `dbus_init.rs` |
| Network interface removed | `StatusChange` → `ConnDisconnected` with error message | `status_handler.rs` disconnected path |
| User clicks Disconnect | `SessDestroyed` after explicit `Disconnect()` D-Bus call | `USER_DISCONNECTED` flag |

Only the last row is intentional. All others are "unexpected" and trigger
the kill-switch notification.

## Drop classification

The `USER_DISCONNECTED` global `HashSet<String>` in `session_ops.rs`
classifies disconnects:

**Set (user-initiated) before:**
- Tray "Disconnect" click → `actions.rs`
- Tray "Reconnect" click → `actions.rs`
- `disconnect_with_message()` (auth failure, connection error) → `session_ops.rs`
- Auth-retry session cleanup → `status_handler.rs`

**Consumed (checked + removed) in:**
- `SessDestroyed` handler → `signal_handlers.rs`

**If not in the set at `SessDestroyed` time → unexpected drop.**

## Packaging

The helper ships as a separate package (`openvpn3-killswitch-helper`) with:

- DEB + RPM packaging metadata.
- D-Bus system bus service file for activation.
- Access policy: users in `netdev` or `sudo` group may invoke the helper.
  No polkit — uses D-Bus system policy instead (trusted-group model).
- GUI package `Recommends:` the helper — installs together but not required.

## Risks

- **Rule leakage on crash:** If the GUI crashes without removing rules,
  the user is locked out of the internet. Mitigation: the helper watches
  the GUI's D-Bus name and auto-removes rules if the name disappears.
- **Race condition on reconnect:** Old tunnel down, new tunnel not yet up.
  Rules from old tunnel may block the new connection attempt. Mitigation:
  the helper allows traffic to all VPN server IPs from the config, not
  just the currently connected one.
- **Split-tunnel conflict:** If the user has split-tunnel rules, the
  kill-switch may override them. Mitigation: document as known limitation;
  future work to integrate with split-tunnel configuration.

## Locked design decisions

**Trusted-group over polkit:** polkit requires interactive authentication
(prompts for password), which doesn't work for a background tray app.
D-Bus system bus policy grants access to `netdev`/`sudo` group members
without interactive auth — same security model as NetworkManager.

**LAN access (configurable):** GSettings `kill-switch-allow-lan` (default
`true`). Most commercial kill-switches default permissive — users need
their printer/NAS to keep working. Trade-off: a malicious LAN host can
still receive metadata.

**IPv6:** match `vpn_server_ips` against both `ip` and `ip6` daddr.
For IPv4-only tunnels, `policy drop` on the `inet` output chain naturally
catches IPv6 leaks. No blanket "drop all IPv6" rule needed.

**DNS during reconnect window:** helper takes pre-resolved IPs. The GUI
resolves the config's `<remote>` hostname before calling `AddRules`.
Resolution happens *before* rules are applied, so no DNS allowance is
needed in the ruleset.

## Distro constraints

| Distro | Firewall backend | Notes |
|--------|-----------------|-------|
| Ubuntu 24.04+ | nftables (via ufw) | Direct nftables rules coexist with ufw |
| Debian 12+ | nftables | Straightforward |
| Fedora 40+ | firewalld (nftables backend) | Must use `firewall-cmd` or direct nft with `--direct` |

The helper uses nftables directly (not ufw/firewall-cmd wrappers) for
consistency. Coexistence with ufw is safe — nft rules are additive.
