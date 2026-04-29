# Kill-Switch Design

## Problem

When a VPN tunnel drops unexpectedly (service crash, network loss, D-Bus
restart), the user's traffic may leak outside the tunnel in the clear.
The user has no immediate indication this happened unless they happen to
notice the tray icon change.

## Scope

### Sprint 15 (this document) — Notify-only slice

- **Persistent critical notification** on unexpected disconnect with
  "Reconnect" / "Dismiss" actions. No timeout — the user must
  explicitly act.
- **GSettings toggle** `warn-on-unexpected-disconnect` (default `true`)
  to gate the notification.
- **Dedup** via existing `replaces_id` map so rapid crash/restart cycles
  don't stack notifications.
- **Design doc** (this file) for Sprint 16 firewall implementation.

### Sprint 16 — Firewall enforcement (deferred)

- Network-level kill-switch using nftables rules.
- Privilege escalation via polkit + D-Bus helper.
- See "Firewall model" section below.

## Failure modes

| Mode | Symptom | Detection |
|------|---------|-----------|
| `openvpn3-service` crashed | `SessDestroyed` signal, no prior `StatusChange` | `SessDestroyed` handler |
| Backend process killed (OOM, signal) | `StatusChange` → `ProcStopped`/`ProcKilled` then `SessDestroyed` | `status_handler.rs` error path → `disconnect_with_message()` |
| D-Bus service restart | Name owner changed on bus, all sessions destroyed | `watch_service_restart()` in `dbus_init.rs` |
| Network interface removed | `StatusChange` → `ConnDisconnected` with error message | `status_handler.rs` disconnected path |
| User clicks Disconnect | `SessDestroyed` after explicit `Disconnect()` D-Bus call | `USER_DISCONNECTED` flag |

Only the last row is intentional. All others are "unexpected" and should
trigger the kill-switch notification.

## Drop classification mechanism

The `USER_DISCONNECTED` global `HashSet<String>` in `session_ops.rs`
already classifies disconnects correctly:

**Set (user-initiated) before:**
- Tray "Disconnect" click → `actions.rs:65`
- Tray "Reconnect" click → `actions.rs:45`
- `disconnect_with_message()` (auth failure, connection error) → `session_ops.rs:146`
- Auth-retry session cleanup → `status_handler.rs:171`

**Consumed (checked + removed) in:**
- `SessDestroyed` handler → `signal_handlers.rs:136`

**If not in the set at `SessDestroyed` time → unexpected drop.**

No new classification code is needed.

## Notification design

### Current state

`show_reconnect_notification()` in `notification.rs` already fires on
unexpected `SessDestroyed`. It shows a notification with a "Reconnect"
action button, urgency 2 (critical).

### Changes for Sprint 15

1. **Remove 30-second timeout.** The notification stays until the user
   clicks "Reconnect" or "Dismiss". This is critical for security — the
   user must acknowledge the tunnel is down.

2. **Wire into `NOTIFICATION_IDS` map.** Currently the reconnect
   notification always creates a new notification (`replaces_id = 0`).
   If the service crashes and restarts rapidly, this stacks duplicate
   notifications. Using the existing `replaces_id` map (keyed by
   `config_name`) replaces the old notification with the current state.

3. **Gate behind `warn-on-unexpected-disconnect` setting.** When `false`,
   the notification is suppressed entirely. The session still disappears
   from the tray — the user just doesn't get an urgent popup.

### User-visible behavior

```
Unexpected drop detected:
┌──────────────────────────────────────────────┐
│ ⚠ VPN Disconnected Unexpectedly: WorkVPN     │
│                                              │
│ The VPN connection was lost. Your traffic    │
│ may not be secured.                          │
│                                              │
│              [Reconnect]  [Dismiss]          │
└──────────────────────────────────────────────┘
```

- Notification persists (no auto-dismiss timeout).
- Clicking "Reconnect" creates a new tunnel from the same config.
- Clicking "Dismiss" closes the notification.
- If the same config drops again before dismissal, the notification
  text is replaced (no stacking).

## GSettings key

```xml
<key name="warn-on-unexpected-disconnect" type="b">
  <default>true</default>
  <summary>Warn on unexpected disconnect</summary>
  <description>
    Whether to show a persistent critical notification when a VPN
    session is lost unexpectedly (service crash, network loss).
    The notification includes a Reconnect action.
  </description>
</key>
```

## Preferences UI

New checkbox in the existing "Security" section of Preferences:

```
Security
─────────────────────────────────────
☑ Warn on unexpected disconnect
[Clear Saved Credentials...]
```

Checked by default. When unchecked, unexpected drops are silent
(session still removed from tray, just no notification).

## Files changed (Sprint 15)

| File | Change |
|------|--------|
| `docs/kill-switch.md` | This document |
| `data/*.gschema.xml` | Add `warn-on-unexpected-disconnect` key |
| `src/settings/gsettings.rs` | Add getter/setter + 2 tests |
| `src/dialogs/notification.rs` | Gate behind setting, remove timeout, add `replaces_id` |
| `src/dialogs/preferences.rs` | Add checkbox in Security section |
| `src/app/signal_handlers.rs` | Read setting before calling notification |

## Firewall model (Sprint 16 — design only)

### Approach: polkit + D-Bus helper

A small privileged helper (installed as a system D-Bus service) manages
nftables rules on behalf of the GUI:

1. **On connect:** GUI calls helper → helper adds nftables rules:
   - Allow traffic to VPN server
   - Allow traffic through tun interface
   - Drop all other outbound traffic

2. **On disconnect (expected):** GUI calls helper → helper removes rules.

3. **On unexpected drop:** Rules stay in place until user acts on the
   notification (Reconnect or Dismiss). "Dismiss" removes rules.
   "Reconnect" keeps rules and establishes a new tunnel.

### Privilege escalation

- The helper runs as root, activated by D-Bus system bus.
- Access controlled by polkit policy: only users in the `netdev` or
  `sudo` group can invoke it.
- The helper is a minimal binary — only understands "add rules for
  interface X" and "remove rules for interface X". No arbitrary command
  execution.

### Rule set (locked Sprint 16 design)

A dedicated `inet` table — `openvpn3_killswitch` — holds all rules.
This isolates them from ufw/firewalld and means cleanup is a single
`nft delete table` command.

**`AddRules(interface, vpn_server_ips)` emits:**

```nft
table inet openvpn3_killswitch {
    chain output {
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        ct state established,related accept
        ip  daddr { <ipv4 server ips> } accept
        ip6 daddr { <ipv6 server ips> } accept    # only if list non-empty
        ip  daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept    # if kill-switch-allow-lan
        oifname "<interface>" accept
    }
}
```

**`RemoveRules()` emits:**

```nft
delete table inet openvpn3_killswitch
```

(idempotent — helper swallows "no such table" errors)

#### Why each base rule

| Rule | Reason |
|------|--------|
| `oifname lo accept` | Local resolver stubs, dbus, X11 — break without this |
| `ct state established,related accept` | Keeps the existing tunnel flow alive across rule apply; otherwise we kill the connection we're protecting |
| `ip daddr { server_ips }` | Lets reconnect attempts reach the gateway after a drop |
| `oifname "<interface>"` | The actual tunneled traffic |

#### Locked decisions

**Q1 — LAN access:** configurable via GSettings `kill-switch-allow-lan`
(default `true`). When true, RFC1918 ranges are added to the accept
list. Most commercial kill-switches default permissive — users need
their printer/NAS to keep working. Trade-off: a malicious LAN host can
still receive metadata; document as a known limitation.

**Q2 — IPv6:** match `vpn_server_ips` against both `ip` and `ip6` daddr
and trust the tunnel config. For IPv4-only tunnels, `policy drop` on
the `inet` output chain naturally catches IPv6 leaks (no `oifname
"tun0"` IPv6 traffic flows). No blanket "drop all IPv6" rule needed.

**Q3 — DNS during reconnect window:** helper takes pre-resolved IPs.
The GUI resolves the config's `<remote>` hostname before calling
`AddRules`. Resolution happens *before* rules are applied, so no DNS
allowance is needed in the ruleset.

### Distro constraints

| Distro | Firewall backend | Notes |
|--------|-----------------|-------|
| Ubuntu 24.04+ | nftables (via ufw) | Direct nftables rules coexist with ufw |
| Debian 12+ | nftables | Straightforward |
| Fedora 40+ | firewalld (nftables backend) | Must use `firewall-cmd` or direct nft with `--direct` |

The helper should use nftables directly (not ufw/firewall-cmd wrappers)
for consistency. Coexistence with ufw is safe — nft rules are additive.

### Risks

- **Rule leakage on crash:** If the GUI crashes without removing rules,
  the user is locked out of the internet. Mitigation: the helper watches
  the GUI's D-Bus name and auto-removes rules if the name disappears.
- **Race condition on reconnect:** Old tunnel down, new tunnel not yet up.
  Rules from old tunnel may block the new connection attempt. Mitigation:
  the helper allows traffic to all VPN server IPs from the config, not
  just the currently connected one.
- **Split-tunnel conflict:** If the user has split-tunnel rules, the
  kill-switch may override them. Mitigation: document this as a known
  limitation; future work to integrate with split-tunnel configuration.
