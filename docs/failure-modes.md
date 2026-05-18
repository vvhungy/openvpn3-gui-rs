# Connect-time failure modes

State x behaviour matrix: rows are failure modes a user can actually hit;
columns are user-visible surfaces. Cells describe what the current code
produces. **Fixed in S24** marks issues closed this sprint.

## Matrix

| # | Failure mode | Tray icon | Tray menu label | Notification | Dialog | Log | Fixed? |
|---|---|---|---|---|---|---|---|
| 1 | KS device_name empty on connected session | unchanged | unchanged (lock icon shown) | **S24**: now falls through to "helper missing" path instead of claiming success | — | warn | **Yes** |
| 2 | KS connected_to address empty | unchanged | unchanged (lock icon shown) | **S24**: same as #1 | — | warn | **Yes** |
| 3 | KS apply_kill_switch D-Bus error | unchanged | unchanged | **S24**: error notification "Kill-Switch Failed" | — | warn | **Yes** |
| 4 | KS helper package not installed | unchanged | unchanged | One-shot "Helper Not Installed" (per app session) | — | — | — |
| 5 | KS startup re-apply fails for pre-connected session | unchanged | unchanged | none (only log) | — | warn | No (S25) |
| 6 | Manager version below minimum | unchanged | unchanged | none | — | error | No (S25) |
| 7 | Helper version below minimum | unchanged | unchanged | none | — | warn | No (S25) |
| 8 | setup_signal_handlers fails | unchanged | unchanged | **S24**: error notification "Status Monitoring Failed" | — | error | **Yes** |
| 9 | D-Bus init fails 10x on startup | unchanged | unchanged | "OpenVPN3 Service Not Running" with Preferences/Don't Show Again | — | error | — |
| 10 | Connect D-Bus call fails | unchanged | unchanged | "Connection Failed" error notification | — | error | — |
| 11 | Reconnect D-Bus call fails | unchanged | unchanged | "Reconnect Failed" error notification | — | error | — |
| 12 | Auth dispatch returns None (proxy/query fail) | unchanged | unchanged | none | none | warn | No (S25) |
| 13 | Disconnect/Pause/Resume/Restart D-Bus call fails | unchanged | unchanged | none | — | error | No (S25) |
| 14 | Unexpected disconnect + warn setting disabled | unchanged | unchanged | none | — | — | By design |
| 15 | Unexpected disconnect + warn setting enabled | changes via signal | session removed after 3s | persistent reconnect notification with Reconnect/Dismiss | — | — | — |
| 16 | Connection timeout exceeded | loading icon persists | "Connecting…" | "Still Connecting" info notification | — | — | — |
| 17 | Bad credentials | changes via signal | unchanged | "Authentication Failed" persistent | credential dialog shown first | — | — |
| 18 | refresh_configs fails (config manager unreachable) | unchanged | stale config list | none | — | error | No (S25) |
| 19 | Service restart re-init fails after 5 attempts | unchanged | stale state | none | — | warn | No (S25) |

## Fixes applied Sprint 24

### #1, #2 — KS false-positive on empty tun/server info

`killswitch_glue.rs`: `apply_kill_switch()` returned `Ok(true)` when
`device_name` or `server_ip` was empty, causing the caller to mark
`kill_switch_active = true` and show "Kill-Switch Active" notification.
Changed to return `Ok(false)`, which routes to the "helper missing" path
instead of falsely claiming success.

### #3 — KS apply D-Bus error silent

`killswitch_glue.rs`: `on_connected()` match arm `Err(e)` only logged a
warning. Added `show_error_notification("Kill-Switch Failed", …)` so the
user is informed that firewall rules were not applied.

### #8 — Signal handler setup failure silent

`application.rs`: `setup_signal_handlers()` failure left the app running
with no status update capability. Added `show_error_notification(
"Status Monitoring Failed", …)` explaining the degraded state.

## Deferred to Sprint 25 (within time budget)

- **#5** KS startup re-apply: low frequency (only on app restart with active
  session + KS enabled + helper transient failure).
- **#6, #7** Version checks: log-only is acceptable for now; users can check
  logs. A notification could be added but is low priority since version
  mismatches are rare and the app degrades gracefully.
- **#12** Auth dispatch returns None: rare D-Bus proxy failure; connection
  will eventually timeout or user can retry. Adding a "check your D-Bus"
  notification would help but requires careful UX design.
- **#13** Disconnect/Pause/Resume/Restart failures: low-severity; the
  StatusChange signal usually arrives and corrects the UI state. Adding
  notifications for every D-Bus call failure could be noisy.
- **#18** refresh_configs failure: stale list self-corrects on next poll.
- **#19** Service restart re-init: rare; user can restart the app.
