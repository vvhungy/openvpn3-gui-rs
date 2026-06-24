# Sprint 31 Tasks

**Theme:** GUI correctness & robustness hardening. No new features — every task traces to a finding from the S30→S31 `gui/` code assessment. Two HIGH correctness bugs in the tray-icon priority logic (both rooted in `idle_since` lifecycle), one structural split (two watch-list files in the 600-LOC band), and mutex-poison / dialog-lifecycle / notification-dedup hygiene. First of a two-sprint split: S31 = `gui/`, S32 = `helper/`.

**Branch:** `sprint-31/all-tasks` (created at sprint start per S25 retro rule).

**Pre-sprint check:** `find {gui,helper}/src -name '*.rs' | xargs wc -l | awk '$1>=600'` — **two files in the 600-band (2026-06-23):** `settings/gsettings.rs` (635), `dialogs/logs/mod.rs` (628). **Correction:** CLAUDE.md:43 sets the split threshold at **~800 lines**, not 600 — neither file has crossed it, so no rule compels a split. (Prior sprints' pre-sprint checks used a 600 cutoff in their `awk` filters — that was a long-standing local convention, not the rule; the rule is 800. Historical sprint records are left as-written.) T4 is a *proactive* headroom split (move-only), justified on the CLAUDE.md:19 watch-list trigger ("split when crossing 800 or when the next sprint touches it") rather than a hard mandate. Watch list: `dialogs/preferences/routing_tab.rs` (565, unchanged). T1 adds ~5 LOC (clears `idle_since` on transitions; net -5 after removing the no-op block); T4 *reduces* line counts by extraction. No remaining file projected to cross 800 post-split.

**Assessment provenance:** Findings from parallel sub-agent reads of all ~50 `gui/src/**/*.rs` files (S30 end). Two findings were independently corroborated by two agents each (the `stats_poller` no-op block; the `idle_since`/error-icon coupling) — those anchor T1. Helper-crate findings deferred to S32.

---

1. ~~**T1 — Fix `idle_since` lifecycle: dead no-op block + error-icon priority.**~~ ✅ Done (commit `a0a6182`, **+ correction `dd567fc`**). See note below.
   - **Correction (`dd567fc`, 2026-06-24):** `a0a6182` removed the no-op block (fixing the *premature*-warning symptom, bullet (a)) but the deeper half of (a) survived — `apply_stall_detection` re-stamped `idle_since = Some(now())` on every zero-delta poll, then cleared it whenever `elapsed < threshold`. One field did double duty (accumulating start-clock + past-threshold warning flag), so the clock reset every poll and **never crossed the threshold** — the warning icon, idle label, and stall-driven auto-reconnect were all dead through the real poll path. Verified by manual repro: iptables IP-drop froze the byte counters and *nothing* fired until the two-field split (`idle_started_at` = persistent start-clock; `idle_since` = set only past threshold) was in. Added `test_idle_clock_accumulates_across_polls`, which fails against the `a0a6182` logic. Assessment gap: the S30 assessment described the dead no-op but missed that removing it left a single non-accumulating field; the accumulation property was never an explicit acceptance criterion. Flagged for retro.

   - **Symptom (two coupled bugs, same root cause):**
     - (a) `stats_poller.rs:125-133` `apply_stall_detection` contains a dead no-op: it sets `session.idle_since = None` then *immediately* re-sets `session.idle_since = Some(since)`. Net effect: nothing. The intended behavior ("clear so menu doesn't show premature warning when below threshold") is defeated by the re-set line. Result: any single zero-delta poll sets `idle_since = Some`, surfacing the idle/stall warning icon **regardless of the configured threshold** — the threshold gate is bypassed.
     - (b) `tray/indicator.rs:191-196` `current_icon()`: when `session.idle_since.is_some()` it sets `has_loading = true` and `continue`s, **skipping the error/active/paused classification entirely**. `status_handler/mod.rs` updates `status` on Connected→Error/Disconnected transitions but never clears `idle_since`. So an errored session with a stale `idle_since` shows the loading/warning icon instead of the error icon — violating the documented `error > loading > active > paused > idle` priority.
   - **Root cause:** `idle_since` is owned/written by `stats_poller` (set on zero-delta poll, cleared only on a *fresh poll of a still-connected session*) but its lifecycle is not coordinated with status transitions in `status_handler`. It is only meaningful while a session is Connected; a non-connected session must never carry a stale `idle_since`.
   - **Design:**
     - Remove the re-set line in the no-op block; keep the clear when below threshold. I.e. `apply_stall_detection` clears `idle_since` while idle-seconds < threshold, and only keeps it set once the threshold is crossed. (Restores threshold gating.)
     - Clear `idle_since = None` on every non-Connected transition in `status_handler/mod.rs` (Error, Disconnected, Paused — verify each transition site). This makes stale `idle_since` impossible off a Connected session, so the `continue` in `current_icon()` is only ever hit by a connected-but-idle session.
     - *Alternative considered:* gate the `current_icon()` `continue` on `session.status.is_connected()` instead of clearing in status_handler. Rejected — leaves stale state around to bite the stats dialog / tooltip / stall-detector, which also read `idle_since`. Clearing at the source is correct.
   - **State × behaviour matrix:**
     - Connected + traffic flowing: `idle_since = None` → active icon. Unchanged.
     - Connected + idle < threshold: `idle_since = None` (T1 fix) → active icon. **Bug fix** (was: premature warning).
     - Connected + idle ≥ threshold: `idle_since = Some` → loading/warning icon. Unchanged (intended).
     - Error transition while idle: `idle_since = None` (T1 fix) → error icon. **Bug fix** (was: loading icon, masking error).
     - Disconnected/Removed: `idle_since` irrelevant. Unchanged.
   - **Critical files:** `gui/src/app/stats_poller.rs:122-133` (remove no-op re-set), `gui/src/app/status_handler/mod.rs` (clear `idle_since` on non-Connected transitions — enumerate every status-write site), `gui/src/tray/indicator.rs:191-196` (no change once root fixed, but re-verify priority).
   - **Tests:** extend the existing `stats_poller` unit test — feed zero-delta with `idle_secs < threshold`, assert `idle_since == None`; feed `idle_secs ≥ threshold`, assert `Some`. (Tests currently pass only because the no-op block happens to leave `Some` — verify the test was asserting the buggy behavior and fix the assertion.)
   - **Acceptance:** idle warning never shows below configured threshold; error transition always shows error icon even if the session was idle.

2. ~~**T2 — Mutex-poison hardening + system-bus connection recovery.**~~ ✅ Done (commit `88af985`).
   - **Symptom:** Three global-mutex lock sites use bare `.lock().unwrap()` while the rest of `app/` uses defensive `if let Ok(...)`. A panic in any closure holding the lock poisons it and bricks all later disconnect/auth bookkeeping:
     - `session_ops.rs:216-219` (`USER_DISCONNECTED` on `disconnect_with_message`)
     - `status_handler/mod.rs:170-172` (`CREDENTIAL_ATTEMPTS`)
     - `status_handler/mod.rs:201-204` (`USER_DISCONNECTED`)
   - **Also:** `dbus/killswitch.rs:23-44` caches the **first** `Connection::system().await` result in a `OnceCell<Option<Connection>>` for process lifetime. If the system bus is briefly unavailable at the first kill-switch call (boot race, dbus restart), every later call returns `None` and silently degrades to "helper absent" until the GUI restarts — even after the bus recovers. Caching `Err` defeats recovery.
   - **Design:**
     - Convert the three `.lock().unwrap()` sites to the `if let Ok(mut guard) = ...lock() { ... } else { warn!(...); }` pattern used by `actions.rs` and the tests. Consistent + poison-tolerant.
     - `killswitch.rs`: cache only the `Ok(conn)` case; on `Err`, log + return `None` but do **not** populate the `OnceCell`, so the next call retries the connection.
   - **Critical files:** `gui/src/app/session_ops.rs`, `gui/src/app/status_handler/mod.rs`, `gui/src/dbus/killswitch.rs`.
   - **Tests:** unit test for the bus-retry path (mock first call Err, second Ok → second call succeeds). Lock sites are covered by existing smoke tests.
   - **Acceptance:** a poisoned lock no longer bricks disconnect/retry bookkeeping; a transient system-bus outage stops requiring a GUI restart.

3. ~~**T3 — Dialog lifecycle + notification dedup hygiene.**~~ ✅ Done (commit `eacd12c`).
   - **Symptom (two module-invariant violations):**
     - `dialogs/configuration.rs:64` `show_config_import_dialog` is the **only** dialog in the module that bypasses `singleton.rs` — it builds a raw `gtk4::Window` and `.present()`s with no `present_global`/`present_keyed` wrapper and no `connect_close_request` cleanup. Two rapid file-chooser completions spawn two Import windows that both write configs. Lower-likelihood than a tray double-click (only reached after file-chooser accept) but it's the one dialog breaking the module's own lifecycle invariant.
     - Generic notifications bypass the `NOTIFICATION_IDS` dedup map — repo rule: "every notification call must use the dedup map." `dialogs/notification/core.rs` `show_info_notification`/`show_error_notification` and `killswitch.rs:18` `show_helper_missing_notification` call `send_notification` → `send_dbus_notification(..., replaces_id=0)` without touching the map. Error toasts (Launch-on-Login failure, clear-credentials failure, log-export failure) can stack. *Note:* none are security-critical tunnel-down events (the persistent reconnect path in `interactive.rs` correctly uses `expire_timeout=0`), so this is dedup/stacking hygiene, not a missed-persistent bug.
   - **Design:**
     - Wrap `show_config_import_dialog` in `present_global("config-import", ...)` (or `present_keyed` if multi-import is desired — decide: single window is safer for the config-write race).
     - Route the three generic-notify helpers through the `NOTIFICATION_IDS` map (generate stable keys; replaces_id semantics prevent stacking).
   - **Critical files:** `gui/src/dialogs/configuration.rs:64`, `gui/src/dialogs/notification/core.rs`, `gui/src/dbus/killswitch.rs:18` (verify `show_helper_missing_notification` site), `gui/src/dialogs/notification/dedup.rs` (add keys).
   - **Tests:** smoke — open Import twice rapidly, assert one window. Smoke — fire `show_error_notification` twice, assert single toast (replaces_id).
   - **Acceptance:** all dialogs route through `singleton.rs`; all notification calls route through the dedup map.

4. ~~**T4 — Proactive split: `gsettings.rs` (635) + `logs/mod.rs` (628) headroom.**~~ ✅ Done (commit `337d88f`). Post-split: `gsettings.rs` 439, `logs/mod.rs` 565 — both well below 800; no file crossed threshold.
   - **Symptom:** Pre-sprint check (2026-06-23) found two files in the 600-LOC band: `settings/gsettings.rs` (635) and `dialogs/logs/mod.rs` (628). **Note:** CLAUDE.md:43 sets the *hard* split threshold at **~800 lines**, not 600 — neither file has crossed it. This is a proactive headroom split, not a rule mandate. Justification (CLAUDE.md:19 watch-list trigger): split *before* the next feature sprint adds to them, since an in-task split discovered one sprint late loses the motivating context (CLAUDE.md:62). Both have clean existing seams.
   - **Design (split along existing seams, behavior-preserving):**
     - `gsettings.rs`: extract the key-getter/setter groups into topical submodules under `settings/` (e.g. `connection.rs` for timeout/refresh/health keys, `bypass.rs` for bypass-CIDR keys, `reconnect.rs` for auto-reconnect keys) with a re-export facade in `gsettings.rs`. Pure mechanical move; no logic change.
     - `logs/mod.rs`: extract the toolbar/export area (added S30 T2) into `dialogs/logs/toolbar.rs` (mirrors the existing `format.rs` sibling). The tab/list construction stays in `mod.rs`.
   - **Critical files:** `gui/src/settings/gsettings.rs` → split; `gui/src/settings/mod.rs` (add submodules); `gui/src/dialogs/logs/mod.rs` → split; new `gui/src/dialogs/logs/toolbar.rs`.
   - **Tests:** existing unit tests (gsettings defaults/bounds, log-format) must pass unchanged — they assert behavior, not layout. Re-run `tests/gsettings_schema_test.sh`.
   - **Acceptance:** `find gui/src -name '*.rs' | xargs wc -l | awk '$1>=800'` returns empty (it already did pre-split — no file was near 800). T4's goal is headroom: `gsettings.rs` and `logs/mod.rs` drop well into the 400–600 band. `routing_tab.rs` (565) remains on watch list but untouched.

5. ~~**T5 — Sprint-end hygiene + v0.3.8 release.**~~ ✅ Done (commits `e2e37f8` docs-park, `1643038` release bump). Dep audit: 6 GUI + 7 helper deps all in use, zero added by T1–T4 (no Cargo.toml touched). 800-LOC re-check: max file 565 (`routing_tab.rs`, `logs/mod.rs`); `gsettings.rs` 439; nothing near 800. metainfo `<release version="0.3.8">` filled (ul-style, matching prior entries). All 6 version surfaces at 0.3.8 (+ Cargo.lock via `make check` rebuild). `make check` clean (59 helper + GUI + smoke reporting 0.3.8). **Tag + release-page verification pending PR merge** — `git tag v0.3.8 && git push origin v0.3.8`, then verify GitHub Release lists 4 artifacts (2 deb + 2 rpm) per S26 rule.
   - **Dep audit:** T1–T4 add zero deps. Re-grep all deps at sprint end. Baseline 6 UI deps (incl. libadwaita from S29).
   - **800-LOC re-check:** confirm `gsettings.rs` and `logs/mod.rs` dropped well below their pre-split sizes (439 and 565 respectively); confirm no file anywhere crossed 800. `routing_tab.rs` (565) and no other file near threshold.
   - **README:** no user-visible feature change — skip.
   - **metainfo:** `<release version="0.3.8">` via `scripts/prepend-metainfo-release.sh`. Body: "Correctness fixes: idle/stall warning now respects configured threshold; error state always takes priority over idle warning. Robustness: poison-tolerant locks, system-bus reconnection recovery. Structural: gsettings and log-viewer modules split under the size threshold."
   - **Version bump:** `make bump-version V=0.3.8` (patch — correctness/quality sprint). Verify all 6 files (gui/Cargo.toml, helper/Cargo.toml, Cargo.lock, pkg/aur/PKGBUILD, pkg/aur-helper/PKGBUILD, metainfo).
   - **Tag + release verification:** `git tag v0.3.8 && git push origin v0.3.8` after PR merge. Verify GitHub Release page lists 4 artifacts (2 deb + 2 rpm) per S26 retro rule.

---

## Backlog (trigger-gated, do NOT auto-promote)

(Carried from S30 backlog. S31 is GUI-only; the three routing/network backlog items belong with the S32 helper sprint's domain but remain trigger-gated.)

- **nft bypass-set drift detection** — S26/S27 deferred. Trigger = real user report of bypass-set drift.
- **DNS leak on bypassed-host queries (per-domain split-DNS)** — S27 T4 finding. Trigger = real user report of metadata-exposure concern.
- **Per-app split-tunneling cgroups v2 variant** — S20 backlog item; **permanently parked** per the standing decision appended to `docs/split-tunneling.md` (S31). Do not re-litigate; promotion criteria recorded there.

---

# Sprint 32 Tasks

**Theme:** Helper-crate fail-closed correctness + command hygiene. Companion to S31; every task traces to a verified finding from the S30→S31 `helper/` re-assessment. The helper is a root-running D-Bus service whose entire purpose is a kill-switch — so the dominant theme is **fail-closed fidelity**: three findings where the current code leaks state or opens a window, contradicting the kill-switch contract. Runs **after** S31 ships, on its own branch + release.

**Branch:** `sprint-32/all-tasks` (to be created at sprint start per S25 retro rule).

**Pre-sprint check:** `find {gui,helper}/src -name '*.rs' | xargs wc -l | awk '$1>=800'` — confirmed empty (helper files: `bypass.rs` 446, `service.rs` 330, `validation.rs` 308, `nft.rs` 245, `watcher.rs` 68, `main.rs` 48). No watch-list entries. T1 adds ~10 LOC to `service.rs` (error-path restore); T2 adds ~8 LOC (routing teardown in watcher); T3 is a refactor of similar size. No file projected to cross 800.

**Assessment provenance + verification note:** Findings come from a parallel sub-agent read of all 6 helper files + D-Bus policy. The agent's headline "HIGH — no D-Bus policy conf shipped, any local user can call the helper" was **investigated and rejected**: `data/net.openvpn.v3.killswitch.conf` ships a `<policy group="netdev">` + `<policy group="sudo">` allowlist and the Cargo install config deploys it to `/etc/dbus-1/system.d/`. The remaining findings below were each re-verified directly against the source (file:line + surrounding code) before being written in — not taken on the agent's word.

---

1. ~~**T1 — Fail-closed: restore `rp_filter` on mid-chain apply failure.**~~ ✅ Done (commit `4808821`). `populate_table` (sole `?`-step after `set_rp_filter_loose`) now wrapped: on Err, restores `rp_filter` to captured original + runs idempotent `teardown_routing` to clear partial ip-rules before surfacing error. `restore_rp_filter` best-effort (iface may vanish) + logged, matching `remove_bypass_routes`. `make check` clean (200 GUI + 59 helper tests). Manual repro documented below per acceptance.

   - **Original brief:**
   - **Symptom:** `service.rs` `apply_bypass_routes` is a sequential chain of `?`-propagating calls: `teardown_routing` → `rt_tables register` → `gateway capture` → `set_rp_filter_loose` → `populate_table` → `install_rules`. `set_rp_filter_loose` switches the physical interface's `rp_filter` to `2` (loose) and returns the original value. If a *later* step (`populate_table` / `install_rules`) fails, the `?` returns `Err` immediately — `restore_rp_filter` is never called in that path, and the original value is lost. The interface is left stuck at loose mode, and the captured original is gone (restore depends on `rp_filter_original` being stored, which happens only on full success). On a kill-switch helper this is a fail-open-leaning leak: a failed apply leaves the host in a looser forwarding state than before.
   - **Design:** make the apply path transactional w.r.t. `rp_filter`. Capture the original returned by `set_rp_filter_loose` into a local; on *any* `Err` after that point, call `restore_rp_filter(iface, &orig)` before returning. Store `rp_filter_original` into state only after the full chain succeeds (current behavior) so the watcher/teardown path still owns the restore in the success case. Use a guard/RAII or an explicit `if let Err` cleanup — match the style already used.
   - **State × behaviour matrix:**
     - Full apply succeeds: `rp_filter` loose during session, restored on teardown. Unchanged.
     - Apply fails before `set_rp_filter_loose`: no state touched. Unchanged.
     - Apply fails *after* `set_rp_filter_loose` (the bug): **T1 fix** — restore `rp_filter` to original before returning Err, return Err. Interface not left loose.
   - **Critical files:** `helper/src/service.rs` (`apply_bypass_routes` chain), `helper/src/bypass.rs` (`set_rp_filter_loose` / `restore_rp_filter` — already exist, no change).
   - **Tests:** unit-test the pure ordering decision if extractable; otherwise an integration-style test mocking the failing step is heavy — cover via a documented manual repro (force `populate_table` failure → assert `/proc/sys/net/ipv4/conf/<iface>/rp_filter` back to original). Add a regression note.
   - **Acceptance:** a failed `apply_bypass_routes` never leaves `rp_filter` at `2`; original value survives the failure.

2. ~~**T2 — Fail-closed: watcher disappearance must tear down bypass routing, not just nft.**~~ ✅ Done (commit `403a7ac`). Watcher disappearance branch now, after nft removal, restores `rp_filter` + runs `teardown_routing` when `bypass_routes_applied` (both idempotent, mirroring `remove_bypass_routes`); clears flag + `rp_filter_original`. Firewall-down-before-routing-down order; lock not held across `.await`. Stale D4 doc comment on `cleanup_rules` updated. `make check` clean (200 GUI + 59 helper). User-tested: GUI kill leaves no priority-100 ip-rules and `rp_filter` restored.
   - **Symptom:** `service.rs:121-127` — the watcher task's `wait_for_disappearance` handler runs only `run_nft(nft::remove_rules_script())` when the GUI vanishes. It does **not** call `remove_bypass_routes` / `teardown_routing`. If `bypass_routes_applied == true` at crash time, the bypass routing layer (secondary table 100, the priority-100 ip-rules, and the loose `rp_filter`) all survive the GUI crash and persist until the helper process itself is stopped. This directly contradicts the module doc comment ("rules are auto-removed so the user is never locked out of the network") and the GUI-crash safety property the watcher exists to provide.
   - **Design:** in the disappearance branch, after the nft removal, check `state.bypass_routes_applied`; if true, call `remove_bypass_routes` (which restores `rp_filter`, flushes table 100, deletes the ip-rules — all idempotent) and clear the flag + `rp_filter_original`. Keep the nft removal first (firewall down before routing down matches the apply order reversed). Guard with the state lock the same way the success path does; do not hold the lock across `.await`.
   - **State × behaviour matrix:**
     - GUI vanishes, kill-switch only (no bypass applied): nft removed. Unchanged.
     - GUI vanishes, bypass applied: **T2 fix** — nft removed AND routing torn down (rp_filter restored, table/rules gone). No leftover state.
     - Clean GUI disconnect (normal path): existing `remove_rules` + explicit teardown. Unchanged.
     - Helper killed -9: out of scope (kernel state persists regardless; documented limitation — a systemd `ExecStopPost`/tidy is a separate hardening item, not this task).
   - **Critical files:** `helper/src/service.rs` (watcher task body ~L118-131), `helper/src/bypass.rs` (`teardown_routing` — exists, reused).
   - **Tests:** manual repro — apply bypass, kill GUI process, assert `ip rule show` has no priority-100 `openvpn3-bypass` entries and `rp_filter` restored. Add regression note.
   - **Acceptance:** GUI crash with bypass active leaves no routing-layer state behind.

3. ~~**T3 — Fail-closed: atomic re-apply (eliminate the no-table window).**~~ ✅ Done (commit `420c18a`). Chose option (B): `add_rules_script` now prepends `add table` (ensure-exists) + `delete table` before the rebuild, all in one `nft -f` script applied as a single atomic transaction — no instant where the table is absent. Dropped the separate `remove_rules_script()` call in `service.rs::add_rules`; first-apply teardown is a no-op. Added `add_script_is_self_contained_atomic_replace` (asserts add→delete→rebuild ordering). `docs/kill-switch.md` updated to document the atomic-replace design. `make check` clean (200 GUI + 60 helper). User-tested OK.
   - **Symptom:** `service.rs:94-98` `add_rules` uses replace semantics: `let _ = run_nft(remove_rules_script()).await;` then `run_nft(&script).await`. Between the remove succeeding and the add succeeding there is a window in which the `openvpn3_killswitch` table does not exist — i.e. **no kill-switch is enforced**. For a firewall whose job is to drop traffic, a transient "everything allowed" window on every re-apply is the wrong failure mode. Triggered on every reconnect/re-apply (S30 auto-reconnect makes this more frequent).
   - **Design:** eliminate the window. Options, pick one and justify:
     - (A) **Build-under-temp-then-swap:** create the new rules under a temp table name, then atomically swap via `nft` table rename / `delete` old + `add` new in a single `nft -f` transaction (nft applies a full script in one atomic transaction, so a single script that flushes+rebuilds within the table is already atomic — verify whether the current two-call split is even necessary, or whether a single `add_rules_script` that includes the flush is sufficient and atomic).
     - (B) **Single-transaction script:** fold the remove+add into one `nft -f` input so nft commits it atomically. Likely the minimal change if nft treats the whole stdin script as one transaction.
   - Re-verify against `docs/kill-switch.md` (the locked rule-set design doc) that the chosen approach matches the documented design intent; update the doc if the design moves.
   - **State × behaviour matrix:**
     - Re-apply during connected session: no window where table is absent. **T3 fix.**
     - First-ever apply (no prior table): remove is a no-op (ignored), add applies. Unchanged.
     - `nft add` itself fails: table absent — but this is a genuine apply failure, surfaced as `Err`, not a silent window. Acceptable (caller sees the error).
   - **Critical files:** `helper/src/service.rs` (`add_rules` ~L94-98), `helper/src/nft.rs` (`add_rules_script` / `remove_rules_script` — may merge), `docs/kill-switch.md` (design doc — verify/update).
   - **Tests:** unit test that the generated script is self-contained/atomic (no dependency on a prior remove call); assert ordering within the script. Manual: rapid re-apply under load, observe no drop-window via a parallel ping (best-effort).
   - **Acceptance:** a `tcpdump`/ping during re-apply shows no "all traffic allowed" gap attributable to the remove/add split.

4. ~~**T4 — Command & teardown hygiene bundle.**~~ ✅ Done (commit `a7d9a3a`). (a) `NFT_BIN` now `/usr/sbin/nft`; extended the same PATH-trust hardening to `ip`/`conntrack` in `bypass.rs` (`IP_BIN`/`CONNTRACK_BIN` constants, all 8 call sites swapped). (b) conntrack `-d` with CIDR verified to imply `--mask-dst` on v1.4.8 (all target distros) — documented in `flush_conntrack_scoped` doc comment, no per-host expansion needed. (c) teardown loop cap tied to `validation::MAX_BYPASS_CIDRS` (now `pub`) * 2 instead of hardcoded `256`. (d) debounce skipped (optional per design): GUI gates `add_rules` on `ConnConnected` transition, thrash risk low; noted. `make check` clean (200 GUI + 60 helper).
   - **Symptom (four small hardening items, bundled because each is <15 LOC):**
     - (a) `service.rs:24` `const NFT_BIN: &str = "nft"` — resolved via `PATH`. A root system service should not trust ambient `PATH`; hardcode `/usr/sbin/nft` (verify the path across Debian/RPM/AUR targets — fall back to a build-time or documented path if it differs).
     - (b) `bypass.rs:225-244` conntrack flush uses `conntrack -D -d <cidr>`. The `-d` flag historically takes a destination *address*; behavior on a network/prefix is version-dependent. Verify against the conntrack-tools version in target distros (accept prefix? or must we expand?). If prefix unsupported, flush per-host or document the limitation in the doc comment rather than silently no-op'ing.
     - (c) `bypass.rs` teardown loop cap is a hardcoded `256` with a comment referencing `MAX_BYPASS_CIDRS*2`, but the constant isn't imported at that site. Import `validation::MAX_BYPASS_CIDRS` (or expose it) so the cap and the cap-comment stay in sync.
     - (d) `service.rs` `add_rules` has no rate-limit/debounce — a spammy/buggy GUI caller can thrash `nft` (2 spawns per call). Add a minimal guard (e.g. ignore re-applies with identical args within N ms, or a short cooldown). Low severity; only if it composes cleanly.
   - **Design:** each item is a local, behavior-preserving hardening. (d) is optional — implement only if it doesn't add a state field that complicates the watcher lifecycle; otherwise defer to backlog with a note.
   - **Critical files:** `helper/src/service.rs` (NFT_BIN, debounce), `helper/src/bypass.rs` (conntrack verify, teardown cap), `helper/src/validation.rs` (expose `MAX_BYPASS_CIDRS` if needed).
   - **Tests:** (c) covered by existing teardown test once the constant is wired; (a)/(b)/(d) manual + doc.
   - **Acceptance:** `nft` invoked via absolute path; conntrack behavior documented-or-correct; teardown cap tied to the single source constant; no unbounded re-apply thrash.

5. **T5 — Sprint-end hygiene + v0.3.9 release.**
   - **Dep audit:** T1–T4 add zero deps. Re-grep all deps at sprint end.
   - **800-LOC re-check:** confirm no helper file crossed 800; confirm no `gui/` regression from S31. Empty result expected.
   - **D-Bus policy re-verification:** confirm `data/net.openvpn.v3.killswitch.conf` is installed to `/etc/dbus-1/system.d/` by the packaging (deb depends / rpm requires / AUR) and that the `<policy>` allowlist is intact. *Explicitly record* that the S30→S31 assessment's "no policy shipped" claim was false, so a future sprint doesn't re-investigate it. (Optional: review whether `netdev` group granularity is appropriate for the target distros — note-only, no change unless a concrete concern surfaces.)
   - **Verified (pre-release):** dep audit clean (zero new deps). 800-LOC recheck empty — largest helper `bypass.rs` (458), no `gui/` regression (largest `routing_tab.rs`/`logs/mod.rs` 565). D-Bus policy confirmed shipped + installed to `/etc/dbus-1/system.d/` by **all three** packagers: `helper/Cargo.toml` cargo-deb asset (L41) + generate-rpm asset (L60-62) + `pkg/aur-helper/PKGBUILD` (L31-32). Allowlist intact: root owns `net.openvpn.v3.killswitch`; `netdev` + `sudo` `<allow send_destination>`. **S30→S31 "no policy shipped" claim was false** — recorded; do not re-investigate.
   - **README:** no user-visible feature change — skip.
   - **metainfo:** `<release version="0.3.9">` via `scripts/prepend-metainfo-release.sh`. Body: "Kill-switch fail-closed fixes: rp_filter restored on apply failure; bypass routing now torn down when the GUI crashes; re-apply no longer opens a no-enforcement window. Helper hardening: absolute nft path, conntrack semantics verified."
   - **Version bump:** `make bump-version V=0.3.9` (patch — correctness/security sprint). Verify all 6 files.
   - **Tag + release verification:** `git tag v0.3.9 && git push origin v0.3.9` after PR merge. Verify 4 artifacts (2 deb + 2 rpm) per S26 retro rule.

---

## Backlog (trigger-gated, do NOT auto-promote)

(Carried from S31 backlog. No new helper findings promoted — T1–T5 above address every verified non-Low finding.)

- **nft bypass-set drift detection** — S26/S27 deferred. Trigger = real user report of bypass-set drift.
- **DNS leak on bypassed-host queries (per-domain split-DNS)** — S27 T4 finding. Trigger = real user report of metadata-exposure concern.
- **Per-app split-tunneling cgroups v2 variant** — S20 backlog item; **permanently parked** per the standing decision in `docs/split-tunneling.md` (S31). Do not re-litigate.
- **Helper `systemd ExecStopPost` tidy** — kernel state survives `kill -9` of the helper (out of scope for S32 T2, which only covers graceful watcher-triggered teardown). Trigger = real user report of lockout after a helper crash/upgrade.

---

# Sprint 30 Tasks

**Theme:** Auto-reconnect + log export + stats dialog + PoC tail cleanup. Four backlog/feature items addressing the most-requested user-facing gaps: (1) automatic reconnection after unexpected tunnel drop, (2) log export to file, (3) connection statistics detail dialog, (4) PoC validation tail items from S22. Backlog items C (per-app cgroups v2) and B (DNS leak) held — no trigger events, no user reports.

**Branch:** `sprint-30/all-tasks` (created at sprint start per S25 retro rule).

**Pre-sprint check:** `find {gui,helper}/src -name '*.rs' | xargs wc -l | awk '$1>=600'` — confirmed empty (2026-05-28). Watch list (500–599): `gsettings.rs` (582), `routing_tab.rs` (565), `logs/mod.rs` (516). T1 adds ~30 LOC to `interactive.rs`; T2 adds ~60 LOC to `logs/mod.rs` (toolbar area); T3 adds new `dialogs/stats.rs` ~120 LOC. No watch-list file projected to cross 600.

**Backlog scan note:** Backlog items unchanged since S29: nft drift, DNS leak, cgroups v2, S22 PoC tail. S22 PoC tail promoted to T4 (trigger = S22 origin, "low priority" held long enough; completing tail validates the split-tunnel feature end-to-end). Auto-reconnect, log export, and stats dialog are new feature tasks derived from user-facing gaps survey.

---

1. ~~**T1 — Auto-reconnect on unexpected disconnect.**~~ ✅ Done (commit `ae841a0`).
   - **Symptom:** When tunnel drops unexpectedly, user gets a persistent notification with "Reconnect" / "Dismiss" buttons. No automatic reconnection — user must click. If the user is away from the machine, VPN stays down until manual action.
   - **Current flow:** `signal_handlers.rs:150` checks `USER_DISCONNECTED` → if absent → `show_reconnect_notification()` → user clicks Reconnect → `TrayAction::Connect(config_path)`. Kill-switch rules stay applied (reconnect re-applies with replace semantics).
   - **Design:** Add GSetting `auto-reconnect` (bool, default false). When enabled AND unexpected disconnect occurs, skip notification, attempt `connect_to_config()` directly after a configurable delay.
   - **New GSettings key:** `auto-reconnect-delay-seconds` (uint, 5–300, default 30). Gated by `auto-reconnect` being true.
   - **Retry policy:** Single attempt. If reconnect fails, fall through to existing reconnect notification (user can retry manually). Reason: repeated auto-retries without backoff can hammer a down server; single attempt handles transient drops (network flap, service restart) without masking persistent outages.
   - **State × behaviour matrix:**
     - Unexpected disconnect + auto-reconnect ON: wait delay → attempt reconnect → success → tray shows Connected → stats resume. Failure → show reconnect notification as today.
     - Unexpected disconnect + auto-reconnect OFF: existing notification behavior, unchanged.
     - User-initiated disconnect: `USER_DISCONNECTED` set, auto-reconnect never fires. Unchanged.
     - Auth-failure auto-retry disconnect: `USER_DISCONNECTED` set, auto-reconnect never fires. Unchanged.
     - Tray icon during delay: stays "loading" (session not yet removed from tray by 3s timer if reconnect in progress). Actually, the 3s removal fires unconditionally — T1 must cancel the removal timer when auto-reconnect is attempted.
     - Kill-switch rules during delay: stay applied (correct — traffic still blocked while reconnect pending).
   - **Critical files:** `gui/src/app/signal_handlers.rs` (reconnect trigger site), `gui/src/dialogs/notification/interactive.rs` (notification code path), `gui/src/app/session_ops.rs` (`connect_to_config`), `gui/src/settings/gsettings.rs` (new keys), `gui/src/dialogs/preferences/general_tab.rs` (new UI row), `data/net.openvpn.openvpn3_gui_rs.gschema.xml` (schema).
   - **Call-site enumeration for lifecycle wiring:** Unexpected disconnect fires from one site: `signal_handlers.rs:182` (`show_reconnect_notification`). Auto-reconnect intercept goes there. Preferences Save: `preferences/mod.rs` Save closure (persist setting, no runtime action needed — setting reads are live from GSettings). General tab UI: `general_tab.rs` (add toggle + spin row).
   - **Implementation sketch:**
     - `gsettings.rs`: add `auto_reconnect() -> bool`, `auto_reconnect_delay_seconds() -> u32`, setters.
     - `gschema.xml`: add two keys.
     - `signal_handlers.rs`: at line ~182, before `show_reconnect_notification()`, check `auto_reconnect`. If true, spawn a `glib::timeout_future(delay)` then `connect_to_config(config_path)`. Cancel the 3s tray-removal timer (track the `SourceId` and remove it).
     - `general_tab.rs`: add `SwitchRow` for auto-reconnect + `SpinRow` for delay, sensitivity-bound to the switch.
   - **Tests:** unit test for delay-bounds (gsettings schema defaults). Smoke: toggle setting, verify getter returns correct value.
   - **Acceptance:** unexpected disconnect with auto-reconnect ON → app waits delay seconds → reconnects automatically. Failure → falls through to notification. Setting OFF → behavior unchanged.

2. ~~**T2 — Log export to file.**~~ ✅ Done (commit `33b9e29`).
   - **Symptom:** Log viewer (`dialogs/logs/mod.rs`) shows per-session logs in a tabbed window with search and level filtering. No way to save logs to a file for bug reports or offline analysis.
   - **Current log buffer:** `gui/src/app/log_buffer.rs` — `LOG_BUFFER` holds up to 5000 `LogEntry` structs with `(timestamp, session_path, config_name, group, category, message)`. `entries_for_session(path)` returns filtered slice.
   - **Design:** Add "Export…" button to log viewer toolbar. Opens `gtk4::FileChooserDialog` (save mode). Writes currently visible tab's filtered entries (respecting search + level filter) as plain text. Format matches existing `format_log_line()` output from `dialogs/logs/format.rs`.
   - **File format:** one line per entry: `YYYY-MM-DD HH:MM:SS [LEVEL] message`. Header line: `# openvpn3-gui-rs log export — <config_name> — exported <timestamp>`. Footer: `# <N> entries`.
   - **Edge cases:** empty log → disable Export button (gray out). Very large exports → write via buffered `BufWriter`, no UI freeze (write is fast for text; 5000 entries ≈ 500 KB).
   - **Critical files:** `gui/src/dialogs/logs/mod.rs` (toolbar + button), `gui/src/app/log_buffer.rs` (read entries), `gui/src/dialogs/logs/format.rs` (reuse formatter).
   - **Tests:** unit test for export format (header + entries + footer) against synthetic `LogEntry` vec. Smoke: open log viewer, click Export, verify file contents.
   - **Acceptance:** Export button in log viewer toolbar → save dialog → file written with filtered entries. Button disabled when no entries visible.

3. ~~**T3 — Connection statistics detail dialog.**~~ ✅ Done (commit `7777375`).
   - **Symptom:** Tray tooltip shows byte counts (`↓ 42.0 MB ↑ 33.0 MB`) and idle timer. No detailed view of session stats: connection duration, connected-since timestamp, tunnel interface name, detailed byte breakdown.
   - **Available D-Bus data:** `SessionProxy.statistics()` returns `HashMap<String, i64>` with keys `BYTES_IN`, `BYTES_OUT`, and potentially others (OpenVPN3 backend may expose `PACKETS_IN`, `PACKETS_OUT`, `TUN_READ`, `TUN_WRITE`). `SessionProxy.status()` returns major/minor. Session object path encodes no metadata.
   - **Design:** New per-session stats dialog. Opens from session submenu (new "Statistics" menu item) in tray. Shows:
     - Config name + status (Connected / Paused)
     - Connected since (tracked locally — set `connected_at: Instant` in `SessionInfo` on `is_now_connected` transition in `status_handler`)
     - Tunnel interface name (if available from D-Bus — `SessionProxy.dev_name()` or equivalent)
     - Bytes in / Bytes out (from `SessionInfo` already populated by stats poller)
     - Duration (computed from `connected_at`)
     - Live refresh (re-read stats from D-Bus every `stats_refresh_interval` seconds while dialog is open)
   - **New fields in `SessionInfo`:** `connected_at: Option<Instant>` (set on connect, cleared on disconnect). Check if `SessionInfo` in `indicator.rs` already has this — if not, add it.
   - **D-Bus probe:** grep `SessionProxy` for `dev_name`, `interface_name`, or equivalent property. If OpenVPN3 session objects don't expose it, omit from dialog (note as "not available from backend").
   - **Dialog structure:** `gtk4::Window` with `adw::PreferencesGroup` rows (read-only labels). Non-modal, per-session singleton (keyed by `session_path` via `present_keyed`).
   - **Menu wiring:** `tray/menu/submenus.rs` — add "Statistics" item to Connected session submenu (after Pause/Resume, before Restart).
   - **Action dispatch:** new `TrayAction::Statistics(session_path)` in `actions.rs`. Opens stats dialog.
   - **Critical files:** new `gui/src/dialogs/stats.rs`; `gui/src/tray/menu/submenus.rs` (menu item); `gui/src/app/actions.rs` (action dispatch); `gui/src/tray/indicator.rs` (`SessionInfo` + `connected_at`); `gui/src/app/status_handler/mod.rs` (set `connected_at`); `gui/src/dbus/session.rs` (check available properties).
   - **Tests:** smoke — open stats dialog, verify no panic. Unit test for duration formatting.
   - **Acceptance:** "Statistics" in connected session tray submenu → dialog with live-updating bytes, duration, connected-since. Dialog auto-closes when session disconnects.

4. ~~**T4 — S22 PoC tail items (conntrack/MTU re-test + kill-switch-ON test mode + test-resume).**~~ ✅ Done (commit `eca1008`).
   - **Symptom:** `scripts/poc-split-tunnel.sh` has three incomplete test scenarios: conntrack and MTU checks SKIP when bypass destination is unreachable, no kill-switch-ON test mode exists, and `test-resume` requires manual GUI interaction.
   - **Current state:** PoC `test` command runs 5 checks. Conntrack and MTU checks probe a bypass destination — if unreachable, SKIP. No kill-switch-ON variant. `test-resume` pauses, waits for user to Resume in GUI, then verifies routing re-capture.
   - **Design:**
     - T4a: Make conntrack/MTU checks probe a known-reachable host instead of relying on bypass destination. Use `1.1.1.1` (Cloudflare DNS, almost always reachable) as the conntrack test target. If still unreachable, SKIP (don't FAIL).
     - T4b: Add `test-with-killswitch` command to PoC script. Same as `test` but enables kill-switch before applying bypass routes. Verifies bypass traffic passes through kill-switch `policy drop` correctly (bypass CIDRs in `@bypass_set` → accept before drop).
     - T4c: Automate `test-resume` using D-Bus calls instead of manual GUI interaction. Send `Pause()` and `Resume()` via `busctl` or `gdbus` to the session object, then verify routing state after each.
   - **Critical files:** `scripts/poc-split-tunnel.sh` (all changes).
   - **Tests:** the PoC script IS the test. Run on a system with openvpn3 active + bypass CIDRs configured. Verify: conntrack/MTU don't SKIP, kill-switch test passes, resume test completes without manual interaction.
   - **Acceptance:** all three PoC tail items complete without manual steps (given openvpn3 + helper active).

5. ~~**T6 — Auto-reconnect on stall (promoted mid-sprint from T1 analysis).**~~ ✅ Done (commit `79ccaf7`).
   - **Trigger:** during T1 review, identified that stall detection produces only a passive icon — a stalled tunnel (zombie session: D-Bus says Connected, zero bytes flow) requires manual user action. Auto-reconnect intercept in `signal_handlers.rs` doesn't fire because no `SessDestroyed` event. Two features address overlapping user need (auto-recovery from broken tunnel) but cover disjoint failure modes.
   - **Design:** When `idle_since` exceeds stall threshold AND `auto_reconnect()` is ON, treat the stalled session as an unexpected drop. Sequence: disconnect the stalled session via `session_ops::disconnect`, wait `auto_reconnect_delay_seconds`, then `connect_to_config(config_path)`. Reuses both existing settings — no new keys, no new UI.
   - **Loop prevention:** add `auto_reconnect_attempted_at: Option<Instant>` field to `SessionInfo`. Skip the retry if any attempt happened within `2 × delay` for this session_path. Field reset on successful reconnect (cleared in new-session path).
   - **State × behaviour matrix:**
     - Stall + auto-reconnect ON + cooldown clear: disconnect → delay → reconnect. Cooldown set.
     - Stall + auto-reconnect ON + cooldown active: keep showing icon, take no action (prevent loop with broken-server case).
     - Stall + auto-reconnect OFF: existing icon warning, unchanged.
     - Stall detection OFF (threshold=0): no-op regardless of auto-reconnect.
     - User-initiated disconnect during stall: `USER_DISCONNECTED` set → auto-reconnect intercept skips (existing logic).
   - **Critical files:** `gui/src/app/stats_poller.rs` (intercept site after `apply_stall_detection` returns), `gui/src/tray/indicator.rs` (`SessionInfo.auto_reconnect_attempted_at` field), `gui/src/dbus_init.rs`, `gui/src/app/session_ops.rs`, `gui/src/app/signal_handlers.rs`, `gui/src/app/status_handler/mod.rs` (all `SessionInfo` constructors — initialize to `None`; clear on transition into Connected).
   - **Tests:** unit test in `stats_poller.rs` for cooldown-window logic (synthetic `SessionInfo` + clock advance via passing `Instant::now() - Duration::from_secs(N)`).
   - **Acceptance:** stalled session with both toggles ON → app disconnects + reconnects automatically after stall threshold + delay. Re-stall within cooldown → no action. Server permanently down → at most one attempt per cooldown window.

6. ~~**T5 — Sprint-end hygiene + v0.3.7 release.**~~ ✅ Done (commit `fb56f87`, PR #30 merged, tag `v0.3.7`, 4/4 artifacts).
   - **Dep audit:** baseline 5 UI deps + libadwaita (added S29). T1 adds 0 deps (GSettings only). T2 adds 0 deps (std::fs + FileChooserDialog from gtk4). T3 adds 0 deps (gtk4 + adw widgets already available). T4 adds 0 deps (shell script). Confirm no new deps.
   - **600-LOC re-check:** verify `gsettings.rs` (582 → +~15 for two new keys = ~597), `routing_tab.rs` (565, unchanged), `logs/mod.rs` (516 → +~60 for export = ~576). None cross 600.
   - **README:** no update needed (features are incremental, not architectural).
   - **metainfo:** `<release version="0.3.7">` via `scripts/prepend-metainfo-release.sh`. Body: "Auto-reconnect after unexpected disconnect; log export to file; connection statistics dialog; split-tunnel PoC validation improvements."
   - **Version bump:** `make bump-version V=0.3.7` (minor — new user-visible features). Verify all 6 files.
   - **Tag + release verification:** `git tag v0.3.7 && git push origin v0.3.7` after PR merge. Verify GitHub Release page lists 4 artifacts (2 deb + 2 rpm) per S26 retro CLAUDE.md rule.
   - **GSettings schema:** verify new keys (`auto-reconnect`, `auto-reconnect-delay-seconds`) have correct defaults and ranges in `.gschema.xml`. Run `tests/gsettings_schema_test.sh`.

---

## Backlog (trigger-gated, do NOT auto-promote)

(Carried from S29 backlog; S22 PoC tail promoted to T4 above.)

- **nft bypass-set drift detection** — S26/S27 deferred. Trigger = real user report of bypass-set drift.
- **DNS leak on bypassed-host queries (per-domain split-DNS)** — S27 T4 finding. Trigger = real user report of metadata-exposure concern.
- **Per-app split-tunneling cgroups v2 variant** — S20 backlog item. Trigger = user request for per-app routing.

---

# Sprint 29 Tasks

**Theme:** Dialog lifecycle hygiene. Survey of `gui/src/dialogs/` found 11 GTK windows with two systemic gaps: zero singleton enforcement on any window (clicking Preferences twice spawns two — Save races, last-writer-wins silent loss), and modality set per-dialog without aggregate analysis (Preferences is modal, which blocks the tray during configuration). Every dialog gets an explicit multiplicity + modality policy. Plus one backlog auto-promotion (About dialog Adwaita title-bar styling — S20-origin item whose "framework offers clean fix" trigger fires by-association since T2 touches `dialogs/about.rs`). No new user-visible features.

**Branch:** `sprint-29/all-tasks` (created at sprint start per S25 retro rule).

**Pre-sprint check:** `find {gui,helper}/src -name '*.rs' | xargs wc -l | awk '$1>=600'` — confirmed empty (2026-05-21). Watch list (500–599): `gsettings.rs` (582), `routing_tab.rs` (565), `logs/mod.rs` (503). T1 adds new `dialogs/singleton.rs` ~80 LOC; T2/T3 trim ~5 LOC per call site by replacing inline `build + present` with helper calls. No watch-list file projected to cross 600.

**Backlog scan note:** the four current S28 backlog items (nft drift, DNS leak, cgroups v2, S22 PoC tail) are all routing/network domain and don't fit dialog theme. Only About styling pairs naturally; promoted as T4. Other backlog items held for a future routing-focused sprint.

---

1. ~~**T1 — Singleton helper module.**~~ ✅ Done.
   - **Symptom:** zero singleton enforcement across all 11 GTK windows in `gui/src/dialogs/`. No `OnceCell`/`Mutex<Option<Window>>`/"raise existing" logic anywhere. Most visible bug: Preferences opens twice → two windows can race on Save (last-writer-wins, silent loss).
   - **API:** new `gui/src/dialogs/singleton.rs` (~80 LOC) exposing:
     ```rust
     pub fn present_global<F: FnOnce() -> gtk4::Window>(key: &'static str, build: F);
     pub fn present_keyed<F: FnOnce() -> gtk4::Window>(key: &str, build: F);
     ```
   - **Internals:** `LazyLock<Mutex<HashMap<String, glib::WeakRef<gtk4::Window>>>>`. `WeakRef` so a closed window auto-drops from map (avoids stale entry preventing re-open). On call: upgrade weak ref → if alive `.present()`, else build/store/present.
   - **Critical files:** new `gui/src/dialogs/singleton.rs`; `gui/src/dialogs/mod.rs` add `pub mod singleton;`.
   - **Tests:** 3 unit tests — first-call-builds, second-call-reuses, after-drop-rebuilds.
   - **Acceptance:** helper compiles, tests pass, no callers wired yet.

2. ~~**T2 — Wire global singletons (5 dialogs).**~~ ✅ Done.
   - **Targets:** About (`dialogs/about.rs:40`), Config Select (`configuration.rs:14`), Quit Confirm (`configuration.rs:191`), Log Viewer (`logs/mod.rs:91`), Preferences (`preferences/mod.rs:19`).
   - **Modality change (Preferences only):** flip `.modal(true)` → `.modal(false)` per policy. Grep `connect_close_request` / `connect_destroy` for Preferences to confirm no code assumes modality (e.g. blocking work-after-close patterns).
   - **State × behaviour matrix:**
     - Tray menu: unchanged (singleton transparent at click site).
     - Preferences with notification arriving while open: notification visible *and* tray reachable (proves non-modal works as intended).
     - Log Viewer (already non-modal): second invocation focuses existing window instead of stacking.
   - **Call sites in `gui/src/app/actions.rs`:** :180 (Import), :211 (Preferences), :221 (View Logs), :225 (About), :235 (Quit). All wrap in `present_global("preferences", || build_preferences_dialog(...))` etc.
   - **Tests:** smoke per dialog — open twice in test harness, assert single window. Manual: click Preferences twice → one window focused.
   - **Acceptance:** all 5 dialogs spawn at most one instance; Preferences non-modal verified.

3. ~~**T3 — Wire per-key singletons (3 dialogs).**~~ ✅ Done.
   - **Targets + keys:**
     - Credentials (`dialogs/credentials.rs:35`) — key = `session_path`. Caller: `credential_handler.rs:181`.
     - Challenge / OTP (`dialogs/credentials.rs:182`) — key = `session_path`. Caller: `challenge_handler.rs:103`.
     - Config Remove Confirm (`dialogs/configuration.rs:140`) — key = `config_path`. Caller: `actions.rs:146`.
   - **Edge case:** credentials dialog open for session X; D-Bus fires *second* credential request for same session X (re-auth race). Current: two stacked dialogs, user types into one, other holds stale request. New: focus existing, drop second request. Verify D-Bus request token semantics tolerate this (caller already holds first one — must not double-respond).
   - **Tests:** unit test for keyed-map (two distinct keys → two windows; same key twice → one). Manual T3a: two sessions need creds → two dialogs visible. Manual T3b: same session re-requests creds → single dialog focused.
   - **Acceptance:** multi-session credential UX preserved; same-session re-request no longer stacks.

4. ~~**T4 — About dialog title-bar styling (backlog auto-promotion via T2).**~~ ✅ Done (libadwaita Path B).
   - **Backlog origin:** S20 line 350 ("blue box around title — Adwaita's `GtkAboutDialog` headerbar styling, fix requires CSS override or libadwaita dep switch"). Carried through S26 backlog line 199. **Trigger:** "framework offers a clean fix" — `libadwaita::AboutWindow` / `AboutDialog` has shipped. **Auto-promotion gate:** T2 touches `dialogs/about.rs` for singleton wiring; per CLAUDE.md "if a sprint task touches the file, do the deferred work too" pattern (mirrors 600-LOC watch-list rule).
   - **Two paths — decide with user before implementation:**
     - **Path A (zero new dep):** keep `gtk4::AboutDialog`, inject a `gtk4::CssProvider` to flatten/blank the headerbar. Pros: no new dep. Cons: brittle (Adwaita CSS selector names drift across versions), distro-fragile.
     - **Path B (libadwaita):** add `libadwaita = "0.7"` (~3 MB transitive), replace with `adw::AboutWindow`. Pros: idiomatic, theme-stable, code becomes ~30% shorter (no manual `Pixbuf::from_stream_at_scale` — `adw::AboutWindow` takes `application_icon` name directly). Cons: `libadwaita-1` becomes a hard runtime dep on Debian/RPM/AUR.
   - **Recommend Path B**; flag dep-size to user before adding.
   - **Critical files:** `gui/src/dialogs/about.rs:40-61`; Path B also adds `gui/Cargo.toml` libadwaita line + `libadwaita-1` to DEB `depends`, RPM `requires`, both AUR PKGBUILDs.
   - **Tests:** smoke — open About in test, no panic. Manual: open About → no blue header artifact (test on GNOME and KDE — KDE renders Adwaita widgets via system theme).
   - **Acceptance:** flat title bar on GNOME + KDE; logo + version + links render correctly.

5. ~~**T5 — Sprint-end hygiene + v0.3.6 release.**~~ ✅ Done (PR #29 merged, tag `v0.3.6` released).
   - **Dep audit:** baseline 5 UI deps (gtk4, glib, gio, ksni, glib-build-tools). T1–T3 add zero deps. T4 Path B adds `libadwaita`; re-grep all deps at sprint end.
   - **600-LOC re-check:** verify `gsettings.rs` (582), `routing_tab.rs` (565), `logs/mod.rs` (503) didn't cross 600. T2 trims a few LOC from `logs/mod.rs` (replacing inline build with `present_global` call), so it should *drop* slightly.
   - **README:** no user-visible feature change — skip.
   - **metainfo:** `<release version="0.3.6">` via `scripts/prepend-metainfo-release.sh`. Body: "Dialog hygiene: Preferences and other windows reuse a single instance instead of stacking; Preferences is non-modal so tray actions remain reachable while configuring." Mention About modernization if Path B chosen.
   - **Version bump:** `make bump-version V=0.3.6` (patch — quality/correctness sprint). Verify all 6 files (gui/Cargo.toml, helper/Cargo.toml, Cargo.lock, pkg/aur/PKGBUILD, pkg/aur-helper/PKGBUILD, metainfo).
   - **Tag + release verification:** `git tag v0.3.6 && git push origin v0.3.6` after PR #29 merge. Verify GitHub Release page lists 4 artifacts (2 deb + 2 rpm) per S26 retro CLAUDE.md rule.

---

## Backlog (trigger-gated, do NOT auto-promote)

(Carried from S28 backlog; About styling promoted to T4 above.)

- **nft bypass-set drift detection** — S26/S27 deferred. Polish; trigger = real user report of bypass-set drift.
- **DNS leak on bypassed-host queries (per-domain split-DNS)** — S27 T4 finding. Trigger = real user report of metadata-exposure concern.
- **Per-app split-tunneling cgroups v2 variant** — S20 backlog item.
- **S22 PoC tail items** (conntrack/MTU re-test on reachable network, kill-switch-ON test mode, `test-resume` interactive validation) — low priority.

---

# Sprint 28 Tasks

**Theme:** Service-lifecycle robustness. Close the two backlog items whose triggers fired during S27 testing — cold-start D-Bus activation race on `NewTunnel`, and stale tray sessions after the `net.openvpn.v3.sessions` service is killed. No new features; pure resilience against openvpn3 backend churn.

**Branch:** `sprint-28/all-tasks` (created at sprint start per S25 retro rule).

**Pre-sprint check:** `find {gui,helper}/src -name '*.rs' | xargs wc -l | awk '$1>=600'` — confirmed empty (2026-05-20). Watch list (500–599): `gsettings.rs` (582), `routing_tab.rs` (565), `logs/mod.rs` (503, S26-dropped, not re-promoted). No S28 task touches these — watch list carried without split scheduling per CLAUDE.md retro rule.

**Trigger justification:** Both T2 and T3 originate from observed-in-testing entries in the S27 backlog (`tasks.md` Sprint 27 backlog lines 20–21). Per CLAUDE.md backlog policy these are auto-promotion eligible — trigger fired in real user testing on real hardware.

---

1. ~~**T1 — Cold-start D-Bus activation race in `NewTunnel`.**~~ ✅
   - **Symptom (S27 testing, 2026-05-20):** First Connect after a fresh login can fail with "Object does not exist at path /net/openvpn/v3/sessions" when the `net.openvpn.v3.sessions` service has not yet been D-Bus activated. Subsequent clicks succeed once dbus-daemon spawns the sessionmgr.
   - **Call sites for `connect_to_config` (grep-enumerated):**
     - `gui/src/app/actions.rs:33` (tray Connect action)
     - `gui/src/app/actions.rs:55` (post-credential-prompt retry path)
     - `gui/src/app/dbus_init.rs:301` (cold-start re-apply of most-recent config — *not* in scope; this fires after `init_dbus()` already raced the service, so the activation event has already occurred by here)
     - `gui/src/dialogs/notification/interactive.rs:220` (Reconnect button on unexpected-disconnect notification — distant from cold start but uses same fn; benefits transparently from the fix)
   - **Design preference:** retry-with-backoff inside `connect_to_config` at `session_manager.NewTunnel(obj_path).await` (`session_ops.rs:70`). Match on `zbus::Error::MethodError` with `org.freedesktop.DBus.Error.UnknownObject` / `Error.ServiceUnknown`; retry up to 3 times with 500 ms / 1 s / 2 s backoff (max ~3.5 s total wait). Any other error fails immediately (so credential / network errors aren't masked by retry).
   - **Why retry (not name-wait):** name-wait at app startup would block UI init on a service the user may never use; per-call retry keeps the cost paid only when actually needed. Matches existing `init_dbus` retry-with-backoff pattern (`service_watcher.rs:69-79`).
   - **State × behaviour matrix:**
     - Tray menu Connect action: silent retry; on persistent failure → `show_error_notification("Connect Failed", "OpenVPN3 service did not respond. Try again or restart the openvpn3 service.")`.
     - Tray icon: stays "Idle" during retry (no false transient connecting state).
     - "Connecting…" toast: deferred until first attempt succeeds (avoid orphan toast on persistent failure).
     - Logs dialog: `info!` per attempt, `warn!` on final failure (already covered by existing `info!`/`error!` lines in actions.rs).
   - **Test plan:** (a) `systemctl --user stop openvpn3-sessions` → click Connect from tray → verify retry succeeds when service activates, OR clean error notification after exhausted retries. (b) Unit test the retry-deciding match arm against a synthetic `zbus::Error::MethodError` value.
   - **Acceptance:** first-connect-after-login flake disappears in user testing; existing connect happy-path latency unchanged.

2. ~~**T2 — Sessions-service watcher (close stale-session gap).**~~ ✅
   - **Symptom (S27 testing, 2026-05-20):** `kill -9` on `openvpn3-sessionmgr` leaves dead `SessionInfo` entries in `tray.sessions` indefinitely. Tray menu still shows the profile as "Connected"; Disconnect / Resume / Pause / Restart all silently fail with "Object does not exist at path …". Only fix is to restart the GUI.
   - **Root cause (`service_watcher.rs:12,27,81`):** watcher subscribes to `NameOwnerChanged` filtered on `arg0='net.openvpn.v3.configuration'` only. The sessions service (`net.openvpn.v3.sessions`) is a separate well-known name owned by a separate process — its lifecycle is invisible to the GUI today.
   - **Fix path 1 (primary):** extend `service_watcher.rs` to install a second match rule for `arg0='net.openvpn.v3.sessions'`. On NameLost (`new_owner.is_empty()`) for this name: clear `tray.sessions`, reset `kill_switch_active` flags, tear down KS rules + bypass routes (matches the user-initiated-disconnect cleanup in `signal_handlers.rs:160-171`). On NameAppeared: rebind via `init_dbus` (existing path covers this).
   - **Fix path 2 (defence-in-depth):** in `session_action` (`session_ops.rs:123`) and `resume_session` (`session_ops.rs:148`), match on the same `UnknownObject` / `ServiceUnknown` error class from T1 and auto-remove the stale entry from `tray.sessions`. Belt-and-suspenders for the window between NameLost arrival and watcher cleanup.
   - **Refactor opportunity:** generalize `is_service_appeared` to `is_owner_changed(name, expected_name, direction)` where `direction` ∈ {Appeared, Lost}, or split into two named predicates (`is_service_appeared` + `is_service_lost`). Existing 4 tests + 4 new tests.
   - **State × behaviour matrix (real surfaces, grounded in code):**
     - Tray icon (`tray/indicator.rs`): updates to "Idle" via the existing `update()` closure pattern.
     - Tray menu session entries (`tray/menu.rs`): cleared.
     - Kill-switch lock icon: cleared (rules removed via existing `crate::dbus::killswitch::remove_rules()`).
     - Bypass state (`tray.bypass_state`): reset to `BypassState::Off`; existing `crate::dbus::killswitch::remove_bypass_routes()` tears down routing.
     - Notifications: one toast — `show_killswitch_inactive_notification` if KS was active; new dedicated "OpenVPN3 sessions service stopped" info-level notification only if `tray.sessions` was non-empty at NameLost (avoid noise on cold-start when sessionmgr was never running).
     - First-run help notification: not relevant (gated on configuration service only).
   - **Test plan:** (a) start connected → `systemctl --user kill openvpn3-sessionmgr` → verify tray clears within ~1 s, KS lock icon clears, bypass tears down, notification fires. (b) sessions service comes back via D-Bus activation on next Connect → existing init_dbus re-bind path is exercised. (c) Unit tests on `is_service_lost`.
   - **Acceptance:** dead session entries are no longer possible without a GUI restart; KS/bypass state cleanly mirrors helper state after a sessions-service crash.

3. ~~**T3 — Sprint-end hygiene + release tag.**~~ ✅
   - **Doc sync:** README behaviour bullet — no change (both fixes are invisible-on-happy-path resilience). `metainfo` `<release version="0.3.5">` block via `prepend-metainfo-release.sh`, body: "Robustness: recover gracefully when openvpn3 sessions service is killed or hasn't D-Bus activated yet."
   - **Dep audit:** verify no new deps added by T1/T2; remove any dep whose grep count drops to zero.
   - **600-LOC re-check:** confirm 0 files ≥600 at sprint end. Track expected delta — T2 adds ~30–50 LOC to `service_watcher.rs` (currently 120L, well under threshold).
   - **Version bump:** `make bump-version V=0.3.5` (patch — bugfix-only sprint). Verify all 6 files updated (gui/Cargo.toml, helper/Cargo.toml, Cargo.lock, pkg/aur/PKGBUILD, pkg/aur-helper/PKGBUILD, metainfo). S27 retro caught `pkg/aur-helper` missing from bump-version; verify the S27 fix held.
   - **Tag + release verification:** `git tag v0.3.5 && git push origin v0.3.5` after PR #28 merge. Verify GitHub Release page lists 4 artifacts (2 deb + 2 rpm) per S26 retro CLAUDE.md rule.

4. ~~**T3b — Partial-failure bypass reporting (mid-sprint promotion).**~~ ✅
   - **Trigger:** grep-check during S28 planning revealed helper `ApplyBypassRoutes` returns all-or-nothing; partial CIDR failure is a real gap on misconfigured networks.
   - **Helper:** `install_rules` collects per-CIDR `(applied, failed)` instead of fail-fast; system-wide steps (gateway capture, rp_filter, table) still fail fast.
   - **GUI:** `BypassState::Active { applied, failed }` struct variant; tray label "X active, Y failed"; persistent notification lists failing CIDRs. `MIN_HELPER_VERSION` raised to 0.3.5 (wire-incompatible signature change).
   - **User testing:** partial failure not reproducible on healthy system (teardown clears duplicates before install) — defense-in-depth path verified via unit tests.

---

## Backlog (trigger-gated, do NOT auto-promote)

(Carried forward from Sprint 27 backlog minus T1/T2 promoted above.)

- **nft bypass-set drift detection** — S26/S27 deferred. Polish; trigger = real user report of bypass-set drift.
- **DNS leak on bypassed-host queries (per-domain split-DNS)** — S27 T4 finding. Trigger = real user report of metadata-exposure concern.
- **Per-app split-tunneling cgroups v2 variant** — S20 backlog item.
- **S22 PoC tail items** (conntrack/MTU re-test on reachable network, kill-switch-ON test mode, `test-resume` interactive validation) — low priority.

---

# Sprint 27 Tasks

**Theme:** Bug fix + split-tunnel defence-in-depth + release-workflow hardening. Two backlog items unlocked (resume re-auth, DNS leak); CI policy gap closed (artifact assertions); sprint-end release tag per S26 retro CLAUDE.md rule.

**Branch:** `sprint-27/all-tasks` (created at sprint start per S25 retro rule).

**Pre-sprint check:** `find {gui,helper}/src -name '*.rs' | xargs wc -l | awk '$1>=600'` — confirm empty. Current 500–599 watch list: `gsettings.rs` (582), `routing_tab.rs` (563). Per S25 retro rule: split only if a sprint task touches the file.

1. ~~**[Read-only] Resume-after-long-pause re-auth investigation.**~~ ✅ (2026-05-20) Code-path traced end-to-end. **Findings:**
   - Resume click → `actions.rs:97` `TrayAction::Resume` → `session_ops::resume_session` (`session_ops.rs:135-168`) → `session.Resume().await?` → `session.Ready().await` → Err branch dispatches `request_credentials` (already wired).
   - StatusChange handler (`status_handler/mod.rs:87-94`) **already exempts auth requests from dedup** (line 90 `is_auth = status.is_auth_request()`), so a re-emitted auth signal after Resume on invalidated session reaches `try_handle_auth`.
   - `credential_handler.rs:97-100` already warns + returns on empty slots (no silent fail there).
   - **Three plausible bug scenarios** (need real-server reproduction to disambiguate):
     - **A.** Race: `Ready()` returns Ok before backend observes invalidation; tunnel appears to resume in tray but sits in connecting/error with no UI prompt.
     - **B.** `Ready()` Err returns wrong variant → `request_credentials` early-return path (already covered by line 97 warn).
     - **C.** Menu state machine: by the time user clicks, session is no longer `ConnPaused` — "Resume" button gone, only "Reconnect" shown. Not a bug, UX confusion.
   - **Deliverable**: this writeup + T2 split into instrumentation-first (T2a) and reproduction-driven fix (T2b). No code commit for T1 (read-only).

2. **T2a — Resume re-auth diagnostic instrumentation.**
   - Add `info!` log on `Ready()` Ok branch in `session_ops::resume_session` (Err branch already logged).
   - Add `info!` log when dedup-exempt auth signal re-emits in `status_handler/mod.rs` (proves the dedup exemption fires on resume-after-invalidation).
   - `credential_handler.rs:97-100` empty-slots warn already in place — no change needed.
   - **Test plan (user-tested before T2b):** reproduce on real OpenVPN server: connect → pause → wait until server invalidates → resume. Capture `journalctl --user -t openvpn3-gui-rs` logs. Logs disambiguate A/B/C.

3. ~~**T2b — Fix reconnect notification after delayed tray removal.**~~ ✅ (2026-05-20) Root cause: `status_handler` removes session from `tray.sessions` 3s after `ConnDisconnected`, but `SessDestroyed` arrives ~8s later. Handler reads `tray.sessions.get()` → `None` → reconnect notification silently fails.
   - **Fix**: `RECENT_DESTROYED_SESSIONS` side-channel cache in `session_ops.rs` — `status_handler` populates it before 3s removal, `signal_handlers` drains it on `SessDestroyed` as fallback.
   - **Tested**: pause → kill backend → SessDestroyed → reconnect notification fires (debug + release builds). Earlier release-build failure was transient (environmental), not code regression.
   - Commit `75adc8f`.

4. ~~**[Read-only] DNS leak on bypass CIDRs investigation.**~~ ✅ (2026-05-20) Code-path traced. **Findings:**
   - Helper has zero DNS code (`grep -ri dns helper/src/` → 1 comment-only match). Bypass operates purely on destination IPs via `ip rule` + `openvpn3-bypass` routing table + nft sets.
   - On Linux with systemd-resolved, DNS queries go to stub `127.0.0.53` via `lo` — never matched by bypass ip rules (which match destination CIDR, not loopback). Upstream resolver path depends on systemd-resolved config (`Domains=`, `DNS=`, link-specific `DNS=`).
   - **Three observable failure modes** (need real-host reproduction for which dominates):
     - **VPN-side leak** (most common with OpenVPN push-DNS): resolved promoted VPN's pushed DNS via `Domains=~.`, all queries (incl. bypassed-host names) hit VPN provider's resolver — bypass IP routing works but query metadata leaks.
     - **ISP-side leak**: no push-DNS, system retains LAN resolver — bypassed-host queries hit ISP (matches no-VPN baseline; arguably the documented goal).
     - **Correct path**: per-domain split-DNS configured in systemd-resolved — rare without explicit user setup.
   - **Verdict**: matches partial expectation of split-tunneling — `docs/split-tunneling.md` already implies destination-IP scope. Documentation gap: README + tooltip don't surface the DNS caveat. Fix deferred to T7 doc sync. Actual DNS-leak resolution (per-domain `Domains=` config or hosts-file override) deferred to backlog with trigger gate (real user report of metadata exposure concern).
   - **Deliverable**: ~120-line code-path + failure-mode section appended to `docs/split-tunneling.md`. No code change.

5. ~~**nft bypass-set drift detection**~~ ⏭️ Deferred to backlog (2026-05-20). T4 surfaced no urgent fix and the conditional gate on this task ("defer if T3 surfaces a more pressing fix or sprint capacity tightens") leaves room — but the remaining sprint value is concentrated in T7 (release tag + hygiene). Drift detection is polish (no observed user-reported drift); preserve sprint focus. Backlog entry below carries the file:line plan from this task body.

6. ~~**Release workflow artifact assertions.**~~ ✅ (2026-05-20) Workflow already had `ls -la <glob>` after all 4 build steps (landed earlier with the v0.3.0 RPM-missing fix). Mirrored to `Makefile` `deb`/`deb-helper`/`rpm`/`rpm-helper` targets — each ends with `ls -la <expected-glob>` so a silent producer failure surfaces at the failing target instead of at install/upload time. Verified locally: `make deb && make deb-helper && make rpm && make rpm-helper` — all 4 assertions pass on green path. Artifact sizes: GUI deb 1.8M, helper deb 956K, GUI rpm 1.9M, helper rpm 1019K.

7. ~~**Sprint-end hygiene + release tag.**~~ ✅ (2026-05-20)
   - **Dep audit**: all 13 GUI + 7 helper deps actively used (grep counts ≥1 for every dep). No removals.
   - **600-LOC re-check**: 0 files ≥600. Watch list (500–599): `gsettings.rs` 582, `routing_tab.rs` 564 (+1 from S27 DNS caveat label, still under 600), `logs/mod.rs` 503 (S26 retro dropped; rediscovered but no S27 task touched it — leave dropped per CLAUDE.md "future audit will rediscover if needed" semantics).
   - **Doc sync**: README split-tunneling bullet + Routing prefs tab description now carry the DNS-leak caveat (commit `19955d8`). metainfo `<release version="0.3.4">` prepended via `prepend-metainfo-release.sh`.
   - **Version bump to 0.3.4**: gui/Cargo.toml + helper/Cargo.toml + Cargo.lock + pkg/aur/PKGBUILD + pkg/aur-helper/PKGBUILD + metainfo (commit `6d4a640`). Caught a bug in `make bump-version` — was missing `pkg/aur-helper/PKGBUILD`; patched in same commit.
   - Tag `v0.3.4` pushed after PR #27 merge. Release page: 4 artifacts (2 deb + 2 rpm).

---

## Backlog (trigger-gated, do NOT auto-promote)

- **nft bypass-set drift detection** — S26/S27 deferred. Periodic check that `nft list set inet openvpn3-bypass bypass_set` matches GSettings `enabled_cidrs()`. Files: `helper/src/bypass.rs` (drift-check fn), `gui/src/dbus/killswitch.rs` (poll trigger or signal), `gui/src/tray/indicator.rs` (state update). Trigger: real user report of bypass-set drift (manual `nft` edit, helper crash mid-apply).
- **DNS leak on bypassed-host queries (per-domain split-DNS)** — S27 T4 finding. Trigger: real user report of metadata-exposure concern. Fix path: per-domain `Domains=` config in systemd-resolved, or `/etc/hosts` override for bypass hostnames.
- **Partial-failure bypass reporting (`Active(x) + Failed(y)` granularity)** — helper API all-or-nothing. Trigger: observed kernel-rule-install failure in practice.
- **Helper version probe / GUI–helper compatibility check** — no concrete trigger yet, hold.
- **Cold-start D-Bus activation race** — `NewTunnel` fails with "Object does not exist at path /net/openvpn/v3/sessions" if sessionmgr service not yet D-Bus activated. Trigger: observed in testing. Fix path: retry-with-backoff in `connect_to_config`, or wait-for-name before `SessionManagerProxy::builder().build()`.
- **Stale session after sessions service killed** — `service_watcher` only monitors `net.openvpn.v3.configuration`, not `net.openvpn.v3.sessions`. Killing sessions service leaves dead session objects in tray with no way to clear (Resume/Disconnect all fail with "Object does not exist"). Trigger: observed in testing. Fix path: also watch `net.openvpn.v3.sessions` for `NameOwnerChanged`, or handle "object does not exist" errors in session actions by auto-removing stale entry.
- **Per-app split-tunneling cgroups v2 variant** — S20 backlog item.
- **S22 PoC tail items** (conntrack/MTU re-test on reachable network, kill-switch-ON test mode, `test-resume` interactive validation) — low priority, defer until next split-tunnel feature work.

---

# Sprint 26 Tasks

**Theme:** UX polish + backlog hygiene. One concrete feature (per-entry bypass toggle), explicit closeout of the silent-failure tail, watch-list cleanup per S25 retro. No new big surfaces — close out S23/S24 deferred items so the tracker reflects reality.

**Branch:** `sprint-26/all-tasks` (created at sprint start per S25 retro rule).

1. ~~**[Structural — gates rest, read-only] Audit + apply S25 retro watch-list rule.**~~ ✅ (2026-05-19) Pre-sprint check confirmed: **0 files ≥600 LOC**. 500–599 watch list grounded: `gsettings.rs` (548), `routing_tab.rs` (509), `logs/mod.rs` (503). Watch-list decisions per S25 retro rule recorded below — `logs/mod.rs` **dropped** (no S26 task touches it), `routing_tab.rs` + `gsettings.rs` retained with explicit T2 trigger. Read-only completion.

   - Pre-sprint check: `find {gui,helper}/src -name '*.rs' | xargs wc -l | awk '$1>=600'` — confirmed empty. Current 500–599 watch list: `gsettings.rs` (548), `routing_tab.rs` (509), `logs/mod.rs` (503).
   - Apply S25 retro watch-list rule: each entry needs explicit trigger or removal. **Triggers:**
     - `routing_tab.rs` (509) — **T2 touches this file**, expected to grow by ~30–50 LOC for the toggle column. If post-T2 size lands ≥600, schedule split as T2 sub-task (extract `CidrListWidget` into `routing_tab/cidr_list.rs`).
     - `gsettings.rs` (548) — T2 adds 1 new key + accessors (~20 LOC). Trigger: split when next sprint touches this file *and* size lands ≥600.
     - `logs/mod.rs` (503) — no S26 task projected to touch it. **Drop from watch list per retro rule.** Future audit will rediscover if needed.
   - Read-only completion: deliverable is the recorded watch-list decisions above. Re-check at sprint end (T4).

2. ~~**[Feature] Per-entry enable/disable toggle in Routing tab.**~~ ✅ (2026-05-19) Shipped in commit `072d001`. New `bypass-cidrs-disabled: as` GSettings key, pure `enabled_cidrs(all, disabled)` filter (4 tests), checkbox per row in routing tab (dim-label when disabled, orphan-cleanup on delete), Save closure persists both lists + pushes filtered subset to helper. Lifecycle wiring covered at all 3 push sites: Preferences Save, on_connected, cold-start re-apply. User tested matrix (empty/add/uncheck/recheck/delete/connect/restart) — pass. Follow-up bug found during testing: cold-start re-apply applied bypass routes but never set `tray.bypass_state`, leaving tray showing "Off" while helper had rules installed. Fixed in commit `c8008d2` (mirror on_connected: Active(count)/Failed + notification). Post-T2 LOC: routing_tab.rs 563, gsettings.rs 582, both under 600 ceiling.
   - Surfaced during S23 T4 user testing 2026-05-13 (S23 backlog). Lets users keep CIDRs in the list while temporarily deactivating them (context-switch workflow: home/coffee shop/work). Current workaround = delete + re-add.
   - **Design (lightweight per S23 backlog):**
     - New GSettings key `bypass-cidrs-disabled: as` (default `[]`) — parallel to existing `bypass-cidrs`. Avoids migration of existing schema.
     - Helper unchanged: enabled-vs-disabled is a GUI concept. Save closure filters disabled out before push to helper via `set_bypass_cidrs`.
     - UI: GtkCheckButton per row in `CidrListWidget` (left of the CIDR label, before the remove button). Unchecked = disabled (greyed CIDR label).
     - Apply-on-Save (matches existing CIDR-list semantics; no live-toggle complexity in v1).
   - **State × behaviour matrix (grounded in real surfaces):**
     - Tray bypass row: shows count of **enabled** entries only (`Off` if 0 enabled, `Active(n)` for n enabled). Disabled entries don't count toward apply.
     - Tray indicator: unchanged (no per-entry view in tray).
     - Notifications: unchanged (success/failure on apply — apply only sees enabled entries).
     - Preferences Routing tab: new checkbox per row.
     - Settings storage: 2 keys (`bypass-cidrs` + `bypass-cidrs-disabled`).
   - **Lifecycle wiring (per CLAUDE.md "every event-driven action gets cold-start path"):** Connect path, cold-start re-apply, Preferences Save — all three filter `bypass-cidrs` by `bypass-cidrs-disabled` before pushing to helper. Grep `set_bypass_cidrs` call sites and confirm all updated.
   - **Tests:** 2 settings tests (default + roundtrip), 1 filter-pure-fn test (`enabled_cidrs(all: &[String], disabled: &[String]) -> Vec<String>`).
   - User-test running app before commit (matrix verification + checked/unchecked behaviour + filter on apply).
   - Mock + design approval required before implementation per CLAUDE.md "describe proposed result and get explicit approval".

3. ~~**[Cleanup] Close out silent-failure tail with explicit "won't fix" rationale.**~~ ✅ (2026-05-19) Commit `7d7f62c`. `docs/failure-modes.md:74-95` rewritten — section header changed from "Deferred to Sprint 26+" to "Won't fix (rationale recorded, S26 closeout)" with explicit per-cell rationale for #6, #7, #12, #18, #19 and re-open trigger (real user report). No code change. Read-only completion per CLAUDE.md exception.
   - 5 cells (#6, #7, #12, #18, #19) deferred from S24 T6 / S25 T4 audits with acceptable rationale recorded at `docs/failure-modes.md:74-83`. Their state in the tracker has been "deferred to S26+" for two sprints — long enough to confirm rationale holds.
   - Action: rewrite the "Deferred to Sprint 26+" section as "Won't fix (rationale recorded)" with explicit decision per cell. No code change.
     - **#6, #7** (version mismatch log-only): documented as user-checkable via `--verbose`; acceptable.
     - **#12** (auth dispatch returns None): rare D-Bus proxy failure; existing error path covers connection failure.
     - **#18** (refresh_configs failure): self-correcting on next poll (existing behaviour).
     - **#19** (service restart re-init): rare; user can restart app; existing recovery path covers normal service restart.
   - **Trigger for revisit:** any of these surfaces in real user reports → re-open as a numbered task in that sprint. Until then, they are closed, not deferred.
   - Read-only completion per CLAUDE.md exception — deliverable is the recorded decisions in `docs/failure-modes.md`.

4. ~~**[Packaging] AUR `openvpn3-killswitch-helper` PKGBUILD.**~~ ✅ (2026-05-19) Commit `468f0da`. New `pkg/aur-helper/PKGBUILD` mirrors `pkg/aur/PKGBUILD` pattern: builds helper crate via `cargo build --release --locked -p openvpn3-killswitch-helper`, installs 3 assets (binary, D-Bus system-service file, access policy) to canonical paths from `helper/Cargo.toml [package.metadata.deb]`. depends=('nftables' 'dbus'). namcap lint deferred (tool unavailable). `make check` clean.
   - Known gap from S24 T5 packaging audit: "no separate `openvpn3-killswitch-helper` PKGBUILD for Arch — documented, not a regression." Closes the parity gap between DEB/RPM (both split GUI + helper) and AUR (only GUI shipped).
   - Scope: new `pkg/aur-helper/PKGBUILD` mirroring the existing `pkg/aur/PKGBUILD` pattern but packaging helper binary + D-Bus service file + access policy file + (if present) `data/openvpn3-killswitch-helper.service` or whatever sysd unit ships with the DEB. Grep DEB asset list (`helper/Cargo.toml [package.metadata.deb]`) for canonical artifact set — AUR helper PKGBUILD must install the same files in the same locations.
   - Verify `makepkg -si` in a clean Arch chroot (or document required Arch toolchain steps if chroot unavailable). PKGBUILD `provides`/`conflicts` consistent with helper's role; `depends` on `nftables` + `dbus` at minimum.
   - **Trigger for proactive scheduling:** S24 T5 documented this as a known gap → 2 sprints elapsed → closeout sprint. Defer if Arch user demand is zero (verify against issue tracker).
   - **Tests:** `make check` clean. No new Rust code — packaging file only.
   - **Acceptance:** `pkg/aur-helper/PKGBUILD` lints clean via `namcap` (if available); installed helper binary runs as the system D-Bus service when invoked.

5. ~~**[Doc refresh] Verify `docs/kill-switch.md` + `docs/split-tunneling.md` reflect current code.**~~ ✅ Commit `2b6c6bd`. `docs/kill-switch.md`: `status_handler.rs` → `status_handler/mod.rs` (4 occurrences); `watch_service_restart()` location corrected to `app/service_watcher.rs`; cold-start section extended to describe bypass route re-apply + `tray.bypass_state` restoration to `Active(N)` / `Failed`; split-tunnel coexistence risk rewritten from "future work" to "implemented" with cross-reference to `split-tunneling.md`. `docs/split-tunneling.md`: status banner added after line 3 documenting Option B (per-route + nft bypass set) as shipped in S26 — Routing tab, helper `SetBypassCidrs`/`ApplyBypassRoutes`/`ClearBypassRoutes`, cold-start re-apply, lifecycle integration, tray bypass state row, per-entry enable/disable. Read-only completion per CLAUDE.md exception (deliverable = patched docs).

6. ~~**[Sprint-end hygiene] Doc sync + dep audit + 600-LOC re-check + dead-icon cleanup.**~~ ✅ Commits `14cd8d1` + `7f15925`. **(a)** README + metainfo updated: split-tunneling per-entry enable/disable checkboxes mentioned in feature bullet and Preferences description; metainfo 0.3.2 `<release>` block gained T2 (per-entry enable/disable) + T4 (AUR PKGBUILD) entries. **(b)** Dep audit: all 12 GUI runtime deps + 6 helper runtime deps + 1 GUI build dep verified used via grep — zero removals, zero additions. **(c)** 600-LOC re-check: `gsettings.rs` 582, `routing_tab.rs` 563, `logs/mod.rs` 503 — all under threshold; watch list retained without S27 split scheduling (per retro rule: explicit trigger only when next sprint actually touches them). **(d)** No release tag cut this sprint — release-page verification deferred. **(e)** Dead-icon cleanup: `killswitch-on.svg` + `killswitch-off.svg` deleted from `data/icons/hicolor/scalable/status/`; corresponding DEB asset lines (gui/Cargo.toml:68-69) and 2 RPM asset blocks (lines 132-140) removed. `make check` clean (163 GUI + 56 helper + smoke).

## Backlog (post-sprint, for S27+ consideration)

Trigger-gated items (do NOT auto-promote without trigger firing):
- **Partial-failure bypass reporting** (`Active(x)+Failed(y)` granularity) — trigger: kernel-rule-install failures observed in practice.
- **DNS leak on bypass CIDRs** — trigger: concrete user report.
- **nft bypass-set drift detection** — trigger: production usage signals need.
- **Per-app split-tunneling cgroups v2 variant** — trigger: concrete user request (rejected for v1 in S21 T4 spike).
- **About dialog Adwaita title-bar styling** — cosmetic, low priority per S20 backlog. Trigger: framework offers a clean fix.
- **S22 PoC tail items** — KS-ON test mode + `test-resume` interactive validation. Trigger: split-tunneling regression in production.

## Dropped

(none yet)

# Sprint 25 Tasks

**Theme:** Production-readiness pass continued — close release-tooling gaps from S24 retro, add launch-on-login UX, sweep silent-failure tail from S24 T6 audit. No new big features beyond autostart.

1. ~~**[Structural — first, gates T3..T5] Audit + split any file ≥600 LOC.**~~ ✅ **Read-only completion** (2026-05-19, pre-sprint). Grep `find {gui,helper}/src -name '*.rs' | xargs wc -l | awk '$1>=600'` returned empty — 0 files at threshold. 4 files in 500–599 band (watch list): `gui/src/dialogs/notification/mod.rs` (555), `gui/src/settings/gsettings.rs` (520), `gui/src/dialogs/preferences/routing_tab.rs` (509), `gui/src/dialogs/logs/mod.rs` (503). T3 targets `general_tab.rs` (different file), T2 touches only Makefile + release.yml, T4 likely touches status_handler/application/dbus_init (none near threshold) — no S25 task projected to cross 600L. Re-check at sprint end.

2. ~~**[Tooling — release hardening, absorbs S24 backlog lines 23+24+25] Release-workflow post-condition + bump-version sed fix.**~~ ✅ Both sub-items shipped in single commit `2f4aba9`. **(a)** Sed at `Makefile:95` replaced with `scripts/prepend-metainfo-release.sh` (awk-based prepend after `<releases>` tag, with placeholder `<p>TBD — fill in before commit</p>` body). Dry-run 0.3.1 → 0.3.2 verified: 5-line insertion, zero edits to prior 0.3.1 entry. Script validates `<releases>` tag exists at expected indentation before writing — fails loudly on schema drift. **(b)** Per-step `ls -la <expected-glob>` post-condition added to all 4 build steps in `.github/workflows/release.yml` (DEB GUI, DEB helper, RPM GUI, RPM helper). Top-of-file comment block documents expected-artifact manifest. v0.3.0-class silent produce-step failures now caught at the producing step instead of downstream at upload. `make check` clean (209 tests + smoke); YAML validated.

3. ~~**[Feature] Launch-on-login (autostart) toggle in Preferences General tab.**~~ ✅ Shipped in commit `191673e`. New `gui/src/autostart.rs` (110L incl 2 unit tests) owns the XDG layer: `autostart_path()` resolves `$XDG_CONFIG_HOME/autostart/net.openvpn.openvpn3_gui_rs.desktop` (HOME fallback), `enable()` writes a static `&'static str` desktop entry (Exec=openvpn3-gui-rs, X-GNOME-Autostart-enabled=true, X-KDE-autostart-phase=2, Hidden=false), `disable()` removes (NotFound = Ok), `is_enabled()` is `path.exists()`, `sync_gsettings_from_fs()` re-aligns the mirror at startup. GSettings key `launch-on-login` (bool, default false) added with `launch_on_login()` / `set_launch_on_login()` accessors + 2 fallback tests. CheckButton appended at top of Startup Behavior group above the radio set (general_tab.rs), wired live on toggle (FS write happens immediately, not on Save) — failure shows `show_error_notification` and leaves widget state; next dialog open re-reads FS for source-of-truth. Cold-start sync called once at `Application::run` after `Settings::new()`. **Plan deviation:** dropped projected `--background` flag — app is purely tray-only (no main window ever shows), flag would be a no-op; autostart Exec is plain `openvpn3-gui-rs`. State×behaviour matrix unchanged (Preferences-only surface). `make check` clean (157 GUI tests + 56 helper + smoke). User tested live before commit.

4. ~~**[Cleanup] Silent-failure tail from S24 T6 audit.**~~ ✅ Shipped in commit `ea41d10` (out-of-band, pre-T3). Two highest-impact silent cells from the 7-cell tail fixed: **#5** (`dbus_init.rs:216` — KS cold-start re-apply Err arm now calls `show_error_notification("Kill-Switch Re-Apply Failed", …)` instead of bare `warn!`; closes the security gap where the lock icon appeared without confirmation that nft rules actually landed) and **#13** (`actions.rs:76,91,108,122` — four `TrayAction` Err arms `Disconnect`/`Pause`/`Resume`/`Restart` each emit a per-action error notification with action-named title, removing "clicked menu, nothing happened" UX on D-Bus failure). Pattern matches S24 T6 fixes (#1/#2/#3/#8): keep `tracing` log + add `show_error_notification`. `docs/failure-modes.md` updated — table cells #5 and #13 marked Fixed, new "Fixes applied Sprint 25" block added, deferred list shrunk to 5 cells (#6, #7, #12, #18, #19) deferred to S26+. `make check` clean (209 tests + smoke). **Tracker sync:** task was already complete when T3 finished — tasks.md was stale, fixed per CLAUDE.md `## Planning` ("If code and tracker disagree, fix the tracker immediately").

5. ~~**[Sprint-end hygiene] Doc sync + dep audit + conditional release-page verification.**~~ ✅ **(a)** README + metainfo: "Launch on login via XDG autostart (toggle in Preferences)" bullet added to both files. Commit `c2dd18a`. **(b)** Dep audit: all 13 GUI runtime deps + 7 helper runtime deps actively used — zero removals. **(c)** 600-LOC re-check: 0 files at threshold. Largest file `gsettings.rs` at 548L. Watch list: `gsettings.rs` (548), `routing_tab.rs` (509), `logs/mod.rs` (503). Notification split (T6) removed `notification/mod.rs` from the watch list (was 555L → 24L hub + 4 focused sub-modules). No release tag this sprint — release-page verification deferred.

6. ~~**[Structural] Split notification module (555 LOC).**~~ ✅ `gui/src/dialogs/notification/mod.rs` (555L) → 5 focused files: `mod.rs` (24L re-export hub), `core.rs` (~120L transport + fire-and-forget), `interactive.rs` (~280L reconnect + first-run help with action buttons), `killswitch.rs` (~115L KS state + helper-missing), `bypass.rs` (~100L split-tunnel state). Public API unchanged. Commit `b684a54`.

## Backlog

(Populated at sprint end per retro outcomes. Inherits all 7 trigger-gated items + 4–5 remaining silent-failure cells from S24 — see S24 backlog inventory below for full list.)

## Dropped

(none yet)

# Sprint 24 Tasks

**Theme:** Production-readiness pass — structural cleanup, logs-dialog UX overhaul, packaging audit, first-release polish, backlog hygiene. No new big features; close gaps that would bite first non-dev users.

1. ~~**[Structural — first, gates T3..T6] Split `helper/src/service.rs` (624L) into ~3 modules.**~~ ✅ Split into **two** modules (not three — projected (b)/(c) seam between State lifecycle and command-orchestration glue didn't exist in practice: `State` and `run_nft` both tightly coupled to the zbus interface impl, only the pure validation surface (a) sat cleanly behind a boundary). New `helper/src/validation.rs` (308L) owns the 4 input-validation free fns (`validate_interface`, `split_ips`, `validate_bypass_cidrs`, `canonicalize_cidr`), `IFNAMSIZ_MAX` + `MAX_BYPASS_CIDRS` constants, and all 25 unit tests; `service.rs` (326L) retains zbus `#[interface]` impl, `State` struct, lifecycle, `cleanup_rules`, `run_nft`. Both under 600 LOC. No public API drift (D-Bus interface name + method names byte-identical). 56 helper tests pass (`validation::tests::*` hosts 25, other modules 31); 134 GUI tests pass; clippy `-D warnings` clean. Commit `bc51f2b`.

2. ~~**[Backlog hygiene — file edits, no code] Prune stale `tasks.md` backlog entries across all historical sprints.**~~ ✅ All 4 brief items applied: (a) S20 "Notification gap" deleted (shipped S21 T3 commit `777d626`); (b) split-tunneling per-app-or-per-route rewritten in S17, S19, S20 backlogs to track only the per-app cgroups v2 variant (per-route shipped S22+S23, per-app rejected for v1 in S21 T4 spike); (c) S20 "`tray/menu.rs` at threshold" deleted (split S21 T1); (d) S22 backlog cleaned — "split-tunneling implementation" line removed (shipped S23 T2..T5c), vague "(other items inherited from S21 backlog)" placeholder removed. **Brief commit step skipped** — `tasks.md` is gitignored (`.gitignore:22`, sprint plan is a private local doc per pre-existing project decision), so `chore: prune stale tasks.md backlog entries` commit cannot land. Brief contradicted project setup; flagged for sprint retro. File reflects reality going forward; no commit produced.

3. ~~**Logs dialog UX overhaul.**~~ ✅ All four sub-features shipped: (i) per-tab case-insensitive substring search; (ii) per-tab level dropdown (All / Warn and above / Error only) — mapped to category thresholds 0/5/6; (iii) per-tab Copy button writing the currently visible (filter-aware) buffer text to clipboard, not full history; (iv) window width/height persisted to GSettings on `close_request`, restored on next open. Search + level compose with AND. Filter state held in three `Rc<RefCell<…>>` handles per tab so switching tabs preserves each view. Live-tail appends to tab-local `entries` vec and conditionally inserts into the buffer based on current filter — keeps filter response O(history) instead of re-locking global `LOG_BUFFER` on every keystroke. New GSettings keys `logs-window-width` (default 800, range 400–4000) and `logs-window-height` (default 600, range 300–3000) with 4 new unit tests (default + no-panic-on-set for each, matching existing `Settings::new_empty()` test pattern). File sizes after landing: `gui/src/dialogs/logs/mod.rs` 498 LOC, `gui/src/settings/gsettings.rs` 520 LOC — both under the 600 ceiling, no structural split required. Mock approved by user before implementation (per-tab header strip inside each tab, between tab-label row and log area). User tested running app + confirmed before commit. `make check` clean (153 GUI + 56 helper = 209 tests). Commit `99b572e`.

4. ~~**GSettings schema migration smoke test.**~~ ✅ All 18 schema keys verified to return correct defaults via isolated `GSETTINGS_BACKEND=memory` + `GSETTINGS_SCHEMA_DIR` temp directory — confirms all three install paths (fresh, empty-dconf, upgrade) resolve cleanly with no migration warnings. `gsettings get` CLI quirks noted: drops `int32` type prefix for signed int defaults, keeps `uint32` prefix for unsigned. Rust-side `gio::Settings` returns actual values regardless of CLI display. New `tests/gsettings_schema_test.sh` (75 LOC). Commit `6052491`.

5. ~~**Packaging audit (`pkg/deb`, `pkg/aur`, `data/`).**~~ ✅ **DEB:** both `make deb` (GUI) and `make deb-helper` produce correct packages. GUI DEB verified via `dpkg-deb --contents`: binary, desktop entry, GSettings schema, metainfo, 9 status/app/mimetype icons, Yaru mimetype icon, postinst/postrm trigger glib-compile-schemas + gtk-update-icon-cache + update-desktop-database. Helper DEB: binary, D-Bus service file, D-Bus access policy. **RPM:** two bugs found and fixed — (a) all data/ asset paths in `gui/Cargo.toml [package.metadata.generate-rpm]` were relative to `gui/` instead of workspace root (missing `../` prefix), causing "file not found" on build; (b) status icons directory glob caused "Is a directory" error — expanded to 7 individual file entries matching DEB pattern. Makefile `rpm` target changed from `cargo generate-rpm -p` (flag unsupported by cargo-generate-rpm) to `cd gui && cargo generate-rpm`. RPM build now produces valid `openvpn3-gui-rs-0.2.0-1.x86_64.rpm`. Helper RPM (`make rpm-helper`) was already correct (uses `cd helper && cargo generate-rpm` with `../` prefixed paths). **AUR:** PKGBUILD covers all GUI artifacts correctly. Known gap: no separate `openvpn3-killswitch-helper` PKGBUILD for Arch — documented, not a regression. **Dead icons:** `killswitch-on.svg` and `killswitch-off.svg` packaged but never referenced in code (KS uses embedded pixmaps, not icon-theme lookup) — harmless but noted for future cleanup. Commit `60b1bbe`.

6. ~~**Connect-time failure-mode audit (state × behaviour matrix per CLAUDE.md).**~~ ✅ Full matrix built in `docs/failure-modes.md` — 19 failure modes × 6 surfaces. Three security-critical/high fixes applied within sprint budget: **(1)** `killswitch_glue::apply_kill_switch()` returned `Ok(true)` when `device_name` or `server_ip` was empty, causing false-positive lock icon + "Kill-Switch Active" notification with no rules applied — changed to `Ok(false)` routing to "helper missing" path. **(2)** `on_connected()` Err branch now shows `show_error_notification("Kill-Switch Failed", …)` instead of silent `warn!`. **(3)** `application.rs` `setup_signal_handlers()` failure now shows `show_error_notification("Status Monitoring Failed", …)` instead of silent `error!`. Remaining 7 silent cells documented as S25 candidates with concrete file:line references in the matrix. Commit `0b14614`.

7. ~~**Sprint-end hygiene — doc sync + dep audit.**~~ ✅ README + metainfo updated: log viewer bullet now lists per-tab search, level filter, filter-aware copy, persistent window size; View Logs menu description updated. Dep audit: all 13 GUI + 7 helper runtime deps actively used (tokio, gtk4, glib, gio, zbus, ksni, oo7, tracing, tracing-subscriber, clap, anyhow, futures, chrono + glib-build-tools build-dep in GUI; tokio, zbus, futures, anyhow, tracing, tracing-subscriber, serde_json in helper). Zero unused deps, zero new deps added during S24 (T3 used existing GTK/GSettings APIs). Commit `5fa3046`.

## Backlog

(Populated at sprint end per retro outcomes. Pre-sprint inventory of trigger-gated items — DO NOT auto-promote without their triggers firing: per-entry enable/disable toggle in Routing tab; partial-failure bypass reporting `Active(x)+Failed(y)`; DNS leak on bypass CIDRs; nft bypass-set drift detection; per-app split-tunneling cgroups v2 variant; About dialog blue title-bar Adwaita styling; S22 PoC tail items — KS-ON test mode + `test-resume` interactive validation. Plus the 7 silent-failure cells from `docs/failure-modes.md` (T6 audit) as S26+ candidates beyond the 2–3 picked by S25 T4.)

- **Fix `make bump-version` to prepend `<release>` entry instead of overwriting.** Current sed at `Makefile:93-94` (`s/release version="[^"]*" date="[^"]*"/.../`) matches the *first existing* `<release>` entry and rewrites its attributes, leaving the body (Sprint 23–24 features) attached to the new version number. Discovered during v0.3.1 release (2026-05-18): bumping 0.3.0 → 0.3.1 silently destroyed the 0.3.0 entry. Manually restored in PR #23. Replace sed with awk/Python that inserts a fresh `<release version="$(V)" date="...">` block immediately after `<releases>`, preserving all previous entries verbatim. Triggers: next patch release, or any time bump-version is used.
- **Add artifact-existence verification step to release workflow.** Insert `ls -la target/debian/*.deb target/generate-rpm/*.rpm` (or `test -f` glob) after the four build steps in `.github/workflows/release.yml` and before "Upload packages". Would have surfaced the v0.3.0 "RPMs missing" bug at the failing step (cargo-generate-rpm output misnamed) instead of two steps downstream at upload time. Trigger: any future packaging/release workflow change.
- **[S25 explicit slot] Schedule release-workflow post-condition audit proactively.** The previous backlog item is reactive ("trigger: next packaging change"). Promote it to an explicit Sprint 25 slot so the assertions land *before* the next release, not after the next breakage. Scope: one `test -f` glob per build step (DEB GUI, DEB helper, RPM GUI, RPM helper) + an expected-artifact manifest documented in `.github/workflows/release.yml` comments. ~30 min of edits, but reactive timing risks another silent release. Seeded by S24 retro (2026-05-19).

## Dropped

(none yet)

# Sprint 23 Tasks

**Theme:** Ship split-tunneling end-to-end. T4 decisions D1–D6 land in code; T5 IPv6-leak finding closed via symmetric v4+v6 rules. Defence-in-depth (conntrack flush, MTU clamping) included per T5 PoC SKIP notes.

1. ~~**[Structural — gates T2..T5b] Helper D-Bus API: `SetBypassCidrs` / `ClearBypassCidrs`.**~~ ✅ Helper: `bypass_cidrs: Vec<String>` state field, `MAX_BYPASS_CIDRS = 128` defence-in-depth ceiling (user-facing limit lives in T3 GSettings, default 32), `validate_bypass_cidrs` + `canonicalize_cidr` free fns using `std::net` only (no new dep) — reject loopback / multicast / link-local (v4 169.254/16, v6 fe80::/10) / unspecified / `/0`, mask host bits, dedup after canonicalization. 17 new unit tests (helper 22 → 39 total). GUI: `SetBypassCidrs` / `ClearBypassCidrs` proxy methods + `set_bypass_cidrs` / `clear_bypass_cidrs` async wrappers matching `add_rules` / `remove_rules` shape; `#[allow(dead_code)]` until T3 call site lands. No rule installation, no GSettings, no UI (T2/T3/T4). Manual `gdbus call` smoke confirmed wire-level method-name agreement (the gap zbus does not check at compile time). `make check` clean (131 GUI + 39 helper + smoke). Commit `a96bc6d`.

2. ~~**Helper rule engine — symmetric v4+v6 `ip rule` + secondary table + nft + conntrack flush.**~~ ✅ New `helper/src/bypass.rs` module owns the routing layer (priority-100 `ip rule` per CIDR, **symmetric v4+v6** closing T5 IPv6-leak finding — each CIDR classified by family and installed on its native family; secondary table `openvpn3-bypass` (id 100) registered in `/etc/iproute2/rt_tables.d/`; pre-VPN gateway captured at apply-time via `ip -j route show default` JSON; `rp_filter` switched to loose (2) with original value preserved for restore; scoped `conntrack -D -d <cidr>` per entry). Teardown matches on structural identifiers (`priority 100 lookup 100`) not CIDR strings per CLAUDE.md (S22 retro from `/32` stripping bug). Two new D-Bus methods `ApplyBypassRoutes` / `RemoveBypassRoutes` independent of KS state per D4. Helper-side cold-start: shutdown path tears down both nft and routing; KS `remove_rules` deliberately leaves routing alone (D4 independence). `helper/src/nft.rs` extended: `add_rules_script` takes `bypass_cidrs_v4`/`v6` params, emits named sets `bypass_set` (ipv4_addr) / `bypass_set_v6` (ipv6_addr) with `flags interval` in the table preamble, `ip daddr @bypass_set accept` / `ip6 daddr @bypass_set_v6 accept` in the chain ordered before `oifname tun*`, and an unconditional `tcp flags syn tcp option maxseg size set rt mtu` (MSS clamp, defence-in-depth per docs). `service.rs::add_rules` partitions stored bypass CIDR list by family via `bypass::split_by_family` and pipes refs into the nft script. Mutex never held across `.await`. `serde_json = "1"` added to helper Cargo.toml (used by `ip -j` parsing — concrete in-sprint use justifies dep). 17 new unit tests (helper 39 → 56): 11 in bypass.rs (split_by_family v4/v6/empty/mixed/malformed, cidr_is_v6 classification, rp_filter path format, CapturedNet shape, PoC-constants pin) + 6 in nft.rs (MSS-clamp unconditional, bypass-set v4/v6 emission, both-families independence, no-cross-family bleed, bypass-accept ordering before tunnel-accept). GUI 131 unchanged. `make check` clean. Manual gdbus smoke validated end-to-end on live system: `SetBypassCidrs(['10.0.0.0/8','2001:db8::/32'])` + `ApplyBypassRoutes` produced expected `ip rule show priority 100` + `ip -6 rule show priority 100` + populated `table openvpn3-bypass` + `rp_filter=2`; `RemoveBypassRoutes` cleanly restored all state. nft side verified via syslog tail (`gdbus call` watcher fires immediately by design — anti-lockout — so rule lives only between "rules applied" and "GUI vanished — removing rules" log lines; real GUI keeps a persistent `OnceCell<Connection>` so this only fires on real disconnection). T3 (GUI wiring on Connect + GSettings cold-start) will land the first call sites for `ApplyBypassRoutes` / `RemoveBypassRoutes`; proxy methods on the GUI side will arrive in T3 with `#[allow(dead_code)]` removed once the caller exists.

3. ~~**GSettings persistence + cold-start re-apply (GUI side, with helper-side restart re-apply).**~~ ✅ Schema: `bypass-cidrs` (as, default `[]`) + `bypass-cidrs-max-count` (i, default 32, clamped 1–128 — helper's hard ceiling is 128). Settings wrapper: `bypass_cidrs()` / `set_bypass_cidrs()` / `bypass_cidrs_max_count()` accessors; latter two carry `#[allow(dead_code)]` with T4 hand-off comment (Preferences UI lands the first call sites). D-Bus proxy: `ApplyBypassRoutes` / `RemoveBypassRoutes` methods added to `KillSwitchProxy`, with `apply_bypass_routes()` / `remove_bypass_routes()` async wrappers mirroring `add_rules` / `remove_rules` shape. `set_bypass_cidrs` wrapper's `#[allow(dead_code)]` removed (callers exist); `clear_bypass_cidrs` kept annotated for T4. Lifecycle wiring on three paths: (a) **connect** (`killswitch_glue.rs::on_connected`) — bypass push runs before KS apply, gated on `set_bypass_cidrs` success; (b) **user-initiated disconnect** (`signal_handlers.rs`) — `remove_bypass_routes` paired with `remove_rules`; (c) **cold-start re-apply** (`dbus_init.rs`) — single ordered future, bypass first, then KS for-loop. **Correctness verification round (post-implementation) caught a real race** in original two-spawn cold-start: helper's `AddRules` snapshots `state.bypass_cidrs` into the nft script (bypass accept rules + MSS clamp), so if KS won the scheduler the firewall shipped without bypass rules and bypassed traffic was dropped until next manual reconnect. Fix: collapse into one ordered future. Same verification also closed dismiss-handler gap (`dialogs/notification/mod.rs:209`) — bypass routes now torn alongside KS so stale ephemeral gateway capture doesn't linger. **D4 preserved**: Preferences KS-toggle-off path correctly leaves bypass untouched (independent layer); `on_connected` fires bypass regardless of `enable-kill-switch`. 3 new Settings tests (GUI 131 → 134); 56 helper tests unchanged. `make check` clean (fmt + clippy `-D warnings` + 134 GUI + 56 helper + smoke). Commit `77204ff`.

4. ~~**Preferences "Routing" tab (per D6).**~~ ✅ New tab in existing Preferences dialog — avoids 3+ indentation per CLAUDE.md "hierarchy depth" rule. CIDR list editor: GtkListBox with add/remove buttons, in-place validation on add. Empty-state explicitly tested. Tab always visible (no gating on session state). User-tested running app before commit. Commit `3e46760`.

5a. ~~**[Read-only] State × behaviour matrix design.**~~ ✅ Originally drafted before T5b with phantom "Status dialog" row (no such surface exists in codebase). Revised matrix grounded in four real surfaces (tray icon, tray menu top rows, D-Bus notifications, Preferences Routing tab). ToolTip explicitly voided per `project_sni_tooltip_unreliable` memory. Session submenus explicitly voided (routing is global, not per-session). Five decisions encoded (D-a through D-e). T5b verified against revised matrix — all 14 spec'd cells match shipped code exactly. Read-only completion per CLAUDE.md exception.

5b. ~~**State × behaviour matrix wiring.**~~ ✅ Implemented all cells from revised T5a matrix. Tray indicator row (`BypassState` enum: `Off` / `Active(n)` / `Failed`) with singular/plural agreement, insensitive rendering, unconditionally visible below KS row. D-Bus notifications: success (urgency=1, expire=-1, one-shot) + failure (urgency=2, expire=0, persistent) sharing `__bypass_state__` dedup key, both gated by `show_notifications`. 4 new menu tests (off/singular/plural/failed). Commit `e24b503`.

5c. ~~**Disconnect-path tray-state reset.**~~ ✅ Two disconnect surfaces tore down helper-side bypass routes without resetting tray `bypass_state`, leaving menu row stuck on `Active(n)` while routes were gone. Fixed both: (a) user-initiated disconnect (`signal_handlers.rs`) — appended `BypassState::Off` to existing `tray_clear.update` block; (b) Dismiss action of reconnect notification (`notification/mod.rs`) — plumbed `ksni::blocking::Handle<VpnTray>` through `show_reconnect_notification` + `do_reconnect_notification`, reset both `bypass_state` and per-session `kill_switch_active` (pre-existing matching gap). User-tested. Commit `8c73eab`.

6. ~~**Sprint-end hygiene.**~~ ✅ (a) ~~Kill-switch apply/remove notifications~~ — **dropped as duplicate**: shipped in Sprint 21 T3 commit `777d626` (persistent KS Active + informational KS Inactive, dedup key, six lifecycle paths). Verified: all 7 call sites across 4 files match spec exactly. (b) README + metainfo updated to reflect split-tunneling (feature bullet, 🌐 tray row, Routing tab in Preferences description, metainfo `<li>`). Dep audit: `serde_json` (T2) is the only new dep across S23; all 13 GUI + 7 helper runtime deps actively used — no removals. Commit `de16040`.

## Backlog

- Four S22 PoC tail items — `TEST_DNS_RESOLVER` derivation from `BYPASS_DEST` and conntrack/MTU re-test absorbed into T2 testing where they pay off. KS-ON test mode + `test-resume` interactive validation deferred to a post-S23 polish slot if needed.
- nft bypass-set drift detection (D3 dimension 3) — hold until production usage signals need.
- DNS leak handling on bypass CIDRs (D2 failure mode #4) — bypass CIDRs may use VPN-pushed DNS, leaking which sites are bypassed via DNS queries. Backlog candidate for explicit DNS routing or split-DNS once a concrete user reports it.
- `gui/src/app/status_handler/killswitch_glue.rs` — re-evaluate file size after S23 lands (T2 + T5b may both touch it).
- **Per-entry enable/disable toggle in Routing tab** — let users keep CIDRs in the list while temporarily deactivating them (context-switch workflow: home/coffee shop/work). Lightweight design: parallel `bypass-cidrs-disabled: as` GSettings key (avoid migrating existing `bypass-cidrs` schema); checkbox column per row in `routing_tab.rs`; Save closure filters disabled out before push to helper. Helper unchanged — disabled vs. enabled is a GUI concept only. Surfaced during T4 user testing 2026-05-13. Defer until repeat-toggle user pain confirmed; current delete-and-re-add workflow acceptable at 64-entry max.
- **Partial-failure bypass reporting (Active(x) + Failed(y) granularity)** — current helper API (`ApplyBypassRoutes() -> Result<()>`) is all-or-nothing; tray row reports binary `Active(n)` / `Failed`. Sprint-24 candidate: change helper to iterate routes without aborting on per-route kernel error, collect per-CIDR outcomes, return `Vec<(cidr, bool)>` (D-Bus signature `a(sb)`). Mirror change in `ValidateBypassCidrs`. GUI extends `BypassState` with `Mixed { active: usize, failed: usize }` variant + label `⚠️ Split tunnel: X active, Y failed`. Files: `helper/src/service.rs` (D-Bus method signatures), `helper/src/bypass.rs::install_rules` (drop `?` between iterations), `gui/src/dbus/killswitch.rs` (proxy update), `gui/src/tray/indicator.rs` (enum variant), `gui/src/tray/menu/mod.rs` (label branch), `gui/src/dialogs/notification/mod.rs` (new wording). Surfaced during T5b user testing 2026-05-13. Defer until kernel-rule-install failures observed in practice (rare — priority 100 is reserved by our helper).

## Dropped

(none yet)

# Sprint 22 Tasks

1. ~~**[Chore] Ignore `.lean-ctx/` runtime cache.**~~ ✅ Single-line `.gitignore` add for the lean-ctx tool's local cache directory. Pre-sprint pickup committed before Sprint 22 branch cut — rides the branch on push. Pre-commit hook's `make check` clean (127 GUI + 22 helper tests + smoke). Commit 788f44f.

2. ~~**[Audit] Re-evaluate `tray/menu/mod.rs` post-split.**~~ ✅ Read-only completion. Findings: 264L total = 147L production + 117L tests (`#[cfg(test)] mod tests` block); production has a single function `build_menu` at 132L. No file-split candidate — there is no second concern to extract into another module. Sprint 21's split (mod.rs + submenus.rs) landed at the right seam. One DRY signal noted but not actioned: `StandardItem { label, activate: Box::new(...) }` shape repeats 14× across both menu files (5 in mod.rs, 9 in submenus.rs). Three scopes considered: (A) extract action-item helper in mod.rs only — asymmetric, rejected; (B) extract closure-taking `item()` helper across both files — saves ~110L net but produces line-count reduction, not legibility gain; (C) no code change — repetition makes intent obvious (every action item identical structure), file under threshold, sprint has heavy back half. Chose Scope C. Pre-commit deliverable = this recorded decision per CLAUDE.md read-only exception. **Watch:** if menu grows in S23+ (more action items, more submenu types), revisit Scope B — helper pays off as soon as the 15th repetition lands.

3. ~~**Helper version probe / GUI↔helper compat check.**~~ ✅ Helper exposes `Version` property (= `env!("CARGO_PKG_VERSION")` = "0.1.0") on `net.openvpn.v3.killswitch`. GUI cold-start probes via new `crate::dbus::killswitch::probe_version()` and emits one of three log lines: `info` on match, `warn` on `< MIN_HELPER_VERSION` (= "0.1.0"), `debug` when helper not present. Compat semantics = Option C (min-version floor, semver-shaped). Hand-rolled `parse_semver` in `dbus_init.rs` (3-tuple of u32 — no `semver` crate added per "no dep unless used"); strips non-numeric suffixes (`1.2.3-beta` → `(1,2,3)`). Pre-impl grep enumerated all 9 helper-call sites in GUI; expected diff touches **only** the proxy-trait declaration (#1) since version probe is orthogonal to existing methods — verified post-commit. Packaging: helper `.service` file unaffected (interface name unchanged); helper version tracks helper-crate `Cargo.toml` automatically. 4 new unit tests (semver_basic, semver_partial_components_default_to_zero, semver_strips_non_numeric_suffix, semver_below_min_compares_correctly) → 131 GUI + 22 helper tests + smoke clean. User-tested: GUI run produced expected `info` line. Commit f403a38.

4. ~~**Split-tunneling × kill-switch interaction design assessment (read-only).**~~ ✅ 244L addendum to `docs/split-tunneling.md` encoding six design decisions: D1 = bypass is full exemption (model b, anchored to kill-switch-allow-lan precedent); D2 = ip-rule priority 100 with five enumerated PoC failure modes (rp_filter, conntrack, MTU/PMTUD, DNS leakage, IPv6 leakage); D3 = helper API is `SetBypassCidrs` / `ClearBypassCidrs` (replace-all, fail-closed); D4 = bypass and KS are independent layers; D5 = idempotent gateway re-capture on every Resume; D6 = new tabbed "Routing" section in Preferences (avoids 3+ indentation levels). Catalogues three S23 candidates explicitly excluded from S22 scope: split-tunnel-only notification, tray row for KS-off+bypass-on, status-dialog bypass visibility. Read-only completion per CLAUDE.md exception — T5 will physically validate priority 100 / `rp_filter=2` / replace-all semantics via the PoC script. Commit 672cb27.

**Original brief (for posterity):** Extends `docs/split-tunneling.md` with an assessment of Option B against the existing kill-switch implementation. Six dimensions:
   1. **Security model (keystone):** does "Bypass Networks" exempt CIDRs from kill-switch firewall, or only from tunnel routing? Two options: (a) routing-only — kill-switch still firewalls bypass CIDRs when VPN down; (b) full exemption — bypass CIDRs always allowed. Cascades into dimensions 3 and 6.
   2. **Routing precedence:** `ip rule` priority space vs OpenVPN3's installed default route + `unspec`/`prohibit` route-install patterns. PoC 1 measures this empirically — T4 enumerates candidate priorities and known failure modes.
   3. **nft bypass set:** if security model (b), who owns sync between `ip rule` table and nft bypass set? Drift failure mode = silent drop, user confusion. If (a), this dimension is irrelevant.
   4. **Lifecycle ordering:** apply/remove order on connect, disconnect, AND cold-start (event-wiring + cold-path together per CLAUDE.md). Mixed states: kill-switch-only, split-tunnel-only, both-on, both-off — four matrix cells, all four need defined behaviour.
   5. **Pause/Resume:** bypass routes across the pause boundary — persist, oscillate, or clear? Tunnel may persist on pause; bypass routes shouldn't churn.
   6. **UI/UX:** combined "Allow-list" tab with kill-switch LAN list + Bypass list, or separate concepts? Choice follows from dimension 1 (model (a) keeps them conceptually distinct; model (b) makes them aspects of one allow-list).

   **Closing requirement:** state × behaviour matrix per CLAUDE.md (tray icon, menu labels, status dialog, notifications, Preferences × cells {bypass empty / bypass active / both-features-on / split-tunnel-only}) — every empty cell becomes a candidate S23 sub-task documented in this T4 deliverable. **Note:** if T4 picks security model (b), `scripts/poc-split-tunnel.sh` needs amending before T5 (script currently assumes kill-switch OFF — testing routing in isolation). **T4 gates T5.** Read-only completion per CLAUDE.md exception (deliverable = recorded decisions).

5. ~~**Run split-tunneling PoCs (conditional on T4 outcome).**~~ ✅ 803-line validation suite (`scripts/poc-split-tunnel.sh`) tested on two networks (iPhone hotspot + home WiFi). **Routing layer validated:** priority 100 `ip rule` correctly intercepts bypass dest (exits via LAN iface) while control traffic stays on tun0. **rp_filter confirmed:** loose mode (effective=2) required for asymmetric routing. **IPv6 leak found:** `redirect-gateway def1` is v4-only; when v6 connectivity exists, bypassed hosts leak via LAN — validates D2 failure mode #5. Sprint 23 must install symmetric v6 rules or keep v6 firewall active. **Conntrack + MTU not field-tested** (both test networks blocked outbound to 8.8.8.8/1.1.1.1; script correctly SKIPs instead of false-FAIL). Script robustness: VPN-detection fix (`ip route get` instead of `ip route show default`), `/32` stripping fix (match by table number), stale-capture guard, unreachable-dest gating. Four known-bug/small-improvement items deferred: `TEST_DNS_RESOLVER` derivation from `BYPASS_DEST`, conntrack/MTU re-test on reachable network, kill-switch-ON test mode, `test-resume` interactive validation. PoC results appended to `docs/split-tunneling.md`. **Verdict: proceed to Sprint 23 implementation.** Commits d996e47 (script) + 96a6358 (docs).

## Backlog

(none — split-tunneling implementation shipped S23 T2..T5c; per-app cgroups v2 variant tracked in S20 backlog below.)

## Dropped

(none yet)

# Sprint 21 Tasks

1. ~~**[Structural] Split `tray/menu.rs`**~~ ✅ (427L → `tray/menu/mod.rs` 264L + `tray/menu/submenus.rs` 218L. Extracted `session_submenu` + `config_submenu` + their 7 tests into the new submodule with `pub(super)` visibility; `build_menu` + 5 menu-shell tests stay in `mod.rs`. `git mv` reported 54% rename similarity (just over the 50% threshold) — partial blame preserved on `mod.rs`; `submenus.rs` blame resets. Test helpers (`menu_labels`, `make_session`) duplicated in both test modules — small functions, simpler than a shared `pub(super)` test-helpers module. Submenu tests now report under `tray::menu::submenus::tests::*`. No external import sites needed updating (`tray/mod.rs:4` `mod menu;` and `tray/indicator.rs:248` `super::menu::build_menu` resolve identically to either layout). 127 GUI tests + 22 helper tests + smoke clean. Commit 3b4bf87.)

2. ~~**Bug — Resume after long pause: no credential dialog.**~~ ✅ (Two independent failure modes fixed. (A) StatusChange dedup in `status_handler/mod.rs` swallowed re-emitted auth signals when the same `(major, minor)` tuple was cached from the original Connect — auth-request statuses now exempt from dedup via new `SessionStatus::is_auth_request()` composite predicate. (B) Resume path in `actions.rs` had no `Ready()`-check like Connect does, so a Resume on an invalidated session silently failed — new `resume_session()` in `session_ops.rs` mirrors the Connect pattern: `Resume()` then `Ready()`, requesting credentials on `Err`. No unit-test surface: the fix is async D-Bus orchestration; existing `session_ops::tests` still pass. 127 GUI + 22 helper tests + smoke clean. Commit c3ecae9.)

3. ~~**Kill-switch apply/remove notifications.**~~ ✅ Two new helpers in `dialogs/notification/mod.rs` sharing single dedup key `__killswitch_state__` so rapid toggles replace rather than stack. `show_killswitch_active_notification` is persistent (`expire_timeout = 0`, urgency=2); `show_killswitch_inactive_notification` is informational (default timeout, urgency=1). Both gated by `show_notifications`. Wired into all six lifecycle entry points: cold-start re-apply (`dbus_init.rs`), Connected edge (`killswitch_glue.rs::on_connected`), Paused edge (`killswitch_glue.rs::on_paused`), user-initiated disconnect (`signal_handlers.rs`), Dismiss action of reconnect notification (`notification/mod.rs`), Preferences mid-session toggle ON/OFF (`preferences/mod.rs`). Bonus fix: pre-existing Pause/Resume icon bug — tray flipped to "loading" after Resume because `last_bytes_*` froze during Pause and first post-Resume poll saw zero delta, tripping stall detection. Fixed by resetting stats baseline on rising edge of Connected in `status_handler/mod.rs`. 127 GUI + 22 helper tests + smoke clean. Commit 777d626.

4. ~~**Split-tunneling design spike (read-only — no code).**~~ ✅ Deliverable: `docs/split-tunneling.md` (149L). Three options analysed (per-app cgroups v2, per-route `ip rule`, hybrid). Hybrid rejected as v1 scope creep. Recommended: per-route — smallest helper-API delta, mechanical kill-switch interaction, discoverability mirrors existing Allow LAN pattern. Sprint 22 verdict: conditionally direct-schedulable pending two 10-min PoC tests (`ip rule` priority interplay, pre-VPN gateway capture). Commit 15f1d39.

5. ~~**Sprint-end hygiene — doc sync + dep audit.**~~ ✅ README and metainfo: kill-switch bullet updated with "notifications on rule apply (persistent) and removal". T2 resume bug is internal fix, no doc change needed. Dep audit: all 14 GUI deps + 6 helper deps confirmed actively used — no removals. Commit 258f9a4.

## Backlog

- Split tunneling **implementation** — pending T4 design spike output. Schedule for Sprint 22+ once the spike yields a recommended approach.
- Helper version probe / GUI–helper compatibility check — no concrete trigger yet, hold until needed.
- `tray/menu/mod.rs` post-split — re-evaluate threshold after T1 lands.

## Dropped

(none this sprint)

# Sprint 20 Tasks

1. ~~**[Structural] Split `notification.rs`**~~ ✅ (466L → 380L `mod.rs` + 96L `dedup.rs`. `NOTIFICATION_IDS` `LazyLock` map + 5 dedup tests extracted to `dialogs/notification/dedup.rs` with `pub(super)` visibility. Per-type wrappers + `send_dbus_notification` stay in `mod.rs`. `git mv` preserved blame (84% similarity). Tests now report under `dialogs::notification::dedup::tests::*`. 126 GUI tests + 22 helper tests + smoke clean. Commit 0e511f3.)
2. ~~**[Structural] Split `dbus_init.rs`**~~ ✅ (421L → 309L `dbus_init.rs` + 120L `service_watcher.rs`. `watch_service_restart` + `is_service_appeared` + 5 service-appeared tests extracted into new `app/service_watcher.rs`; `parse_manager_version` stays in `dbus_init.rs` because `init_dbus` calls it. Tests reroute: 6 under `app::dbus_init::tests::*`, 5 under `app::service_watcher::tests::*` — all 11 preserved. `git mv` not applicable (original file kept), so blame on the watcher code resets. Single import-site update in `application.rs:19`. 126 GUI tests + 22 helper tests + smoke clean. Commit 97dad25.)
3. ~~**[Structural] Split `preferences.rs`**~~ ✅ (457L → `preferences/mod.rs` 148L + `general_tab.rs` 158L + `security_tab.rs` 199L. Widget-struct pattern: each tab's `build()` returns `(GtkBox, WidgetsStruct)`; Save closure reads through the structs. `was_killswitch_on` returned as third tuple element from security build. `git mv` preserved blame on scaffolding; tab code blame resets. No UI change. 126 GUI tests + 22 helper tests + smoke clean. Commit 7689ac0.)
4. ~~**About dialog — fix missing icon**~~ ✅ (Replaced `logo_icon_name(APPLICATION_NAME)` (icon-theme lookup that fails in dev/uninstalled runs) with embedded SVG via `include_bytes!` → `Pixbuf::from_stream_at_scale` @128px → `Texture::for_pixbuf()` → `set_logo()`. Icon now renders correctly in both dev and installed runs. Blue box around title deferred to backlog — it's Adwaita's `GtkAboutDialog` headerbar styling, not our code; fix requires either CSS override or `libadwaita` dep switch. Commit TBD.)
5. ~~**Always-visible kill-switch state row in tray menu**~~ ✅ (Top-of-menu insensitive row: 🔒 Kill-switch: On / 🔓 Kill-switch: Off. Uses Unicode emoji in label text (same pattern as existing session 🔒 marker) — themed icon_name causes image-missing fallback in D-Bus menus. VpnTray.kill_switch_enabled field synced on init_dbus and Preferences Save. Two padlock SVGs added to data/icons/ for future icon-theme use. 127 GUI tests + 22 helper tests + smoke clean. Commit db49ac2.)
6. ~~**Sprint-end hygiene — doc sync + dep audit**~~ ✅ (README: kill-switch bullet updated with always-visible state row, top-level menu section updated with 🔒/🔓 row. Metainfo: kill-switch li updated. Cargo.toml: DEB assets updated with 2 new killswitch SVGs (RPM already covers via directory copy). Dep audit: all 13 crates actively used, no removals.)

## Backlog

- **Bug — Resume after long pause: no credential dialog on server-side session invalidation.** When a session is paused long enough that the OpenVPN3 server invalidates it, resuming triggers a re-auth requirement but the credential dialog does not appear. User is stuck — must fully disconnect + reconnect to recover. Likely surfaces as an unhandled `CfgRequireUser` (or equivalent) attention event on the resume path. Investigation needed: trace status flow on Resume vs. fresh Connect, confirm `auth_dispatch` is wired into the resume code path, and verify the credential dialog is shown for the resume case.
- Per-app split tunneling (cgroups v2) — per-route/per-CIDR variant shipped S22 + S23; per-app variant explicitly rejected for v1 in S21 T4 spike (`docs/split-tunneling.md`). Hold until concrete user request.

## Dropped

- T5 alternative A′ (kill-switch tray icon overlay with locked/open padlocks) — discriminability concern at small icon sizes (corner badge ~10–14 px); B chosen instead

# Sprint 19 Tasks

1. ~~**Empty-tray-state polish**~~ ✅ (Disabled "No profiles imported" header row when `configs.is_empty() && sessions.is_empty()`, separator zone between hint and Import Config. Boundary test confirms hint hidden when session present. 122 tests + smoke clean. User-tested. Commit f3e203f.)
2. ~~**Quit-while-connected confirmation**~~ ✅ (Dialog warns that quitting removes kill-switch firewall rules. Only shown when a session is connected AND `enable_kill_switch` is on. Buttons: Cancel / Quit anyway. 122 tests + smoke clean. User-tested. Commit 81fc991.)
3. ~~**Stall detection: 0 → "Disabled" UX**~~ ✅ ("Detect stalled connections" CheckButton gates an indented "Stall threshold (seconds):" spinner. Spinner range 10–600 (0 reachable only via unticked checkbox); seeds 60s on first enable when stored value is 0. Schema unchanged — `health-check-stall-seconds = 0` remains the disabled sentinel. 122 tests + smoke clean. User-tested. Commit 24d553b.)
4. ~~**Kill-switch indicator in menu label**~~ ✅ (Appended 🔒 to session status label when firewall rules are actively applied. New `kill_switch_active` field on `SessionInfo` tracks rule application — accurate even when helper is missing. All apply/remove sites set/clear the flag: `on_connected`, `on_paused`, cold-start re-apply, mid-session Preferences toggle, user-initiated disconnect. User-tested. Commit 539aa7d.)
5. ~~**Preferences hierarchy fixes**~~ ✅ (Reshaped as 2-tab Notebook layout — General tab holds startup/notifications/intervals/stall detection; Security tab holds kill-switch options with `warn_on_unexpected_disconnect` indented under kill-switch so the forced-on coupling is visible. Renamed "Stats refresh interval" → "Menu update interval" to reflect what the setting actually controls (tray menu byte counts + idle timer, not tooltips). Both original sub-items addressed by the tab restructure. User-tested. Commit dbdd101.)
6. ~~**Sprint-end hygiene — doc sync + dep audit**~~ ✅ (README documents kill-switch lock indicator, quit confirmation, tabbed Preferences dialog; relabelled stats refresh interval references to menu update interval. Metainfo updated to reflect lock indicator, quit confirmation, tabbed layout. Commit bdbaa0c.)

## Backlog

- Per-app split tunneling (cgroups v2) — per-route/per-CIDR variant shipped S22 + S23; per-app variant explicitly rejected for v1 in S21 T4 spike (`docs/split-tunneling.md`). Hold until concrete user request.

---

# Sprint 18 Tasks

1. ~~**[Structural] Split `status_handler.rs`**~~ ✅ (438→391L `mod.rs` + 61L `killswitch_glue.rs`. Extracted `apply_kill_switch` + `on_connected`/`on_paused` dispatch helpers. "Remove on user disconnect" stays in `signal_handlers.rs` — was outside this file's scope. `pub(crate) use` re-export in `app/mod.rs` resolves transparently through `mod.rs`. git mv preserved blame (88% similarity). 119 tests + smoke clean. Commit 9a5b8d6.)
2. ~~**[Structural] Split `credential_handler.rs`**~~ ✅ (416→349L. Extracted `display_label_for` + `is_storable_field` + 7 tests into new `crate::credentials::policy` module (78L). Main file keeps async D-Bus dispatch + retry. Tests now report under `credentials::policy::tests::*`. 119 tests + smoke clean. Commit d2d658f.)
3. ~~**[Structural] Split `logs.rs`**~~ ✅ (410→355L `mod.rs` + 68L `format.rs`. Extracted pure `format_log_line` + private `log_category_label` helper + 4 tests into new `dialogs/logs/format` submodule. `format_log_line` is `pub(super)`, `log_category_label` stays private (only called internally). git mv preserved blame (88% rename). Tests now report under `dialogs::logs::format::tests::*`. 119 tests + smoke clean. Commit 2bcce1f.)
4. ~~**First-run: detect missing `openvpn3-service`**~~ ✅ (Hooked into existing `!initialized` branch at application.rs:128 — no new watcher needed. Info notification with Open Preferences / Don't Show Again actions, withdrawn via `CloseNotification` when service appears in `watch_service_restart`. New GSettings `show-first-run-help` (bool, default `true`), independent of `show-notifications`. Preferences checkbox indented under notifications. 121 tests + smoke clean. User-tested: notification, actions, persistence all confirmed. Commit 07606eb.)
5. ~~**Helper-missing UX polish**~~ ✅ (`add_rules` returns `bool` (false = helper absent). One-shot `AtomicBool` notification in `on_connected`, gated by `show_notifications`. Preferences dim hint label "Helper not installed — install openvpn3-killswitch-helper" with async `helper_present` probe. `apply_kill_switch` widened to `Result<bool>` — existing `Err`-only callers unaffected. 121 tests + smoke clean. User-tested. Commit bcdc5b2.)
6. ~~**Test depth audit**~~ ✅ (Read-only. 45 files surveyed. 17 modules have 3+ tests. 1 module with extractable surface not extracted as too trivial: `main.rs` log-level selector (4-branch if/else, obviously correct, embedded in entry-point glue). 22 zero/low-test modules are genuinely no testable pure surface: all GTK widget builders, async D-Bus wrappers, or declarative proxy traits. No code extractions warranted. Module-header notes added to all 21 zero-/low-test modules (single-line `//! No testable pure surface — …` paragraph, archetype-tailored: async D-Bus wrapper, GTK widget builder, declarative proxy trait, or entry-point glue), so a future contributor sees the audit verdict at the top of each file.)
7. ~~**Sprint-end hygiene — doc sync + dep audit**~~ ✅ (README: expanded kill-switch bullet with helper-missing notification + Preferences hint, added first-run help bullet. Metainfo: added two feature `<li>` entries. Dep audit: all 13 GUI runtime deps + 1 build dep + 6 helper deps actively used — no removals. Commit 3bc4fc5.)

## Backlog

- **Empty-tray-state polish** → scheduled as Sprint 19 T1.
- ~~Config export/sharing~~ — **Dropped 2026-05-04**: no concrete use case after 3 sprints of deferral; system tools (`gsettings dump`, original `.ovpn` file, file copy) cover plausible scenarios. Re-add if a user asks.
- Split tunneling → carried forward to Sprint 19 backlog.

---

# Sprint 17 Tasks

1. ~~**Doc debt — `docs/kill-switch.md`**~~ ✅ (Rewritten as reference doc: polkit→trusted-group, added architecture/settings/behaviour/packaging sections. Commit 323d035.)
2. ~~**Helper input-validation audit**~~ ✅ (Read-only review: `validate_interface` whitelist + length cap + empty check, `split_ips` via `IpAddr::parse`, `nft.rs` pure generation, `run_nft` stdin piping. No actionable gaps found. No code changes.)
3. ~~**Kill-switch mid-session toggle**~~ ✅ (Preferences Save closure now applies rules for all connected sessions when kill-switch toggled ON, removes when toggled OFF. `apply_kill_switch` promoted to `pub(crate)` via re-export. `make check` clean.)
4. ~~**Kill-switch + Pause/Resume — configurable semantics**~~ ✅ (GSettings `kill-switch-block-during-pause` (bool, default `false`). Pause branch in `status_handler.rs` conditionally calls `remove_rules()`. `is_paused()` promoted from `#[cfg(test)]` to production. Preferences sub-checkbox with grey-out wiring. 2 settings tests. `docs/kill-switch.md` updated with Pause/Resume/mid-session-toggle behaviour sections. 119 tests, `make check` clean.)
5. ~~**Sprint-end hygiene — doc sync + dep audit**~~ ✅ (Dep audit: all 13 GUI runtime deps + 6 helper deps actively used; helper tokio features `macros`/`signal`/`io-util`/`process` all map to concrete call sites; chrono is used in `logs.rs` + `log_buffer.rs`. No removals. Doc sync: README adds kill-switch + stall-detection bullets, expands Preferences description, notes `openvpn3-killswitch-helper` package; metainfo features list updated. No version bump — release notes deferred to next packaging cut. Commit e728f19.)

## Backlog

- Per-app split tunneling (cgroups v2) — per-route/per-CIDR variant shipped S22 + S23; per-app variant explicitly rejected for v1 in S21 T4 spike (`docs/split-tunneling.md`). Hold until concrete user request.

---

# Sprint 16 Tasks

1. ~~**[Structural] Convert to Cargo workspace**~~ ✅ (root Cargo.toml → virtual workspace with `gui/` + `helper/` members; `[profile.release]` moved to workspace root; gui/Cargo.toml package manifest; helper/ stub with minimal main.rs; build.rs + pixmaps.rs path updates; Makefile workspace-aware targets; DEB paths relative to package manifest, RPM paths relative to workspace root. 48 files, 116 tests, `make check` clean. Commit 4ce6423.)
2. ~~**Helper binary — nftables + D-Bus interface**~~ ✅ (system D-Bus service `net.openvpn.v3.killswitch` running as root. `AddRules`/`RemoveRules` methods via zbus 5 interface. Pure nft rule generator (9 tests), D-Bus name watcher for auto-cleanup on GUI crash (4 tests), interface + IP validation (9 tests). 22 helper tests total. `nft -c` syntax-validated against live kernel. Makefile `--workspace` flag ensures helper is linted/tested by `make check`. Commit b567233.)
3. ~~**Polkit policy + packaging**~~ ✅ (trusted-group model: D-Bus system bus activation + access policy for netdev/sudo groups, no polkit. DEB+RPM packaging metadata for helper binary. GUI recommends helper. Makefile deb-helper/rpm-helper targets. DEB verified; RPM builds cleanly. Commit 6baa60e.)
4. ~~**GUI integration — kill-switch wiring**~~ ✅ (D-Bus proxy with persistent system-bus connection; apply rules on `is_connected`, remove on user disconnect; Dismiss action in reconnect notification removes rules; Preferences toggle with enable-kill-switch + kill-switch-allow-lan; cold-start re-application for already-connected sessions; graceful degradation when helper not installed. 139 tests, `make check` clean. Commit 652c9fb.)
5. ~~**Tooltip audit**~~ ✅ (removed tooltip_line() + 4 tests; simplified tool_tip() to static stub; renamed GSettings key tooltip-refresh-interval → stats-refresh-interval; renamed Preferences SpinButton label; removed unused ToolTip import. Commit 03c29a1.)
6. ~~**Dep audit**~~ ✅ (all 13 gui deps + 6 helper deps actively used; removed unused `macros` + `time` features from gui tokio. Commit 03c29a1.)

# Sprint 15 Tasks

1. ~~**[Structural] Split `status_handler.rs` + extract stats polling**~~ ✅ (status_handler 526→373 lines; extracted `auth_handlers.rs` 136 lines, `timeout_watcher.rs` 62 lines with thread_local generation map, `stats_poller.rs` 56 lines moved from application.rs. 106 tests + smoke pass. Commit 8d0618d.)
2. ~~**Connection health check (stall detection)**~~ ✅ (zero-delta detection in `stats_poller.rs` via `apply_stall_detection()` pure fn; idle sessions show "(idle Xs)" in menu label, amber icon in tray, idle suffix in tooltip for KDE; GSettings `health-check-stall-seconds` (default 60, 0–600, 0=disabled); SpinButton in Preferences; 4 unit tests for stall logic + 2 settings tests; 114 tests total. Commit 11aef90.)
3. ~~**Kill-switch spike — design + notify-only slice**~~ ✅ (design doc in `docs/kill-switch.md`; persistent critical notification on unexpected drop with Reconnect action, no auto-dismiss; `replaces_id` dedup prevents stacking; GSettings `warn-on-unexpected-disconnect` (default `true`) with Preferences checkbox in Security section; 2 settings tests; 116 tests total. User-tested: killing openvpn3 backend process mid-session triggers notification, setting toggle works. Commit 90ac592.)
4. ~~**Dep audit**~~ ✅ (all 13 runtime deps actively used: tokio, gtk4, glib, gio, zbus, ksni, oo7, tracing, tracing-subscriber, clap, anyhow, futures, chrono. No removals needed.)
5. ~~**Fix tray icon not rendering on GNOME — deliver icons as SNI pixmap**~~ ✅ (embedded 5 SVGs via `include_bytes!`, rasterize at 22px+32px ARGB32 at startup, serve via `ksni::Tray::icon_pixmap()`; `icon_name()` returns `""` to force GNOME's AppIndicator extension to use pixmap data. New `src/tray/pixmaps.rs` 120 lines with 2 tests. 108 tests pass. Commit 81ed43b.)

**Cross-task note (unified notification strategy):** Tasks 2 + 3 both surface "VPN is unhealthy" events. Task 2 → passive menu-label state (tooltip is secondary, invisible on GNOME). Task 3 → critical notification with actions. Both reuse `replaces_id` map from Sprint 7 to prevent stacking.

~~Backlog absorbed into Sprint 17~~

---

# Sprint 14 Tasks

1. ~~**Fix reconnect race condition**~~ ✅ (TrayAction::Reconnect calls Session.Restart() directly)
2. ~~**Fix duplicate timeout watchers**~~ ✅ (cancel previous 60s watcher before spawning new one)
3. ~~**Remove unused icons**~~ ✅ (deleted configuring.svg, active-error.svg)
4. ~~**Connection statistics**~~ ✅ (poll BYTES_IN/OUT via statistics property; display in tray menu label with ↓ ↑ arrows)
5. ~~**"All" tab in View Logs**~~ — Dropped (tab-per-profile design already clear; "All" tab adds complexity without strong use case)
6. ~~**Quick-connect**~~ — Dropped (redundant with "Connect most recent" startup preference + Reconnect action in session submenu)
7. ~~**Fix "No Sessions" placeholder in View Logs**~~ ✅ (remove placeholder tab when live logs arrive for new session)

---

# Sprint 13 Tasks

1. ~~**Fix duplicate log lines in "View logs"**~~ ✅ (removed duplicate LogForward call in connect_to_config; handle_session_created already calls LogForward for new sessions)
2. ~~**Cancel button disconnect verification**~~ ✅ (code verified, user tested — Cancel disconnects session correctly with "Connection Cancelled" notification)
3. ~~**Fix notification spam on disconnect**~~ ✅ (T3.1: inline dedup HashMap; T3.2: delayed session removal 3s/5s; T3.3: info note in View Logs about GNOME notification suppression)
4. ~~**Fix stale session on reconnect**~~ ✅ (retain() cleanup in connect_to_config removes stale sessions for same config before NewTunnel)
5. ~~**Document sync audit**~~ ✅ (README: install target, deps, CLI flags, menu table; metainfo: feature list, screenshots; credential label rename; auth-flow note)
6. ~~**Smoke test for Sprint 12 fixes**~~ ✅ (T1: session removed after ~3s; T2: all credential fields shown on retry; T3: correct status labels during connection/auth)

---

# Sprint 12 Tasks

1. ~~**Remove terminal sessions from tray immediately**~~ ✅ (status_handler removes session from `t.sessions` when `is_disconnected()` instead of just clearing `connected_at`; SessDestroyed remains as safety net)
2. ~~**Handle stale credential slots**~~ ✅ (check-before-consume + re-dispatch on queue reset; 4 attempts total, first 3 reverted)
3. ~~**Status→menu state sync audit**~~ ✅ (6 gaps found, 4 fixed: double-notification in disconnect_with_message, ghost session in SessCreated or_insert_with → and_modify, URL auth uses info notification, auth handlers skip tray update causing "Unknown" status. Remaining noted: duplicate timeout watchers on reconnecting.)
4. ~~**Tests for fixes**~~ — skipped (all changes in async D-Bus code, no new pure functions; underlying data structures already covered)
5. ~~**Dep audit**~~ ✅ (no new deps this sprint, all 13 runtime deps still active)

---

# Sprint 11 Tasks

1. ~~**Configurable connection timeout**~~ ✅ (added `connection-timeout` GSettings key, default 30s, range 5–300s; exposed via SpinButton in Preferences; status_handler reads live setting at connect-time so user changes take effect on next connect; 2 new tests; 103 total tests)
2. ~~**Dead code audit**~~ ✅ (removed unused AppArgs verbose/debug/silent fields, CredentialStore sync stubs, should_connect_* predicates; 98 tests)
3. ~~**Extract "VPN Connection" fallback constant**~~ ✅ (7 string literals → `FALLBACK_NAME` const in status_handler.rs)
4. ~~**Tests for `credential_handler.rs`**~~ ✅ (extracted `is_storable_field()` + `display_label_for()` pure functions; 7 tests; 105 total tests)
5. ~~**Tests for `config_ops.rs`**~~ — skipped (all functions are thin async D-Bus wrappers with no testable pure logic)
6. ~~**Tests for `challenge_handler.rs`**~~ — skipped (same — entirely D-Bus proxy calls, no branching logic to unit test)
7. ~~**Stale docs cleanup**~~ ✅ (plan.md and features.md archived to docs/; metainfo updated with release notes)
8. ~~**Dep audit**~~ ✅ (13 runtime deps, all active)

---

# Sprint 10 Tasks

1. ~~**Fix authentication challenge + session reconnect**~~ ✅ (auth_dispatch module routes CfgRequireUser to credentials or challenge handler; credential retry dialog preserves all 3 fields across retries without re-querying D-Bus; keyring resolved in async context; session submenu shows Reconnect for disconnected/error states via is_reconnectable())
2. ~~**Fix View Logs design**~~ ✅ (tabbed window with one tab per VPN profile; LogBuffer captures logs from app startup; timestamps HH:MM:SS; tabs keyed by config_name so retries don't create duplicates; migrated from deprecated Dialog to gtk4::Window)
3. ~~**Connection timeout notification**~~ ✅ (30s watcher notifies user if session still connecting; promoted is_connecting() from test-only to production)

---

# Sprint 9 Tasks

1. ~~**Make View Logs always accessible**~~ ✅ (top-level "View Logs" menu item, always visible regardless of session state)
2. ~~**Fix notification grouping**~~ ✅ (group connection notifications per config using replaces_id; replaces_id tracking map with unit tests)
3. ~~**Fix SessAuthUrl handling**~~ ✅ (open browser and notify for web authentication)
4. ~~**SessCreated handling**~~ ✅ (call LogForward and populate tray for new sessions)

---

# Sprint 8 Tasks

1. ~~**Split StatusChange loop**~~ ✅ (extracted into status_handler module)
2. ~~**Split challenge flow**~~ ✅ (extracted into challenge_handler module)
3. ~~**Remove dead code**~~ ✅ (removed unused 'restore' startup action)
4. ~~**Notification ID tracking tests**~~ ✅ (unit tests for tracking map)
5. ~~**Dep cleanup**~~ ✅ (removed gsettings-macro, thiserror, serde)

---

# Sprint 7 Tasks

1. ~~**Configurable tooltip refresh interval**~~ ✅ (via Preferences)
2. ~~**Tooltip with connected duration**~~ ✅ (30s timer refreshes "Name — Status (1h 23m)")
3. ~~**Group connection notifications**~~ ✅ (per config using replaces_id)
4. ~~**Handle SessAuthUrl**~~ ✅ (open browser and notify for web authentication)
5. ~~**Handle SessCreated**~~ ✅ (call LogForward and populate tray for new sessions)
6. ~~**Fix connect-specific startup**~~ ✅ (reads specific_config_path, not most_recent_config)
7. ~~**Gate notifications behind setting**~~ ✅ (show_notifications GSettings key)
8. ~~**Preferences dialog**~~ ✅ (replaced Startup Settings submenu)

---

# Sprint 6 Tasks

1. ~~**Split menu building**~~ ✅ (extracted from indicator.rs into tray/menu.rs)
2. ~~**Split signal loops**~~ ✅ (extracted from dbus_init.rs into signal_handlers.rs)
3. ~~**Split SessionStatus**~~ ✅ (extracted into dbus/session_status.rs)
4. ~~**Preferences dialog**~~ ✅ (replaced Startup Settings submenu)
5. ~~**Dead code cleanup**~~ ✅

---

# Sprint 5 Tasks

1. ~~**Implement credential clearing**~~ ✅ (clear_all_async() in CredentialStore; ClearCredentials tray action)
2. ~~**Connection error handling**~~ ✅ (is_error() moved to production; catch-all for unknown errors)
3. ~~**Reconnect notification**~~ ✅ (show reconnect notification on unexpected session drop)
4. ~~**Initial release v0.2.0**~~ ✅

---

# Sprint 4 Tasks

1. ~~**Fix lingering warnings**~~ ✅ (tooltip_line wired; test-only methods moved; unused SessionStatus fields removed)
2. ~~**Basic unit tests**~~ ✅ (15 new tests; 53 total passing)
3. ~~**Integration test**~~ ✅ (tests/smoke_test.sh; make smoke-test target)
4. ~~**Error handling audit**~~ ✅ (gsettings eprintln→tracing; keyring errors logged; config_ops unwrap→warn)
5. ~~**GitHub CI/CD**~~ ✅ (ci.yml: fmt+build+test+clippy+smoke; release.yml: DEB+RPM packages)

---

# Sprint 3 Tasks

1. ~~**Purge dead code**~~ ✅ (removed SharedTrayState, dead dialog stubs, unused constants)
2. ~~**Fix unused imports**~~ ✅ (all warnings cleared)
3. ~~**Remove or keep unused D-Bus enums**~~ ✅ (removed ClientAttentionGroup; kept SessionManagerEventType + ClientAttentionType replacing magic numbers)
4. ~~**Auto-connect on startup**~~ ✅ (connect-recent/connect-specific/restore all trigger connect_to_config)
5. ~~**VPN status tooltip**~~ ✅ (tooltip_line shows "Name — Status (1h 23m)" with live duration)
6. ~~**Challenge/OTP dialog**~~ ✅ (request_challenge(); split routing in dbus_init.rs)

---

# Sprint 2 Tasks

1. ~~**Fix .gitignore**~~ ✅ (exclude build artifacts)
2. ~~**Audit and trim unused deps**~~ ✅ (removed uuid, url, gettext-rs)
3. ~~**Split application.rs**~~ ✅ (1031 lines → split into actions, config_ops, session_ops, credential_handler, dbus_init)
4. ~~**Expand test coverage**~~ ✅ (40 tests passing)
5. ~~**DEB package**~~ ✅ (cargo-deb config; make deb target)
6. ~~**RPM package**~~ ✅ (cargo-generate-rpm config; make rpm target)
7. ~~**AUR package**~~ ✅ (PKGBUILD in pkg/aur/)

---

# Sprint 1 Tasks

1. ~~**Status change notifications**~~ ✅ (push notification "Status change from {X} to {Y}")
2. ~~**GSettings schema file**~~ ✅ (schema created)
3. ~~**Desktop entry + icons packaging**~~ ✅ (.desktop file, icon installation)
4. ~~**About dialog polish**~~ ✅ (final UI touches)
5. ~~**Credential form labels**~~ ✅ (username → "Auth Username", password → "Auth Password", authentication code → "Authentication Code")
6. ~~**Rename project**~~ ✅ (from "openvpn3-indicator-qt" to "openvpn3-gui-rs")
