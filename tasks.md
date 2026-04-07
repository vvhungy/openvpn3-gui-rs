# Sprint 5 Tasks

1. ~~**Implement credential clearing**~~ ✅ (clear_all_async() added to CredentialStore; ClearCredentials tray action wired; --clear-secret-storage flag TODO resolved)
2. ~~**Connection error handling**~~ ✅ (is_error() moved to production; catch-all for CfgError/ProcStopped/ProcKilled added; startup auto-connect failure now notifies)
3. **Reconnect on connection drop** — When a session is destroyed unexpectedly (not user-initiated), show a tray notification with a "Reconnect" action button.

---

# Sprint 6 Tasks (Planned)

1. **Split oversized files** — `dbus_init.rs` (478 lines), `dbus/types.rs` (405 lines), `tray/indicator.rs` (471 lines) all breach the 400-line rule. Split by concern.
2. **Preferences dialog** — Add a GUI preferences dialog (startup action, notification toggle, specific-config-path) reachable from the tray menu.

---

# Sprint 4 Tasks (Completed)

1. ~~**Fix lingering warnings**~~ ✅ (tooltip_line wired into tool_tip; test-only methods moved to #[cfg(test)]; removed unused SessionStatus fields; D-Bus API enums suppressed with explanation)
2. ~~**Basic unit tests**~~ ✅ (10 new tests in settings/gsettings.rs fallback behavior + predicates; 5 new tests in tray/indicator.rs for status_label and tooltip_line; 53 total passing)
3. ~~**Integration test**~~ ✅ (tests/smoke_test.sh: build + --version check; make smoke-test target added)
4. ~~**Error handling audit**~~ ✅ (gsettings eprintln→tracing warn/error; keyring set/delete errors logged; config_ops unwrap→warn+continue; tray send_action error logged)
5. ~~**GitHub CI/CD**~~ ✅ (ci.yml: fmt+build+test+clippy+smoke on push/PR; release.yml: DEB+RPM packages + GitHub release on tag push)

---

# Sprint 3 Tasks (Completed)

1. ~~**Purge dead code**~~ ✅ (removed SharedTrayState, dead dialog stubs, unused constants; suppressed test-only code)
2. ~~**Fix unused imports**~~ ✅ (all unused import warnings cleared)
3. ~~**Remove or keep unused D-Bus enums**~~ ✅ (removed ClientAttentionGroup; kept SessionManagerEventType + ClientAttentionType and wired them to replace magic numbers)
4. ~~**Auto-connect on startup**~~ ✅ (connect-recent/connect-specific/restore all trigger connect_to_config with most-recent saved config)
5. ~~**VPN status tooltip**~~ ✅ (tooltip_line shows "Name — Status (1h 23m)" with live duration when connected)
6. ~~**Challenge/OTP dialog**~~ ✅ (request_challenge() in credential_handler.rs; split routing in dbus_init.rs; re-exported show_challenge_dialog)

---

# Sprint 2 Tasks (Completed)

1. ~~**Fix `.gitignore`** — exclude `data/gschemas.compiled` and other build artifacts~~ ✅
2. ~~**Audit and trim unused deps** — decide on `gettext-rs` (implement or remove), check `uuid` and `url`~~ ✅ (removed `uuid`, `url`, `gettext-rs` — all unused)
3. ~~**Split `application.rs`** — 1,031 lines; extract session management, menu building, and event handling into separate modules~~ ✅ (split into actions, config_ops, session_ops, credential_handler, dbus_init)
4. ~~**Expand test coverage** — add smoke tests for D-Bus types and credential store~~ ✅ (40 tests passing: 19 new in dbus/types.rs + 5 new in credentials/store.rs)
5. ~~**DEB package** — `cargo-deb` config in Cargo.toml; `make deb` target~~ ✅
6. ~~**RPM package** — `cargo-generate-rpm` config in Cargo.toml; `make rpm` target~~ ✅
7. ~~**AUR package** — `PKGBUILD` in `pkg/aur/`~~ ✅

---

# Sprint 1 Tasks (Completed)

1. ~~**Status change notifications** — For each status change, push notification "Status change from {X} to {Y}"~~ ✅
2. ~~**GSettings schema file** — Create the schema so settings persist~~ ✅ (schema exists, needs `sudo glib-compile-schemas /usr/share/glib-2.0/schemas/`)
3. ~~**Desktop entry + icons packaging** — `.desktop` file, icon installation~~ ✅
4. ~~**About dialog polish** — Final UI touches~~ ✅
5. ~~**Credential form labels** — Rename labels: username → "Auth Username", password → "Auth Password", authentication code → "Authentication Code"~~ ✅
6. ~~**Rename project** — Refactor project directory, name, binary name, and related things from "openvpn3-indicator-qt" to "openvpn3-gui-rs"~~ ✅
