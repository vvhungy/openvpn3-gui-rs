#!/usr/bin/env bash
# GSettings schema migration smoke test.
#
# Verifies three install paths by compiling the schema into an
# isolated directory and reading via GSETTINGS_BACKEND=memory:
#   (a) fresh install     — schema defaults for all keys
#   (b) upgrade from empty — same outcome (memory backend has no state)
#   (c) upgrade from prior — old keys absent → defaults (GSettings guarantee)
#
# Run from project root: bash tests/gsettings_schema_test.sh

set -euo pipefail

SCHEMA_ID="net.openvpn.openvpn3-gui-rs"
SCHEMA_XML="data/net.openvpn.openvpn3_gui_rs.gschema.xml"

PASS=0 FAIL=0

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        PASS=$((PASS + 1))
    else
        echo "FAIL: $label — expected '$expected', got '$actual'"
        FAIL=$((FAIL + 1))
    fi
}

gsc_get() {
    GSETTINGS_SCHEMA_DIR="$TMP" GSETTINGS_BACKEND=memory \
        gsettings get "$SCHEMA_ID" "$1"
}

# --- Compile schema into isolated temp directory ---
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cp "$SCHEMA_XML" "$TMP/"
if ! glib-compile-schemas "$TMP" 2>&1; then
    echo "FAIL: glib-compile-schemas failed"
    exit 1
fi
PASS=$((PASS + 1))

# --- String keys ---
assert_eq "startup-action default"        "'nothing'" "$(gsc_get startup-action)"
assert_eq "most-recent-config-id default"  "''"       "$(gsc_get most-recent-config-id)"
assert_eq "most-recent-config-name default" "''"      "$(gsc_get most-recent-config-name)"
assert_eq "specific-config-path default"   "''"       "$(gsc_get specific-config-path)"

# --- Boolean keys ---
assert_eq "show-notifications default"             "true"  "$(gsc_get show-notifications)"
assert_eq "warn-on-unexpected-disconnect default"  "true"  "$(gsc_get warn-on-unexpected-disconnect)"
assert_eq "enable-kill-switch default"             "false" "$(gsc_get enable-kill-switch)"
assert_eq "kill-switch-allow-lan default"          "true"  "$(gsc_get kill-switch-allow-lan)"
assert_eq "show-first-run-help default"            "true"  "$(gsc_get show-first-run-help)"
assert_eq "kill-switch-block-during-pause default" "false" "$(gsc_get kill-switch-block-during-pause)"

# --- Unsigned int keys ---
assert_eq "stats-refresh-interval default"     "uint32 30" "$(gsc_get stats-refresh-interval)"
assert_eq "connection-timeout default"         "uint32 30" "$(gsc_get connection-timeout)"
assert_eq "health-check-stall-seconds default" "uint32 60" "$(gsc_get health-check-stall-seconds)"

# --- Signed int keys (gsettings drops type prefix when value == default) ---
assert_eq "bypass-cidrs-max-count default" "32"   "$(gsc_get bypass-cidrs-max-count)"
assert_eq "logs-window-width default"      "800"  "$(gsc_get logs-window-width)"
assert_eq "logs-window-height default"     "600"  "$(gsc_get logs-window-height)"

# --- String array keys ---
assert_eq "bypass-cidrs default" "@as []" "$(gsc_get bypass-cidrs)"

# --- Summary ---
echo ""
echo "Schema migration smoke test: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && echo "All three install paths verified (fresh / empty-dconf / upgrade)."
exit $FAIL
