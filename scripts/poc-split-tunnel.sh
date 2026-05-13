#!/usr/bin/env bash
# =============================================================================
# PoC — Split-tunneling validation suite (Sprint 22 / T5)
# =============================================================================
#
# WHAT THIS ANSWERS
# -----------------
# This script physically validates the design decisions encoded in
# docs/split-tunneling.md addendum (Sprint 22 / T4):
#
#   D2: bypass route uses `ip rule` priority 100. The "test-priority-sweep"
#       command verifies this by iterating candidates {50, 100, 32500} and
#       reporting which one actually wins against OpenVPN3's default route.
#
#   D2 failure modes: rp_filter, conntrack, MTU/PMTUD, DNS leakage, IPv6
#       leakage. The "test" command runs one named check_* helper per mode,
#       so every failure mode triages back to a specific section in T4.
#
#   D5: gateway re-capture is idempotent on every Resume. The "test-resume"
#       command snapshots the captured gateway, prompts the user to Pause
#       + Resume the session, re-snapshots, and reports whether the snapshot
#       stayed valid or went stale.
#
# If all 5 mode checks pass + priority 100 wins the sweep + Resume re-capture
# yields a stable snapshot, Sprint 23 can proceed to helper API + UI work
# with high confidence. Failures yield specific S23 follow-ups documented in
# T4's S23-candidates section.
#
# WHAT THIS DOES NOT TEST
# -----------------------
# - Kill-switch interaction layered on top of bypass routing. T4 / D4 stated
#   bypass and kill-switch are INDEPENDENT layers — in production model b
#   ships with both layers running. For this PoC we disable kill-switch so
#   the routing measurements are not masked by nft drops. This is a
#   methodology choice (isolate the routing layer), not a design statement.
# - Per-app routing via cgroups v2 / fwmark. The spike doc rejected per-app
#   for v1; this PoC validates per-route (Option B) only.
# - Helper-API surface (`SetBypassCidrs` / `ClearBypassCidrs`). That's
#   Sprint 23 code, gated on this PoC passing.
#
# REQUIREMENTS
# ------------
# Required (must be present):
#   - Linux with iproute2 (ip, ip rule, ip route)
#   - Root (uses `ip route add`, `ip rule add`, sysctl reads)
#   - python3 (parses `ip -j` JSON output)
#   - mtr (manual verification step printed by `test`)
#
# Optional (each check_* helper probes for its tool; missing = skip with note):
#   - conntrack       (conntrack-tools) — check_conntrack
#   - traceroute      — check_mtu_pmtud (uses ping -M do as fallback)
#   - dig, tcpdump    (dnsutils, tcpdump) — check_dns
#
# Environment:
#   - An active LAN connection (so capture has a pre-VPN gateway to snapshot)
#   - openvpn3-gui-rs (or `openvpn3` CLI) to bring tunnel up between
#     `capture` and `test` phases
#   - Kill-switch DISABLED in the GUI (methodology — see above)
#
# WORKFLOW
# --------
#   1. (VPN DOWN, LAN connected, kill-switch OFF)
#        sudo ./scripts/poc-split-tunnel.sh capture
#      Snapshots pre-VPN default gateway + iface to /tmp/poc-pre-vpn.env.
#
#   2. Connect the VPN via openvpn3-gui-rs (or `openvpn3 session-start`).
#      Confirm tunnel is up:  ip route show 0/0   (should list tun*/wg*).
#
#   3. (VPN UP)
#        sudo ./scripts/poc-split-tunnel.sh test
#      Installs bypass rule + table at PRIORITY (default 100), then runs
#      five check_* helpers in sequence. Prints PASS/FAIL/SKIP per check.
#
#   4. (VPN UP, optional)
#        sudo ./scripts/poc-split-tunnel.sh test-priority-sweep
#      Re-runs the install at priorities {50, 100, 32500} and reports
#      which one wins. Validates D2's choice of 100.
#
#   5. (VPN UP, optional, INTERACTIVE)
#        sudo ./scripts/poc-split-tunnel.sh test-resume
#      Snapshots captured gateway, asks user to Pause + Resume the session,
#      re-snapshots, reports diff. Validates D5.
#
#   6. (VPN UP or DOWN)
#        sudo ./scripts/poc-split-tunnel.sh teardown
#      Removes rule + flushes table. Idempotent.
#
# CONFIGURATION
# -------------
# Defaults (override at invocation):
#   BYPASS_DEST=8.8.8.8/32              Google DNS — predictable AS path
#   TABLE_ID=100                        Secondary routing table number
#   PRIORITY=100                        ip rule priority (T4 / D2)
#   PRIORITY_SWEEP_LIST="50,100,32500"  test-priority-sweep candidates
#   MTU_TEST_SIZES="1280,1492,1500"     check_mtu_pmtud probe sizes
#   TEST_DNS_RESOLVER=8.8.8.8           check_dns target resolver
#   TEST_BYPASS_V6=2001:4860:4860::8888 check_ipv6 v6 control target
#   STATE_FILE=/tmp/poc-pre-vpn.env     capture/test handover file
#
# Example:
#   BYPASS_DEST=192.168.50.0/24 PRIORITY=50 sudo $0 test
#
# FAILURE-MODE TRIAGE
# -------------------
# Per T4 / D2 the five failure modes are:
#
#   1. rp_filter (reverse path filtering)
#      Strict mode (sysctl =1) drops packets whose return path doesn't
#      match the incoming iface — exactly what asymmetric bypass routing
#      creates. T4 / D2 requires rp_filter=2 (loose) on both `all` and
#      $PRE_VPN_IFACE for bypass to work. check_rp_filter reads both.
#      Fix: `sysctl -w net.ipv4.conf.all.rp_filter=2` (and per-iface).
#
#   2. conntrack pinning
#      If conntrack established a flow over tun* before the bypass rule
#      went in, that flow's later packets may still be classified to tun*
#      regardless of the new rule. check_conntrack triggers a new flow
#      via the bypass dest and inspects `conntrack -L`. Fix: in production,
#      bypass rule install + `conntrack -F` flush together; in PoC, a
#      simple `conntrack -F` between test runs.
#
#   3. MTU / PMTUD
#      Pre-VPN iface MTU is typically 1500; tunnel iface is typically
#      1420–1492. Apps that learned a tunnel-sized MTU may produce packets
#      too large for the bypass path. check_mtu_pmtud probes with -M do
#      (don't-fragment) at sizes {1280, 1492, 1500} and looks for
#      "Frag needed" responses. Fix: TCP MSS clamping on the bypass iface,
#      or PMTUD black-hole detection in the kernel.
#
#   4. DNS leakage
#      If glibc's resolver was pinned to a DNS server pushed by the VPN
#      (via systemd-resolved or /etc/resolv.conf rewrite), queries for the
#      bypass dest may still leak through the tunnel. check_dns runs dig
#      against TEST_DNS_RESOLVER via the bypass path and inspects which
#      iface the query actually exits. Fix: route DNS queries through the
#      same path as their parent flow (helper-side `ip rule` for port 53).
#
#   5. IPv6 leakage
#      Linux maintains separate v4 / v6 routing tables. A v4 bypass rule
#      does nothing for v6 traffic to the same host. check_ipv6 inspects
#      whether v6 is enabled, has a default route, and warns that the
#      bypass is v4-only. Fix: helper installs symmetric v4+v6 rules, or
#      kill-switch's v6 firewall stays on regardless of bypass state.
#
# UNREACHABLE BYPASS_DEST
# -----------------------
# `test` first installs the bypass rule + table, then probes BYPASS_DEST via
# ICMP (ping) AND TCP/443 (bash /dev/tcp). If BOTH fail, the bypass rule is
# in place but no traffic actually flows along it. The script then SKIPs the
# flow-dependent checks (conntrack, MTU/PMTUD) instead of FAILing them with
# misleading remediation advice ("Fix: TCP MSS clamping" makes no sense when
# the real fix is "use a reachable destination").
#
# Common causes:
#   - iPhone Personal Hotspot blocks ICMP to 8.8.8.8 (default BYPASS_DEST)
#     and may filter outbound TCP/443 to certain IPs.
#   - Captive-portal Wi-Fi (hotel, airport) intercepts traffic until login.
#   - Corporate / ISP egress filter or transparent proxy.
#   - The bypass dest is genuinely down.
#
# Workaround: re-run with a different destination known to answer:
#   BYPASS_DEST=1.1.1.1/32 sudo $0 test
#   BYPASS_DEST=9.9.9.9/32 sudo $0 test
# Routing layer + rp_filter + DNS + IPv6 checks remain valid even when the
# dest is unreachable — only conntrack and MTU SKIP because they need a flow.
#
# LEAVE NOTHING BEHIND
# --------------------
# Always run `teardown` when finished. A bypass rule left in place will
# continue diverting matching traffic outside the VPN even after disconnect
# (until reboot or explicit removal). Forgetting this leaves a covert
# split-tunnel on the box.
#
# =============================================================================

set -euo pipefail

TABLE_ID="${TABLE_ID:-100}"
PRIORITY="${PRIORITY:-100}"
BYPASS_DEST="${BYPASS_DEST:-8.8.8.8/32}"
STATE_FILE="${STATE_FILE:-/tmp/poc-pre-vpn.env}"
PRIORITY_SWEEP_LIST="${PRIORITY_SWEEP_LIST:-50,100,32500}"
MTU_TEST_SIZES="${MTU_TEST_SIZES:-1280,1492,1500}"
TEST_DNS_RESOLVER="${TEST_DNS_RESOLVER:-8.8.8.8}"
TEST_BYPASS_V6="${TEST_BYPASS_V6:-2001:4860:4860::8888}"

RESULTS_FAILED=0
RESULTS_SKIPPED=0
BYPASS_UNREACHABLE=0

result_pass() { echo "  PASS: $*"; }
result_fail() { echo "  FAIL: $*"; RESULTS_FAILED=$((RESULTS_FAILED + 1)); }
result_skip() { echo "  SKIP: $*"; RESULTS_SKIPPED=$((RESULTS_SKIPPED + 1)); }
result_note() { echo "  NOTE: $*"; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: must run as root (use sudo)" >&2
        exit 1
    fi
}

require_python3() {
    if ! command -v python3 >/dev/null 2>&1; then
        echo "ERROR: python3 not found (used to parse 'ip -j' JSON output)" >&2
        exit 1
    fi
}

# probe_bypass_reachable — returns 0 if BYPASS_DEST is reachable via the
# bypass path (ICMP echo OR TCP-443). Used to gate failure-mode checks that
# need a working flow to measure (conntrack, MTU). Common environmental
# causes for failure: iPhone hotspot blocking 8.8.8.8, captive portals,
# corporate NAT, ISP ICMP shaping. The TCP-443 fallback handles ICMP-blocked
# networks; if both fail, the destination genuinely isn't reachable from
# this host and the dependent checks correctly SKIP rather than print
# misleading FAIL verdicts ("Fix: TCP MSS clamping" makes no sense when
# the actual fix is "use a different BYPASS_DEST").
probe_bypass_reachable() {
    local dst="${BYPASS_DEST%/*}"
    if ping -c 1 -W 2 "$dst" >/dev/null 2>&1; then return 0; fi
    if timeout 2 bash -c "exec 3<>/dev/tcp/$dst/443" >/dev/null 2>&1; then return 0; fi
    return 1
}

# require_vpn_intercepting — confirms a tunnel iface (tun*/wg*/ppp*) actually
# carries traffic to a control destination (1.1.1.1). NOT based on
# `ip route show default`: with redirect-gateway def1, OpenVPN3 installs
# 0.0.0.0/1 + 128.0.0.0/1 via the tunnel and leaves the default route on the
# LAN iface. The default route is a poor witness for "VPN is up".
require_vpn_intercepting() {
    local control_iface
    control_iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    if [[ -z "$control_iface" ]]; then
        echo "ERROR: cannot determine route to 1.1.1.1. Is networking up?" >&2
        exit 1
    fi
    case "$control_iface" in
        tun*|wg*|ppp*)
            local cur_default_iface
            cur_default_iface=$(ip route show default | awk '/^default/ {print $5; exit}')
            echo "VPN intercepting traffic via $control_iface (default route on '$cur_default_iface', pre-VPN was '$PRE_VPN_IFACE')."
            echo "Note: with redirect-gateway def1, OpenVPN3 covers all v4 via 0.0.0.0/1 + 128.0.0.0/1; the default route stays on the LAN iface."
            ;;
        *)
            echo "ERROR: route to 1.1.1.1 exits via '$control_iface', not a tunnel iface (tun*/wg*/ppp*)." >&2
            echo "       VPN doesn't appear to be intercepting. Connect VPN before running this command." >&2
            echo "       (If your VPN config lacks 'redirect-gateway def1', this PoC has nothing to validate —" >&2
            echo "        split-tunneling is meaningful only when the VPN otherwise carries all traffic.)" >&2
            exit 1
            ;;
    esac
}

# require_capture_fresh — validates STATE_FILE contents are still applicable to
# the current network. Two guards in one helper:
#   1. STATE_FILE actually has PRE_VPN_GATEWAY + PRE_VPN_IFACE set.
#   2. The captured gateway is still on PRE_VPN_IFACE's current subnet.
#
# (2) works because the kernel's connected route for a LAN
# (e.g. `192.168.1.0/24 dev wlp0s20f3 proto kernel scope link`) is the most
# specific match for any in-subnet gateway IP. So `ip route get $GW`:
#   - Fresh capture (same network):  → exit via PRE_VPN_IFACE.
#   - Stale capture (switched nets): connected route gone, kernel falls back
#     to OpenVPN3's 0.0.0.0/1 over tun0, → exit via tunnel iface.
# The helper aborts in case (2) before `install_bypass` runs and before
# the kernel returns the cryptic "Nexthop has invalid gateway" RTNETLINK
# error. Common trigger: user re-ran `test` after switching from hotspot
# to WiFi without re-running `capture`.
require_capture_fresh() {
    if [[ -z "${PRE_VPN_GATEWAY:-}" || -z "${PRE_VPN_IFACE:-}" ]]; then
        echo "ERROR: $STATE_FILE missing PRE_VPN_GATEWAY or PRE_VPN_IFACE" >&2
        echo "       Re-run: sudo $0 capture" >&2
        exit 1
    fi

    local gw_iface
    gw_iface=$(ip route get "$PRE_VPN_GATEWAY" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')

    if [[ "$gw_iface" != "$PRE_VPN_IFACE" ]]; then
        echo "ERROR: captured gateway $PRE_VPN_GATEWAY is not on $PRE_VPN_IFACE's current subnet" >&2
        echo "       (kernel routes it via '${gw_iface:-<no route>}'). Captured state is stale —" >&2
        echo "       likely you switched networks since 'capture' (e.g. hotspot → WiFi)." >&2
        echo "       Fix: disconnect VPN, then re-run on current network:" >&2
        echo "            sudo $0 teardown" >&2
        echo "            sudo $0 capture" >&2
        echo "            (reconnect VPN)" >&2
        echo "            sudo $0 test" >&2
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Phase: capture — snapshot pre-VPN default route + iface to STATE_FILE.
# Must run BEFORE the VPN is brought up. Unchanged from original PoC.
# -----------------------------------------------------------------------------

cmd_capture() {
    require_root
    require_python3

    local default_json
    default_json=$(ip -j route show default 2>/dev/null || echo "[]")

    if [[ -z "$default_json" || "$default_json" == "[]" ]]; then
        echo "ERROR: no default route present. Connect to LAN first." >&2
        exit 1
    fi

    local gw iface
    gw=$(echo "$default_json" | python3 -c '
import json, sys
routes = json.load(sys.stdin)
if not routes or "gateway" not in routes[0] or "dev" not in routes[0]:
    sys.exit("ERROR: default route lacks gateway+dev fields")
print(routes[0]["gateway"])
')
    iface=$(echo "$default_json" | python3 -c '
import json, sys
print(json.load(sys.stdin)[0]["dev"])
')

    case "$iface" in
        tun*|wg*|ppp*)
            echo "ERROR: captured iface '$iface' looks like an existing tunnel." >&2
            echo "       Disconnect any active VPN before running 'capture'." >&2
            exit 1
            ;;
    esac

    cat > "$STATE_FILE" <<EOF
# Captured by scripts/poc-split-tunnel.sh at $(date -Iseconds)
PRE_VPN_GATEWAY=$gw
PRE_VPN_IFACE=$iface
EOF
    chmod 644 "$STATE_FILE"

    echo "Captured pre-VPN state to $STATE_FILE:"
    cat "$STATE_FILE"
    echo
    echo "Next: connect VPN, then run:  sudo $0 test"
}

# -----------------------------------------------------------------------------
# install_bypass / remove_bypass — shared helpers, idempotent.
# -----------------------------------------------------------------------------

# NOTE: `ip rule show` strips /32 from v4 host CIDRs when printing — so a
# rule we created with `to 8.8.8.8/32 ... lookup 100` is shown as
# `to 8.8.8.8 ... lookup 100`. Grepping by CIDR string mis-matches and the
# stale rule survives, causing `ip rule add` to fail with "File exists".
# Match by lookup table number instead — `ip rule show` always prints it
# verbatim as `lookup <N>` and we own TABLE_ID inside this PoC, so flushing
# every rule pointing at it is safe.
flush_rules_for_table() {
    local guard=0
    while ip rule show | awk -v t="$TABLE_ID" '$0 ~ ("lookup "t"$") {found=1} END{exit !found}'; do
        ip rule del lookup "$TABLE_ID" 2>/dev/null || break
        guard=$((guard + 1))
        if (( guard > 16 )); then
            echo "WARNING: gave up flushing rules for table $TABLE_ID after 16 iterations" >&2
            break
        fi
    done
}

install_bypass() {
    local prio="$1"

    flush_rules_for_table
    ip route flush table "$TABLE_ID" 2>/dev/null || true
    ip route add default via "$PRE_VPN_GATEWAY" dev "$PRE_VPN_IFACE" table "$TABLE_ID"
    ip rule add to "$BYPASS_DEST" lookup "$TABLE_ID" priority "$prio"
}

remove_bypass() {
    flush_rules_for_table
    ip route flush table "$TABLE_ID" 2>/dev/null || true
}

# -----------------------------------------------------------------------------
# check_rp_filter — D2 failure mode 1.
# Linux uses MAX(all, iface). 1=strict (FAIL), 2=loose (PASS), 0=off (NOTE).
# -----------------------------------------------------------------------------

check_rp_filter() {
    echo "[1/5] rp_filter (reverse path filtering)"
    local all_v iface_v
    all_v=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo "?")
    iface_v=$(sysctl -n "net.ipv4.conf.${PRE_VPN_IFACE}.rp_filter" 2>/dev/null || echo "?")

    if [[ "$all_v" == "?" || "$iface_v" == "?" ]]; then
        result_skip "rp_filter — sysctl read failed (all=$all_v iface=$iface_v)"
        return
    fi

    local effective
    if (( all_v > iface_v )); then
        effective=$all_v
    else
        effective=$iface_v
    fi

    case "$effective" in
        0) result_note "rp_filter — disabled (all=$all_v, $PRE_VPN_IFACE=$iface_v). Bypass works but host has no return-path guard." ;;
        1) result_fail "rp_filter — STRICT (all=$all_v, $PRE_VPN_IFACE=$iface_v). Will drop bypass packets. Fix: sysctl -w net.ipv4.conf.all.rp_filter=2; sysctl -w net.ipv4.conf.${PRE_VPN_IFACE}.rp_filter=2" ;;
        2) result_pass "rp_filter — loose (all=$all_v, $PRE_VPN_IFACE=$iface_v). Bypass-compatible." ;;
        *) result_note "rp_filter — unexpected value (all=$all_v, $PRE_VPN_IFACE=$iface_v)" ;;
    esac
}

# -----------------------------------------------------------------------------
# check_conntrack — D2 failure mode 2.
# Flushes conntrack, probes bypass dest, inspects flow's selected iface.
# -----------------------------------------------------------------------------

check_conntrack() {
    echo "[2/5] conntrack (flow pinning)"
    if ! command -v conntrack >/dev/null 2>&1; then
        result_skip "conntrack — tool not installed (apt install conntrack)"
        return
    fi

    conntrack -F 2>/dev/null || true

    local dst="${BYPASS_DEST%/*}"
    # Trigger flow via TCP/443 (works on ICMP-blocked networks like iPhone
    # hotspots). ICMP fallback only if TCP also fails — we still want SOMETHING
    # in the conntrack table to inspect.
    if ! timeout 2 bash -c "exec 3<>/dev/tcp/$dst/443" >/dev/null 2>&1; then
        ping -c 1 -W 2 "$dst" >/dev/null 2>&1 || true
    fi

    local flow
    flow=$(conntrack -L -d "$dst" 2>/dev/null | head -n 1)

    if [[ -z "$flow" ]]; then
        if (( BYPASS_UNREACHABLE )); then
            result_skip "conntrack — bypass dest $dst unreachable (TCP/443 + ICMP both failed); cannot trigger flow to inspect."
        else
            result_skip "conntrack — no flow recorded for $dst (probe may have been dropped before conntrack saw it)"
        fi
        return
    fi

    local route_iface
    route_iface=$(ip route get "$dst" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')

    case "$route_iface" in
        "$PRE_VPN_IFACE")
            result_pass "conntrack — kernel selects $route_iface for $dst; conntrack entry recorded."
            echo "        flow: $flow"
            ;;
        tun*|wg*|ppp*)
            result_fail "conntrack — kernel selects $route_iface (tunnel) for $dst, not $PRE_VPN_IFACE. Bypass rule is being shadowed."
            ;;
        *)
            result_note "conntrack — kernel selects unexpected iface '$route_iface' for $dst"
            ;;
    esac
}

# -----------------------------------------------------------------------------
# check_mtu_pmtud — D2 failure mode 3.
# Pings BYPASS_DEST with -M do at MTU_TEST_SIZES. Any unreachable = MTU
# black-hole at that size on the bypass path.
# -----------------------------------------------------------------------------

check_mtu_pmtud() {
    echo "[3/5] MTU / PMTUD"
    if (( BYPASS_UNREACHABLE )); then
        result_skip "mtu_pmtud — bypass dest unreachable (ICMP+TCP/443 both failed); MTU probe needs working flow. Re-run with a reachable BYPASS_DEST."
        return
    fi
    local dst="${BYPASS_DEST%/*}"
    local iface_mtu
    iface_mtu=$(ip -o link show "$PRE_VPN_IFACE" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="mtu"){print $(i+1); exit}}')
    echo "        $PRE_VPN_IFACE MTU = ${iface_mtu:-unknown}"

    local sizes
    IFS=',' read -r -a sizes <<< "$MTU_TEST_SIZES"

    local any_fail=0
    local size payload
    for size in "${sizes[@]}"; do
        payload=$((size - 28))
        if [[ $payload -le 0 ]]; then continue; fi
        if ping -c 1 -W 2 -M do -s "$payload" "$dst" >/dev/null 2>&1; then
            echo "        size=$size  OK"
        else
            echo "        size=$size  BLOCKED (Frag needed or no reply)"
            any_fail=1
        fi
    done

    if (( any_fail )); then
        result_fail "mtu_pmtud — one or more sizes blocked. Fix: TCP MSS clamping on $PRE_VPN_IFACE bypass path."
    else
        result_pass "mtu_pmtud — all probe sizes succeeded over bypass path."
    fi
}

# -----------------------------------------------------------------------------
# check_dns — D2 failure mode 4.
# Catches routing-layer leakage (does the query exit via the bypass path?).
# Application-layer leakage from /etc/resolv.conf needs tcpdump (printed hint).
# -----------------------------------------------------------------------------

check_dns() {
    echo "[4/5] DNS leakage"
    if ! command -v dig >/dev/null 2>&1; then
        result_skip "dns — dig not installed (apt install dnsutils)"
        return
    fi

    local route_iface
    route_iface=$(ip route get "$TEST_DNS_RESOLVER" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')

    local exits_via_bypass=0
    case "$route_iface" in
        "$PRE_VPN_IFACE") exits_via_bypass=1 ;;
    esac

    if dig @"$TEST_DNS_RESOLVER" +time=2 +tries=1 example.com >/dev/null 2>&1; then
        if (( exits_via_bypass )); then
            result_pass "dns — query to $TEST_DNS_RESOLVER exits via $PRE_VPN_IFACE (bypass path)."
        else
            result_fail "dns — query to $TEST_DNS_RESOLVER exits via $route_iface, not $PRE_VPN_IFACE. Routing-layer DNS leak."
        fi
    else
        result_note "dns — dig query failed; resolver $TEST_DNS_RESOLVER unreachable from this host."
    fi

    if ! command -v tcpdump >/dev/null 2>&1; then
        result_note "dns — install tcpdump to verify application-layer DNS path (resolv.conf may still leak to VPN-pushed resolver regardless of routing)."
    fi
}

# -----------------------------------------------------------------------------
# check_ipv6 — D2 failure mode 5.
# v4 bypass rule does NOT cover v6 traffic to the same host. Production must
# install symmetric v4+v6 rules OR keep kill-switch v6 firewall on.
# -----------------------------------------------------------------------------

check_ipv6() {
    echo "[5/5] IPv6 leakage"
    local v6_disabled
    v6_disabled=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "?")

    if [[ "$v6_disabled" == "1" ]]; then
        result_note "ipv6 — disabled host-wide (/proc/sys/net/ipv6/conf/all/disable_ipv6 = 1). No v6 leak surface."
        return
    fi

    local v6_default
    v6_default=$(ip -6 route show default 2>/dev/null | head -n 1)

    if [[ -z "$v6_default" ]]; then
        result_note "ipv6 — enabled but no v6 default route. No v6 leak surface."
        return
    fi

    local v6_iface
    v6_iface=$(ip -6 route get "$TEST_BYPASS_V6" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')

    case "$v6_iface" in
        tun*|wg*|ppp*)
            result_note "ipv6 — v6 traffic to $TEST_BYPASS_V6 exits via $v6_iface (tunnel). v4 bypass does NOT cover v6 — production must install symmetric v6 rules."
            ;;
        "")
            result_note "ipv6 — could not determine v6 path to $TEST_BYPASS_V6."
            ;;
        *)
            result_fail "ipv6 — v6 traffic to $TEST_BYPASS_V6 exits via $v6_iface (NOT a tunnel iface). v6 leak — kill-switch v6 firewall needed."
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Phase: test — driver. Installs bypass at PRIORITY, runs 5 checks.
# -----------------------------------------------------------------------------

cmd_test() {
    require_root
    if [[ ! -f "$STATE_FILE" ]]; then
        echo "ERROR: $STATE_FILE missing. Run 'capture' BEFORE connecting VPN." >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    source "$STATE_FILE"

    require_capture_fresh
    require_vpn_intercepting
    echo

    install_bypass "$PRIORITY"

    if probe_bypass_reachable; then
        BYPASS_UNREACHABLE=0
        echo "Bypass dest ${BYPASS_DEST%/*} is reachable (ICMP or TCP/443 OK)."
    else
        BYPASS_UNREACHABLE=1
        echo "WARNING: bypass dest ${BYPASS_DEST%/*} is UNREACHABLE via bypass path"
        echo "         (ICMP and TCP/443 both failed). Routing is in place, but"
        echo "         flow-dependent checks (conntrack, MTU) will SKIP because"
        echo "         they cannot measure what isn't flowing. Common causes:"
        echo "         iPhone hotspot blocking 8.8.8.8, captive portal, ISP"
        echo "         filter. Try BYPASS_DEST=1.1.1.1/32 or a known-reachable host."
    fi
    echo

    echo "Installed:"
    echo "  rule:  to $BYPASS_DEST lookup $TABLE_ID  priority $PRIORITY"
    echo "  route: default via $PRE_VPN_GATEWAY dev $PRE_VPN_IFACE  table $TABLE_ID"
    echo

    echo "=== Kernel routing decision ==="
    echo
    echo "\$ ip rule show priority $PRIORITY"
    ip rule show priority "$PRIORITY" || true
    echo
    echo "\$ ip route show table $TABLE_ID"
    ip route show table "$TABLE_ID"
    echo
    echo "\$ ip route get ${BYPASS_DEST%/*}     # bypass dest"
    ip route get "${BYPASS_DEST%/*}"
    echo
    echo "\$ ip route get 1.1.1.1     # control: should still take tunnel"
    ip route get 1.1.1.1
    echo

    echo "=== Failure-mode checks (D2 / T4) ==="
    echo
    RESULTS_FAILED=0
    RESULTS_SKIPPED=0
    check_rp_filter
    check_conntrack
    check_mtu_pmtud
    check_dns
    check_ipv6
    echo
    echo "Summary: failed=$RESULTS_FAILED  skipped=$RESULTS_SKIPPED  (5 checks total)"
    echo

    echo "=== Manual verification (run these now, before teardown) ==="
    echo
    echo "  mtr -rwc 5 ${BYPASS_DEST%/*}     # first hop should be $PRE_VPN_GATEWAY"
    echo "  mtr -rwc 5 1.1.1.1               # first hop should be VPN gateway"
    echo "  curl -s https://ifconfig.me      # should show VPN exit IP (control)"
    echo
    echo "Optional next steps:"
    echo "  sudo $0 test-priority-sweep     # validate D2 priority 100"
    echo "  sudo $0 test-resume             # validate D5 Resume re-capture"
    echo "  sudo $0 teardown                # when done"
}

# -----------------------------------------------------------------------------
# Phase: test-priority-sweep — runs install_bypass at each candidate
# priority and reports which one wins (via `ip route get`).
# -----------------------------------------------------------------------------

cmd_test_priority_sweep() {
    require_root
    if [[ ! -f "$STATE_FILE" ]]; then
        echo "ERROR: $STATE_FILE missing. Run 'capture' first." >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    source "$STATE_FILE"

    require_capture_fresh
    require_vpn_intercepting
    echo

    local dst="${BYPASS_DEST%/*}"
    local prios
    IFS=',' read -r -a prios <<< "$PRIORITY_SWEEP_LIST"

    echo "=== Priority sweep: $PRIORITY_SWEEP_LIST ==="
    echo "Each row: priority, kernel-selected iface for $dst, verdict."
    echo

    local prio iface verdict
    for prio in "${prios[@]}"; do
        install_bypass "$prio"
        iface=$(ip route get "$dst" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
        case "$iface" in
            "$PRE_VPN_IFACE") verdict="WINS  (intercepts before main + default)" ;;
            tun*|wg*|ppp*)    verdict="LOSES (shadowed by main-table tunnel route)" ;;
            *)                verdict="UNEXPECTED iface '$iface'" ;;
        esac
        printf "  priority=%-6s  iface=%-12s  %s\n" "$prio" "$iface" "$verdict"
    done

    remove_bypass

    echo
    echo "Bypass removed after sweep. If you want to leave a specific priority"
    echo "installed for further manual testing, re-run:  sudo PRIORITY=<n> $0 test"
}

# -----------------------------------------------------------------------------
# Phase: test-resume — INTERACTIVE. Validates D5 (idempotent re-capture).
# -----------------------------------------------------------------------------

snapshot_gateway() {
    ip route show default | head -n 1 | awk '{
        for(i=1;i<=NF;i++) {
            if($i=="via") gw=$(i+1);
            if($i=="dev") dev=$(i+1);
        }
        print gw "|" dev;
    }'
}

cmd_test_resume() {
    require_root
    if [[ ! -f "$STATE_FILE" ]]; then
        echo "ERROR: $STATE_FILE missing. Run 'capture' first." >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    source "$STATE_FILE"

    echo "=== Resume re-capture test (D5) ==="
    echo
    echo "Snapshot 1 (now): default route =  $(snapshot_gateway)"
    echo "Captured pre-VPN: $PRE_VPN_GATEWAY|$PRE_VPN_IFACE"
    echo
    echo "ACTION REQUIRED: in the OpenVPN3 GUI, Pause the session, wait >=10s,"
    echo "then Resume. After Resume, press Enter here to continue."
    read -r
    echo
    echo "Snapshot 2 (after Resume): default route =  $(snapshot_gateway)"
    echo
    echo "If Snapshot 1 == Snapshot 2 AND both equal '$PRE_VPN_GATEWAY|$PRE_VPN_IFACE'"
    echo "(or both equal a tunnel iface — either is fine, what matters is stability),"
    echo "then D5's idempotent re-capture assumption holds: the captured pre-VPN"
    echo "gateway survived the Pause/Resume cycle."
    echo
    echo "If Snapshot 2 changed unexpectedly (e.g. gateway IP differs), D5 needs"
    echo "tightening: helper must re-run capture on every Resume, not just on"
    echo "initial connect."
}

# -----------------------------------------------------------------------------
# Phase: teardown — remove rule(s), flush table, drop state file. Idempotent.
# -----------------------------------------------------------------------------

cmd_teardown() {
    require_root

    remove_bypass
    rm -f "$STATE_FILE"

    echo "Teardown complete. Verify nothing remains:"
    echo
    echo "  ip rule show | grep 'lookup $TABLE_ID'    # (should print nothing)"
    echo "  ip route show table $TABLE_ID             # (should print nothing)"
    echo
    ip rule show | grep "lookup $TABLE_ID" || echo "  [confirmed: no rule for table $TABLE_ID]"
    if [[ -n "$(ip route show table "$TABLE_ID" 2>/dev/null)" ]]; then
        echo "  WARNING: table $TABLE_ID still has entries:"
        ip route show table "$TABLE_ID"
    else
        echo "  [confirmed: table $TABLE_ID is empty]"
    fi
}

usage() {
    cat <<EOF
Usage: $0 {capture|test|test-priority-sweep|test-resume|teardown}

Workflow:
  1. (VPN DOWN, kill-switch OFF)  sudo $0 capture
  2. Connect VPN via openvpn3-gui-rs
  3. (VPN UP)                     sudo $0 test
  4. (optional, VPN UP)           sudo $0 test-priority-sweep
  5. (optional, INTERACTIVE)      sudo $0 test-resume
  6.                              sudo $0 teardown

Optional environment overrides (see script header for full list):
  BYPASS_DEST=8.8.8.8/32
  TABLE_ID=100
  PRIORITY=100
  PRIORITY_SWEEP_LIST="50,100,32500"
  MTU_TEST_SIZES="1280,1492,1500"
  TEST_DNS_RESOLVER=8.8.8.8
  TEST_BYPASS_V6=2001:4860:4860::8888

See top of script for full design context, failure-mode triage, and the
T4 design-decision references each check validates.
EOF
}

case "${1:-}" in
    capture)              cmd_capture ;;
    test)                 cmd_test ;;
    test-priority-sweep)  cmd_test_priority_sweep ;;
    test-resume)          cmd_test_resume ;;
    teardown)             cmd_teardown ;;
    *)                    usage; exit 1 ;;
esac
