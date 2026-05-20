# Split-Tunneling Design Spike

Sprint 21 / T4 — read-only spike, deliverable is this document.

> **Current status (S26):** Implemented per Option B (per-route + nft bypass set).
> Shipped: Preferences Routing tab (Add/Remove CIDR), helper `SetBypassCidrs` +
> `ApplyBypassRoutes` + `ClearBypassRoutes`, cold-start re-apply
> (`dbus_init.rs`), connect/disconnect/pause/resume integration, tray bypass
> state row, S26/T2 per-entry enable/disable checkbox without deleting rows.
> Below this banner is a historical record of S21–S22 design/PoC; "Sprint 23
> action" notes are snapshots from that period — refer to current code for
> the shipped behaviour.

## Problem statement

Split-tunneling lets a subset of traffic bypass the VPN tunnel and travel
through the host's default route instead. Two common motivations:

1. **Per-app** — a media app, conferencing client, or LAN-discovery tool
   should reach the local network or its CDN without VPN-induced latency.
2. **Per-destination** — corporate VPN with internal IPs that must NOT route
   through the personal VPN; or LAN/printer ranges that the tunnel would
   otherwise capture.

OpenVPN3 itself does not implement split-tunneling on Linux; the feature
must live in the GUI/helper pair. The kill-switch already running in this
codebase makes the interaction non-trivial: any bypass mechanism must
**also** be allow-listed by the nftables drop rules, otherwise bypassed
traffic gets blocked the moment the tunnel drops.

## Architecture options

### A. Per-app via cgroups v2 + nftables `meta cgroupv2`

Mechanism:

1. Helper creates `/sys/fs/cgroup/openvpn3-bypass/` (cgroup v2 unified
   hierarchy).
2. GUI moves a PID into the cgroup via `cgroup.procs` write.
3. Helper installs nft rules that match `meta cgroupv2 level 2 "openvpn3-bypass"`
   and set `meta mark 0x42`.
4. Helper installs `ip rule fwmark 0x42 lookup bypass`, where `bypass`
   table holds a default route via the host's pre-VPN gateway.

Requirements: kernel ≥ 5.7 for `meta cgroupv2`, cgroup v2 unified
hierarchy active (Ubuntu 22+, Fedora 31+, Debian 11+ — fine for our
target distros).

UX surface: an app-picker dialog. User browses `.desktop` files under
`/usr/share/applications` and `~/.local/share/applications`, selects
which apps go through the bypass cgroup. The launcher wrapper would need
to write the spawned PID into `cgroup.procs` *before* `exec` — typically
via a small `systemd-run --slice=openvpn3-bypass.slice` shim, or a custom
`systemd` service template.

Already-running processes can be added (write current PID), but their
descendants only inherit the cgroup if started after the move. Browsers
often spawn helper processes before any user action — moving the parent
PID covers most of their network traffic, but not all.

### B. Per-route via `ip rule` + secondary routing table

Mechanism:

1. Helper creates a `bypass` routing table in `/etc/iproute2/rt_tables.d/`.
2. For each user-specified CIDR `<prefix>`:
   - `ip route add <prefix> via <pre-vpn-gw> dev <pre-vpn-iface> table bypass`
   - `ip rule add to <prefix> lookup bypass priority 100`
3. Kill-switch nft rules grow an explicit allow set: `daddr @bypass_set
   accept` placed before the catch-all drop.

Requirements: any kernel with policy routing (everything in scope).

UX surface: a "Bypass Networks" list in Preferences (mirrors the existing
"Allow LAN" pattern in the Security tab). Each entry is a CIDR string;
optional comment field. No per-process coordination needed.

DNS-resolved entries (e.g. "github.com") are out of scope for v1 — would
require periodic re-resolution and route churn. CIDRs only.

### C. Hybrid (cgroup marks consult per-app routing table)

Combine A and B: use cgroup membership to *select which apps* trigger the
bypass, but route their traffic via B's policy table rather than fwmark.

In practice this collapses to A — cgroup membership is the entry point;
the routing table is an implementation detail. The "hybrid" framing
mostly buys flexibility we don't need at v1: per-app *and* per-CIDR
overlap is a rare configuration that adds significant complexity to both
the helper API and the Preferences UI.

## Trade-off table

| Concern                                | A. Per-app cgroup     | B. Per-route        | C. Hybrid           |
| -------------------------------------- | --------------------- | ------------------- | ------------------- |
| Kernel/distro requirements             | ≥ 5.7, cgroup v2     | Any                 | Same as A           |
| Helper D-Bus API delta                 | Large (cgroup ops, app registry, fwmark) | Small (route + rule per CIDR) | Largest (A + B) |
| OpenVPN3 integration cost              | None                  | None                | None                |
| Pre-VPN gateway/iface discovery        | Helper needs to capture this on connect (parse `ip route` before tunnel) | Same | Same |
| Coordination with app launch           | Mandatory shim (systemd-run or wrapper) | None | Mandatory |
| UX surface (new dialog/tab)            | App picker dialog (new), launcher integration | Preferences tab section (existing pattern) | Both |
| Kill-switch interaction                | Add fwmark exception to nft chain | Add `@bypass_set` to nft chain before drop | Both exceptions |
| Per-process granularity                | Yes                   | No                  | Yes                 |
| Per-destination granularity            | No                    | Yes                 | Yes                 |
| Already-running app coverage           | Partial (descendants miss) | N/A — destination-based | Same as A |
| Failure mode if helper crashes mid-set | Cgroup persists; rules orphaned (recover on next AddSplit*) | Routes orphaned; user loses bypass until re-applied | Both |

## Recommendation

**Option B (per-route).** Three reasons:

1. **Smallest helper-API delta.** The helper already invokes external
   binaries (`nft`) with validated arguments. Adding `ip` invocations
   for `route add`/`rule add` follows the same pattern. Option A
   requires a new app-registry concept, cgroup file writes, fwmark
   coordination, and a launcher shim — that's a much wider change.
2. **Kill-switch interaction is mechanical.** The `bypass_set` becomes
   one new `add` line in `nft.rs::add_script`. Option A requires fwmark
   matching in the nft chain *plus* the existing kill-switch logic to
   skip-or-include marked packets — easy to get wrong.
3. **Discoverability mirrors existing UX.** "Bypass Networks" in the
   Security tab reuses the `Allow LAN` pattern (CIDR list, allow-list
   semantics). Option A introduces a new top-level concept (apps with
   bypass status) that needs its own dialog and the user must understand
   both per-app and per-destination thinking.

Tradeoffs accepted: Option B cannot answer "always send Spotify outside
the VPN" — only "always send 35.186.224.0/20 outside the VPN", which
covers Spotify CDNs but won't follow them if they migrate. For v1, the
target user (technical, CIDR-comfortable) is fine with this.

## Sprint-22-readiness verdict

**Conditionally direct-schedulable.** Two open questions need a small
proof-of-concept before estimating:

1. **`ip rule` priority interplay with OpenVPN3's installed default
   route.** OpenVPN3 installs its tunnel default route at a known
   priority via the netcfg service. The bypass rule must sit at a
   priority that wins for matching destinations but does not override
   the catch-all. Verifiable in a 10-minute manual test: bring up a
   tunnel, `ip rule add to 8.8.8.8/32 lookup bypass priority 100`, ping
   8.8.8.8, observe interface via `mtr`.
2. **Pre-VPN gateway/iface capture.** The helper needs to snapshot the
   pre-VPN default route at the moment of tunnel-up so its bypass table
   has a usable nexthop. The kill-switch already needs this information
   (LAN range detection) — confirm the existing capture path is
   sufficient or extend it once.

If the PoC confirms (1) and (2), Sprint 22 can include the full
implementation: helper API expansion, Preferences UI section, nft
allow-list integration, persistence in GSettings. Estimated 2–3 sprint
slots — comparable to the original kill-switch implementation
(Sprints 16–17).

If (1) reveals priority conflicts, Sprint 22 schedules a second spike
with a kernel-side workaround (e.g. fwmark-based instead of
destination-based rule) before any user-facing work.

# Sprint 22 / T4 — Interaction Assessment with Existing Kill-Switch

Read-only deliverable. Extends the Option B recommendation (above) with the
contract for how split-tunneling and the already-shipped kill-switch coexist.
Gates Sprint 22 / T5 (PoCs).

## D1 — Security model: full exemption (model b)

Bypass CIDRs are exempt from both tunnel routing AND kill-switch firewall.
The nft chain grows an explicit `daddr @bypass_set accept` before the
catch-all drop. Bypass entries continue to flow even when the VPN drops.

**Rationale:**
- Consistency with existing `kill-switch-allow-lan` which is already full
  exemption (LAN ranges allowed even with VPN down).
- Matches the dominant use case: LAN printer / NAS / dev server should keep
  working regardless of VPN state.
- Single source of truth (`@bypass_set`) — both routing and firewall
  reference the same CIDR list. Model (a) would split that into two layers
  with different semantics, creating drift surface.

**Risks accepted:** weakens kill-switch promise. Mitigated by:
- Helper-side rejection of CIDRs that would shadow kill-switch entirely:
  prefix length 0 (`0.0.0.0/0`, `::/0`), loopback (`127.0.0.0/8`, `::1/128`).
- GUI-side warning text on Add CIDR dialog: *"Bypass networks are always
  allowed, even when the VPN is disconnected."*
- GUI-side warn (not block) for very broad CIDRs outside RFC1918.

## D2 — Routing precedence: `ip rule` priority 100

OpenVPN3's netcfg writes only to the `main` routing table (priority 32766);
priority space `1..32765` is ours. Sprint 21 spike picked `100`; T4 confirms
via priority-space analysis. Range **100–101** reserved for split-tunnel
(one for v4, one for v6). Helper enforces — won't write outside this range.

**PoC 1 must verify five failure modes:**

1. **Tunnel route wins anyway.** OpenVPN3's `0.0.0.0/1` + `128.0.0.0/1` are
   more specific than `0.0.0.0/0`, but our `ip rule` triggers a table lookup
   before `main` is consulted. **Signal:** `mtr <bypass-CIDR>` shows tun0.
2. **`bypass` routing table not registered.** Helper must create
   `/etc/iproute2/rt_tables.d/openvpn3-bypass.conf` idempotently before
   adding routes. **Signal:** `ip rule list` shows rule but
   `ip route show table bypass` is empty.
3. **Reverse-path filter (rp_filter).** *Most likely silent killer on Linux
   split-tunneling.* Default `rp_filter=1` (strict) drops bypass replies
   whose return path differs from arrival interface. Helper sets
   `rp_filter=2` (loose) on physical bypass iface during apply, captures
   original value, restores on remove. **Signal:** `nstat | grep -i martian`
   rises; outbound visible in `mtr` but no reply.
4. **Conntrack stale entries.** New rule applies to new flows only —
   existing tun0-flows persist. Helper invokes `conntrack -D -d <cidr>`
   after rule add. **Signal:** existing flows tun0, new flows physical.
5. **Pre-VPN gateway becomes stale.** Roaming Wi-Fi invalidates captured
   gateway. Out of scope for PoC 1; handled in D5.

**PoC 1 pass criteria** (with kill-switch ON, bypass CIDR `8.8.8.8/32`):
- `mtr 8.8.8.8` shows physical interface, no tun0
- `mtr 1.1.1.1` (non-bypass) shows tun0
- After `ip link set tun0 down`: `ping 8.8.8.8` still works (model-b proof)
- No martian counter increase

## D3 — nft bypass set: replace-all API, fail-closed transitions

**Family:** `inet openvpn3_killswitch` (existing kill-switch table). New sets
`bypass_set` (ipv4) and `bypass_set_v6` (ipv6) added, both with `flags
interval` for CIDR matching. Chain gains `ip daddr @bypass_set accept` and
the v6 equivalent, both before the catch-all drop.

**Helper API:**
```
SetBypassCidrs(cidrs: Vec<String>) -> ()
ClearBypassCidrs() -> ()
```
Replace-all, not delta. Single source of truth = GUI's GSettings list;
helper is a stateless transformer.

**Sync ordering** (both surfaces — routes + firewall — fail-closed during
transition):

| Op | Order | Transient state |
|---|---|---|
| Apply | (1) routes/rules → (2) `nft add element` | routed but firewall-blocked → no traffic |
| Remove | (1) `nft flush set` → (2) routes torn down | routed but firewall-blocked → no traffic |

**Atomicity:** nft batch is single-transaction. `ip` ops are individually
atomic; helper rolls back partial route installs on failure before touching
nft. Re-applying the same list is observable no-op (idempotent by design —
flush-and-rewrite, not delta).

**Drift prevention:** scoped to priority 100–101 + `bypass` table only.
External admin rules at other priorities untouched.

## D4 — Lifecycle ordering: 7 entry points, independent layers

**Coupling decision:** bypass routing layer (ip rule + ip route) is gated on
*tunnel up + bypass list non-empty*. Bypass firewall layer (nft `@bypass_set`)
is gated on *that AND kill-switch on*. Independent layers, two apply paths.

Rejected alternative: tight coupling (bypass exists only when KS on). Loses
the "I want split-tunnel for routing reasons but not kill-switch firewall"
use case. Cost of independence is one extra apply path; benefit is no
surprising side-effects when KS toggles.

**Lifecycle entry points:**

| # | Site | Bypass action |
|---|---|---|
| 1 | `dbus_init.rs` cold-start | Apply KS (if on) + apply bypass (if list non-empty) |
| 2 | `killswitch_glue::on_connected` | Same as #1 |
| 3 | `killswitch_glue::on_paused` | Bypass follows `kill-switch-block-during-pause` (D5) |
| 4 | `signal_handlers.rs` user disconnect | Tear down bypass + tear down KS table |
| 5 | `notification/mod.rs` Dismiss reconnect | Same as #4 |
| 6 | `preferences/mod.rs` KS ON/OFF toggle | KS→ON: re-apply KS + re-add bypass set. KS→OFF: remove KS table; bypass routes persist. |
| 7 | `preferences/mod.rs` Bypass list Save (**new**) | `SetBypassCidrs(new_list)` — full replace |

**State transitions** (KS × bypass — 4 cells, all defined):

|  | bypass empty | bypass active |
|---|---|---|
| KS off | tunnel routes everything | bypass via physical; tunnel routes rest; no firewall |
| KS on | KS firewall, tunnel routes everything | KS firewall + bypass routes + `@bypass_set` exemption |

**No `bypass-during-pause` setting** in v1. Bypass-without-KS during pause
is incoherent (KS defines the firewall context that makes bypass-exemption
meaningful). Revisit S23+ only if user demand emerges.

## D5 — Pause/Resume: re-capture gateway on every Resume

Bypass inherits kill-switch's `kill-switch-block-during-pause` setting:
- `true` → routes + nft set retained across pause; gateway re-captured on
  Resume and routes replaced if changed (idempotent per D3).
- `false` → both removed at Pause edge; full re-apply on Resume with fresh
  gateway capture.

**Stale-gateway hazard** (the keystone D5 issue): captured pre-VPN gateway
can go stale across a pause via Wi-Fi roam or DHCP lease renewal. Failure
mode is silent — packets dispatched to unreachable gateway, no log signal.

**Mitigation:** every Resume invokes `SetBypassCidrs(current_list)`. Helper
re-runs gateway capture, compares to stored value, replaces routes if
changed. Cost: one `ip route show 0.0.0.0/0` per Resume (negligible).
Implementation site: rising-edge-of-Connected handler in
`status_handler/mod.rs` (same site that resets stats baseline).

**Conntrack flush** belongs on every apply path (initial Connect AND
Resume), not just initial Connect.

**Notifications across pause** piggyback on existing `__killswitch_state__`
dedup key. Single notification covers both states; text adapts:

| State | Text |
|---|---|
| KS on, bypass empty | 🔒 Kill-switch active |
| KS on, bypass non-empty | 🔒 Kill-switch active — N CIDRs bypassing VPN |
| KS off, bypass non-empty | 🔀 Split-tunnel active — N CIDRs bypassing VPN |
| KS off, bypass empty | (no notification) |

**Cold-start on Paused session:** no-op for both KS and bypass. User must
Resume to trigger apply. Matches existing KS behaviour.

## D6 — UI/UX: Security tab grows "Bypass Networks" list

**Layout choice:** Option 2 — two separately-labelled controls in the
existing Security tab. Allow LAN stays as boolean checkbox; Bypass Networks
is a new editable list below it. Rejected: unified list with type column
(would require refactoring Allow LAN into per-CIDR list — scope creep) and
nested sub-tab (over-engineering for v1).

**Security tab structure:**

```
[✓] Enable kill-switch
    [✓] Allow LAN traffic
    [ ] Block during pause
    [✓] Warn on unexpected disconnect (forced)

    Bypass Networks ─────────────────────────
    CIDRs always allowed, even when VPN drops
    ┌─────────────────────────────────────┐
    │ 192.168.1.0/24    home LAN          │
    │ 10.0.0.0/8        office VPN range  │
    │ 35.186.224.0/20   Spotify CDN       │
    └─────────────────────────────────────┘
    [Add CIDR…] [Remove Selected]
```

**Add CIDR modal:** CIDR field + optional comment + warning text. Inline
validation rejects malformed input, `0.0.0.0/0`, `::/0`, and loopback;
warns on broad CIDRs outside RFC1918.

**Tray menu:** existing kill-switch state row (Sprint 20/T4) extends text
when bypass list non-empty:
- `🔒 Kill-switch: On (3 bypasses)` (KS on + bypass active)
- `🔓 Kill-switch: Off (3 bypasses)` (KS off + bypass active — see open
  cell #2 below)

No per-session bypass indicator (bypass is global, not per-session). No
status-dialog or tray-icon changes for v1.

## State × Behaviour matrix (CLAUDE.md closing requirement)

| Surface | bypass empty | bypass active | both-on (KS+bypass) | split-tunnel-only (KS off + bypass) |
|---|---|---|---|---|
| Tray icon | unchanged | unchanged | unchanged | unchanged |
| Tray KS row | 🔒 / 🔓 with KS state | matches `bypass empty` | 🔒 KS: On (N bypasses) | 🔓 KS: Off (N bypasses) — **open cell #2** |
| Per-session label | `Status` + 🔒 if KS applied | matches `bypass empty` | `Status` + 🔒 (no per-session bypass mark) | `Status` (no 🔒, no bypass mark) |
| Status dialog | byte counts, idle | matches `bypass empty` — **open cell #3** | matches `bypass empty` | matches `bypass empty` |
| Notify on Connect | 🔒 KS active (if KS on) | matches `bypass empty` | 🔒 KS active — N CIDRs | 🔀 Split-tunnel active — N CIDRs — **open cell #1** |
| Notify on Disconnect | 🔓 KS inactive (if KS was on) | matches `bypass empty` | 🔓 KS inactive | "Split-tunnel inactive" — **open cell #1** |
| Preferences | empty Bypass list + [Add CIDR] | N rows shown | N rows + KS on | N rows + KS off |

## Sprint 23 candidate sub-tasks (open matrix cells)

1. **Split-tunnel-only notification path.** Separate `__bypass_state__` (or
   unified `__network_overlay_state__`) dedup key for the KS-off+bypass-on
   case. Both apply ("🔀 Split-tunnel active") and remove ("Split-tunnel
   inactive") notifications.
2. **Tray row text for KS off + bypass on.** "🔓 Kill-switch: Off (3
   bypasses)" mixes two concepts. Choose: second row "🔀 Split-tunnel: 3
   CIDRs", or rephrase. Decide during S23 layout review.
3. **Status dialog bypass visibility (optional, deferrable).** "Routes
   bypassing VPN: 3 CIDRs" line. Low priority — Preferences is canonical.

## Helper-side validation (consolidated)

Reject in helper (privilege boundary):
- Malformed CIDR (parse failure)
- Prefix length 0 (`0.0.0.0/0`, `::/0`)
- Loopback ranges (`127.0.0.0/8`, `::1/128`)
- CIDRs outside priority-100–101 / `bypass`-table scope (helper writes only
  in its reserved range)

GUI-side validation mirrors helper; helper rejection is defence in depth.

## T5 carry-forward

`scripts/poc-split-tunnel.sh` must be amended before T5 runs:
- Test with kill-switch ON (current script tests routing in isolation).
- Verify all five D2 failure modes (tunnel-route override, table
  registration, rp_filter, conntrack, stale gateway).
- Verify model-b semantics: bypass CIDR remains reachable after tunnel
  forced down.

# Sprint 22 / T5 — PoC Validation Results

803-line validation suite (`scripts/poc-split-tunnel.sh`). Tested on two
networks: iPhone Personal Hotspot and home WiFi. VPN via openvpn3-gui-rs
with `redirect-gateway def1`.

## Routing layer — VALIDATED

Core T4/D2 claim confirmed on both networks:

```
$ ip route get 8.8.8.8          # bypass dest → exits via LAN
8.8.8.8 via 172.20.10.1 dev wlp0s20f3 table 100

$ ip route get 1.1.1.1          # control dest → exits via tunnel
1.1.1.1 via 10.40.241.129 dev tun0
```

Priority 100 wins over OpenVPN3's `0.0.0.0/1` + `128.0.0.0/1` (main
table, priority 32766). `ip rule` table lookup fires before main table
consultation, exactly as designed.

## check_rp_filter — PASS

```
rp_filter — loose (all=0, wlp0s20f3=2). Bypass-compatible.
```

Effective value = MAX(all=0, iface=2) = 2 (loose). Asymmetric routing
works. T4/D2 prediction validated: strict mode (1) would silently drop
bypass replies.

## check_conntrack — NOT FIELD-TESTED (SKIP)

Both test networks blocked outbound to 8.8.8.8 (ICMP + TCP/443). Script
correctly SKIPs with diagnostic message instead of false-FAIL. Conntrack
flow-trigger path exercised in code review (TCP/443 primary, ICMP
fallback) but not under live traffic. **Sprint 23 action:** re-run on a
network where bypass dest is reachable, or accept as unvalidated
(KS-conntrack-flush-on-apply covers the production case).

## check_mtu_pmtud — NOT FIELD-TESTED (SKIP)

Same root cause as conntrack. MTU probes require working flow. Sprint 23
production helper should still install TCP MSS clamping on bypass path as
defence in depth, regardless of PoC validation.

## check_dns — NOT CONCLUSIVE

On iPhone hotspot: `dig @8.8.8.8` failed (unreachable). On home WiFi
with `BYPASS_DEST=1.1.1.1/32`: DNS resolver still defaulted to 8.8.8.8
(not overridden), producing a false "leak" verdict. Script should derive
`TEST_DNS_RESOLVER` from `BYPASS_DEST` by default — recorded as known
bug for next edit pass. Routing-layer DNS query path is correct (same
`ip rule` governs all traffic to bypass dest, including port 53).

## check_ipv6 — REAL FINDING

**iPhone hotspot (v6 enabled with default route):**
```
FAIL: ipv6 — v6 traffic to 2001:4860:4860::8888 exits via wlp0s20f3
      (NOT a tunnel iface). v6 leak — kill-switch v6 firewall needed.
```

**Home WiFi (v6 enabled but no default route):**
```
NOTE: ipv6 — enabled but no v6 default route. No v6 leak surface.
```

`redirect-gateway def1` is v4-only. When v6 connectivity exists (hotspot),
bypassed hosts leak via LAN regardless of our v4 `ip rule`. **Validates
T4/D2 failure mode #5 in strongest possible way.** Sprint 23 production
code must install symmetric v6 rules (`ip -6 rule add ...`) or keep
kill-switch v6 firewall active.

## Script robustness fixes applied during T5

1. **VPN detection heuristic.** Original script used `ip route show default`
   — wrong with `redirect-gateway def1` (default route stays on LAN iface).
   Replaced with `ip route get 1.1.1.1` checking for tunnel iface.

2. **ip rule show /32 stripping.** `ip rule show` omits `/32` from v4 host
   CIDRs, so regex matching by CIDR string silently failed, leaving stale
   rules in place → `RTNETLINK answers: File exists` on re-install. Fixed
   by matching on lookup table number instead.

3. **Stale-capture detection.** `require_capture_fresh()` gates `cmd_test`
   and `cmd_test_priority_sweep` — checks that captured gateway is still
   on the captured iface's subnet. Prevents cryptic "Nexthop has invalid
   gateway" when user switches networks between capture and test.

4. **Unreachable-dest handling.** `probe_bypass_reachable()` (ICMP + TCP/443
   fallback) gates flow-dependent checks to SKIP instead of printing
   misleading FAIL + bogus remediation. Tested on both networks — correct
   SKIP behaviour confirmed.

## Sprint 23 readiness verdict

**Proceed to implementation.** Core routing claim validated. Two checks
(conntrack, MTU) not field-tested due to environmental reachability —
neither blocks implementation; both are defensive measures that production
code should include regardless. IPv6 leak finding adds one concrete
requirement to S23 scope: symmetric v6 rules or persistent v6 firewall.

# Sprint 27 / T3 — DNS-leak behaviour on bypass CIDRs

Read-only investigation. Closes the `check_dns — NOT CONCLUSIVE` follow-up
from S22 T5 PoC (lines 451-458 above) and the S26 backlog DNS-leak item.

## Scope

What happens to DNS queries for hosts whose **resolved IP** lands inside a
configured bypass CIDR? The connection itself follows the documented
bypass path (priority-100 `ip rule` → `openvpn3-bypass` table → LAN
gateway). The question is what path the *name resolution* takes before
the connection is established.

## Code-path analysis (no live measurement needed)

`grep -ri "dns\|resolv\|nameserver\|udp.*53" helper/src/` returns zero
matches outside the one comment in `bypass.rs:36`. The helper installs
**only** `ip rule` + `ip route` + `nft` rules. No code touches
`/etc/resolv.conf`, systemd-resolved, NetworkManager, or any per-link DNS
configuration. The bypass mechanism is **destination-IP-based**, full
stop.

DNS resolution on a typical Linux desktop with OpenVPN3 follows:

1. App calls `getaddrinfo("bypass-host.example")`.
2. glibc reads `/etc/resolv.conf` → typically `nameserver 127.0.0.53`
   (systemd-resolved stub).
3. systemd-resolved picks an upstream per-link:
   - **Tunnel link** (`tun0`): DNS servers pushed by VPN via
     `dhcp-option DNS`, configured into resolved by `openvpn3-service-netcfg`.
   - **Physical link** (`wlp0s20f3`, `enp0s31f6`): DNS from DHCP / NM.
4. The query exits via whichever link resolved chose. **Our `ip rule`
   does not see it** — the query goes to `127.0.0.53`, which is `lo`,
   not a bypass CIDR.
5. systemd-resolved's outbound query to the chosen upstream DNS goes
   via that upstream's link route. If upstream is the VPN-pushed DNS
   (e.g. `10.8.0.1`), the query exits via `tun0`. If upstream is
   DHCP-pushed (`1.1.1.1`), the query exits via the LAN iface.
6. Once the IP comes back, the app connects to `192.0.2.50` → **then**
   our priority-100 `ip rule` catches the destination and routes via LAN.

## Failure modes

**Failure mode 1 — VPN-side DNS leak (most common configuration).**
When the VPN profile uses `push "dhcp-option DNS"` (typical for
corporate / commercial VPNs), the VPN provider's DNS resolver sees
every `bypass-host.example` lookup. Connection traffic correctly
bypasses, but **DNS metadata leaks to the VPN provider** — the
provider can enumerate which bypass hosts the user resolves, even
though it sees zero TCP/UDP traffic to them.

**Failure mode 2 — ISP-side DNS leak (no VPN DNS push).**
If the VPN profile does *not* push DNS, queries use the physical
link's DNS (DHCP-provided, typically ISP or 1.1.1.1/8.8.8.8). This
matches the no-VPN baseline for bypassed hosts. Acceptable for users
whose threat model is "hide bypass traffic from VPN provider" but
not for users whose threat model is "hide DNS from ISP".

**Failure mode 3 — Correct path (rare).**
Only if the user manually configures `nameserver` in `/etc/resolv.conf`
to a private IP inside a bypass CIDR (e.g. `nameserver 10.0.0.1`
where `10.0.0.0/8` is in `bypass-cidrs`) does the DNS query itself
get caught by our `ip rule` and routed via LAN. This is not the
default for any common setup.

## Verdict

**Matches partial expectation, gap documented.** The current
implementation is consistent with the design intent stated at line 78
("CIDRs only — DNS-resolved entries out of scope") and with the
Option B trade-off table line 104 (per-destination granularity, not
per-process or per-domain). DNS leakage is a known limitation of
destination-IP-based split-tunneling.

What was not previously documented: users may reasonably assume that
bypassing `192.0.2.0/24` also hides their interest in those hosts
from the VPN provider. It does not. **README + Preferences Routing
tab tooltip should state this explicitly** so users with metadata
threat models know to expect it.

## Fix scope (deferred to backlog)

A genuine DNS fix requires one of:

- **Per-domain DNS routing via systemd-resolved.** Push a routing-only
  link with `Domains=~bypass-host.example` and `DNS=<LAN resolver>` to
  resolved. Requires us to know the *domains*, not just CIDRs — which
  was rejected at v1 (line 78). Would also need integration with
  `resolvectl` and a fallback when systemd-resolved isn't the active
  resolver.
- **Intercept localhost DNS queries.** Add an `ip rule` for
  `udp dport 53` to the bypass table. Catches queries to public
  resolvers (`1.1.1.1`, `8.8.8.8`) but not to systemd-resolved on
  `127.0.0.53` (that's `lo`, not routable). Half-measure at best.
- **Run a DNS proxy in the bypass network namespace.** Heavy. Out of
  scope for a system-tray indicator.

**Recommendation:** defer the fix. Land the documentation update
(README + tooltip) in **T7 (sprint-end hygiene)**, not T5 (drift
detection) — DNS leakage is orthogonal to nft set drift. Real fix
goes to backlog gated on user demand (no concrete user report yet).

## Backlog entry

- **DNS-leak fix for bypass CIDRs** — destination-IP-based split-tunnel
  does not cover the resolver query path. Three implementation options
  documented above; each carries non-trivial design cost. Trigger: real
  user report of metadata exposure concern, or expansion of
  split-tunneling to per-domain entries (which would force a DNS
  solution anyway).
