# Split-Tunneling Design Spike

Sprint 21 / T4 — read-only spike, deliverable is this document.

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
