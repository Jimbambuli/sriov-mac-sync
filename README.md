# sriov-mac-sync

Make hosts that sit *behind* a Linux bridge reachable from an SR-IOV virtual
function.

## Is this your problem?

- A guest with a VF reaches everything on the physical switch, but not a
  container, a second VM, or a device on another NIC in the same host.
- Ping to those peers times out. Nothing is logged, nothing is firewalled.
- ARP or ND for the very same address resolves fine — which is what makes it
  look like an MTU or filtering problem. It is neither.
- `tcpdump` on the uplink shows the frame leaving on the wire, addressed to
  something that is not out there.

That is the NIC's internal switch — a VEB — missing on an address it was never
told about, and doing what a miss does: sending the frame out of the physical
port. The fix is to put the address in the uplink's unicast filter. Keeping
that filter in step with everything the bridge learns, as it changes, is what
this daemon does.

Confirmed end to end on this hardware; the daemon itself is driver-agnostic:

| NIC | driver |
|---|---|
| Mellanox ConnectX-4 Lx | `mlx5_core` |
| Mellanox ConnectX-3 Pro | `mlx4_core` |
| Intel 82599ES | `ixgbe` |
| Intel X710 | `i40e` |

None of these can present a VF as a real bridge port, which is the proper
answer where the hardware has it. See [What this is not](#what-this-is-not).

## Why it happens

A NIC with SR-IOV has an internal switch whose forwarding table holds exactly
one thing: the MAC addresses of its own vports, the PF and the VFs. A frame
from a VF to anything else misses that table, and the miss action is *send it
out on the wire*. That is right as long as every peer really is out there.

It stops being right the moment the uplink is a bridge port and the bridge
carries other things too. Those peers are *behind* the uplink, not beyond it.
Broadcast and multicast are flooded to every vport, so ARP and ND still work —
which is exactly why the failure is so confusing: address resolution succeeds
and the unicast that follows disappears.

```
        ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐
guests  │   guest   │  │   guest   │  │    VM     │  │ container │
        └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
              │ VF1          │ VF2          │ tap          │ veth
              │              │   ┌──────────┴──────────────┴───────┐
bridge        │              │   │               br0               │
              │              │   └────┬───────────────────────┬────┘
              │              │        │ PF                    │ eth1
         ┌────┴──────────────┴────────┴────┐             ┌────┴────┐
NICs     │              NIC 1              │             │  NIC 2  │
         └────────────────────────────┬────┘             └────┬────┘
                                      │                       │
wires                              wire A                  wire B
```

`VF1` and `VF2` go straight to their guests, past `br0`. `PF` *is* a port of
the bridge. NIC 1 knows only the three interfaces hanging off it — everything
in the box above is invisible to it.

From `VF1`, peers on wire A, the other VF, and anything broadcast are fine.
These are lost:

| Destination | Why |
|---|---|
| **tap** — a VM on the bridge | it sits behind the PF; the frame goes past it onto the wire |
| **veth** — a container on the bridge | same |
| the **host**, when `br0` carries an address of its own | the switch has never heard of it |
| a peer on **wire B**, behind a second NIC | reaching it means going *through* the bridge, not past it |

The last one may appear to work if both wires are the same physical segment —
by luck, and it stops the moment they differ or that switch is powered down.
The opposite direction never breaks: a VF address *is* a vport address.

Registering an address turns every one of those into a hit: the switch hands
the frame to the PF and the bridge takes over. Both VFs are served by the same
list — one per uplink, not one per guest.

## The fix

An address can be pushed into a port's unicast filter, which iproute2 spells

```
bridge fdb add <mac> dev <uplink> self permanent
```

(`RTM_NEWNEIGH` over `AF_BRIDGE` with `NTF_SELF`). The driver mirrors that list
into the NIC's vport context. That works for addresses you know in advance —
guests are knowable, wireless clients coming and going are not. This daemon
closes the gap: it watches what the bridges learn and keeps the list in step.

## Install

Everything below is statically linked and depends on nothing — no runtime, no
libc, no configuration.

**Debian, Ubuntu, Proxmox VE.** Installs the binary, a systemd unit and a
commented `/etc/sriov-mac-sync.conf`, then enables and starts the service.
Removing the package takes its entries back out of the card.

```
curl -LO https://github.com/Jimbambuli/sriov-mac-sync/releases/latest/download/sriov-mac-sync_amd64.deb
dpkg -i sriov-mac-sync_amd64.deb
```

**OpenWrt**, with a procd service instead. 24.10 replaced opkg with apk, and
that apk reads only its own v3 format, so there is one package per era:

```
# 24.10 and newer
curl -LO https://github.com/Jimbambuli/sriov-mac-sync/releases/latest/download/sriov-mac-sync_x86_64.apk
apk add --allow-untrusted --force-non-repository ./sriov-mac-sync_x86_64.apk

# 23.05 and older
curl -LO https://github.com/Jimbambuli/sriov-mac-sync/releases/latest/download/sriov-mac-sync_x86_64.ipk
opkg install ./sriov-mac-sync_x86_64.ipk
```

Both `apk` flags are the price of a package outside a repository: unsigned, and
one apk could not reinstall by itself after a reboot.

**Anything else** — the bare binary, `x86_64` or `aarch64`:

```
curl -LO https://github.com/Jimbambuli/sriov-mac-sync/releases/latest/download/sriov-mac-sync-$(uname -m)
install -m 755 sriov-mac-sync-$(uname -m) /usr/local/sbin/sriov-mac-sync
```

No file name carries a version — they are fetched through
`/releases/latest/download/`, so these commands do not go stale. Which version
you got is inside the package, where `dpkg -I`, `apk info` and `opkg info` will
tell you. `cargo install sriov-mac-sync` works too.

**From source:**

```
cargo build --release
install -m 755 target/release/sriov-mac-sync    /usr/local/sbin/
install -m 644 dist/sriov-mac-sync.service      /etc/systemd/system/
install -m 644 dist/sriov-mac-sync.conf.example /etc/sriov-mac-sync.conf  # optional
systemctl enable --now sriov-mac-sync
```

One dependency, `libc`. For everything a release ships — static binaries,
`.deb`, `.ipk`, both architectures — `rustup target add
x86_64-unknown-linux-musl aarch64-unknown-linux-musl && ./dist/package.sh`
leaves it in `dist/out`. Nothing is cross-compiled against a sysroot; the musl
targets link with `rust-lld`. There is no 32-bit ARM build, and that is not an
oversight: SR-IOV needs a PCIe root complex that implements it, which no armv7
machine pairs with. The Debian packages install `sriov-mac-sync(8)`; from a
checkout, `man ./dist/sriov-mac-sync.8`.

## Use

Before installing anything, or on a host you would rather look at first:

```
sriov-mac-sync --check              does this NIC accept filter entries at all?
                                    (it writes a probe entry and takes it back)
sriov-mac-sync --once --dry-run     what would be registered, and why
sriov-mac-sync --status             what is detected, wanted and registered
```

If `--check` passes and `--dry-run` names the addresses you expected, install
the unit and let it run. `--check` only proves the *kernel* took the entry;
whether the card acts on it is [a question for
traffic](#verify-it-actually-works).

```
sriov-mac-sync --once               reconcile and exit; the exit code says
                                    whether every change went through
sriov-mac-sync --flush              remove what this daemon registered
sriov-mac-sync --timings            after every pass, what each phase cost
sriov-mac-sync --interval SEC       seconds between timed passes (default 300)
sriov-mac-sync --max NUM            warn above this many addresses (default 128)
sriov-mac-sync -v ...               explain what is skipped, and list addresses
```

`--extra <macs>` registers addresses unconditionally, for a device that never
speaks first; the exclusion rules still override it, with a warning when they
do. `--exclude <macs>` is its opposite.

Pairs are found automatically: any interface with VFs — or itself a VF — that
ends up in a bridge. Override with `--pair DEV:BRIDGE`, repeatable.
`/etc/sriov-mac-sync.conf` may set `PAIRS`, `RESYNC`, `MAX_MACS`, `EXCLUDE` and
`EXTRA`; numbers from the command line override the file, lists add up. Naming
pairs by hand also stops the daemon concluding that a note belongs to no
uplink — only autodetection sees every uplink, so only autodetection may draw
that conclusion.

## What gets registered

Only what is reachable *behind* the bridge:

* everything the bridge learnt on ports other than the uplink,
* everything learnt by bridges stacked on top of it — VLAN-aware setups,
  Proxmox SDN vnets. This matters more than it looks: a container's address is
  often never learnt by the lower bridge at all, because its traffic enters
  from the bridge's own local port and a bridge does not learn from itself,
* the host's own L3 endpoints on that bridge.

Deliberately **not** registered: anything learnt on the uplink itself. Those
peers live on the wire, and registering them would divert their traffic to the
bridge, which cannot send it back out of the port it came in on.

Nothing is decided by interface name — guessing from naming conventions is how
a tool like this breaks on someone else's machine. The direction of the uplink
comes from the device stacking the kernel reports.

Each bridge and each uplink is handled on its own. **Several SR-IOV NICs in one
bridge** get one list each; an address on one uplink's wire is behind the
bridge as far as the other is concerned. **Several VFs per NIC** need nothing
extra. **Bonds are followed**, and the whole bond counts as the wire side.
**The uplink need not be a PF** — a VF can carry the bridge just as well; turn
spoof checking off for it and release its link state from the PF's. There is a
good reason to prefer this, under *when the wire goes dark* below.

## Verify it actually works

Whether the NIC acts on an accepted address is a property of the driver and
there is no way to ask. Test with traffic:

1. From inside the VF's guest, ping something behind the bridge. It should fail.
2. `bridge fdb add <that mac> dev <uplink> self permanent`
3. Ping again. It should work.
4. `bridge fdb del ...` — it should fail again.

If step 3 changes nothing, this approach does not work on your hardware and
this daemon will not help you. Reports for hardware beyond the four cards above
are welcome; those four steps are the whole test.

## Putting it on trial

`bench/trial.py` (root, opt-in) provokes the situations the running daemon
exists for, verifies each came out right, and reports what it cost:

```
python3 bench/trial.py vmbr1 --vlan 22
```

Eight scenarios: addresses learnt one at a time, in close succession, and as a
burst of sixteen; a hundred cold `--once` passes with the CPU governor logged;
an address of ours turning up on the uplink's own port (a guest that moved
host — the registration has to come back out); a VF's own address learnt
behind the bridge (it must never be registered); the port's removal; and a
closing quiescence check — journal quiet, no `[timed]` pass that had to fix
anything, no residue. A failed verification fails the exit code.

It refuses to start unless everything holds: service active and not in
`--dry-run`, the bridge actually watched, STP off, the VLAN named on a
VLAN-aware bridge, no leftovers, and enough headroom in every filter — the
list drops addresses silently past its capacity, and a benchmark must not be
what pushes a real guest out.

Two boundaries, so the numbers are read for what they are: latencies end at
the kernel's forwarding-database notification, and absolute times swing with
CPU frequency scaling — compare two software states only by interleaving their
trials.

If a failed run leaves test entries behind (prefix `02:be:5c`), remove them
with `bridge fdb del <mac> dev <uplink> self permanent` and leave the note
files alone; the daemon heals its notes through the ENOENT path on the next
pass. How a pass scales with the forwarding table is `cargo test --release
scaling -- --ignored --nocapture` (measured: 40x the entries cost 28x the
time).

## Limits and things worth knowing

**The first registration after a topology change can wait on the host's own
tooling.** Writing a filter entry takes the kernel's rtnl lock, and so does
everything else that manages interfaces. On a Proxmox node a link change
prompts `ifquery`, and a plain fdb add has been measured waiting up to two
seconds behind it. The daemon cannot dodge this: the write is sent instantly
and sits in the kernel until rtnl frees up. In steady state, registrations run
in well under a millisecond.

**A guest that moves hosts is followed within the batch that says so.** When a
VM migrates away the bridge starts learning its address on the uplink's own
port. An address of ours seen there is unregistered immediately, before
anything else in the batch is registered. A deletion on its own is not acted
on: a VLAN-aware bridge learns one address once per VLAN while the filter holds
a single entry for all of them, so only the full dump that follows can tell
that the last one has gone.

**Stopping the daemon leaves the filter as it is.** Nothing is unregistered and
the notes in `/run` stay, which is what makes restarting it — for an update,
say — invisible to every guest. It says on the way out how many addresses it
left. `--flush` is how you ask for the card to be cleared.

**Under a stream of learning, the cost depends on whose it is.** A batch that
leaves nothing to reconcile is answered and dropped without scheduling a pass,
because a pass dumps the host's whole forwarding table. On a namespace of 406
interfaces learning 4000 addresses over 20 s: 0.06 s of CPU when all of it is
wire-side, 3.1 s when every address is a guest that has to be registered. A
host of this project's kind learns a few an hour.

**A VF's address has to be knowable, or it cannot be excluded.** Registering
the address of a VF of the uplink's own PF is the one thing that must never
happen. The daemon recognises such an address two ways: set from the host with
`ip link set <pf> vf N mac ...`, or a netdev for that function still bound
here. A function handed straight to a guest with neither is in no exclusion
set, and the protection then rests entirely on the rule that nothing learnt on
the uplink's own port is registered; the daemon says so once per uplink when it
finds one. Setting the address from the host closes it, and so does `EXCLUDE`.

What actually happens if it is registered was measured, and it differs by
driver: on `i40e` the eSwitch delivers every frame to *both* claimants, so the
guest keeps working while the host receives a copy of its traffic and the
bridge learns the guest's address on the uplink. On `ixgbe` the uplink wins
outright and the guest receives **nothing**. Neither driver refuses the entry
or warns. Order makes no difference, and withdrawing the registration restores
the VF immediately.

**The list is finite and its size cannot be queried.** On ConnectX-4 Lx it
holds 128 entries. Beyond that the driver drops addresses silently, and *which*
is not predictable — with 257 entries a given address still worked, with 513 it
did not. `MAX_MACS` only decides when you get a warning.

**There is a race, and it is small.** An address is registered when the bridge
learns it, as the device's own first frame passes through, before anything can
answer it. What remains is the daemon's reaction time, and retransmission
covers the rest.

**Idle devices fall out and come back by themselves.** Bridge FDB entries age
out — 300 s by default — and the registration goes with them. Harmless: the
next attempt starts with an ARP or ND, which is broadcast, and the reply
repopulates both.

**The filter list knows nothing about VLANs.** There is no room for one; adding
`vlan 22` is refused with `Invalid argument`. One entry covers a MAC in every
VLAN, which is usually what you want. The corollary is that registering is
all-or-nothing: an address the bridge has learnt on the uplink in *any* VLAN is
left out entirely, because diverting working traffic is worse than leaving one
path unreachable. Assigning a VF to a VLAN is a separate matter and works
normally.

**This daemon only removes what it added.** It keeps a note in
`/run/sriov-mac-sync/`, written 0600 in a 0700 directory — a note another user
can write is a note that decides what a root daemon takes out of a card. The
note outlives the pair it was made for on purpose: when a device stops being an
uplink, what was registered for it is taken back out, or it would go on
steering addresses at a port that leads nowhere until the next reboot.

**A bridge port without a carrier does not forward.** Testing on a bench with
nothing plugged into the SR-IOV NIC fails for a reason unrelated to any of the
above: Linux puts a carrier-less port into the disabled state. A short cable
between two ports of the machine is enough — but not two ports of the *same
bridge*, which is a loop.

**When the wire goes dark, the PF stops talking to its own VFs.** Switch the
switch off and the PF loses carrier. The internal switch carries on forwarding
between VFs, but the path between PF and VF stops dead in both directions —
measured on a ConnectX-4 Lx with no bridge in the way. A bridge whose port is
the PF therefore goes down with the cable and takes the host with it.

Giving the bridge a VF of its own removes that coupling: VF-to-VF traffic does
not depend on the carrier (0.13 ms with the cable out, where PF-to-VF lost
every packet). One setting decides whether that works, because a VF follows its
PF's link state by default:

```
ip link set <pf> vf <n> state enable
```

Then the port stays forwarding with no cable in the machine — measured end to
end, a guest on one VF reached a container behind the bridge in 0.15 ms both
ways. The PF stays out of the bridge but still has to be `up`. Do not set this
on a VF carrying a WAN link, where a lost carrier is news the guest needs.

**Intel: the VF's link follows the PF's.** `ip link set <pf> vf N state enable`
is rejected outright by `ixgbe` (`not supported`), so a VF on a NIC without a
cable stays down. And once an address has been assigned to a VF from the PF
side, the guest may not change it (`Operation not permitted`) — assign it
before the VF driver binds, or rebind afterwards.

**ixgbe: registrations are slower than elsewhere.** On an 82599 the
registration lands on the VF, and `ixgbevf` answers every change to its unicast
list by re-sending the *whole* list to the PF through the VF/PF mailbox, one
polled transaction per address — so the cost of one registration grows with how
many are already in the filter. Measured on an 82599: about 0.5 ms for a single
address and 5–7 ms for a burst of sixteen, against tens of microseconds on
`mlx5` and `i40e`. Earlier versions of this daemon measured far more on the
same card — about 6 ms and 320 ms — but the difference has not been isolated to
a single change, so read it as the range this hardware has been seen in. In
steady state none of it matters.

**FreeBSD guests: turn off local loopback.** FreeBSD's `mlx5en` enables it by
default (`dev.mce.N.conf.uc_local_lb` and `mc_local_lb`). The guest's own
neighbour solicitations come back to it, FreeBSD spots the loop, restarts
duplicate address detection and never finishes — the address stays `tentative`
and IPv6 is dead. Set both to `0`. Nothing to do with this daemon, but you will
hit it in the same afternoon.

## Prior art

The mechanism is not new. A [Proxmox forum
thread](https://forum.proxmox.com/threads/communication-issue-between-sriov-vm-vf-and-ct-on-pf-bridge.68638/)
worked it out years ago, and
[jdlayman/pve-hookscript-sriov](https://github.com/jdlayman/pve-hookscript-sriov)
packages it as a Proxmox hookscript: on guest start it reads the MAC from the
PVE config, finds a bridge port with VFs, and registers it. If your guests are
the only thing you need to reach, that script is smaller than this and does the
job.

[yujincheng08/mlx4_br](https://github.com/yujincheng08/mlx4_br) is closer
still, and was found only after this was written: a C++ daemon on the same two
netlink groups, propagating learnt addresses into other bridge ports' filters,
following bonds, packaged for Debian and OpenWrt. Same problem, same mechanism.
It differs in recognising an uplink by driver name from a fixed list
(`mlx4_core`, `mlx5_core`, `iavf`, `ixgbevf`) — on Intel those are the *VF*
drivers, so a bridge whose port is an `ixgbe` or `i40e` PF matches nothing.
It propagates to every other port that learnt an address rather than working
out which one is the uplink, so a bridge stacked on a VLAN interface — what
Proxmox SDN vnets produce — never reaches the filter that needs it. And it
keeps no record of what it registered, so after a restart its entries are
indistinguishable from anyone else's, with no `--dry-run`, `--check`,
`--status` or `--flush`.

Two things led to this being written instead. **Only configured guests are
covered** by a hookscript: it cannot know about the wireless client that just
associated, the printer on the second NIC, or the host's own address — those
are learnt, not configured, and they are the majority on a real segment. And
**a stacked bridge hides the uplink**: working it out structurally, through
`master` chains and `lower_*` links, is most of what this daemon does before it
registers anything.

## What this is not

It is not a substitute for switchdev / bridge offload. Where the hardware can
represent VFs as real bridge ports, use that instead. This exists for the cards
that cannot — and they are not a shrinking remainder. `ixgbe` (82599, X520,
X540, X550), `i40e` (X710, XL710) and `mlx4` (ConnectX-3) carry no switchdev
support at all: not *yet*, but at all. `mlx5` and `ice` do, but on `mlx5` it is
a per-card property — a ConnectX-4 Lx answers the mode change with `Failed
setting eswitch to offloads` on firmware 14.32.1912, with or without a bound
VF. For that hardware the gap does not close by waiting, only by replacing the
card.

Do not try it on a machine you care about just to see. The driver tears the
legacy eswitch down *before* building the offloads one, and when the second
step fails the first is not undone: the VFs stay dark and the host needs a
reboot.

## Implementation

Plain rtnetlink, by hand, on top of `libc`. Three operations on `AF_BRIDGE`
neighbour messages: dump the forwarding database, add or remove an `NTF_SELF`
entry, and subscribe to `RTNLGRP_NEIGH`. No shelling out to `bridge`, no output
parsing, no async runtime — and real error codes, which is what makes `EEXIST`
and `ENOSPC` distinguishable instead of guessed at.

Topology comes from one `RTM_GETLINK` dump: master for bonds, `IFLA_LINK` with
the interface kind for stacking. The VF count is *not* in that dump —
`IFLA_NUM_VF` is only sent when the request asks for the functions themselves,
which is the expensive thing the daemon avoids — so it is read from
`device/sriov_numvfs`, along with the `physfn` and `virtfn` relations. A test
holds the netlink and `/sys` readings against each other on whatever host it
runs on, so they cannot drift apart in silence.

The daemon works from notifications: an address is registered as soon as the
kernel says a bridge learnt it, dropped when the bridge ages it out, and the
picture is rebuilt whenever an interface changes — including a VF whose address
was set from the host. `RESYNC` is a timed pass on top of that, and it has
never been seen to do anything: run at ten seconds while deleting entries by
hand, reassigning addresses and destroying veths under traffic, all twenty-five
corrections came from notifications and none from the timer. It is kept because
"nothing could be provoked" is not "nothing exists", and it doubles as a canary
— a change line ending in `[timed]` means the notification path missed
something. Recovery passes label themselves `[lost events]` and `[recovery]`
instead, so the canary stays honest.

### What a pass costs

On a namespace built for the purpose — 406 interfaces, 9826 forwarding
entries, 4200 addresses wanted, because a normal host is too small to see
anything:

```
pass total 19.45 ms          syscall time 19.11 ms  (98.2%)
  fdb dump 17.70 ms            recvfrom   17.38 ms   49 calls
  topology  1.28 ms            sendto      1.18 ms    3 calls
  pairs     0.23 ms            statx       0.04 ms    4 calls
```

Everything this program does with that data — parsing 9826 entries, building
the graph, putting 4200 addresses through several sets — is the 0.35 ms that is
*not* syscall time. The cost of a pass is the kernel serialising its tables. On
a normal host a whole pass is about 2 ms.

Four things were tried against that profile and are recorded so they are not
tried again on the strength of how sensible they sound:

* **Topology from netlink rather than `/sys`** — done, the largest single win:
  0.80 ms to 0.185 ms on a normal host, 9.3 to 2.3 on a large one. An earlier
  attempt measured no difference because it asked with `RTEXT_FILTER_VF`, which
  makes every driver with VFs answer out of its firmware.
* **Not asking for what is not read** — done, and the largest thing left in a
  pass. `RTEXT_FILTER_SKIP_STATS` took a ConnectX-4 pass from 2.17 ms to 0.73,
  43% of a cold pass, for counters this daemon never looks at.
* **A faster hash** — done, worth 45% of the phase that puts addresses through
  sets, and nothing anywhere else.
* **MAC addresses as integers** — not done. It would work on part of that
  0.35 ms, under 1% of a pass, and it touches every type in the program.
* **Keeping the interface graph and updating it from link events** — not done,
  and now pointless: reading it afresh costs 0.185 ms, and a stale graph is a
  class of silent error no test would catch.

## Versions

Releases are dated: `YEAR.MONTH.N`, where `N` counts releases within that
month. The number tells you how old a build is, which is the question people
actually ask about a daemon. There is no semantic-version promise: this is a
program, not a library, and nothing depends on it as a crate. Releases up to
1.5.0 used semantic versions; `dpkg`, `apk` and cargo all order 2026 after 1,
so upgrading works.

## Development

```
cargo test        # topology and parsing logic, no hardware needed
cargo clippy --all-targets -- -D warnings
cargo fmt --check
sudo bench/integration.sh target/release/sriov-mac-sync   # against a real kernel
```

The parts most likely to be wrong on unfamiliar hardware are the ones that
decide *which way the wire is* and *which addresses count*, and those are pure
functions over topologies the tests build by hand. The integration script holds
the built binary to every mode's promise against the kernel itself, in a
throwaway namespace, and refuses to run where a daemon is already at work. CI
runs all of that, an MSRV build and a static build on every push and pull
request.

## License

MIT.
