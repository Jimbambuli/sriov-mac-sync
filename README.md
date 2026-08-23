# sriov-mac-sync

Make hosts that sit *behind* a Linux bridge reachable from an SR-IOV virtual
function.

## The problem

You pass a VF to a VM — a router, a firewall, anything that has to talk to the
whole segment — and most of the network works. Everything on the physical
switch answers. Then you notice that some peers are simply unreachable: a
container on the same host, another VM, a device on a second NIC in the same
bridge. Ping gets no reply. ARP resolves fine, which makes it look like a
firewall or an MTU problem. It is neither.

A NIC with SR-IOV has an internal switch, a VEB. Its forwarding table holds
exactly one thing: the MAC addresses of its own vports, the PF and the VFs. A
frame from a VF to anything else misses that table, and the miss action is
*send it out on the wire*. That is right as long as every peer really is out
there.

It stops being right the moment the uplink is a bridge port and the bridge
carries other things too — another NIC, a tap device, a veth pair. Those peers
are behind the uplink, not beyond it. Frames for them leave on the wire and are
lost. Broadcast and multicast are flooded to every vport, so ARP and ND still
work, and that is exactly why the failure is so confusing: address resolution
succeeds, and the unicast that follows disappears.

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

Boxes are things; the labels on the lines are the interfaces that connect them.
Read it from the bottom up.

`VF1` and `VF2` leave NIC 1 and go straight to their guests — past `br0`, not
through it. `PF` leaves the same NIC and *is* a port of the bridge, next to
`eth1` from the second NIC and the `tap` and `veth` of the two other guests.

NIC 1 is a switch in its own right, and the only addresses it knows are the
three interfaces hanging off it: `PF`, `VF1` and `VF2`. Everything in the box
above is invisible to it.

Here is every destination a guest holding `VF1` might want, and what becomes of
it before this daemon does anything.

| From VF1, to … | Without this daemon | Why |
|---|---|---|
| a peer on **wire A** | fine | the miss action is *send it out*, and out is where it is |
| **VF2**, the other VF on the same NIC | fine | same switch, and it knows its own vports |
| the **host**, when `br0` carries the PF's address | fine | that is a vport address too |
| **broadcast or multicast**, anywhere | fine | flooded to every vport — which is exactly why ARP and ND mislead you |
| the **host**, when `br0` carries an address of its own | **lost** | the switch has never heard of it |
| **tap** — a VM on the bridge | **lost** | it sits behind the PF, and the frame goes past it onto the wire |
| **veth** — a container on the bridge | **lost** | same |
| a peer on **wire B**, behind the second NIC | **lost** | reaching it means going *through* the bridge, not past it |

That last row depends on how the cables are patched: if wire B is the same
physical segment as wire A, frames sent out of the PF do reach those peers — by
luck rather than by design, and the moment the segments differ, or that switch
is powered down, they stop.

The opposite direction never breaks, and neither does anything that does not
involve a VF at all:

| | | Why |
|---|---|---|
| anything → **VF1** | fine | a VF address is a vport address, and its own switch knows it |
| tap ↔ veth, tap → wire, host → anything | fine | ordinary bridging; the NIC's switch is never asked |

Registering an address turns every **lost** above into **fine**: the switch has
a hit, hands the frame to the PF, and the bridge takes over from there. Both
VFs are served by the same list — one per uplink, not one per guest.

## The fix

An address can be pushed into a port's unicast filter list — `RTM_NEWNEIGH`
over `AF_BRIDGE` with `NTF_SELF`, which iproute2 spells

```
bridge fdb add <mac> dev <uplink> self permanent
```

The driver mirrors that list into the NIC's vport context. The internal switch
then has a hit for those addresses and delivers the frames to the uplink vport,
where the Linux bridge takes over and does what bridges do.

That works, but only for addresses you know in advance. Guests are knowable;
wireless clients coming and going are not. This daemon closes the gap: it
watches what the bridges learn and keeps the uplink's filter list in step.

## What gets registered

Only what is reachable *behind* the bridge:

* everything the bridge learnt on ports other than the uplink,
* everything learnt by bridges stacked on top of it — VLAN-aware setups,
  Proxmox SDN vnets and the like. This matters more than it looks: a
  container's address is often never learnt by the lower bridge at all, because
  its traffic enters from the bridge's own local port and a bridge does not
  learn from itself,
* the host's own L3 endpoints on that bridge, in case they do not share the
  uplink's address.

Deliberately **not** registered: anything the bridge learnt on the uplink
itself. Those peers live on the wire. Registering them would divert their
traffic to the bridge, which cannot send it back out of the port it came in on,
and you would break connectivity that was working.

Nothing is decided by interface name. Naming conventions differ between
distributions, and guessing from them is how a tool like this breaks on someone
else's machine; the direction of the uplink is worked out from the actual
device stacking in `/sys/class/net`.

## Topologies

Each bridge is handled on its own, and so is each uplink into it.

* **Several SR-IOV NICs in one bridge** get one filter list each. An address on
  the wire of one uplink is behind the bridge as far as the other is concerned,
  and is registered there — which is what makes it reachable at all.
* **Several VFs per NIC** need nothing extra. They share one internal switch,
  so they share the uplink's list, and they reach each other directly.
* **Bonds are followed.** A PF enslaved to a bond that is the bridge port is
  found through the bond, and the whole bond — every member — counts as the
  wire side.
* **The uplink need not be a PF.** A VF can carry the bridge just as well and
  is picked up on its own; the mechanism is identical. It has to send with the
  addresses of everything behind the bridge, so turn spoof checking off for it.
  There is a reason to prefer this — see *when the wire goes dark* below.

## Build and install

```
cargo build --release
install -m 755 target/release/sriov-mac-sync /usr/local/sbin/
install -m 644 dist/sriov-mac-sync.service   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sriov-mac-sync
```

One dependency, `libc`. For a binary that runs on an older distribution than
the one you built on:

```
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release
```

## Use

```
sriov-mac-sync --check              does this NIC accept filter entries at all?
sriov-mac-sync --status             what was detected, wanted, registered
sriov-mac-sync --once --dry-run     what would change
sriov-mac-sync --once               reconcile and exit
sriov-mac-sync --flush              remove what this daemon registered
sriov-mac-sync -v ...               explain what is skipped, and list addresses
```

`--extra <macs>` registers addresses unconditionally, for a device that never
speaks first; the wire-side and own-address rules still override it, and you
get a warning when they do. `--exclude <macs>` is its opposite.

Pairs are found automatically: any interface with VFs that ends up in a bridge.
Override with `--pair DEV:BRIDGE`, repeatable. `/etc/sriov-mac-sync.conf` may
set `PAIRS`, `RESYNC`, `MAX_MACS`, `EXCLUDE` and `EXTRA`.

`--compare-topology` reads the interface layout twice — once out of `/sys` and
once out of a single netlink dump — and reports any field where the two
disagree. It changes nothing, and exists so the faster path can be trusted
before anything depends on it. Reports from unusual setups are welcome.

The daemon works from notifications. An address is registered as soon as the
kernel says a bridge learnt it, dropped when the bridge ages it out, and the
whole picture is rebuilt whenever an interface appears, disappears or is
reconfigured — including a virtual function whose address was set from the
host, which changes what must be excluded without moving a single forwarding
entry.

`RESYNC` is the interval of a timed pass on top of that, and it has never been
seen to do anything. Run at ten seconds on a host while deleting filter entries
by hand, reassigning a VF's address to one that was registered, adding and
removing bridge ports, and creating and destroying a dozen veths with traffic,
every one of twenty-five corrections came from a notification and none from the
timer. It is kept because "nothing could be provoked" is not "nothing exists",
and because the failure it guards against — a missed notification — would
otherwise be silent and permanent. It also doubles as a canary: a log line
ending in `[timed]` means the notification path missed something, and is worth
looking into.

Every log line names what triggered the pass, for exactly that reason.

## Verify it actually works

`--check` only proves the kernel accepted the address. Whether the NIC acts on
it is a property of the driver, and there is no way to ask. Test with traffic:

1. From inside the VF's guest, ping something behind the bridge. It should fail.
2. `bridge fdb add <that mac> dev <uplink> self permanent`
3. Ping again. It should work.
4. `bridge fdb del ...` — it should fail again.

If step 3 changes nothing, this approach does not work on your hardware and
this daemon will not help you.

Measured working:

| NIC | driver | confirmed with |
|---|---|---|
| Mellanox ConnectX-4 Lx | `mlx5_core` | a network namespace on the VF, and a FreeBSD guest holding the VF |
| Mellanox ConnectX-3 Pro | `mlx4_core` | a network namespace on the VF |
| Intel 82599ES | `ixgbe` | a network namespace and a Windows 11 guest, against the real neighbours of a live bridge |
| Intel X710 | `i40e` | a network namespace on the VF |

The clearest run was the Windows one, because the frames could be watched
leaving. The uplink's wire went to a second NIC in the same machine, so both
ends were visible at once. With nothing registered, 60 unicast frames from the
guest went out onto the cable in twenty seconds and none reached the bridge —
whose other ports were an inch away. One `--once` reversed it exactly: none on
the cable, and they arrived. `--flush` sent them back out. Broadcast came
through the whole time, which is why the guest had an address and looked
connected.

Two Mellanox generations and two Intel ones, all in legacy eswitch mode, all
with the same signature: a peer behind the bridge is unreachable while ARP for
it resolves, registering its address fixes it, and removing the registration
breaks it again. Reports for other hardware are welcome — the four steps above
are the whole test.

## Limits and things worth knowing

**The list is finite and its size cannot be queried.** On ConnectX-4 Lx it
holds 128 entries. Beyond that the driver drops addresses silently, and *which*
ones is not predictable — with 257 entries a given address still worked, with
513 it did not. `MAX_MACS` only decides when you get a warning. Count what is
behind your bridge before relying on this.

**There is a race, and it is small.** An address is registered when the bridge
learns it, which happens as the device's own first frame passes through, before
anything can answer it. What remains is the daemon's reaction time; new entries
are registered on the netlink notification rather than at the next pass, and
retransmission covers the rest.

**Idle devices fall out and come back by themselves.** Bridge FDB entries age
out — 300 s by default — and the registration goes with them. That is harmless:
the next attempt to reach such a device starts with an ARP or ND, which is
broadcast and gets through, and the reply repopulates both the bridge and the
list.

**The filter list knows nothing about VLANs.** There is no room for one:
`bridge fdb add <mac> dev <uplink> self permanent vlan 22` is refused with
`Invalid argument`. One entry covers a MAC in every VLAN, which is usually what
you want — a router holding one address across a dozen VLANs collapses to a
single entry, and a bridge that learnt it a dozen times still needs registering
only once.

The corollary is that registering is all-or-nothing. If an address is on the
wire in one VLAN and behind the bridge in another, there is no way to say so,
and this daemon takes the cautious side: an address the bridge has learnt on
the uplink in *any* VLAN is left out entirely, because diverting working
traffic is worse than leaving one path unreachable. Assigning a VF to a VLAN is
a separate matter and works normally, either from the PF (`ip link set <pf> vf
N vlan 22`) or by the guest itself when the VF is trusted.

**This daemon only removes what it added.** It keeps a note in
`/run/sriov-mac-sync/`; entries put there by something else are left alone.

**A bridge port without a carrier does not forward.** Testing this on a bench
with nothing plugged into the SR-IOV NIC will fail for a reason that has
nothing to do with any of the above: Linux puts a carrier-less port into the
disabled state, and a disabled port passes nothing. A short cable between two
ports of the machine is enough — but not two ports of the *same bridge*, which
is a loop.

**When the wire goes dark, the PF stops talking to its own VFs.** Switch the
switch off and the PF loses carrier. The internal switch carries on forwarding
between VFs, but the path between the PF and a VF stops dead in both
directions — measured on a ConnectX-4 Lx with no bridge in the way at all. A
bridge whose port is the PF therefore goes down with the cable, and takes the
host with it: a guest on a VF can no longer reach a container on that bridge,
though the two sit in the same machine.

Giving the bridge a VF of its own instead removes that coupling. VF-to-VF
traffic does not depend on the carrier — 0.13 ms with the cable out, where
PF-to-VF lost every packet — and the registration described here is what steers
it, so the host keeps talking to itself while the wire is dark. The PF then
stays out of the bridge, but it still has to be `up`.

**Intel: the VF's link follows the PF's.** `ip link set <pf> vf N state enable`
is rejected outright by `ixgbe` (`NDO set VF 0 link state 1 - not supported`),
so a VF on a NIC without a cable stays down and can do nothing at all. And once
an address has been assigned to a VF from the PF side, the guest may not change
it — `RTNETLINK answers: Operation not permitted` — so assign it before the VF
driver binds, or rebind afterwards.

**FreeBSD guests: turn off local loopback.** FreeBSD's `mlx5en` enables it by
default (`dev.mce.N.conf.uc_local_lb` and `mc_local_lb`, both `1`). The guest's
own neighbour solicitations come back to it, FreeBSD spots the loop, restarts
duplicate address detection, and never finishes — the address stays `tentative`
and IPv6 on that interface is dead. Set both to `0`. This has nothing to do
with this daemon, but you will hit it in the same afternoon.

## Prior art

The mechanism is not new. A [Proxmox forum
thread](https://forum.proxmox.com/threads/communication-issue-between-sriov-vm-vf-and-ct-on-pf-bridge.68638/)
worked it out years ago, and
[jdlayman/pve-hookscript-sriov](https://github.com/jdlayman/pve-hookscript-sriov)
packages it as a Proxmox hookscript: on guest start it reads the guest's MAC
out of the PVE config, walks the bridge's ports to find one with virtual
functions, follows bonds on the way, and registers the address — the same
`bridge fdb add` this daemon issues over netlink. On guest stop it removes it
again. If your guests are the only thing you need to reach, that script is
smaller than this and does the job.

Two things led to this being written instead:

**Only configured guests are covered.** A hookscript knows what is in
`/etc/pve`; it cannot know about the wireless client that just associated, the
printer on the second NIC, or the host's own address on the bridge. Those are
learnt, not configured, and they are the majority on a real segment.

**A stacked bridge hides the uplink.** The hookscript looks for a NIC with VFs
among the ports of the bridge named in the guest's config. On a VLAN-aware
setup — Proxmox SDN vnets, for instance — that bridge's ports are a VLAN
interface and some veths; the NIC is a layer further down and is never found,
so nothing is registered at all. Working out the uplink structurally, through
`master` chains and `lower_*` links, is most of what this daemon does before it
registers anything.

## What this is not

It is not a substitute for switchdev / bridge offload. Where the hardware can
represent VFs as real bridge ports, use that instead — it is the proper answer
and needs no daemon. This exists for the cards that cannot.

## Implementation

Plain rtnetlink, by hand, on top of `libc`. Three operations on `AF_BRIDGE`
neighbour messages: dump the forwarding database, add or remove an `NTF_SELF`
entry, and subscribe to `RTNLGRP_NEIGH` for changes. No shelling out to
`bridge`, no output parsing, no async runtime — and real error codes, which is
what makes `EEXIST` and `ENOSPC` distinguishable instead of guessed at.

Topology comes from `/sys/class/net`: `master` chains upward for bonds,
`lower_*` links downward for stacking, `sriov_numvfs` and `physfn`/`virtfn` for
the SR-IOV relationships.

## Development

```
cargo test        # topology and parsing logic, no hardware needed
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The parts most likely to be wrong on unfamiliar hardware are the ones that
decide *which way the wire is* and *which addresses count*, and those are pure
functions over a topology that tests build by hand — bonds, stacked VLAN
interfaces, vnet bridges, a second unrelated bridge, a bridge carrying its own
address. CI runs all of that plus a static build on every push.

## License

MIT.
