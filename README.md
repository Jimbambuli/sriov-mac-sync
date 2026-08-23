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
              ┌─────────── host ────────────┐
   wire ──────┤ PF ─┬─ br0 ─┬─ tap  (VM)    │    VF ──▶ tap    lost on the wire
              │     │       ├─ veth (CT)    │    VF ──▶ veth   lost on the wire
              │ VF ─┘       └─ eth1 ─ wire2 │    VF ──▶ wire   fine
              └─────────────────────────────┘
```

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
* **The uplink need not be a PF.** If you bridge a VF instead, name the pair
  with `--pair`; the mechanism is identical.

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

Pairs are found automatically: any interface with VFs that ends up in a bridge.
Override with `--pair DEV:BRIDGE`, repeatable. `/etc/sriov-mac-sync.conf` may
set `PAIRS`, `RESYNC`, `MAX_MACS` and `EXCLUDE`.

## Verify it actually works

`--check` only proves the kernel accepted the address. Whether the NIC acts on
it is a property of the driver, and there is no way to ask. Test with traffic:

1. From inside the VF's guest, ping something behind the bridge. It should fail.
2. `bridge fdb add <that mac> dev <uplink> self permanent`
3. Ping again. It should work.
4. `bridge fdb del ...` — it should fail again.

If step 3 changes nothing, this approach does not work on your hardware and
this daemon will not help you.

Measured working: **Mellanox ConnectX-4 Lx** (`mlx5_core`), legacy eswitch
mode, confirmed from a Linux network namespace and from a FreeBSD guest holding
the VF.

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

**This daemon only removes what it added.** It keeps a note in
`/run/sriov-mac-sync/`; entries put there by something else are left alone.

**FreeBSD guests: turn off local loopback.** FreeBSD's `mlx5en` enables it by
default (`dev.mce.N.conf.uc_local_lb` and `mc_local_lb`, both `1`). The guest's
own neighbour solicitations come back to it, FreeBSD spots the loop, restarts
duplicate address detection, and never finishes — the address stays `tentative`
and IPv6 on that interface is dead. Set both to `0`. This has nothing to do
with this daemon, but you will hit it in the same afternoon.

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

## License

MIT.
