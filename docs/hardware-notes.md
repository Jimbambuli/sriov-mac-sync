# Hardware notes

What the cards actually do. All of it was measured on the hardware named, not
read out of a datasheet.

## The filter list is finite, and past its end addresses vanish

On ConnectX-4 Lx it holds 128 entries. Beyond that the driver drops addresses
silently, and *which* is not predictable — with 257 entries a given address
still worked, with 513 it did not. (It is predictable after all: mlx5 fills
the vport list in hash order of the address's last byte and truncates the
tail, see [driver-limits.md](driver-limits.md).)

That 128 was arrived at by experiment. The number the daemon works with now
comes from the kernel driver sources: [driver-limits.md](driver-limits.md) is
the evidence, five reviews of the mainline drivers with file and function per
row, and `src/drivers.rs` the table the daemon reads, one row per driver and
role. ConnectX (mlx5) holds `1 << log_max_current_uc_list`, 128 on every card
seen, and truncates silently past it - the experimental figure. bnxt holds 4,
an untrusted iavf about 12, igbvf 3; many cards go unicast-promiscuous past
their limit instead of dropping; and several VF drivers never program the list
at all (ena, mana, bnx2x, qede untrusted, fm10k), which the daemon says at
start because nothing registered there takes effect. Where trust decides -
bnxt, qede, hns3, rvu and the Intel VF drivers - the daemon reads the PF's
answer and says whom its number is for; a VF whose address the PF set without
trusting it gets a warning, because those PFs then refuse every other address.
Where the limit lives in firmware the assumed 128 stays. `--max` or `MAX_MACS`
overrides all of it.

mlx4 and mlx5 also report the number through the devlink parameter
`max_macs`, and an earlier version asked it over generic netlink. The table
answers the same for them and for everybody else, so the question is gone.

## A VF's own address must never be registered

Registering the address of a VF belonging to the uplink's own PF tells the
eSwitch that guest lives behind the bridge. The daemon recognises such an
address two ways: set from the host with `ip link set <pf> vf N mac ...`, or a
netdev for that function still bound here. A function handed straight to a guest
with neither — its address made up by the driver inside the guest — is in no
exclusion set, and the protection then rests entirely on the rule that nothing
learnt on the uplink's own port is registered. The daemon says so once per
uplink when it finds one. Setting the address from the host closes it, and so
does `EXCLUDE`.

What happens if it *is* registered was measured, with the address claimed both
by a VF and by the uplink's filter, and a frame sent from the wire:

| | i40e (X710) | ixgbe (82599) |
|---|---|---|
| VF owns it, nothing else | VF | VF |
| filter holds it, no VF owns it | uplink | uplink |
| **both claim it** | **both, every frame** | **uplink only — VF gets nothing** |

Neither driver refuses the entry or warns. Order makes no difference, and
withdrawing the registration restores the VF immediately. So the same mistake
looks like two different faults: on ixgbe the guest goes deaf, on i40e it keeps
working while the host receives a copy of its traffic and the bridge learns the
guest's address on the uplink.

## A bridge port without a carrier does not forward

Testing on a bench with nothing plugged into the SR-IOV NIC fails for a reason
unrelated to anything else here: Linux puts a carrier-less port into the
disabled state, and a disabled port passes nothing. A short cable between two
ports of the machine is enough — but not two ports of the *same bridge*, which
is a loop.

## When the wire goes dark, the PF stops talking to its own VFs

Switch the switch off and the PF loses carrier. The internal switch carries on
forwarding between VFs, but the path between PF and VF stops dead in both
directions — measured on a ConnectX-4 Lx with no bridge in the way at all. A
bridge whose port is the PF therefore goes down with the cable and takes the
host with it: a guest on a VF can no longer reach a container on that bridge,
though the two sit in the same machine.

Giving the bridge a VF of its own removes the coupling. VF-to-VF traffic does
not depend on the carrier — 0.13 ms with the cable out, where PF-to-VF lost
every packet. One setting decides whether that works, because a VF follows its
PF's link state by default and a carrier-less bridge port is disabled:

```
ip link set <pf> vf <n> state enable
```

Then the port stays forwarding with no cable in the machine: measured end to
end, a guest on one VF reached a container behind the bridge in 0.15 ms both
ways, with the daemon doing the registration. The PF stays out of the bridge but
still has to be `up`. Do not set this on a VF carrying a WAN link, where a lost
carrier is news the guest needs to hear.

Turn spoof checking off for a VF used this way — it has to send with the
addresses of everything behind the bridge.

## Intel: the VF's link follows the PF's

`ip link set <pf> vf N state enable` is rejected outright by `ixgbe` (`not
supported`), so a VF on a NIC without a cable stays down and can do nothing at
all. And once an address has been assigned to a VF from the PF side, the guest
may not change it (`Operation not permitted`) — assign it before the VF driver
binds, or rebind afterwards.

## ixgbe: registrations are slower than elsewhere

On an 82599 the registration lands on the VF, and `ixgbevf` answers every change
to its unicast list by re-sending the *whole* list to the PF through the VF/PF
mailbox, one polled transaction per address — so the cost of one registration
grows with how many are already in the filter.

Measured on an 82599: about 0.5 ms for a single address, 5–7 ms for a burst of
sixteen. `mlx5` and `i40e` place an address in tens of microseconds. Earlier
versions of this daemon measured far more on the same card — about 6 ms and
320 ms — but the difference has not been isolated to a single change, so read it
as the range this hardware has been seen in. In steady state none of it matters;
it is the price of many *new* guests appearing at once.

## FreeBSD guests: turn off local loopback

FreeBSD's `mlx5en` enables it by default (`dev.mce.N.conf.uc_local_lb` and
`mc_local_lb`, both `1`). The guest's own neighbour solicitations come back to
it, FreeBSD spots the loop, restarts duplicate address detection and never
finishes — the address stays `tentative` and IPv6 on that interface is dead. Set
both to `0`. Nothing to do with this daemon, but you will hit it in the same
afternoon.

## A router that caches ARP longer than the bridge ages will blackhole quiet guests

Measured on an OPNsense (FreeBSD) living on a VF in front of a Proxmox host -
which is much of this project's audience. FreeBSD holds ARP entries for
1200 s (`net.link.ether.inet.max_age`); the Linux bridge forgets a silent
MAC after 300 s (`ageing_time`). A guest that stays quiet for five minutes
ages out of the bridge, the filter entry used to go with it — and the
router then keeps sending unicast for another fifteen minutes without asking
again. The eSwitch misses, the frame leaves on the wire, and every
connection attempt dies in a dial timeout. Observed as 259 reverse-proxy 502s
over four weeks, alternating with successes exactly as the 15-minute poll
beat against the 20-minute ARP lifetime.

Who is bitten depends on where the miss lands. A missed frame leaves on the
uplink port's own wire — for a peer on that wire (a printer on the same
switch) the miss *is* the delivery: the path degrades to the physical switch
and heals itself, and such wire-learnt addresses are never registered anyway.
Every destination the bridge would have to carry the frame to is blackholed:
guests behind the bridge, and just as much a device behind another NIC in
the same bridge — the frame leaves on the uplink's wire, not on that NIC's.

The quiet-keep covers the bitten set whole: an aged-out address is kept
while the port it was learnt behind still hangs in the bridge — ageing is
the bridge managing its own table, not news about the device. The entry
goes when its port goes, when the address moves out to the wire, or under
filter pressure, longest silent first. The memory is written down beside
the notes, so an update carries the keeps over instead of unregistering
every quiet guest on the daemon's first pass, and a `--once` run by hand
reads the same file rather than working against it. Where none of it helps
- an older build, or a reboot, after which nothing is registered anyway -
either pin the address with `EXTRA`, or align the one pair of numbers this
hinges on: the router's ARP lifetime against the bridge's `ageing_time`.

## The first registration after a topology change can wait on the host

Writing a filter entry takes the kernel's rtnl lock, and so does everything else
that manages interfaces. On a Proxmox node a link change prompts the status
daemon to re-check the network configuration (`ifquery`), and a plain fdb add has
been measured waiting up to two seconds behind it. The daemon is not the cause
and cannot dodge it: the write is sent instantly and sits in the kernel until
rtnl frees up. In steady state — no interfaces coming or going — registrations
run in well under a millisecond.
