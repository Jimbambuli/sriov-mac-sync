# Internals

## How it works

Plain rtnetlink, by hand, on top of `libc`. Three operations on `AF_BRIDGE`
neighbour messages: dump the forwarding database, add or remove an `NTF_SELF`
entry, and subscribe to `RTNLGRP_NEIGH` for changes. No shelling out to
`bridge`, no output parsing, no async runtime — and real error codes, which is
what makes `EEXIST` and `ENOSPC` distinguishable instead of guessed at.

Topology comes from one `RTM_GETLINK` dump: master for bonds, `IFLA_LINK` with
the interface kind for stacking (a veth reports a peer there and a tunnel its
underlay — neither is stacking). The VF count is *not* in that dump:
`IFLA_NUM_VF` is only sent when the request asks for the functions themselves,
which is the expensive thing the daemon avoids, so it is read from
`device/sriov_numvfs`, along with the `physfn` and `virtfn` relations. A test
holds the netlink and `/sys` readings against each other on whatever host it
runs on, so they cannot drift apart in silence. Interfaces are held by index,
and the graph carries both directions of each edge, so "what sits on top of this
bridge" is one walk rather than one per interface.

The daemon works from notifications. An address is registered as soon as the
kernel says a bridge learnt it, dropped when the bridge ages it out, and the
whole picture rebuilt whenever an interface appears, disappears or is
reconfigured — including a VF whose address was set from the host, which changes
what must be excluded without moving a single forwarding entry.

**A guest that moves hosts is followed within the batch that says so.** When a
VM migrates away the bridge starts learning its address on the uplink's own
port. Until the registration goes, the eSwitch keeps handing that traffic to the
uplink, where the bridge cannot send it back out of the port it arrived on. An
address of ours seen there is therefore unregistered immediately, before
anything else in the batch is registered. A deletion on its own is not acted on:
a VLAN-aware bridge learns one address once per VLAN while the filter holds a
single entry for all of them, so only the full dump that follows can tell that
the last one has gone.

**Under a stream of learning, the cost depends on whose it is.** A batch that
leaves nothing to reconcile — addresses on the uplink's own port, entries on
bridges unrelated to any uplink — is answered and dropped without scheduling a
pass, because a pass dumps the host's whole forwarding table. Measured on a
namespace of 406 interfaces learning 4000 addresses over 20 s: 0.06 s of CPU
when all of it is wire-side, 3.1 s when every address is a guest that has to be
registered. That second figure is real work, and it is what a host learning 200
addresses a second costs. A host of this project's kind learns a few an hour.

**`RESYNC` has never been seen to do anything.** Run at ten seconds while
deleting filter entries by hand, reassigning a VF's address to one that was
registered, adding and removing bridge ports, and destroying a dozen veths under
traffic, all twenty-five corrections came from notifications and none from the
timer. It is kept because "nothing could be provoked" is not "nothing exists",
and because a missed notification would otherwise be silent and permanent. It
doubles as a canary: a change line ending in `[timed]` means the notification
path missed something. Recovery passes label themselves `[lost events]` and
`[recovery]` instead, so the canary stays honest. Every line reporting a change
names what triggered the pass, for exactly that reason.

**The note outlives the pair it was made for**, on purpose: when a device stops
being an uplink — the bridge taken apart, the port moved elsewhere — what was
registered for it is taken back out. Left in place it would go on telling the
card to steer those addresses at a port that leads nowhere, and nothing short of
a reboot would undo it. Only autodetection may draw that conclusion, because
only autodetection sees every uplink; naming pairs by hand says nothing about
the pairs it omits. Notes are written 0600 in a 0700 directory — a note another
user can write is a note that decides what a root daemon takes out of a card.

## What a pass costs

Measured on a namespace built for the purpose — 406 interfaces, 9826 forwarding
entries, 4200 addresses wanted — because a normal host is too small to see
anything:

```
pass total 19.45 ms          syscall time 19.11 ms  (98.2%)
  fdb dump 17.70 ms            recvfrom   17.38 ms   49 calls
  topology  1.28 ms            sendto      1.18 ms    3 calls
  pairs     0.23 ms            statx       0.04 ms    4 calls
```

Everything this program does with that data — parsing 9826 entries, building the
graph, putting 4200 addresses through several sets — is the 0.35 ms that is
*not* syscall time. The cost of a pass is the kernel serialising its tables. On
a normal host a whole pass is about 2 ms.

Five things were tried against that profile, recorded so they are not tried
again on the strength of how sensible they sound:

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
  0.35 ms, under 1% of a pass, for a change touching every type in the program.
* **Keeping the interface graph and updating it from link events** — not done,
  and now pointless: reading it afresh costs 0.185 ms, and a stale graph is a
  class of silent error no test would catch.

## Putting it on trial

`bench/trial.py` (root, opt-in) provokes the situations the running daemon
exists for, verifies each came out right, and reports what it cost:

```
python3 bench/trial.py vmbr1 --vlan 22
```

Eight scenarios: addresses learnt one at a time, in close succession, and as a
burst of sixteen; a hundred cold `--once` passes with the CPU governor logged;
an address of ours turning up on the uplink's own port (a guest that moved
host); a VF's own address learnt behind the bridge; the port's removal; and a
closing quiescence check — journal quiet, no `[timed]` pass that had to fix
anything, no residue. A failed verification fails the exit code.

It refuses to start unless everything holds: the service active and not in
`--dry-run`, the bridge actually watched, STP off, the VLAN named on a
VLAN-aware bridge, no leftovers from a previous run, and enough headroom in
every filter — the list drops addresses silently past its capacity, and a
benchmark must not be what pushes a real guest's address out.

Two boundaries, so the numbers are read for what they are: latencies end at the
kernel's forwarding-database notification — the driver programs the NIC
asynchronously just afterwards — and absolute times swing with CPU frequency
scaling, so two software states are compared only by interleaving their trials.

If a failed run leaves test entries behind (prefix `02:be:5c`), remove them with
`bridge fdb del <mac> dev <uplink> self permanent` and leave the note files
alone: the daemon heals its own notes through the ENOENT path on the next pass.
After a hard kill the bridge entries age out within 300 s and the daemon takes
the registrations back by itself.

How a pass scales with the size of the forwarding table is a question for
`cargo test --release scaling -- --ignored --nocapture`: an SDN-shaped topology,
a share of entries out on the wire, asserted to stay roughly linear (measured:
40x the entries cost 28x the time).
