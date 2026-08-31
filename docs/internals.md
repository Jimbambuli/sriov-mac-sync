# Internals

## How it works

Plain rtnetlink, by hand, on top of `libc`. Three operations on `AF_BRIDGE`
neighbour messages: dump the forwarding database, add or remove an `NTF_SELF`
entry, and subscribe to `RTNLGRP_NEIGH` *and* `RTNLGRP_LINK` for changes —
interfaces matter as much as addresses, and the picture-rebuilding below hangs
on the link subscription. No shelling out to `bridge`, no output parsing, no
async runtime — and real error codes, which is what makes `EEXIST` and
`ENOSPC` distinguishable instead of guessed at. The one thing outside
rtnetlink is a single generic-netlink question — the devlink parameter
`max_macs`, the card's real filter capacity, asked at startup and again for a
pair that appears at runtime; hardware-notes has the details.

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
kernel says a bridge learnt it, dropped when the bridge ages it out - unless
its port testifies otherwise: the pass remembers which bridge port
each owned address was last learnt behind, and an aged-out address whose port
still exists in the bridge is kept - for a guest the kernel deletes the veth
or tap with its endpoint, so the port existing is the guest existing, and a
device behind a physical port in the bridge is blackholed by ageing all the
same. What bounds the keep is capacity, not time: nearing the filter's limit,
the entries silent longest are released first, and every fresh learn makes
an entry young again. The pressure is measured against the card's own
unicast list, read back each pass - foreign entries occupy real slots and
count - and the event path carries that count between passes, surrendering
the longest-missing keep synchronously when a burst would not fit: past its
limit the card drops arbitrarily, and 200 ms of overflow is 200 ms of
somebody unreachable. What stays free below the limit is a few slots of
counting drift, not the blind tenth it once was. The entry also goes when
its port goes or the address moves out to the wire.

That memory outlives the process. It is written to `.<dev>.owned.ports`
beside the note, under the same lock and through the same temp-and-rename.
Its first line names the format, so a file whose numbers meant something
else is ignored rather than misread - that mistake was made once, when the
stamps changed from missing-since to last-seen.
Then one line per address: the port by name *and* index, and the boot-clock
reading at which the bridge was last seen holding it - milliseconds,
because between two passes the daemon is blind anyway and a finer digit
would claim a precision the observation has not got. Every pass refreshes
that stamp for everything it finds learnt, and so does every learn on the
event path - which is what makes "quiet" a fact rather than a guess: an
address whose stamp predates the last pass is one the last pass did not
see. The same number orders the pressure valve's evictions, and it records
when the guest last *spoke* rather than when the daemon noticed the
silence, so two addresses that fall out between the same two passes are
told apart by their traffic instead of by their names. Two passes may
never share a stamp - everything would then read as loud - so a pass whose
clock reading matches its predecessor's takes the next number up rather
than a finer clock being asked for.

The bridge's own deletions refine that stamp. A bridge forgets an address
exactly its ageing time after the last frame from it, so `RTM_DELNEIGH`
arriving now says the guest spoke one ageing time ago - which the daemon
reads out of the same link dump the topology comes from
(`IFLA_BR_AGEING_TIME`). It is taken only when it places that frame
*later* than the last pass did: a vlan-aware bridge holds one entry per
VLAN and ages them apart, so a deletion may well concern an address that
spoke in another VLAN a moment ago, and our own observation is then the
better one. So the event can say "it went on speaking after you last
looked" and never the reverse - which is also why a deletion is still no
reason to unregister anything, only to look. A restart is mostly an update,
and an update that forgot its keeps would unregister every quiet guest on
its first pass - the outage the keep exists to prevent, delivered by our
own package. A line is believed only where it still describes this kernel,
which is what the name-and-index pair is for: an interface replaced under
the same name does not inherit somebody else's keeps. The clock is
`CLOCK_BOOTTIME` in milliseconds, which can be written down and read back
and cannot step under NTP; the file shares the notes' tmpfs, so a stamp and
the clock that reads it always come from the same boot. Losing the file
costs the keeps and nothing else: a write that fails is one warning per
device and a carry on, and a file that cannot be read or parsed is simply
no memory - the fall back to what every build before it did. The whole picture is rebuilt whenever an
interface appears, disappears or is reconfigured. What notifications do *not* cover is a VF's address changing
silently: a PF that is administratively down announces nothing, and a
guest-side change runs over the ixgbe/i40e driver mailbox without ever
reaching rtnetlink — an "up PFs announce" gate built on the opposite
assumption was refuted from the kernel source and removed. Invariant 2 is
carried on the event path by the grow-only driver refresh instead: any batch
or pass that would *grow* a filter asks the driver afresh before registering;
only shrinking trusts a carried answer.

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
names what triggered the pass, for exactly that reason. The quiet-keep adds
three lines of its own: `kept [quiet]` when addresses enter the kept state,
`took over ...` when a fresh daemon adopts the previous run's memory, and
`released N quiet address(es) [pressure]` when the capacity valve sheds -
each said by the process that acts, never by `--status`.

**The note outlives the pair it was made for**, on purpose: when a device stops
being an uplink — the bridge taken apart, the port moved elsewhere — what was
registered for it is taken back out. Left in place it would go on telling the
card to steer those addresses at a port that leads nowhere, and nothing short of
a reboot would undo it. Only autodetection may draw that conclusion, because
only autodetection sees every uplink; naming pairs by hand says nothing about
the pairs it omits. Notes are written 0600 in a 0700 directory — a note another
user can write is a note that decides what a root daemon takes out of a card.

**An address is noted before the card takes it** — the order `--check` has
always used, now used everywhere. Written the other way round, a crash between
the netlink acknowledgement and the note (an OOM kill, an abort) left an entry
no note named: counted as foreign from the next start on, and foreign entries
are deliberately never touched. Note first, the same crash leaves an intent the
ordinary paths heal — the add is retried while the address is wanted, and the
removal's ENOENT settles the note once it is not — and a note that cannot be
written keeps the card untouched entirely. An address the card then refuses as
somebody else's (EEXIST) has its fresh intent taken back out. The card is
written under the note's lock, so a `--flush` running in the same moment cannot
settle the intent away between the append and the add.

**A rename moves the name and nothing else** — the interface, its index and its
filter entries live on, and the note is found by name. The index is therefore
recorded beside each note (`.<dev>.owned.index`), and a noted name that is gone
while its index lives on is read as the rename it is: the note follows the
interface instead of being unlinked with every entry it names still in the
card. Within one boot an index identifies an interface outright — the kernel
hands them out from a counter that does not re-use one — and `/run` does not
outlive a boot either. `--flush` resolves through the same record, so it
reaches the entries under whatever name the interface wears now.

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
a normal host a whole cold pass was about 2 ms before the optimisations
below; with them it is ~0.7 ms on a ConnectX-4.

Two things keep the event path quiet between passes: wake-ups drain the
socket in one burst (up to 256 datagrams) so an ARP storm buys one pass, not
one per packet, and a small cBPF filter on the subscription drops
neighbour-table noise for other address families in the kernel, before it
wakes anybody.

Five things were tried against that profile, recorded so they are not tried
again on the strength of how sensible they sound:

* **Topology from netlink rather than `/sys`** — done, the largest single win:
  0.80 ms to 0.185 ms on a normal host, 9.3 to 2.3 on a large one. An earlier
  attempt measured no difference because it asked with `RTEXT_FILTER_VF`, which
  makes every driver with VFs answer out of its firmware.
* **Not asking for what is not read** — done, and the largest thing left in a
  pass. `RTEXT_FILTER_SKIP_STATS` took the VF-address call on a ConnectX-4 from
  2.17 ms to 0.73 — worth 43% of the whole cold pass — for traffic counters
  this daemon never looks at.
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

Nine scenarios: addresses learnt one at a time, in close succession, and as a
burst of sixteen; a hundred cold `--once` passes with the CPU governor logged;
an address of ours turning up on the uplink's own port (a guest that moved
host); a VF's own address learnt behind the bridge; a guest going quiet whose
entry has to stay — the keep, proven on the real eSwitch; the port's removal;
and a closing quiescence check — journal quiet, no `[timed]` pass that had to
fix anything, no residue, the quiet-keep memory file included. A failed
verification fails the exit code.

It refuses to start unless everything holds: the service active and not in
`--dry-run`, the bridge actually watched, STP off, the VLAN named on a
VLAN-aware bridge, no leftovers from a previous run, and enough headroom in
every filter — the list drops addresses silently past its capacity, and a
benchmark must not be what pushes a real guest's address out.

Two boundaries, so the numbers are read for what they are: latencies end at the
kernel's forwarding-database notification — the driver programs the NIC
asynchronously just afterwards — and absolute times swing with CPU frequency
scaling, so two software states are compared only by interleaving their trials.

If a failed run leaves test entries behind (prefixes `02:be:5c` and
`fe:be:5c`), remove them with
`bridge fdb del <mac> dev <uplink> self permanent` and leave the note files
alone: the daemon heals its own notes through the ENOENT path on the next pass.
After a hard kill the bridge entries age out within 300 s and the daemon takes
the registrations back by itself - except those whose guest port lives on,
which is the point of the quiet-keep; the trial's own veth goes with the
teardown, so its entries do come back out.

How a pass scales with the size of the forwarding table is a question for
`cargo test --release scaling -- --ignored --nocapture`: an SDN-shaped topology,
a share of entries out on the wire, asserted to stay roughly linear (measured:
40x the entries cost 28x the time).
