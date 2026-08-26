#!/usr/bin/env python3
"""Put the running daemon on trial.

One run provokes the situations the daemon exists for, verifies that each
came out right, and reports what it cost:

  S1  eight addresses learnt one at a time   -> fast-path latency, each
  S2  pairs sent 50 ms apart                 -> close-succession latency
  S3  a burst of sixteen at once             -> burst turnaround, one figure
  S4  a hundred cold passes of --once        -> per-phase min/median/p95/max
  S5  one of ours learnt on the uplink port  -> unregistered, and how fast
  S6  a virtual function's own address       -> never registered at all
  S7  the test port deleted                  -> everything taken back, bounded
  S8  the daemon's own journal and the state -> quiet, and byte-identical

The run fails loudly if any verification does not hold; the exit code says so.

It runs as root against the production bridge, so it refuses to start unless
every precondition holds - and it never touches the ownership notes: should
anything be left behind, the way out is `bridge fdb del <mac> dev <uplink>
self permanent` per address, after which the daemon heals its own notes
through the ENOENT path on the next pass.

Honesty notes, so the numbers are read for what they are:
- Latencies end at the kernel's forwarding-database notification. mlx5
  programs the NIC itself asynchronously afterwards (a workqueue); the
  packet-level effect follows unmeasured microseconds later.
- Learn and register events are timestamped by this process on one monotonic
  clock; the error is this process's scheduling latency, kept small by
  SCHED_FIFO where permitted.
- Absolute times swing ~2x with CPU frequency scaling. Compare two software
  states only by running their trials interleaved; within one report, `min`
  is the steadiest comparator.
"""

import argparse
import glob
import atexit
import json
import os
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import time

# The whole of the test's footprint, recognisable at a glance.
SRC_PREFIX = bytes([0x02, 0xBE, 0x5C, 0x00])  # source MACs: 02:be:5c:00:xx:yy
PORT_MAC = "fe:be:5c:00:00:b0"  # deliberately HIGH: the bridge takes the
PEER_MAC = "fe:be:5c:00:00:b1"  # lowest port MAC as its own when unpinned
ETHERTYPE = 0x88B5  # IEEE 802 local experimental - carries nothing
VETH = "bench0"  # the bridge-port end
VETH_PEER = "bench1"  # where frames are injected

RTMGRP_NEIGH = 4  # 1 << (RTNLGRP_NEIGH - 1)
RTM_NEWNEIGH, RTM_DELNEIGH = 28, 29
AF_BRIDGE = 7
NTF_SELF = 0x02
NDA_LLADDR = 2
SO_RCVBUFFORCE = 33

FILTER_CAPACITY = 128  # ConnectX-4 Lx vport list; the README's measured limit
TEST_MACS_TOTAL = 8 + 8 + 16
CAPACITY_MARGIN = 16


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def fail(msg):
    print(f"REFUSED: {msg}", file=sys.stderr)
    sys.exit(2)


def read(path):
    with open(path) as f:
        return f.read().strip()


def mac_bytes(s):
    return bytes(int(p, 16) for p in s.split(":"))


def mac_str(b):
    return ":".join(f"{x:02x}" for x in b)


def fmt_ms(ns):
    return f"{ns / 1e6:8.2f} ms"


def percentile(sorted_vals, p):
    return sorted_vals[min(len(sorted_vals) - 1, int(p * (len(sorted_vals) - 1) + 0.5))]


class Governor:
    """The CPU frequency governor, pinned for the measurement and put back
    afterwards.

    A benchmark that does not say what the CPU was doing is not reproducible,
    and on a host left in `powersave` - which is where a hypervisor that pays
    its own electricity bill belongs - the first pass of a burst is measured
    while the governor is still ramping. Pinning it to `performance` removes
    that from the numbers.

    Putting it back matters more than setting it: this runs on someone's live
    machine, and a benchmark that quietly leaves the CPUs pinned has changed
    the host it was only supposed to observe. atexit covers the normal end and
    every sys.exit, including the one the signal handlers take.
    """

    PATTERN = "/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"

    def __init__(self):
        self.previous = {}
        self.pinned = False

    def pin(self, wanted="performance"):
        paths = sorted(glob.glob(self.PATTERN))
        if not paths:
            print("(no cpufreq here; governor left alone)")
            return
        try:
            for path in paths:
                with open(path) as fh:
                    self.previous[path] = fh.read().strip()
            for path in paths:
                with open(path, "w") as fh:
                    fh.write(wanted)
        except OSError as e:
            # Not root, or a kernel that will not have it. Say so and measure
            # anyway - a number with a caveat beats no number.
            print(f"(cannot set the governor: {e}; measuring as found)")
            self.previous.clear()
            return
        was = sorted(set(self.previous.values()))
        self.pinned = True
        atexit.register(self.restore)
        print(f"governor: {wanted} for the duration (was {', '.join(was)})")

    def restore(self):
        if not self.pinned:
            return
        self.pinned = False
        for path, value in self.previous.items():
            try:
                with open(path, "w") as fh:
                    fh.write(value)
            except OSError:
                pass
        print(f"governor: back to {', '.join(sorted(set(self.previous.values())))}")

    def describe(self):
        """What the numbers below were measured under."""
        paths = sorted(glob.glob(self.PATTERN))
        if not paths:
            return "no cpufreq"
        seen = set()
        for path in paths:
            with open(path) as fh:
                seen.add(fh.read().strip())
        return ", ".join(sorted(seen))


class Cleanup:
    """Tear down in the one order that leaves evidence: stop injecting,
    keep the monitor until the removals are seen, then the veth, then verify.
    PID-based and idempotent; pkill -f has killed its own SSH session before."""

    def __init__(self):
        self.done = False
        # (pf, vf index, address it had) - set while a scenario borrows a
        # virtual function's address, cleared when it gives it back.
        self.vf_address = None

    def __call__(self, *_):
        if self.done:
            return
        self.done = True
        subprocess.run(["ip", "link", "del", VETH], capture_output=True)
        if self.vf_address:
            pf, idx, mac = self.vf_address
            subprocess.run(["ip", "link", "set", pf, "vf", str(idx), "mac", mac],
                           capture_output=True)
        purge_learned_residue()
        # No note surgery, ever: the daemon's ENOENT path heals the notes on
        # the next pass once the entries are gone from the card.

    def arm(self):
        atexit.register(self)
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, lambda s, f: (self(), sys.exit(130)))


class Monitor:
    """The kernel's own account of what happened, on our clock."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
        try:  # a full buffer would silently cost events; root may force it
            self.sock.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, 4 << 20)
        except OSError:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        self.sock.bind((0, RTMGRP_NEIGH))
        self.sock.setblocking(False)
        self.events = []  # (t_ns, 'NEW'|'DEL', ifindex, flags, mac)

    def pump(self, until_ns):
        """Read everything that arrives before the deadline."""
        while True:
            left = (until_ns - time.monotonic_ns()) / 1e9
            if left <= 0:
                return
            r, _, _ = select.select([self.sock], [], [], left)
            if not r:
                return
            try:
                data = self.sock.recv(1 << 16)
            except BlockingIOError:
                continue
            t = time.monotonic_ns()
            off = 0
            while off + 16 <= len(data):
                ln, ty, _fl, _seq, _pid = struct.unpack_from("IHHII", data, off)
                if ln < 16:
                    break
                if ty in (RTM_NEWNEIGH, RTM_DELNEIGH):
                    fam, ifindex, _state, flags, _typ = struct.unpack_from(
                        "BxxxiHBB", data, off + 16
                    )
                    if fam == AF_BRIDGE:
                        mac = None
                        aoff = off + 16 + 12
                        while aoff + 4 <= off + ln:
                            alen, atype = struct.unpack_from("HH", data, aoff)
                            if alen < 4:
                                break
                            if atype == NDA_LLADDR and alen >= 10:
                                mac = bytes(data[aoff + 4 : aoff + 10])
                            aoff += (alen + 3) & ~3
                        if mac:
                            self.events.append(
                                (t, "NEW" if ty == RTM_NEWNEIGH else "DEL", ifindex, flags, mac)
                            )
                off += (ln + 3) & ~3

    def learns(self, mac, port_idx):
        return [t for (t, k, i, f, m) in self.events
                if k == "NEW" and m == mac and i == port_idx and not f & NTF_SELF]

    def selfs(self, mac, uplink_idxs, kind="NEW"):
        return {i: t for (t, k, i, f, m) in self.events
                if k == kind and m == mac and i in uplink_idxs and f & NTF_SELF}


def watched_pairs(binary):
    """The pairs the daemon itself says it is watching - the arguments must
    not be trusted over the daemon, or the cleanup logic guards the wrong
    interfaces."""
    st = run([binary, "--status"])
    pairs = []
    for line in st.stdout.splitlines():
        m = re.match(r"^(\S+) on (\S+) \(", line)
        if m:
            pairs.append((m.group(1), m.group(2)))
    return pairs


def self_macs(uplink):
    out = run(["bridge", "fdb", "show", "dev", uplink]).stdout
    return sorted(l.split()[0] for l in out.splitlines() if " self permanent" in " " + l)


def purge_learned_residue():
    """A bridge carrying stacked vnets is promiscuous: every injected frame
    gets a host-bound copy regardless of its destination, and the vnet
    bridges above learn the test sources from it. The copies never leave the
    host, but the learned entries would sit there for the 300 s ageing time -
    so they are taken out, and only they: learned master entries under our
    prefixes, never anything self or foreign."""
    out = run(["bridge", "fdb", "show"]).stdout
    removed = 0
    for line in out.splitlines():
        f = line.split()
        if not f or not f[0].startswith(("02:be:5c", "fe:be:5c")):
            continue
        if "master" in f and "self" not in f and "permanent" not in f:
            dev = f[f.index("dev") + 1]
            run(["bridge", "fdb", "del", f[0], "dev", dev, "master"])
            removed += 1
    return removed


def fdb_residue():
    return [
        l for l in run(["bridge", "fdb", "show"]).stdout.splitlines()
        if l.startswith(("02:be:5c", "fe:be:5c"))
    ]


def learn_on(dev, mac, vlan=None):
    """Make the bridge believe it learnt an address on a port of our choosing.

    A `dynamic` entry is what learning produces - not permanent, not self -
    and the kernel announces it the same way, so the daemon cannot tell it
    from the real thing. This is how the wire side is reachable at all in a
    trial that has only one host: an address that turns up on the uplink's own
    port is what a guest migrating away looks like from here, and there is no
    other way to produce one without a second machine sending frames.

    With a VLAN, in the VLAN: on a vlan-aware bridge an entry added without
    one goes in through the vid-0 path and lands in every VLAN the port has -
    twenty-two of them on the host this was written for, which is a far larger
    footprint than the test needs and a far larger one to clean up."""
    # `replace`, not `add`: within a VLAN the address is already on the port
    # the guest is behind, and moving it is exactly what a guest that migrated
    # away looks like. `add` is refused with EEXIST, which is how this scenario
    # first appeared to fail against a daemon that was right.
    cmd = ["bridge", "fdb", "replace", mac_str(mac), "dev", dev, "master", "dynamic"]
    if vlan is not None:
        cmd += ["vlan", str(vlan)]
    # Whether the kernel took it. A port without carrier sits in the
    # disabled state and refuses dynamic entries with EPERM - an uplink
    # nothing is plugged into cannot have a wire imitated on it, and a
    # scenario that failed the daemon over that blamed the wrong party.
    return run(cmd).returncode == 0


def unlearn_on(dev, mac, vlan=None):
    cmd = ["bridge", "fdb", "del", mac_str(mac), "dev", dev, "master"]
    if vlan is not None:
        cmd += ["vlan", str(vlan)]
    run(cmd)


def admin_vf_address(pf, index):
    """The address set for a virtual function *from the host* - which is a
    different field from the netdev's own address, and normally unset.

    Restoring the wrong one is how a benchmark leaves a host changed: writing
    a netdev address back through `ip link set <pf> vf N mac` pins an
    administrative address where there was none, which survives the run and
    can stop a guest later given that function from setting its own."""
    out = run(["ip", "-j", "-d", "link", "show", pf]).stdout
    try:
        info = json.loads(out)[0].get("vfinfo_list", [])
    except (ValueError, IndexError):
        return None
    for vf in info:
        if vf.get("vf") == index:
            return vf.get("address")
    return None


def free_virtual_function(uplink):
    """A virtual function nothing is using, whose address can be borrowed for
    a moment: bound on the host (so not handed to a guest), not the uplink
    itself, in no bridge, administratively down, with no addresses and nothing
    stacked on it.

    Looks both ways - at the uplink's own physical function when the uplink is
    a VF, and at the uplink itself when it is a PF. Only looking sideways made
    this scenario skip itself, silently, on every host whose uplink is a
    physical function.

    None when there is no such function - the ordinary case on a host whose
    functions are all in guests. The scenario then says so and is skipped
    rather than failed."""
    here = f"/sys/class/net/{uplink}/device"
    physfn = f"{here}/physfn"
    pf_dir = os.path.realpath(physfn) if os.path.isdir(physfn) else os.path.realpath(here)
    if not os.path.isdir(f"{pf_dir}/net"):
        return None
    pf_names = os.listdir(f"{pf_dir}/net")
    if not pf_names:
        return None
    pf = pf_names[0]
    for entry in sorted(os.listdir(pf_dir)):
        if not entry.startswith("virtfn"):
            continue
        index = int(entry[len("virtfn"):])
        net = f"{pf_dir}/{entry}/net"
        if not os.path.isdir(net):
            continue  # handed to a guest; not ours to touch
        for name in os.listdir(net):
            if name == uplink or name == pf:
                continue
            base = f"/sys/class/net/{name}"
            if os.path.exists(f"{base}/master"):
                continue  # in a bridge
            if "UP" in read(f"{base}/flags_str") if os.path.exists(f"{base}/flags_str") else False:
                continue
            if read(f"{base}/operstate") == "up":
                continue  # carrying traffic for somebody
            if any(e.startswith("upper_") for e in os.listdir(base)):
                continue  # a macvtap or vlan sits on it
            if run(["ip", "-j", "addr", "show", "dev", name]).stdout.count('"local"'):
                continue  # it answers on an address of its own
            return pf, index, name, admin_vf_address(pf, index)
    return None


def note_bytes(uplink):
    try:
        with open(f"/run/sriov-mac-sync/{uplink}.owned", "rb") as f:
            return f.read()
    except FileNotFoundError:
        return b""


def preflight(args, binary):
    if os.geteuid() != 0:
        fail("this has to run as root")
    if run(["systemctl", "is-active", "--quiet", "sriov-mac-sync"]).returncode != 0:
        fail("sriov-mac-sync.service is not active - the trial needs the accused present")
    execstart = run(["systemctl", "show", "sriov-mac-sync", "-p", "ExecStart"]).stdout
    if "--dry-run" in execstart:
        fail("the daemon runs with --dry-run; it would never register anything")
    if "--pair" in execstart:
        fail("the daemon runs with explicit --pair flags; a fresh --status "
             "cannot see them, so the trial would guard the wrong uplinks")

    pairs = watched_pairs(binary)
    uplinks = [dev for (dev, br) in pairs if br == args.bridge]
    if not uplinks:
        fail(f"the daemon is not watching any uplink on {args.bridge} "
             f"(it watches: {', '.join(f'{d}:{b}' for d, b in pairs) or 'nothing'})")

    if read(f"/sys/class/net/{args.bridge}/bridge/stp_state") != "0":
        fail("STP is enabled on the bridge; adding a port would trigger a "
             "topology change and the trial would measure STP, not the daemon")

    vlan_aware = read(f"/sys/class/net/{args.bridge}/bridge/vlan_filtering") == "1"
    if vlan_aware and args.vlan is None:
        fail("the bridge is VLAN-aware; say --vlan N or the frames land in the default VLAN")
    if args.vlan is not None:
        for up in uplinks:
            vl = run(["bridge", "vlan", "show", "dev", up]).stdout
            # iproute2 prints ranges ("2-4094", the PVE default); a substring
            # match would refuse the very host this was written for.
            member = any(
                int(lo) <= args.vlan <= int(hi or lo)
                for lo, hi in re.findall(r"(\d+)(?:-(\d+))?", vl)
            )
            if not member:
                fail(f"VLAN {args.vlan} is not configured on {up}")

    for dev in (VETH, VETH_PEER):
        if os.path.exists(f"/sys/class/net/{dev}"):
            fail(f"{dev} already exists - a previous run did not clean up; "
                 f"remove it with `ip link del {dev}` and check the filters for 02:be:5c:")

    tables = run(["bridge", "fdb", "show"]).stdout
    for prefix in ("02:be:5c", "fe:be:5c"):
        if prefix in tables:
            fail(f"the test prefix {prefix} is already present somewhere in a "
                 f"forwarding table - not touching anything")

    for up in uplinks:
        # multicast self entries do not live in the UC vport list the
        # 128-entry limit is about
        occupied = sum(1 for m in self_macs(up) if int(m[:2], 16) & 1 == 0)
        if occupied + TEST_MACS_TOTAL + CAPACITY_MARGIN > FILTER_CAPACITY:
            fail(f"{up} holds {occupied} entries; adding {TEST_MACS_TOTAL} would "
                 f"come within {CAPACITY_MARGIN} of the {FILTER_CAPACITY}-entry "
                 f"filter, which drops addresses silently past its limit")
    return uplinks


class Trial:
    def __init__(self, args, binary, uplinks, cleanup):
        self.cleanup = cleanup
        self.args = args
        self.binary = binary
        self.uplinks = uplinks
        self.uplink_idx = {int(read(f"/sys/class/net/{u}/ifindex")): u for u in uplinks}
        self.results = []  # (scenario, passed, detail)
        self.next_mac = 0

    def macs(self, n):
        out = []
        for _ in range(n):
            out.append(SRC_PREFIX + bytes([self.next_mac >> 8, self.next_mac & 0xFF]))
            self.next_mac += 1
        return out

    def verdict(self, name, passed, detail):
        self.results.append((name, passed, detail))
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}: {detail}")

    def setup_port(self):
        # IPv6 fully off on both ends, and the VLAN before anything comes
        # up: addrgenmode none alone only withholds the address - the stack
        # still emits an MLD report from the port's MAC, which the bridge
        # floods out of the uplink into the real network. Found the honest
        # way: a later run on the neighbour host refused itself because it
        # discovered exactly that MAC learnt on its wire side.
        cmds = [
            ["ip", "link", "add", VETH, "address", PORT_MAC,
             "type", "veth", "peer", "name", VETH_PEER, "address", PEER_MAC],
            ["sysctl", "-qw", f"net.ipv6.conf.{VETH}.disable_ipv6=1"],
            ["sysctl", "-qw", f"net.ipv6.conf.{VETH_PEER}.disable_ipv6=1"],
            ["ip", "link", "set", VETH, "addrgenmode", "none"],
            ["ip", "link", "set", VETH_PEER, "addrgenmode", "none"],
            ["ip", "link", "set", VETH, "master", self.args.bridge],
        ]
        if self.args.vlan is not None:
            cmds.append(["bridge", "vlan", "add", "dev", VETH, "vid",
                         str(self.args.vlan), "pvid", "untagged"])
        cmds += [
            ["ip", "link", "set", VETH, "up"],
            ["ip", "link", "set", VETH_PEER, "up"],
        ]
        for cmd in cmds:
            r = run(cmd)
            if r.returncode != 0:
                fail(f"{' '.join(cmd)}: {r.stderr.strip()}")
        self.port_idx = int(read(f"/sys/class/net/{VETH}/ifindex"))
        self.tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.tx.bind((VETH_PEER, 0))

    def send(self, mac):
        # dst == src: the bridge learns the source at ingress, then finds the
        # destination on that very port and drops the frame - source-port
        # suppression. Nothing leaves bench0, in any VLAN, yet the learn
        # notification fires all the same. Every cleverer destination leaked
        # somewhere: the bridge's own MAC is unknown unicast outside the
        # bridge-self VIDs (flooded to the wire), and the port's own MAC is a
        # LOCAL entry - "deliver to the host" - which climbs the VLAN stack
        # into the bridges above and their guests.
        self.tx.send(mac + mac + ETHERTYPE.to_bytes(2, "big") + b"\x00" * 46)
        return time.monotonic_ns()

    def await_registered(self, mon, macs, deadline_ns):
        """Wait until every mac has a self entry on every watched uplink."""
        while time.monotonic_ns() < deadline_ns:
            mon.pump(min(deadline_ns, time.monotonic_ns() + 50_000_000))
            if all(len(mon.selfs(m, self.uplink_idx)) == len(self.uplinks) for m in macs):
                return True
        return False

    def latency(self, mon, mac):
        """learn -> last self across the uplinks, from the kernel's stream."""
        learns = mon.learns(mac, self.port_idx)
        selfs = mon.selfs(mac, self.uplink_idx)
        if not learns or len(selfs) != len(self.uplinks):
            return None
        return max(selfs.values()) - min(learns)

    def noted(self, mac, deadline_s=1.0):
        # The kernel event fires inside set_self_fdb; the note is written
        # after the whole add/remove loop - a single read can race it.
        s = mac_str(mac)
        end = time.monotonic() + deadline_s
        while True:
            if all(s in note_bytes(u).decode(errors="replace") for u in self.uplinks):
                return True
            if time.monotonic() > end:
                return False
            time.sleep(0.05)

    # --- scenarios -------------------------------------------------------

    def s1_fast_path(self, mon):
        print("\nS1  fast path, one address at a time")
        macs = self.macs(8)
        lats = []
        for m in macs:
            self.send(m)
            self.await_registered(mon, [m], time.monotonic_ns() + 3_000_000_000)
            time.sleep(0.3)  # generous spacing: each address stands alone
        mon.pump(time.monotonic_ns() + 200_000_000)
        for m in macs:
            l = self.latency(mon, m)
            if l is not None:
                lats.append(l)
        ok = len(lats) == len(macs) and all(self.noted(m) for m in macs)
        lats.sort()
        detail = (f"{len(lats)}/8 registered+noted on {len(self.uplinks)} uplink(s); "
                  f"latency min {fmt_ms(lats[0])} median {fmt_ms(percentile(lats, 0.5))} "
                  f"max {fmt_ms(lats[-1])}" if lats else "no address made it")
        self.verdict("fast path", ok, detail)

    def s2_settle_path(self, mon):
        print("\nS2  the second of two addresses sent 50 ms apart")
        lats = []
        pairs_ok = 0
        for _ in range(4):
            a, b = self.macs(2)
            self.send(a)
            time.sleep(0.05)  # b follows a closely, as devices in a burst do
            self.send(b)
            self.await_registered(mon, [a, b], time.monotonic_ns() + 6_000_000_000)
            l = self.latency(mon, b)
            if l is not None and self.noted(a) and self.noted(b):
                pairs_ok += 1
                lats.append(l)
            time.sleep(3)  # let the follow-up pass finish before the next pair
        ok = pairs_ok == 4
        lats.sort()
        detail = (f"{pairs_ok}/4 pairs; second-address latency min {fmt_ms(lats[0])} "
                  f"median {fmt_ms(percentile(lats, 0.5))} max {fmt_ms(lats[-1])} "
                  f"(the price of arriving in close succession)" if lats else "none made it")
        self.verdict("settle path", ok, detail)

    def s3_burst(self, mon):
        print("\nS3  sixteen addresses in one burst")
        macs = self.macs(16)
        for m in macs:
            self.send(m)
        done = self.await_registered(mon, macs, time.monotonic_ns() + 8_000_000_000)
        # One figure only: per-address stamps inside one receive batch would
        # be scheduling noise dressed up as precision.
        first = min((t for m in macs for t in mon.learns(m, self.port_idx)), default=None)
        last = max((t for m in macs for t in mon.selfs(m, self.uplink_idx).values()),
                   default=None)
        ok = done and all(self.noted(m) for m in macs)
        if ok and first is not None and last is not None:
            detail = (f"all 16 registered+noted, first learn to last register "
                      f"{fmt_ms(last - first)}")
        elif ok:
            detail = "all 16 registered+noted (monitor missed stamps for the figure)"
        else:
            detail = "not all sixteen arrived"
        self.verdict("burst of 16", ok, detail)

    def s4_pass_stats(self):
        print(f"\nS4  {self.args.rounds} cold passes of --once --dry-run --timings")
        def cpufreq(what):
            try:
                return read(f"/sys/devices/system/cpu/cpu0/cpufreq/{what}")
            except OSError:
                return "?"

        gov = cpufreq("scaling_governor")
        freq = cpufreq("scaling_cur_freq")
        phases = {}
        failures = 0
        for _ in range(self.args.rounds):
            r = run([self.binary, "--once", "--dry-run", "--timings"])
            if r.returncode != 0:
                failures += 1
                continue
            # --timings prints to stdout (with the rest of a one-shot run's output);
            # older harnesses read stderr and saw nothing.
            for line in r.stdout.splitlines():
                m = re.match(r"\s+(pass total|topology|fdb dump|vf macs|orphans|pairs)\s+([0-9.]+) ms",
                             line)
                if m:
                    phases.setdefault(m.group(1), []).append(float(m.group(2)))
        ok = failures == 0 and "pass total" in phases
        print(f"      governor {gov}, cpu0 at {freq} kHz before; "
              f"{cpufreq('scaling_cur_freq')} after")
        for name in ("pass total", "topology", "fdb dump", "vf macs", "orphans", "pairs"):
            vals = sorted(phases.get(name, []))
            if vals:
                print(f"      {name:10s} min {vals[0]:7.2f}  median "
                      f"{percentile(vals, 0.5):7.2f}  p95 {percentile(vals, 0.95):7.2f}  "
                      f"max {vals[-1]:7.2f} ms  (n={len(vals)})")
        detail = (f"{self.args.rounds - failures}/{self.args.rounds} passes; this is the "
                  f"cold form (fresh process and topology) - event latency is S1")
        self.verdict("cold pass statistics", ok, detail)

    def s5_reflection(self, mon):
        """A guest that moved to another host: its address, which we
        registered while it was here, starts being learnt on the uplink's own
        port. The registration is now worse than useless - the eSwitch keeps
        handing that traffic to the uplink, and the bridge cannot send it back
        out of the port it arrived on - so it has to come out."""
        print("\nS5  an address of ours turns up on the wire")
        mac = self.macs(1)[0]
        self.send(mac)
        if not self.await_registered(mon, [mac], time.monotonic_ns() + 3_000_000_000):
            self.verdict("wire reflection", False,
                         "the address was never registered, so nothing could "
                         "be reflected - see S1")
            return
        # One uplink, not all of them: an address on this uplink's wire is
        # behind the bridge as far as a second uplink of the same bridge is
        # concerned, and registered there quite correctly. Requiring it gone
        # everywhere would fail a daemon doing the right thing.
        uplink = self.uplinks[0]
        t0 = time.monotonic_ns()
        if not learn_on(uplink, mac, self.args.vlan):
            self.verdict("wire reflection", True,
                         f"skipped: {uplink} has no carrier, and a port in "
                         "the disabled state refuses the dynamic entry that "
                         "imitates the wire - nothing to reflect from")
            return
        deadline = t0 + 5_000_000_000
        gone = False
        while time.monotonic_ns() < deadline and not gone:
            mon.pump(time.monotonic_ns() + 100_000_000)
            gone = mac_str(mac) not in self_macs(uplink)
        took = (time.monotonic_ns() - t0) / 1e6
        noted_gone = mac_str(mac).encode() not in note_bytes(uplink)
        unlearn_on(uplink, mac, self.args.vlan)
        self.verdict(
            "wire reflection", gone and noted_gone,
            f"unregistered {took:.1f} ms after the address appeared on the "
            f"uplink port, note cleared" if gone and noted_gone else
            ("still in the filter after 5 s - a guest that moved away is a "
             "black hole until the next pass" if not gone else
             "out of the filter but still in the note - nothing owns it now"))

    def s6_vf_address(self, mon):
        """A virtual function's own address must never be registered.
        Registering it tells the eSwitch that the guest holding that function
        lives behind the bridge, and its traffic is sent past it.

        The address is set from the host here, which is what a guest setting
        its own does from the outside: the kernel announces it as a link
        message and nothing in the forwarding tables moves."""
        print("\nS6  an address that belongs to a virtual function")
        # preflight() already narrowed the uplinks to this bridge's, which
        # matters here: a virtual function of some other card's physical
        # function is an ordinary foreign address as far as this bridge is
        # concerned, and registering it would be correct.
        uplink = self.uplinks[0]
        found = free_virtual_function(uplink)
        if not found:
            self.verdict("virtual function address", True,
                         "skipped: no virtual function of this uplink's own "
                         "physical function is free to borrow an address from")
            return
        pf, index, vf_name, original = found
        # `None` means the driver reports no administrative address for it;
        # putting the netdev's own address there instead would pin one where
        # there was none, which survives the run.
        original = original or "00:00:00:00:00:00"
        mac = self.macs(1)[0]
        cleanup_vf = (pf, index, original)
        self.cleanup.vf_address = cleanup_vf
        set_mac = run(["ip", "link", "set", pf, "vf", str(index), "mac", mac_str(mac)])
        if set_mac.returncode != 0:
            # Without the address actually set there is nothing to exclude,
            # and the daemon would be failed for registering an ordinary
            # address correctly.
            self.cleanup.vf_address = None
            self.verdict("virtual function address", True,
                         f"skipped: {pf} vf {index} would not take an address "
                         f"({set_mac.stderr.strip()})")
            return
        # The kernel reports what it accepted; a driver may refuse quietly.
        if mac_str(mac) not in run(["ip", "-d", "link", "show", pf]).stdout:
            run(["ip", "link", "set", pf, "vf", str(index), "mac", original])
            self.cleanup.vf_address = None
            self.verdict("virtual function address", True,
                         f"skipped: {pf} vf {index} did not take the address")
            return
        time.sleep(1.5)  # the link message, and the pass that answers it

        # ... and now something behind the bridge speaks with that address.
        self.send(mac)
        time.sleep(1.5)
        mon.pump(time.monotonic_ns() + 200_000_000)
        registered = mac_str(mac) in self_macs(uplink)

        run(["ip", "link", "set", pf, "vf", str(index), "mac", original])
        restored = admin_vf_address(pf, index)
        self.cleanup.vf_address = None
        if restored != original:
            self.verdict(
                "virtual function address", False,
                f"{pf} vf {index} was left at {restored} instead of {original} - "
                f"put it back by hand with `ip link set {pf} vf {index} mac "
                f"{original}`")
            purge_learned_residue()
            return
        if registered:
            run(["bridge", "fdb", "del", mac_str(mac), "dev", uplink, "self", "permanent"])
        purge_learned_residue()
        self.verdict(
            "virtual function address", not registered,
            f"{vf_name}'s address stayed out of {uplink}'s filter while the "
            f"bridge had learnt it" if not registered else
            f"REGISTERED on {uplink} - the guest holding {vf_name} would have "
            f"its traffic sent past it")

    def s7_teardown(self, mon):
        print("\nS7  the port disappears; everything has to come back out")
        t0 = time.monotonic_ns()
        run(["ip", "link", "del", VETH])
        purged = purge_learned_residue()
        if purged:
            print(f"      ({purged} learned copies swept out of the stacked "
                  f"bridges - a promiscuous bridge hands every frame upstairs)")
        deadline = t0 + 15_000_000_000
        clean = False
        while time.monotonic_ns() < deadline and not clean:
            mon.pump(time.monotonic_ns() + 200_000_000)
            clean = all(
                not any(m.startswith(("02:be:5c", "fe:be:5c")) for m in self_macs(u))
                and b"02:be:5c" not in note_bytes(u)
                and b"fe:be:5c" not in note_bytes(u)
                for u in self.uplinks
            )
        # A bound, not a latency: removal is full-pass work and the pass is
        # rate-limited, so anything inside the bound is simply correct.
        detail = (f"filters and notes clean on all uplinks within "
                  f"{(time.monotonic_ns() - t0) / 1e9:.1f} s (bound 15 s)"
                  if clean else "TEST ENTRIES LEFT BEHIND - see cleanup advice below")
        self.verdict("removal after port loss", clean, detail)
        return clean

    def s8_quiescence(self, since_epoch, pre_state):
        print("\nS8  the daemon's own account, and the state afterwards")
        j = run(["journalctl", "-u", "sriov-mac-sync", "-q",
                 "--since", f"@{since_epoch}", "-o", "cat"])
        noise = [l for l in j.stdout.splitlines()
                 if re.search(r"warning|error", l, re.I)]
        timed = [l for l in j.stdout.splitlines()
                 if "[timed]" in l and re.search(r"\+[1-9]|-[1-9]", l)]
        post = {u: (self_macs(u), note_bytes(u)) for u in self.uplinks}
        # The trial's own footprint has to be gone; the rest of the bridge is
        # a live network whose guests come and go - that drift is the
        # daemon's ordinary work, reported but never blamed on the trial.
        residue = [
            m
            for u in self.uplinks
            for m in post[u][0]
            if m.startswith(("02:be:5c", "fe:be:5c"))
        ] + fdb_residue()
        drift = {
            u
            for u in self.uplinks
            if post[u] != pre_state[u]
        }
        ok = not noise and not timed and not residue
        problems = []
        if noise:
            problems.append(f"{len(noise)} warning/error line(s): {noise[0]!r}")
        if timed:
            problems.append(f"[timed] pass had to fix something: {timed[0]!r} "
                            "- the event path missed it")
        if residue:
            problems.append(f"test residue left in filters: {residue}")
        note = ""
        if drift and not residue:
            note = (f" (ambient change on {', '.join(sorted(drift))} - "
                    f"real guests coming or going, not the trial's doing)")
        self.verdict("quiescence and state", ok,
                     ("; ".join(problems) if problems else
                      "journal quiet, no [timed] corrections, no test residue")
                     + note)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("bridge")
    ap.add_argument("--vlan", type=int)
    ap.add_argument("--rounds", type=int, default=100,
                    help="cold --once passes for the statistics section")
    ap.add_argument("--binary", default="/usr/local/sbin/sriov-mac-sync")
    ap.add_argument("--governor", default="performance",
                    help="CPU governor to pin for the run, restored at the end; "
                         "'leave' measures the machine as it is (default: "
                         "performance)")
    args = ap.parse_args()

    uplinks = preflight(args, args.binary)
    print(f"On trial: sriov-mac-sync on {args.bridge}, "
          f"uplink(s) {', '.join(uplinks)}"
          + (f", VLAN {args.vlan}" if args.vlan is not None else ""))

    try:  # keep our timestamps honest on a busy host; fine to go without
        os.sched_setscheduler(0, os.SCHED_FIFO, os.sched_param(10))
    except (OSError, AttributeError):
        print("(running without SCHED_FIFO; timestamps carry scheduling noise)")

    governor = Governor()
    if args.governor != "leave":
        governor.pin(args.governor)
    else:
        print(f"governor: left as found ({governor.describe()})")

    since_epoch = f"{time.time():.6f}"
    pre_state = {u: (self_macs(u), note_bytes(u)) for u in uplinks}

    cleanup = Cleanup()
    cleanup.arm()
    mon = Monitor()

    t = Trial(args, args.binary, uplinks, cleanup)
    t.setup_port()
    time.sleep(2.5)  # the port add is an interface event; let its pass run

    t.s1_fast_path(mon)
    t.s2_settle_path(mon)
    t.s3_burst(mon)
    t.s4_pass_stats()
    t.s5_reflection(mon)
    t.s6_vf_address(mon)
    clean = t.s7_teardown(mon)
    cleanup.done = True  # the veth is gone; nothing else was ever created
    time.sleep(1)
    t.s8_quiescence(since_epoch, pre_state)

    print("\n" + "=" * 64)
    print(f"Measured with the governor at: {governor.describe()}")
    failed = [n for (n, ok, _) in t.results if not ok]
    if failed:
        print(f"VERDICT: FAILED ({', '.join(failed)})")
        if not clean:
            print("Cleanup left to you: for every remaining 02:be:5c / "
                  "fe:be:5c address:")
            for u in uplinks:
                print(f"  bridge fdb del <mac> dev {u} self permanent")
            print("Do NOT edit the note files - the daemon heals them itself "
                  "(ENOENT on the next pass).")
        sys.exit(1)
    print("VERDICT: PASSED - every situation came out right; "
          "the numbers above say what it cost.")
    print("(Latency boundary: kernel notification; the NIC is programmed "
          "asynchronously just after. Compare software states only with "
          "interleaved trials.)")


if __name__ == "__main__":
    main()
