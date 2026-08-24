#!/usr/bin/env python3
"""Put the running daemon on trial.

One run provokes the situations the daemon exists for, verifies that each
came out right, and reports what it cost:

  S1  eight addresses learnt one at a time   -> fast-path latency, each
  S2  four addresses landing mid-settle      -> full-pass latency, separately
  S3  a burst of sixteen at once             -> burst turnaround, one figure
  S4  a hundred cold passes of --once        -> per-phase min/median/p95/max
  S5  the test port deleted                  -> everything taken back, bounded
  S6  the daemon's own journal and the state -> quiet, and byte-identical

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
import atexit
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


class Cleanup:
    """Tear down in the one order that leaves evidence: stop injecting,
    keep the monitor until the removals are seen, then the veth, then verify.
    PID-based and idempotent; pkill -f has killed its own SSH session before."""

    def __init__(self):
        self.done = False

    def __call__(self, *_):
        if self.done:
            return
        self.done = True
        subprocess.run(["ip", "link", "del", VETH], capture_output=True)
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
    def __init__(self, args, binary, uplinks):
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
        # addrgenmode none, and the VLAN before anything comes up: a veth
        # that goes up starts IPv6 address configuration, and its multicast
        # would land in the default PVID - the real network - sourced from a
        # MAC the daemon would then dutifully register.
        cmds = [
            ["ip", "link", "add", VETH, "address", PORT_MAC,
             "type", "veth", "peer", "name", VETH_PEER, "address", PEER_MAC],
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
        # dst = bench0's own address: our `bridge vlan add dev bench0` gives
        # that MAC a local FDB entry in the test VLAN itself, so the frame
        # terminates at the ingress port in the plain and the VLAN-aware case
        # alike. The bridge's own MAC would NOT do: on a VLAN-aware bridge it
        # is local only in the VIDs of the bridge-self port, and everything
        # else is unknown unicast - flooded out of the uplink into the real
        # network.
        self.dst = mac_bytes(PORT_MAC)
        self.tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.tx.bind((VETH_PEER, 0))

    def send(self, mac):
        self.tx.send(self.dst + mac + ETHERTYPE.to_bytes(2, "big") + b"\x00" * 46)
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
            time.sleep(0.3)  # stay clear of the 200 ms settle lull on purpose
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
        print("\nS2  an address arriving mid-settle (the slow, ordinary case)")
        lats = []
        pairs_ok = 0
        for _ in range(4):
            a, b = self.macs(2)
            self.send(a)
            time.sleep(0.05)  # b lands inside a's settle window
            self.send(b)
            self.await_registered(mon, [a, b], time.monotonic_ns() + 6_000_000_000)
            l = self.latency(mon, b)
            if l is not None and self.noted(a) and self.noted(b):
                pairs_ok += 1
                lats.append(l)
            time.sleep(3)  # let settle + pass finish before the next pair
        ok = pairs_ok == 4
        lats.sort()
        detail = (f"{pairs_ok}/4 pairs; second-address latency min {fmt_ms(lats[0])} "
                  f"median {fmt_ms(percentile(lats, 0.5))} max {fmt_ms(lats[-1])} "
                  f"(includes the daemon's settle window by design)" if lats else "none made it")
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
            for line in r.stderr.splitlines():
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

    def s5_teardown(self, mon):
        print("\nS5  the port disappears; everything has to come back out")
        t0 = time.monotonic_ns()
        run(["ip", "link", "del", VETH])
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
        # A bound, not a latency: the figure is dominated by the daemon's own
        # 2 s settle window, so anything inside the bound is simply correct.
        detail = (f"filters and notes clean on all uplinks within "
                  f"{(time.monotonic_ns() - t0) / 1e9:.1f} s (bound 15 s)"
                  if clean else "TEST ENTRIES LEFT BEHIND - see cleanup advice below")
        self.verdict("removal after port loss", clean, detail)
        return clean

    def s6_quiescence(self, since_epoch, pre_state):
        print("\nS6  the daemon's own account, and the state afterwards")
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
        ]
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
    args = ap.parse_args()

    uplinks = preflight(args, args.binary)
    print(f"On trial: sriov-mac-sync on {args.bridge}, "
          f"uplink(s) {', '.join(uplinks)}"
          + (f", VLAN {args.vlan}" if args.vlan is not None else ""))

    try:  # keep our timestamps honest on a busy host; fine to go without
        os.sched_setscheduler(0, os.SCHED_FIFO, os.sched_param(10))
    except (OSError, AttributeError):
        print("(running without SCHED_FIFO; timestamps carry scheduling noise)")

    since_epoch = f"{time.time():.6f}"
    pre_state = {u: (self_macs(u), note_bytes(u)) for u in uplinks}

    cleanup = Cleanup()
    cleanup.arm()
    mon = Monitor()

    t = Trial(args, args.binary, uplinks)
    t.setup_port()
    time.sleep(2.5)  # the port add is an interface event; let its settle pass

    t.s1_fast_path(mon)
    t.s2_settle_path(mon)
    t.s3_burst(mon)
    t.s4_pass_stats()
    clean = t.s5_teardown(mon)
    cleanup.done = True  # the veth is gone; nothing else was ever created
    time.sleep(1)
    t.s6_quiescence(since_epoch, pre_state)

    print("\n" + "=" * 64)
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
