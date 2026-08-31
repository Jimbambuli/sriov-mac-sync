#!/bin/bash
# Run the daemon against a real kernel bridge and check every mode's promise.
#
# The unit tests drive the code against a fake socket; this drives the built
# binary against the kernel itself, inside a throwaway network namespace: a
# bridge, a veth pair standing in for the uplink, a second one standing in
# for a guest port. The NTF_SELF entries land in the veth's own unicast
# filter through the same ndo_dflt_fdb path a real NIC without a driver
# handler uses, so what is asserted here is the daemon's whole conversation
# with the kernel - requests, acknowledgements, notifications, /sys - with
# only the eSwitch itself missing. bench/trial.py covers that, on hardware.
#
# Needs root and iproute2, creates the namespace "sms-it", and uses the real
# /run/sriov-mac-sync - so it refuses to run where a daemon is already
# working. Everything it creates is removed on exit, pass or fail.
#
#   sudo bench/integration.sh target/release/sriov-mac-sync
set -u
BIN="${1:?usage: integration.sh <path-to-binary>}"
NS="ip netns exec sms-it"
STATE=/run/sriov-mac-sync
PASS=0
FAIL=0
DPID=""

say() { echo "== $*"; }

# Bounded stop for scenario daemons: S6 proves prompt termination once;
# the others must not hang the whole suite if that ever regresses.
stop_daemon() {
  kill -TERM "$DPID" 2>/dev/null
  for _ in $(seq 1 30); do
    kill -0 "$DPID" 2>/dev/null || { wait "$DPID" 2>/dev/null; DPID=""; return; }
    sleep 0.1
  done
  kill -9 "$DPID" 2>/dev/null
  wait "$DPID" 2>/dev/null
  DPID=""
}
ok() {
  PASS=$((PASS + 1))
  echo "   PASS: $*"
}
bad() {
  FAIL=$((FAIL + 1))
  echo "   FAIL: $*"
}
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
# Same, but give an event-driven daemon up to five seconds to get there.
# A fixed sleep either flakes or slows every run down to the worst case.
check_soon() {
  for _ in $(seq 1 50); do
    eval "$2" && break
    sleep 0.1
  done
  check "$1" "$2"
}
# A self entry is a line carrying the self flag; a master entry for the same
# address does not, and `bridge fdb show dev X self` prints both.
has_self() { $NS bridge fdb show dev veth-up | grep "$1" | grep -q self; }

# Up and listening, said by the daemon itself rather than guessed at: it
# prints what it is watching once its first pass is done, and everything a
# scenario does afterwards depends on that having happened.
wait_ready() {
  for _ in $(seq 1 50); do
    grep -q "watching" "$1" && return 0
    sleep 0.1
  done
  echo "   note: the daemon never said what it was watching" >&2
}

# A scenario daemon on the shared pair, logging to the named file.
start_daemon() {
  $NS "$BIN" --pair veth-up:br0 --interval 1 >"$1" 2>&1 &
  DPID=$!
  wait_ready "$1"
}

# Re-create the guest port and M1's registration for whatever follows a
# scenario that deleted veth-g1. The port sits in state disabled until
# linkwatch runs, and a dynamic entry on a disabled port earns EPERM - the
# restore would silently never happen, the same race trial.py guards
# against - hence the wait for forwarding.
restore_guest_port() {
  $NS ip link add veth-g1 type veth peer name veth-g1P
  $NS ip link set veth-g1 master br0
  $NS sh -c 'ip link set veth-g1 up; ip link set veth-g1P up'
  for _ in $(seq 1 50); do
    $NS bridge link show dev veth-g1 2>/dev/null | grep -q "state forwarding" && break
    sleep 0.1
  done
  $NS bridge fdb replace $M1 dev veth-g1 master dynamic
  $NS "$BIN" --once --pair veth-up:br0 >/dev/null 2>&1
}

cleanup() {
  # Only the PID this script started - a pattern kill would match any
  # process whose command line mentions the path. stop_daemon waits and
  # escalates: the rm -rf below racing a daemon that is still writing
  # recreates the state directory, and every later run then refuses with
  # "state directory exists" until a hand cleans up.
  if [ -n "$DPID" ]; then
    stop_daemon
  fi
  ip netns del sms-it 2>/dev/null
  rm -rf "$STATE" "$SNAP"
}

# Refusals before anything is touched - and before the cleanup trap is
# armed, because the trap removes the state directory, and the whole point
# of one refusal is that a real daemon's state directory is already there.
[ "$(id -u)" -eq 0 ] || {
  echo "error: needs root (creates a network namespace)" >&2
  exit 2
}
command -v ip >/dev/null && command -v bridge >/dev/null || {
  echo "error: needs iproute2 (ip and bridge)" >&2
  exit 2
}
if pgrep -x sriov-mac-sync >/dev/null 2>&1; then
  echo "error: a sriov-mac-sync is already running on this host - not testing beside it" >&2
  exit 2
fi
if [ -e "$STATE" ]; then
  echo "error: $STATE exists - a daemon has state here, not testing over it" >&2
  exit 2
fi
[ -x "$BIN" ] || {
  echo "error: $BIN is not an executable binary" >&2
  exit 2
}
BIN=$(readlink -f "$BIN")

SNAP=$(mktemp)
trap cleanup EXIT
# Interface NAMES, not `ip -br link` in full: the state column of a host
# this suite never touches can change under it - a runner brings a service
# up mid-run - and that is not this suite having leaked anything. What it
# could leak is an interface, and an interface has a name.
ip -br link | awk '{print $1}' | sort >"$SNAP"
ip netns del sms-it 2>/dev/null
ip netns add sms-it
# No IPv6 anywhere in here, set before a single interface exists so that
# `default` covers the ones made below. An interface that comes up with IPv6
# sends duplicate-address detection and a listener report, and the bridge
# learns the sender - a veth peer's own address - some tens of milliseconds
# after the link came up. That is a second learner arriving on its own
# schedule, in the middle of a test whose whole subject is what the daemon
# does about what the bridge has learnt: S2 asks whether a second pass
# changes anything, and a peer's address landing between the two passes made
# the answer yes, correctly and at random. Nothing here needs IP at all - the
# addresses are put in the forwarding table by hand.
$NS sysctl -q -w net.ipv6.conf.default.disable_ipv6=1
$NS sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
$NS ip link set lo up
$NS ip link add br0 type bridge
$NS ip link add veth-up type veth peer name veth-upP
$NS ip link add veth-g1 type veth peer name veth-g1P
$NS ip link set veth-up master br0
$NS ip link set veth-g1 master br0
$NS sh -c 'for i in br0 veth-up veth-upP veth-g1 veth-g1P; do ip link set $i up; done'
$NS ip link set br0 type bridge stp_state 0

# And then wait for the table to stop moving before anything is asserted
# about it. Disabling IPv6 removes the learner this test has actually been
# seen to trip over; the wait is what makes the test independent of there
# being another one - a kernel that announces something new at link-up, a
# distribution that runs something in a fresh namespace. Three identical
# readings in a row, or two seconds, whichever comes first; a table still
# moving after two seconds is reported rather than silently tested on.
settle_fdb() {
  local last="" now="" same=0 tries=0
  while [ "$tries" -lt 20 ]; do
    tries=$((tries + 1))
    now=$($NS bridge fdb show br br0)
    if [ "$now" = "$last" ]; then
      same=$((same + 1))
      [ "$same" -ge 2 ] && return 0
    else
      same=0
    fi
    last="$now"
    sleep 0.1
  done
  echo "   note: the forwarding table was still changing after 2 s" >&2
  return 0
}
settle_fdb

M1=02:be:5c:00:00:11
M2=02:be:5c:00:00:12

say "S1: --once registers what the bridge learnt and notes it"
$NS bridge fdb add $M1 dev veth-g1 master dynamic
$NS "$BIN" --once --pair veth-up:br0 >/tmp/sms-it-s1.log 2>&1
RC=$?
check "exit 0" "[ $RC -eq 0 ]"
check "M1 in the self filter" "has_self $M1"
check "M1 in the note" "grep -q $M1 $STATE/veth-up.owned"

say "S2: a second --once changes nothing"
# Idempotence is the claim, so what is compared is the filter and the note
# either side of the pass, not only what the pass said about itself. A pass
# that registered and unregistered the same address would print nothing and
# still not be idempotent.
FILTER_BEFORE=$($NS bridge fdb show dev veth-up)
NOTE_BEFORE=$(cat $STATE/veth-up.owned)
$NS "$BIN" --once --pair veth-up:br0 >/tmp/sms-it-s2.log 2>&1
check "exit 0" "[ $? -eq 0 ]"
check "no +/- line" "! grep -qE '^veth-up: [+-]' /tmp/sms-it-s2.log"
check "filter unchanged" "[ \"$FILTER_BEFORE\" = \"$($NS bridge fdb show dev veth-up)\" ]"
check "note unchanged" "[ \"$NOTE_BEFORE\" = \"$(cat $STATE/veth-up.owned)\" ]"

say "S3: --dry-run touches nothing"
$NS bridge fdb add $M2 dev veth-g1 master dynamic
NOTE_BEFORE=$(cat $STATE/veth-up.owned)
$NS "$BIN" --once --dry-run -v --pair veth-up:br0 >/tmp/sms-it-s3.log 2>&1
check "M2 NOT in the filter" "! has_self $M2"
check "note unchanged" "[ \"$NOTE_BEFORE\" = \"$(cat $STATE/veth-up.owned)\" ]"
# -v on a single pass lists the addresses themselves, under a heading that
# names the uplink - the report line above it appears only when something
# changed, so on a quiet host it is not there to name anything.
check "the addresses are listed" "grep -q '^    $M2$' /tmp/sms-it-s3.log"
check "the list is headed" "grep -q 'veth-up: .* address(es) wanted' /tmp/sms-it-s3.log"

say "S4: the daemon's fast path registers within seconds"
$NS "$BIN" --pair veth-up:br0 >/tmp/sms-it-s4.log 2>&1 &
DPID=$!
wait_ready /tmp/sms-it-s4.log
$NS bridge fdb replace $M2 dev veth-g1 master dynamic
check_soon "M2 in the filter (fast path)" "has_self $M2"
check_soon "M2 in the note" "grep -q $M2 $STATE/veth-up.owned"

say "S5: an address that moves out onto the wire is unregistered"
$NS bridge fdb replace $M2 dev veth-up master dynamic
check_soon "M2 self entry removed" "! has_self $M2"
check_soon "M2 out of the note" "! grep -q $M2 $STATE/veth-up.owned"
check_soon "reflection line in the log" "grep -q 'reflection' /tmp/sms-it-s4.log"

say "S6: SIGTERM stops the daemon promptly and the notes survive"
kill -TERM $DPID
T0=$(date +%s%N)
# Bounded: an unbounded wait on the very property under test would hang
# the suite on a regression instead of failing it.
DEAD=""
for _ in $(seq 1 30); do
  kill -0 $DPID 2>/dev/null || { DEAD=1; break; }
  sleep 0.1
done
T1=$(date +%s%N)
MS=$(((T1 - T0) / 1000000))
if [ -z "$DEAD" ]; then kill -9 $DPID 2>/dev/null; fi
wait $DPID 2>/dev/null
DPID=""
check "exit within 3 s (took ${MS}ms)" "[ -n \"$DEAD\" ] && [ $MS -lt 3000 ]"
check "note survives" "[ -s $STATE/veth-up.owned ]"
check "parting line" "grep -qi 'left registered' /tmp/sms-it-s4.log"

say "S6b: a short-interval daemon repairs what happened behind its back"
$NS "$BIN" --pair veth-up:br0 --interval 1 --timings >/tmp/sms-it-s6b.log 2>&1 &
DPID=$!
check_soon "the restart pass calls itself [start]" "grep -q 'pass \[start\]' /tmp/sms-it-s6b.log"
# Removed by hand, behind the daemon's back. The deletion notification may
# buy a prompt pass, the 1-second refresh certainly follows - either way
# the entry has to come back without anyone asking.
$NS bridge fdb del $M1 dev veth-up self permanent
check_soon "M1 restored" "has_self $M1"
check_soon "a pass reported the repair" "grep -qE '\+1' /tmp/sms-it-s6b.log"
stop_daemon

say "S6c: a quiet guest outlives the bridge's ageing while its port does"
# The port's KIND does not matter to the keep - quiet_survivors judges by
# edges and indices alone, which is why the dummy-port twin this scenario
# once had proved nothing a veth does not; the unit suite pins the
# physical-port arm on the fixture instead.
start_daemon /tmp/sms-it-s6c.log
$NS bridge fdb replace $M2 dev veth-g1 master dynamic
check_soon "M2 registered while learnt" "has_self $M2"
# The bridge forgets - the kernel announces it exactly as ageing does -
# while veth-g1 lives on. The keep must hold the entry.
KEPT_BEFORE=$(grep -c 'kept \[quiet\]' /tmp/sms-it-s6c.log || true)
$NS bridge fdb del $M2 dev veth-g1 master
# Waited on the daemon's own account of having dealt with THIS deletion,
# not on a guess at how long that takes and not on a line an earlier
# scenario left in the log: the entry surviving is only worth asserting
# once the pass that could have removed it has run.
check_soon "the keep is said" \
  "[ \"\$(grep -c 'kept \[quiet\]' /tmp/sms-it-s6c.log)\" -gt $KEPT_BEFORE ]"
check "M2 kept after ageing (port lives)" "has_self $M2"
# The guest actually stops: the veth goes, and the entry must follow.
$NS ip link del veth-g1
check_soon "M2 gone once its port is" "! has_self $M2"
stop_daemon
restore_guest_port

say "S6f: the filter fills up and a keep buys the newcomer its slot"
# The valve, end to end - unit tests aside, nothing has ever driven it on a
# real kernel. A veth uplink answers no devlink max_macs, so --max alone
# opens it. The limit is derived from what is registered right now rather
# than assumed: whatever the scenarios before this one left behind, the
# room is exactly the two keeps, and the newcomer is one too many.
M7="02:be:5c:00:00:77"
M8="02:be:5c:00:00:78"
M9="02:be:5c:00:00:79"
BASE=$($NS "$BIN" --status --pair veth-up:br0 | awk '/registered by us/ {print $NF}')
MAX=$((BASE + 2 + 4))  # allowed = MAX - headroom(4) = BASE + 2
$NS "$BIN" --pair veth-up:br0 --interval 1 --max $MAX >/tmp/sms-it-s6f.log 2>&1 &
DPID=$!
wait_ready /tmp/sms-it-s6f.log
$NS bridge fdb replace $M7 dev veth-g1 master dynamic
sleep 1
$NS bridge fdb replace $M8 dev veth-g1 master dynamic
check_soon "both registered while learnt" "has_self $M7 && has_self $M8"
# M7 goes quiet first, M8 a moment later: M7 is the older keep. Each is
# announced by the pass that notices it, so the wait is for two more
# announcements than the log already had.
KEPT_BEFORE=$(grep -c 'kept \[quiet\]' /tmp/sms-it-s6f.log || true)
$NS bridge fdb del $M7 dev veth-g1 master
check_soon "M7's silence is noticed" \
  "[ \"\$(grep -c 'kept \[quiet\]' /tmp/sms-it-s6f.log)\" -gt $KEPT_BEFORE ]"
$NS bridge fdb del $M8 dev veth-g1 master
check_soon "M8's silence is noticed" \
  "[ \"\$(grep -c 'kept \[quiet\]' /tmp/sms-it-s6f.log)\" -gt $((KEPT_BEFORE + 1)) ]"
check "both kept while their port lives" "has_self $M7 && has_self $M8"
# A third guest speaks. There is no room: the longest-silent keep pays.
$NS bridge fdb replace $M9 dev veth-g1 master dynamic
check_soon "the newcomer got its slot" "has_self $M9"
check_soon "the longest-silent keep paid for it" "! has_self $M7"
check "the younger keep was left alone" "has_self $M8"
check_soon "the release is said" "grep -q 'released .* \[pressure\]' /tmp/sms-it-s6f.log"
check "the limit was derived, not guessed" "[ \"$BASE\" -ge 1 ]"
# The port was never deleted here, so only the test addresses go; M1 is
# re-registered by the --once the next scenario's daemon start follows.
$NS bridge fdb del $M9 dev veth-g1 master 2>/dev/null
$NS bridge fdb del $M8 dev veth-g1 master 2>/dev/null
stop_daemon
$NS bridge fdb replace $M1 dev veth-g1 master dynamic
$NS "$BIN" --once --pair veth-up:br0 >/dev/null 2>&1

say "S6e: an update hands the keeps to the next process"
# The scenario the persistence exists for: a quiet guest whose daemon is
# replaced under it must not be unregistered by the new one's first pass.
start_daemon /tmp/sms-it-s6e.log
M6="02:be:5c:00:00:66"
$NS bridge fdb replace $M6 dev veth-g1 master dynamic
check_soon "M6 registered while learnt" "has_self $M6"
# It ages out, and is kept.
$NS bridge fdb del $M6 dev veth-g1 master
# The handover is the memory file, so the wait is for this process to have
# really written M6 into it - what the next one reads there is the whole
# point of the scenario, and a log line about some other address is not it.
check_soon "M6 is in the handover file" "grep -q $M6 $STATE/.veth-up.owned.ports"
check "M6 kept while its port lives" "has_self $M6"
# The update: stop, start again, and let the new process run a full pass.
stop_daemon
start_daemon /tmp/sms-it-s6e2.log
check_soon "the takeover is said" "grep -q 'took over' /tmp/sms-it-s6e2.log"
# And on the keep decision itself having been made - the takeover line is
# printed as the pass begins, and it is the pass that could unregister M6.
# Not on a pass REPORT: a pass that changed nothing prints none.
check_soon "the new process made its keep decision" \
  "grep -q 'kept \[quiet\]' /tmp/sms-it-s6e2.log"
check "M6 survived the restart" "has_self $M6"
# And the memory is still live in the new process: the port going still ends it.
$NS ip link del veth-g1
check_soon "M6 gone once its port is" "! has_self $M6"
stop_daemon
restore_guest_port

say "S6g: a memory file this build does not recognise is no memory"
# Both harnesses otherwise only ever hand the daemon a file the same binary
# wrote. The first line says what the numbers mean, and a build that does
# not know the format has to fall back to what every build before the file
# existed did - keep nothing - rather than read the stamps as something
# else.
start_daemon /tmp/sms-it-s6g.log
MG="02:be:5c:00:00:67"
$NS bridge fdb replace $MG dev veth-g1 master dynamic
check_soon "the guest is registered" "has_self $MG"
$NS bridge fdb del $MG dev veth-g1 master
check_soon "it is in the handover file" "grep -q $MG $STATE/.veth-up.owned.ports"
stop_daemon
# A file from a future format. Nothing else about it changes.
sed -i "1s/.*/sriov-mac-sync ports 99/" $STATE/.veth-up.owned.ports
start_daemon /tmp/sms-it-s6g2.log
check_soon "the pass ran" "grep -q 'registered' /tmp/sms-it-s6g2.log"
check "no takeover was claimed" "! grep -q 'took over' /tmp/sms-it-s6g2.log"
check_soon "the unrecognised memory kept nothing" "! has_self $MG"
stop_daemon
# No restore_guest_port here: this scenario never took the port away, and
# asking for it back printed "RTNETLINK answers: File exists" into a log
# whose whole job is to be quiet.

say "S7: --status reads without writing"
NOTE_BEFORE=$(cat $STATE/veth-up.owned)
$NS "$BIN" --status --pair veth-up:br0 >/tmp/sms-it-s7.log 2>&1
check "exit 0" "[ $? -eq 0 ]"
check "note unchanged" "[ \"$NOTE_BEFORE\" = \"$(cat $STATE/veth-up.owned)\" ]"
check "shows registered>=1" "grep -qE 'registered by us *: *[1-9]' /tmp/sms-it-s7.log"

say "S7b: --check probes the uplink and leaves no trace"
NOTE_BEFORE=$(cat $STATE/veth-up.owned)
SELF_BEFORE=$($NS bridge fdb show dev veth-up self | sort)
$NS "$BIN" --check --pair veth-up:br0 >/tmp/sms-it-s7b.log 2>&1
check "exit 0" "[ $? -eq 0 ]"
check "says ok" "grep -q 'ok - accepts unicast filter entries' /tmp/sms-it-s7b.log"
check "probe entry gone again" "[ \"$SELF_BEFORE\" = \"$($NS bridge fdb show dev veth-up self | sort)\" ]"
check "note unchanged" "[ \"$NOTE_BEFORE\" = \"$(cat $STATE/veth-up.owned)\" ]"

say "S8: --flush takes everything back out"
$NS "$BIN" --flush >/tmp/sms-it-s8.log 2>&1
RC=$?
check "exit 0" "[ $RC -eq 0 ]"
check "M1 self entry gone" "! has_self $M1"
check "notes gone" "[ -z \"\$(ls -A $STATE 2>/dev/null | grep -v '.lock\$')\" ]"

say "S9: the host outside the namespace is untouched"
DIFF=$(diff "$SNAP" <(ip -br link | awk '{print $1}' | sort))
[ -n "$DIFF" ] && printf '%s\n' "$DIFF" >&2
check "interface snapshot identical" "[ -z \"$DIFF\" ]"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
