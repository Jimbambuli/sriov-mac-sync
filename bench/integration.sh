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
SNAP=$(mktemp)
PASS=0
FAIL=0
DPID=""

say() { echo "== $*"; }
ok() {
  PASS=$((PASS + 1))
  echo "   PASS: $*"
}
bad() {
  FAIL=$((FAIL + 1))
  echo "   FAIL: $*"
}
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
# A self entry is a line carrying the self flag; a master entry for the same
# address does not, and `bridge fdb show dev X self` prints both.
has_self() { $NS bridge fdb show dev veth-up | grep "$1" | grep -q self; }

cleanup() {
  # Only the PID this script started. A pattern kill would match any
  # process whose command line mentions the path - including whatever
  # terminal or supervisor ran this script from the repository.
  [ -n "$DPID" ] && kill "$DPID" 2>/dev/null
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

trap cleanup EXIT
ip -br link >"$SNAP"
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
  local last="" now="" same=0 i
  for i in $(seq 1 20); do
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
$NS "$BIN" --once --dry-run --pair veth-up:br0 >/tmp/sms-it-s3.log 2>&1
check "M2 NOT in the filter" "! has_self $M2"
check "note unchanged" "[ \"$NOTE_BEFORE\" = \"$(cat $STATE/veth-up.owned)\" ]"

say "S4: the daemon's fast path registers within seconds"
$NS "$BIN" --pair veth-up:br0 >/tmp/sms-it-s4.log 2>&1 &
DPID=$!
sleep 1
$NS bridge fdb replace $M2 dev veth-g1 master dynamic
sleep 2
check "M2 in the filter (fast path)" "has_self $M2"
check "M2 in the note" "grep -q $M2 $STATE/veth-up.owned"

say "S5: an address that moves out onto the wire is unregistered"
$NS bridge fdb replace $M2 dev veth-up master dynamic
sleep 2
check "M2 self entry removed" "! has_self $M2"
check "M2 out of the note" "! grep -q $M2 $STATE/veth-up.owned"
check "reflection line in the log" "grep -q 'reflection' /tmp/sms-it-s4.log"

say "S6: SIGTERM stops the daemon promptly and the notes survive"
kill -TERM $DPID
T0=$(date +%s%N)
wait $DPID 2>/dev/null
DPID=""
T1=$(date +%s%N)
MS=$(((T1 - T0) / 1000000))
check "exit within 3 s (took ${MS}ms)" "[ $MS -lt 3000 ]"
check "note survives" "[ -s $STATE/veth-up.owned ]"
check "parting line" "grep -qi 'left registered' /tmp/sms-it-s4.log"

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
DIFF=$(diff <(ip -br link) "$SNAP")
check "interface snapshot identical" "[ -z \"$DIFF\" ]"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
