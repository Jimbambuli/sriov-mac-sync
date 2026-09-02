//! The daemon: what happens between events, and when.
//!
//! Everything here is a decision about time or about what the world said; the
//! world arrives as a trait so the tests can hand in a scripted one. `main`
//! keeps the command line, the configuration file and the one-shot modes.

use crate::netlink::Socket;
use crate::sync::{self, Pair, Syncer};
use crate::topology::Topology;
use crate::Options;
use crate::{clamp_max_macs, devlink, netlink, note, pair_names, report_changes, stopping};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

/// How long to wait before trying again when the kernel would not describe the
/// interfaces. Short, because until it answers the daemon is not doing its job
/// at all; not zero, because a kernel that just refused will refuse again.
const RETRY_AFTER: Duration = Duration::from_secs(5);
/// How long a batch that only reported deletions may hold the pass off. Long
/// enough that a table ageing out is answered once rather than fifty times,
/// short enough that a filter slot is not held by a guest that left.
const AGEING_SETTLE: Duration = Duration::from_secs(5);

/// The interface picture, from the kernel in one dump.
pub(crate) fn read_topology(sock: &mut Socket) -> Result<Topology, String> {
    let links = sock
        .dump_links()
        .map_err(|e| format!("cannot ask the kernel about the interfaces: {e}"))?;
    Ok(Topology::from_links(links))
}

/// Everything the daemon loop reaches for outside itself: the clock, the two
/// sockets and the stop flag.
///
/// Every scheduling decision is a function of time and of what the sockets
/// said, and reaching for `Instant::now()` directly put all of it beyond any
/// test: `Live` forwards to the real clock and sockets, the tests stand in a
/// scripted world and watch what the loop decides.
///
/// `FdbWriter` as the supertrait because the pass and the fast path already
/// take their socket through it. (A trait object would need trait upcasting,
/// newer Rust than this builds with; the loop is generic instead.)
pub(crate) trait World: sync::FdbWriter {
    fn now(&self) -> Instant;
    fn stopping(&self) -> bool;
    /// Whether the operator asked for a pass (SIGHUP). Consumed on read.
    fn resync_wanted(&mut self) -> bool {
        false
    }
    /// Wait on the subscription for at most this many milliseconds; whether
    /// something arrived. An interrupted wait reads as "nothing", so a stop
    /// is noticed at the loop's top rather than after the full interval.
    fn wait(&mut self, millis: i32) -> std::io::Result<bool>;
    fn recv_events(&mut self) -> std::io::Result<netlink::Events>;
    /// Sit out a moment without listening - the brake for error paths
    /// where even waiting itself is what fails.
    fn pause(&mut self, wait: Duration);
    fn read_topology(&mut self) -> Result<Topology, String>;
    /// What the cards report their unicast filters hold - one devlink
    /// reading for the whole list, answered per uplink.
    fn filter_capacities(&mut self, devs: &[String]) -> Vec<(String, CapacityAnswer)>;
}

/// The world as it actually is: the command socket, the subscription, the
/// wall clock, the signal flag.
pub(crate) struct Live {
    pub(crate) sock: Socket,
    pub(crate) mon: Socket,
    /// The stop pipe's read end; a byte here is a signal that landed
    /// outside the poll and must still cut the wait short.
    pub(crate) stop_rx: Option<std::os::fd::OwnedFd>,
}

impl sync::FdbWriter for Live {
    fn dump_fdb(&mut self) -> std::io::Result<Vec<netlink::FdbEntry>> {
        self.sock.dump_fdb()
    }
    fn dump_links(&mut self) -> std::io::Result<Vec<netlink::LinkInfo>> {
        self.sock.dump_links()
    }
    fn vf_macs_of(&mut self, indices: &[u32]) -> std::io::Result<Vec<(u32, [u8; 6])>> {
        self.sock.vf_macs_of(indices)
    }
    fn set_self_fdb(&mut self, ifindex: u32, mac: &[u8; 6], add: bool) -> std::io::Result<()> {
        self.sock.set_self_fdb(ifindex, mac, add)
    }
}

impl World for Live {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn stopping(&self) -> bool {
        stopping()
    }
    fn resync_wanted(&mut self) -> bool {
        crate::resync_wanted()
    }
    fn wait(&mut self, millis: i32) -> std::io::Result<bool> {
        let Some(stop_rx) = &self.stop_rx else {
            return self.mon.wait(millis);
        };
        let mut pfds = [
            libc::pollfd {
                fd: self.mon.raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stop_rx.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let rc = unsafe { libc::poll(pfds.as_mut_ptr(), 2, millis.max(0)) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(e);
        }
        if pfds[1].revents != 0 {
            // Drain, so the next wait sleeps again; the loop's top reads
            // the flag. "Nothing arrived" is the honest answer - a stop
            // byte is not an event.
            let mut sink = [0u8; 16];
            while unsafe { libc::read(pfds[1].fd, sink.as_mut_ptr().cast(), sink.len()) } > 0 {}
            return Ok(false);
        }
        Ok(rc > 0 && pfds[0].revents != 0)
    }
    fn recv_events(&mut self) -> std::io::Result<netlink::Events> {
        self.mon.recv_events()
    }
    fn pause(&mut self, wait: Duration) {
        // A poll on the stop pipe rather than a sleep: SIGTERM during the
        // wait-failure brake must not wait the brake out.
        let Some(stop_rx) = &self.stop_rx else {
            std::thread::sleep(wait);
            return;
        };
        let mut pfd = libc::pollfd {
            fd: stop_rx.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = wait.as_millis().min(i32::MAX as u128) as i32;
        unsafe { libc::poll(&mut pfd, 1, millis) };
    }
    fn read_topology(&mut self) -> Result<Topology, String> {
        read_topology(&mut self.sock)
    }
    fn filter_capacities(&mut self, devs: &[String]) -> Vec<(String, CapacityAnswer)> {
        capacities_via_devlink(devs)
    }
}

/// When the next pass is due and what to call it. These were separate locals
/// whose coupling was the subtlest thing in this file - every batch renames
/// the pass, and a rule gated on the name silently stopped holding. Held
/// together, every rule about them is one of these methods.
struct Schedule {
    /// A deadline, not a sleep: wake-ups that are none of our business must
    /// not push the pass away. Every completed pass moves it a whole interval
    /// out, so the timer fires only after an interval of silence, and that
    /// pass trusts nothing it carried.
    next_full: Instant,
    /// When the last full pass ran, so event storms are answered with a
    /// bounded pass rate rather than with waiting. Registrations never wait.
    last_pass: Instant,
    /// Which of the three reasons for a pass produced work is the only way to
    /// tell whether the timed one earns its keep.
    trigger: &'static str,
    interval: Duration,
}

impl Schedule {
    fn new(now: Instant, interval: Duration) -> Self {
        Self {
            next_full: now,
            last_pass: now - interval,
            trigger: "start",
            interval,
        }
    }

    fn pass_due(&self, now: Instant) -> bool {
        now >= self.next_full
    }

    /// A pass that could not run comes back soon rather than sitting out the
    /// interval, and keeps the name of the pass that failed: a forwarding
    /// change whose pass hit a transient rtnl error is still a forwarding
    /// change five seconds later.
    fn retry_soon(&mut self, now: Instant) {
        self.next_full = now + RETRY_AFTER;
        // The attempt counts as a pass for pacing, not for the trigger name:
        // `last_pass` bounds the 200 ms floor `handle_batch` puts under every
        // batch-bought pass. Left standing during a refusal streak, every
        // notification bought another attempt on a host already unable to
        // answer one.
        self.last_pass = now;
    }

    /// A pass that ran. The next belongs to the timer until something claims
    /// it, which is what keeps `[timed]` honest.
    fn completed(&mut self, now: Instant) {
        self.last_pass = now;
        self.next_full = now + self.interval;
        self.trigger = "timed";
    }

    /// A batch wants a pass sooner. Everything that does goes through here.
    fn bring_forward(&mut self, due: Instant, trigger: &'static str) {
        self.next_full = self.next_full.min(due);
        self.trigger = trigger;
    }

    /// Nothing carried over may be believed and the pass cannot wait: a failed
    /// wait, or notifications the kernel dropped.
    fn at_once(&mut self, now: Instant, trigger: &'static str) {
        self.next_full = now;
        self.trigger = trigger;
    }

    fn wait_for(&self, now: Instant) -> Duration {
        self.next_full.saturating_duration_since(now)
    }
}

/// One reading of the interfaces and what it cost, measured at the World
/// seam so a scripted world can assert the figure.
fn read_picture<W: World>(world: &mut W) -> Result<(Topology, Duration), String> {
    let started = world.now();
    let topo = world.read_topology()?;
    Ok((topo, world.now().saturating_duration_since(started)))
}

/// The daemon: answer batches through the fast path, keep the pass rate
/// bounded. Every pass and every batch reads the interfaces afresh - 0.4 ms
/// on a 38-interface host - so nothing about the topology is ever carried,
/// and nothing about it can go stale. The world arrives as a parameter so the
/// tests can hand in a scripted one.
pub(crate) fn daemon_loop<W: World>(world: &mut W, syncer: &mut Syncer, opts: &Options) {
    let mut schedule = Schedule::new(world.now(), Duration::from_secs(opts.interval));
    // The previous reading, kept for one question only: what a link message
    // was about. An interface that has just gone is in no fresh reading.
    let mut last: Option<Topology> = None;
    let mut wait_failures = 0u32;
    let mut state = LoopState {
        said_empty: false,
        // In autodetect mode the adoption rides on pair-set changes instead.
        capacity_pending: !opts.pairs.is_empty() && !opts.max_macs_set,
    };

    loop {
        if world.stopping() {
            break;
        }
        // The operator knocked: now, and believe nothing.
        if world.resync_wanted() {
            syncer.vf_stale = true;
            schedule.at_once(world.now(), "operator");
        }
        // The timer fired, which means an interval of silence: the carried
        // driver answer is old enough to be asked afresh.
        if schedule.pass_due(world.now()) && schedule.trigger == "timed" {
            syncer.vf_stale = true;
        }
        if schedule.pass_due(world.now()) {
            match run_pass(world, syncer, &mut last, opts, schedule.trigger, &mut state) {
                Pass::Done => schedule.completed(world.now()),
                Pass::Refused => {
                    schedule.retry_soon(world.now());
                    continue;
                }
            }
        }

        let due = schedule.wait_for(world.now());
        // Rounded up, not truncated: poll sleeps at most what it is told, so
        // a truncated wait woke just before the deadline and spun through
        // poll(0) for the last millisecond. The deadline is re-checked at the
        // top.
        let millis = due.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32;
        let woken = match world.wait(millis) {
            Ok(w) => {
                wait_failures = 0;
                w
            }
            Err(e) => {
                eprintln!("warning: waiting for events failed: {e}");
                // The first failure buys a prompt recovery pass. A wait that
                // KEEPS failing (sustained ENOMEM) must not turn the daemon
                // into a hot loop of whole-table dumps, so from the second
                // failure on the retry pace applies before the pass.
                if wait_failures > 0 {
                    world.pause(RETRY_AFTER);
                }
                wait_failures = wait_failures.saturating_add(1);
                schedule.at_once(world.now(), "recovery");
                syncer.vf_stale = true;
                continue;
            }
        };
        if !woken {
            continue; // the deadline came round; the pass happens above
        }

        let events = match world.recv_events() {
            Ok(events) => events,
            // ENOBUFS: the kernel dropped notifications because we could not
            // keep up. Survivable - a full pass reads the real state - but
            // what was in them is unknowable, so nothing carried may be
            // believed.
            Err(e) => {
                eprintln!("warning: lost neighbour notifications: {e}");
                schedule.at_once(world.now(), "lost events");
                syncer.vf_stale = true;
                continue;
            }
        };

        if let Some((due, trigger)) =
            handle_batch(world, syncer, &mut last, &events, schedule.last_pass)
        {
            schedule.bring_forward(due, trigger);
        }
    }
}

/// Whether a pass got as far as reconciling. It is the caller that owns the
/// clock, so a pass says what happened and schedules nothing itself.
enum Pass {
    Done,
    Refused,
}

/// One full pass: read the picture if it can no longer be believed, work out
/// the pairs, reconcile every one against the kernel.
/// The loop's say-once and adoption state, threaded through the passes as one
/// thing because it lives exactly as long as the loop.
struct LoopState {
    said_empty: bool,
    /// Whether a configured pair's card still owes its capacity answer.
    capacity_pending: bool,
}

fn run_pass<W: World>(
    world: &mut W,
    syncer: &mut Syncer,
    last: &mut Option<Topology>,
    opts: &Options,
    trigger: &'static str,
    state: &mut LoopState,
) -> Pass {
    // Nothing to work from fails closed; the caller comes back soon.
    let (topo, topo_load) = match read_picture(world) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("warning: {e}");
            return Pass::Refused;
        }
    };

    // Autodetection is redone every pass - a pure function of the reading,
    // far cheaper than the reading - so a NIC that gets its VFs later or a
    // bridge built after boot needs no restart, and starting before the
    // network is up does not crash-loop.
    if opts.pairs.is_empty() {
        let found: Vec<Pair> = topo
            .autodetect()
            .0
            .into_iter()
            .map(|(dev, bridge)| Pair { dev, bridge })
            .collect();
        if pair_names(&found) != pair_names(&syncer.pairs) {
            if !found.is_empty() {
                note!("now watching {}", pair_names(&found).join(" "));
                state.said_empty = false;
            }
            syncer.pairs = found;
            // A pair adopted at runtime brings its card's capacity with it:
            // the start-time question never saw this uplink, and a daemon
            // that started before its bridges would otherwise warn against
            // the assumed number for life. The operator's --max still wins.
            if !opts.max_macs_set && !syncer.pairs.is_empty() {
                if let Some(v) = ask_the_cards(world, syncer, &topo) {
                    // One number, one home: the warning threshold and the
                    // pressure valve read the same field. The operator's
                    // --max never moves - the max_macs_set gate above
                    // enforces that.
                    syncer.max_macs = v;
                }
            }
        }
    }
    // Pairs the operator wrote down are asked until every card has answered:
    // a daemon started before its configured uplink exists gets no devlink
    // answer at start. `capacity_pending` implies configured pairs and no
    // --max, so it carries the gate alone.
    if state.capacity_pending {
        if let Some(v) = ask_the_cards(world, syncer, &topo) {
            syncer.max_macs = v;
        }
        if syncer.capacity_settled {
            state.capacity_pending = false;
        }
    }
    if syncer.pairs.is_empty() && !state.said_empty {
        note!("waiting for an SR-IOV interface to appear in a bridge");
        state.said_empty = true;
    }

    let outcome = match syncer.reconcile(world, true, &topo, topo_load) {
        Ok(reports) => {
            report_changes(&reports, opts.dry_run, trigger);
            if opts.timings {
                note!("pass [{}]\n{}", trigger, syncer.timings.report().trim_end());
            }
            Pass::Done
        }
        Err(e) => {
            eprintln!("warning: reconciliation failed: {e}");
            Pass::Refused
        }
    };
    *last = Some(topo);
    outcome
}

/// One batch: register what just appeared, before anything else, so the first
/// reply to it is not sent into the void. Says whether a full pass has to
/// follow and what to call it.
///
/// `None` buys nothing and no name: a pass on the timer has to say "timed",
/// or the canary line stops meaning it.
fn handle_batch<W: World>(
    world: &mut W,
    syncer: &mut Syncer,
    last: &mut Option<Topology>,
    events: &netlink::Events,
    last_pass: Instant,
) -> Option<(Instant, &'static str)> {
    if events.fdb.is_empty() && !events.links_changed {
        return None; // something else's neighbour, not a bridge's
    }
    // A batch carrying both kinds is called a forwarding change.
    let trigger = if events.fdb.is_empty() {
        "interface change"
    } else {
        "forwarding change"
    };
    // Whether the batch left anything for a pass. A pass dumps the whole
    // forwarding table, so a batch that was entirely somebody else's must not
    // buy one. Link changes always do.
    let mut urgency = if events.links_changed {
        sync::Urgency::Now
    } else {
        sync::Urgency::Nothing
    };

    // A fresh reading for every batch. What the batch's link messages were
    // about is judged against the reading before it as well, because an
    // interface that has just gone is only in that one.
    let fresh = match read_picture(world) {
        Ok((topo, _)) => Some(topo),
        Err(e) => {
            eprintln!("warning: {e}");
            None
        }
    };
    if !events.changed_links.is_empty()
        && (fresh.is_none()
            || sync::vf_may_have_changed(last.as_ref(), fresh.as_ref(), &events.changed_links))
    {
        // Nothing readable to judge with spends the carried answer too.
        syncer.vf_stale = true;
    }
    match &fresh {
        // The whole batch, both kinds; what each means is the fast path's
        // business (see `fast_apply`).
        Some(topo) => match syncer.fast_apply(world, topo, &events.fdb) {
            Ok(u) => urgency = urgency.max(u),
            // It could not do its work, so the pass has to.
            Err(e) => {
                eprintln!("warning: answering the batch failed: {e}");
                urgency = sync::Urgency::Now;
            }
        },
        None => urgency = sync::Urgency::Now, // the pass reads again
    }
    if let Some(topo) = fresh {
        *last = Some(topo);
    }
    if urgency == sync::Urgency::Nothing {
        return None;
    }

    // The full pass still follows - it removes stale entries and reconciles
    // the notes - but nothing waits for it: a rate bound does what a
    // lull-wait did without making anything later than it has to be.
    //
    // Registrations and interface changes get the ordinary bound; a
    // deletions-only batch waits longer, because an ageing table produces
    // those by the hundred and each would buy a whole-table dump - unless the
    // filter is filling up, when entries that should be gone take room from
    // entries that should be there. Asked of the occupancy the last pass
    // measured against the card, not of the notes, which miss every foreign
    // entry.
    let filling = syncer.fullest_filter() * 10 >= syncer.max_macs * 9;
    let wait = if urgency == sync::Urgency::Now || filling {
        Duration::from_millis(200)
    } else {
        AGEING_SETTLE
    };
    Some(((last_pass + wait).max(world.now()), trigger))
}

/// One uplink's capacity answer: what the card says, that it says
/// nothing, or why asking failed - the last two look identical from the
/// threshold and are not the same bug.
type CapacityAnswer = Result<Option<u32>, String>;

/// One devlink reading for the whole list, answered per uplink. The
/// answer is device-independent; asking per pair re-ran the identical
/// dump and discarded it, from the second pair on.
pub(crate) fn capacities_via_devlink(devs: &[String]) -> Vec<(String, CapacityAnswer)> {
    let read = devlink::read();
    devs.iter()
        .map(|d| {
            let answer = match &read {
                Ok(Some(caps)) => Ok(caps.for_netdev(d)),
                Ok(None) => Ok(None), // no devlink on this kernel
                Err(e) => Err(e.clone()),
            };
            (d.clone(), answer)
        })
        .collect()
}

/// The smallest capacity the cards report, as the threshold to warn at: one
/// number governs every uplink, and the filter that fills first drops
/// addresses. A card that says nothing changes nothing, nor does a number
/// this program would refuse from a person - a driver is not more trustworthy
/// than an operator. `None` means the assumed threshold stands; the `--max`
/// gate lives at the call sites.
/// Ask the cards behind the pairs what their filters hold: fills the per-card
/// table, returns the assumed number for everything that reported none, and
/// records whether every configured device was there to be asked - "the card
/// says nothing" being an answer.
fn ask_the_cards<W: World>(world: &mut W, syncer: &mut Syncer, topo: &Topology) -> Option<usize> {
    let devs: Vec<String> = syncer.pairs.iter().map(|p| p.dev.clone()).collect();
    let answers = world.filter_capacities(&filter_carriers(&devs, Some(topo)));
    let all_present = devs.iter().all(|d| topo.index_of(d).is_some());
    syncer.capacity_settled = all_present && answers.iter().all(|(_, a)| a.is_ok());
    for (karte, wert) in reported_capacities(answers.clone(), syncer.max_macs) {
        syncer.max_macs_je_karte.insert(karte, wert);
    }
    adopt_reported_capacity(answers, syncer.max_macs)
}

/// The interfaces that really hold the uplinks' filters: the uplink itself,
/// or for a VLAN the interface below - the only one with a capacity devlink
/// can be asked about.
pub(crate) fn filter_carriers(devs: &[String], topo: Option<&Topology>) -> Vec<String> {
    let Some(topo) = topo else {
        return devs.to_vec();
    };
    let mut aus: Vec<String> = Vec::new();
    for d in devs {
        let name = topo
            .index_of(d)
            .map(|i| topo.filter_carrier(i))
            .and_then(|c| topo.name_of(c))
            .unwrap_or(d)
            .to_string();
        if !aus.contains(&name) {
            aus.push(name);
        }
    }
    aus
}

/// What the cards reported, per card, plus the minimum as the default for
/// everything that reported nothing - so a large card does not work to the
/// smallest one's measure.
pub(crate) fn reported_capacities(
    answers: Vec<(String, CapacityAnswer)>,
    assumed: usize,
) -> Vec<(String, usize)> {
    let mut usable: Vec<(String, usize)> = Vec::new();
    for (dev, answer) in answers {
        match answer {
            Ok(Some(v)) => match clamp_max_macs(v as usize) {
                Ok(v) => usable.push((dev, v)),
                Err(_) => {
                    note!("{dev}: reported capacity {v} is unusable, ignored");
                }
            },
            Ok(None) => {
                note!("{dev}: no filter capacity reported; keeping the assumed {assumed}");
            }
            Err(e) => {
                note!("{dev}: could not ask for the filter capacity: {e}");
            }
        }
    }
    usable
}

pub(crate) fn adopt_reported_capacity(
    answers: Vec<(String, CapacityAnswer)>,
    assumed: usize,
) -> Option<usize> {
    let mut usable: Vec<(String, usize)> = Vec::new();
    for (dev, answer) in answers {
        match answer {
            Ok(Some(v)) => match clamp_max_macs(v as usize) {
                Ok(v) => usable.push((dev, v)),
                Err(_) => {
                    note!("{dev}: reported capacity {v} is unusable, ignored");
                }
            },
            Ok(None) => {
                note!("{dev}: no filter capacity reported; keeping the assumed {assumed}");
            }
            Err(e) => {
                note!("{dev}: could not ask for the filter capacity: {e}");
            }
        }
    }
    let (dev, value) = usable.into_iter().min_by_key(|(_, v)| *v)?;
    if value == assumed {
        // Worth saying only to somebody who asked what was skipped: the
        // number moved nowhere, but that it was *asked for* is the
        // difference between a card that agrees and a card that is silent.
        note!("{dev} says its filter holds {value} addresses, which is what was assumed");

        return None;
    }
    note!(
        "{dev} says its filter holds {value} addresses instead of the assumed \
         {assumed}; warning above that, and releasing quiet addresses as the \
         list comes near it"
    );
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mode;

    /// The trigger labels are what bench/trial.py's quiescence check and the
    /// [timed] canary read, and internals.md promises recovery passes name
    /// themselves; a retry that stole a batch's label made the canary cry
    /// wolf.
    #[test]
    fn the_trigger_labels_survive_what_the_schedule_does() {
        let now = Instant::now();
        let interval = Duration::from_secs(300);
        let mut s = Schedule::new(now, interval);
        assert_eq!(s.trigger, "start", "the first pass is the restart catch-up");
        s.completed(now);
        assert_eq!(s.trigger, "timed", "the default between events");
        assert!(
            !s.pass_due(now + interval / 2),
            "a completed pass pushes the timer a whole interval out"
        );
        assert!(
            s.pass_due(now + interval),
            "and after an interval of silence it fires"
        );
        s.bring_forward(now, "forwarding change");
        assert_eq!(
            s.trigger, "forwarding change",
            "an event keeps its own label"
        );
        s.retry_soon(now);
        assert_eq!(
            s.trigger, "forwarding change",
            "the retried pass forgot whose pass it was"
        );
        s.at_once(now, "recovery");
        assert_eq!(s.trigger, "recovery");
        s.completed(now);
        assert_eq!(s.trigger, "timed");
    }

    /// The capacity policy, over answers rather than over hardware: the
    /// smallest usable answer wins, an unusable one is dropped rather than
    /// allowed to veto, silence and failure leave the default standing.
    #[test]
    fn the_reported_capacity_policy() {
        let dev = |d: &str, a: CapacityAnswer| (d.to_string(), a);
        // The smallest usable answer wins across uplinks.
        assert_eq!(
            adopt_reported_capacity(
                vec![dev("nic0", Ok(Some(256))), dev("nic1", Ok(Some(64)))],
                128
            ),
            Some(64)
        );
        // A card reporting nonsense is ignored, not a veto on the good one.
        assert_eq!(
            adopt_reported_capacity(
                vec![dev("nic0", Ok(Some(0))), dev("nic1", Ok(Some(64)))],
                128
            ),
            Some(64)
        );
        // Nothing usable at all leaves the default standing.
        assert_eq!(
            adopt_reported_capacity(vec![dev("nic0", Ok(Some(0)))], 128),
            None
        );
        // Agreement is not a change.
        assert_eq!(
            adopt_reported_capacity(vec![dev("nic0", Ok(Some(128)))], 128),
            None
        );
        // Silence and failure leave the default standing.
        assert_eq!(
            adopt_reported_capacity(
                vec![dev("nic0", Ok(None)), dev("nic1", Err("no".into()))],
                128
            ),
            None
        );
    }

    mod loop_tests {
        use super::*;
        use crate::netlink::{Events, RTM_DELNEIGH, RTM_NEWNEIGH};
        use crate::sync::tests::{host, learned, FakeSock};
        use crate::sync::FdbWriter;
        use crate::topology::fixture::mac;
        use std::collections::VecDeque;

        /// A world made of script: time passes only when the loop waits,
        /// events arrive when the script says. Everything the loop decides is
        /// then a pure function of the script.
        struct FakeWorld {
            base: Instant,
            offset: Duration,
            /// (when, what arrives) - ascending, absolute offsets. An errno
            /// stands in for a receive error.
            script: VecDeque<(Duration, Result<Events, i32>)>,
            stop_at: Duration,
            /// Until this offset the topology is a bare host with nothing
            /// autodetectable - the world before a bridge was built.
            bare_until: Duration,
            /// Until this offset the topology does not contain nic1 at
            /// all - the world before the card was plugged in.
            absent_until: Duration,
            topo_fails: bool,
            topo_calls: usize,
            /// how long a topology read takes in this world
            read_cost: Duration,
            fdb: FakeSock,
            /// when each full pass ran - the dump is what a pass is
            passes: Vec<Duration>,
            /// errno wait() answers with, for this many calls
            fail_wait: Option<i32>,
            fail_wait_times: u32,
            /// 1-based wait() call numbers that fail, whatever else says
            wait_fail_calls: Vec<usize>,
            wait_calls: usize,
            /// every pause the loop asked for
            paused: Vec<Duration>,
            /// what filter_capacities answers, per netdev
            capacities: crate::hash::Map<String, u32>,
            /// netdevs whose devlink question fails outright
            capacity_errors: Vec<String>,
            /// each list of devices it was asked about
            capacity_asks: Vec<Vec<String>>,
        }

        impl FakeWorld {
            fn new(stop_at_secs: u64) -> Self {
                FakeWorld {
                    base: Instant::now(),
                    offset: Duration::ZERO,
                    script: VecDeque::new(),
                    stop_at: Duration::from_secs(stop_at_secs),
                    bare_until: Duration::ZERO,
                    absent_until: Duration::ZERO,
                    topo_fails: false,
                    topo_calls: 0,
                    read_cost: Duration::ZERO,
                    fdb: FakeSock::default(),
                    passes: Vec::new(),
                    fail_wait: None,
                    fail_wait_times: 0,
                    wait_fail_calls: Vec::new(),
                    wait_calls: 0,
                    paused: Vec::new(),
                    capacities: crate::hash::map(),
                    capacity_errors: Vec::new(),
                    capacity_asks: Vec::new(),
                }
            }
            fn at(mut self, secs: u64, ev: Result<Events, i32>) -> Self {
                self.script.push_back((Duration::from_secs(secs), ev));
                self
            }
        }

        impl FdbWriter for FakeWorld {
            fn dump_fdb(&mut self) -> std::io::Result<Vec<crate::netlink::FdbEntry>> {
                self.passes.push(self.offset);
                self.fdb.dump_fdb()
            }
            fn dump_fdb_of(
                &mut self,
                ifindex: u32,
            ) -> std::io::Result<Vec<crate::netlink::FdbEntry>> {
                self.fdb.dump_fdb_of(ifindex)
            }
            fn dump_links(&mut self) -> std::io::Result<Vec<crate::netlink::LinkInfo>> {
                self.fdb.dump_links()
            }
            fn vf_macs_of(&mut self, indices: &[u32]) -> std::io::Result<Vec<(u32, [u8; 6])>> {
                self.fdb.vf_macs_of(indices)
            }
            fn set_self_fdb(
                &mut self,
                ifindex: u32,
                mac: &[u8; 6],
                add: bool,
            ) -> std::io::Result<()> {
                self.fdb.set_self_fdb(ifindex, mac, add)
            }
        }

        impl World for FakeWorld {
            fn now(&self) -> Instant {
                self.base + self.offset
            }
            fn stopping(&self) -> bool {
                self.offset >= self.stop_at
            }
            fn wait(&mut self, millis: i32) -> std::io::Result<bool> {
                self.wait_calls += 1;
                if self.wait_fail_calls.contains(&self.wait_calls) {
                    return Err(std::io::Error::from_raw_os_error(libc::ENOMEM));
                }
                if let Some(errno) = self.fail_wait {
                    if self.fail_wait_times > 0 {
                        self.fail_wait_times -= 1;
                    } else {
                        self.fail_wait = None;
                    }
                    return Err(std::io::Error::from_raw_os_error(errno));
                }
                let until = self.offset + Duration::from_millis(millis.max(0) as u64);
                if let Some((at, _)) = self.script.front() {
                    if *at <= until {
                        self.offset = (*at).max(self.offset);
                        return Ok(true);
                    }
                }
                self.offset = until;
                Ok(false)
            }
            fn recv_events(&mut self) -> std::io::Result<Events> {
                match self.script.pop_front() {
                    Some((_, Ok(ev))) => Ok(ev),
                    Some((_, Err(errno))) => Err(std::io::Error::from_raw_os_error(errno)),
                    None => Ok(Events::default()),
                }
            }
            fn pause(&mut self, wait: Duration) {
                self.paused.push(wait);
                self.offset += wait;
            }
            fn filter_capacities(&mut self, devs: &[String]) -> Vec<(String, CapacityAnswer)> {
                self.capacity_asks.push(devs.to_vec());
                devs.iter()
                    .map(|d| {
                        let a = if self.capacity_errors.contains(d) {
                            Err(format!("{d}: devlink said no"))
                        } else {
                            Ok(self.capacities.get(d).copied())
                        };
                        (d.clone(), a)
                    })
                    .collect()
            }
            fn read_topology(&mut self) -> Result<Topology, String> {
                self.topo_calls += 1;
                self.offset += self.read_cost;
                if self.topo_fails {
                    Err("no picture today".into())
                } else if self.offset < self.absent_until {
                    Ok(crate::topology::fixture::Builder::new()
                        .add("lo", 1, None)
                        .build())
                } else if self.offset < self.bare_until {
                    Ok(crate::topology::fixture::Builder::new()
                        .add("nic1", 2, Some(mac(1)))
                        .vfs(1)
                        .build())
                } else {
                    Ok(host(mac(1)))
                }
            }
        }

        /// A state directory that removes itself when the test ends -
        /// unless the test is panicking, because a failed run's state is
        /// exactly the evidence one wants to look at.
        struct Scratch(std::path::PathBuf);

        impl Drop for Scratch {
            fn drop(&mut self) {
                if !std::thread::panicking() {
                    let _ = std::fs::remove_dir_all(&self.0);
                }
            }
        }

        fn scratch(name: &str) -> Scratch {
            let d = std::env::temp_dir()
                .join(format!("sriov-mac-sync-loop-{}-{name}", std::process::id()));
            // Pre-cleaned as well as post-cleaned: process ids are recycled,
            // and a leftover from a crashed run under the same number would
            // be read as this run's own state.
            let _ = std::fs::remove_dir_all(&d);
            Scratch(d)
        }

        /// nic1:vmbr1 named on the command line, so the loop does not
        /// autodetect.
        /// The guard MUST be bound at the call site: dropped early, the
        /// directory vanishes while the daemon still writes into it.
        fn setup(name: &str, interval: u64) -> (Syncer, Options, Scratch) {
            let mut opts = Options {
                interval,
                pairs: vec!["nic1:vmbr1".into()],
                ..Default::default()
            };
            opts.mode = Mode::Daemon;
            let dir = scratch(name);
            let syncer = Syncer::new(
                vec![Pair {
                    dev: "nic1".into(),
                    bridge: "vmbr1".into(),
                }],
                dir.0.clone(),
            );
            (syncer, opts, dir)
        }

        fn secs(d: Duration) -> u64 {
            d.as_secs()
        }

        /// The timed pass runs at the interval, exactly, for as long as
        /// nothing happens - the heartbeat everything else is measured
        /// against, and until now the one thing no test could see.
        #[test]
        fn a_quiet_host_gets_its_pass_once_per_interval() {
            let (mut syncer, opts, _dir) = setup("cadence", 10);
            let mut world = FakeWorld::new(25);
            daemon_loop(&mut world, &mut syncer, &opts);
            assert_eq!(
                world.passes.iter().map(|d| secs(*d)).collect::<Vec<_>>(),
                vec![0, 10, 20],
                "the pass has to run at the interval, and only then"
            );
        }

        /// A bridge built at runtime is adopted by the prompt pass its own
        /// link event buys, not by the next timed pass. The batch reads the
        /// fresh picture *before* the pass, so needs_reading() cannot tell;
        /// replaced_since_pass carries the news. Without it a runtime pair
        /// waited out the whole interval.
        #[test]
        fn a_pair_appearing_at_runtime_is_adopted_by_the_prompt_pass() {
            let mut opts = Options {
                interval: 300,
                ..Default::default()
            };
            opts.mode = Mode::Daemon;
            let _dir = scratch("hotplug");
            let mut syncer = Syncer::new(Vec::new(), _dir.0.clone());
            let mut world = FakeWorld::new(5);
            world.bare_until = Duration::from_secs(1);
            world.script.push_back((
                Duration::from_secs(2),
                Ok(Events {
                    fdb: Vec::new(),
                    links_changed: true,
                    changed_links: vec![2],
                }),
            ));
            daemon_loop(&mut world, &mut syncer, &opts);
            let names: Vec<String> = syncer
                .pairs
                .iter()
                .map(|p| format!("{}:{}", p.dev, p.bridge))
                .collect();
            assert!(
                world.passes.iter().any(|d| secs(*d) == 2),
                "the link event did not buy a prompt pass"
            );
            assert!(
                names.contains(&"nic1:vmbr1".to_string()),
                "the prompt pass did not adopt the new pair (got {names:?}); \
                 it would have waited for the timer"
            );
        }

        /// The timed pass believes nothing it was told: the interfaces are
        /// read afresh as always, and the driver is asked again.
        #[test]
        fn the_timed_refresh_rereads_the_picture_and_reasks_the_driver() {
            let (mut syncer, opts, _dir) = setup("refresh-distrust", 10);
            let mut world = FakeWorld::new(25);
            daemon_loop(&mut world, &mut syncer, &opts);
            assert_eq!(
                world.topo_calls, 3,
                "each interval owes the picture a fresh reading"
            );
            assert_eq!(
                world.fdb.vf_asked, 3,
                "each interval owes the driver a fresh question"
            );
        }

        /// A failed wait is survived, answered with a prompt pass, and
        /// nothing carried is believed - the only user of the "recovery"
        /// label, which no test could reach before.
        #[test]
        fn a_failed_wait_is_survived_and_distrusted() {
            let (mut syncer, opts, _dir) = setup("wait-fails", 8);
            let mut world = FakeWorld::new(8);
            world.fail_wait = Some(libc::EINTR);
            daemon_loop(&mut world, &mut syncer, &opts);
            assert!(
                world.passes.len() >= 2,
                "the failed wait did not buy a prompt pass: {:?}",
                world.passes
            );
            assert!(
                world.topo_calls >= 2,
                "the recovery pass believed the carried picture"
            );
            assert!(
                world.fdb.vf_asked >= 2,
                "the recovery pass believed the carried VF answer"
            );
        }

        /// A pair adopted at runtime brings its card's capacity with it:
        /// without the re-ask a daemon started before its bridges warned
        /// against the assumed 128 for life.
        #[test]
        fn a_runtime_pair_brings_its_capacity_along() {
            let mut opts = Options {
                interval: 300,
                ..Default::default()
            };
            opts.mode = Mode::Daemon;
            let _dir = scratch("hotplug-capacity");
            let mut syncer = Syncer::new(Vec::new(), _dir.0.clone());
            let mut world = FakeWorld::new(5);
            world.bare_until = Duration::from_secs(1);
            world.capacities.insert("nic1".to_string(), 64);
            world.script.push_back((
                Duration::from_secs(2),
                Ok(Events {
                    fdb: Vec::new(),
                    links_changed: true,
                    changed_links: vec![2],
                }),
            ));
            daemon_loop(&mut world, &mut syncer, &opts);
            assert!(
                !world.capacity_asks.is_empty(),
                "the adopted pair was never asked for its capacity"
            );
            assert_eq!(
                syncer.max_macs, 64,
                "asking is not adopting - the valve still measures the assumed number"
            );
            // The operator's word is never moved: the same run with --max
            // set must not ask at all.
            let mut opts = Options {
                interval: 300,
                max_macs: 200,
                max_macs_set: true,
                ..Default::default()
            };
            opts.mode = Mode::Daemon;
            let _dir = scratch("hotplug-capacity-set");
            let mut syncer = Syncer::new(Vec::new(), _dir.0.clone());
            let mut world = FakeWorld::new(5);
            world.bare_until = Duration::from_secs(1);
            world.capacities.insert("nic1".to_string(), 64);
            world.script.push_back((
                Duration::from_secs(2),
                Ok(Events {
                    fdb: Vec::new(),
                    links_changed: true,
                    changed_links: vec![2],
                }),
            ));
            daemon_loop(&mut world, &mut syncer, &opts);
            assert!(
                world.capacity_asks.is_empty(),
                "--max was set and the cards were asked anyway"
            );
        }

        /// A batch of learning is answered twice: the fast path registers
        /// the moment the batch is read, and the full pass follows at the
        /// bounded rate rather than at the interval.
        #[test]
        fn a_learning_batch_registers_at_once_and_buys_a_prompt_pass() {
            let (mut syncer, opts, _dir) = setup("learn", 300);
            let guest = [0xaa, 0, 0, 0, 0, 0x51];
            let mut world = FakeWorld::new(8).at(
                5,
                Ok(Events {
                    fdb: vec![(RTM_NEWNEIGH, learned(3, 10, guest))],
                    ..Default::default()
                }),
            );
            daemon_loop(&mut world, &mut syncer, &opts);
            assert!(
                world.fdb.added.contains(&(2, guest)),
                "the guest's address never reached the uplink's filter"
            );
            assert_eq!(
                world.passes.iter().map(|d| secs(*d)).collect::<Vec<_>>(),
                vec![0, 5],
                "the pass after a registration must not wait out the interval"
            );
        }

        /// Deletions are never urgent: an ageing table produces them by the
        /// hundred, and each pass dumps the whole forwarding table. A batch
        /// of nothing but deletions waits out the settle time.
        #[test]
        fn a_deletions_only_batch_waits_for_the_table_to_settle() {
            let (mut syncer, opts, _dir) = setup("ageing", 300);
            let gone = [0xaa, 0, 0, 0, 0, 0x52];
            let mut world = FakeWorld::new(8).at(
                1,
                Ok(Events {
                    fdb: vec![(RTM_DELNEIGH, learned(3, 10, gone))],
                    ..Default::default()
                }),
            );
            daemon_loop(&mut world, &mut syncer, &opts);
            assert_eq!(
                world.passes.iter().map(|d| secs(*d)).collect::<Vec<_>>(),
                vec![0, 5],
                "a deletion at t=1 has to be answered at settle time, not at once"
            );
        }

        /// A batch that was entirely somebody else's - learning on an
        /// unrelated bridge - buys no pass at all. On a busy host this is
        /// the difference between answering traffic and being buried by it.
        #[test]
        fn somebody_elses_batch_buys_no_pass() {
            let (mut syncer, opts, _dir) = setup("foreign", 300);
            let other = [0xaa, 0, 0, 0, 0, 0x53];
            let mut world = FakeWorld::new(8).at(
                1,
                Ok(Events {
                    fdb: vec![(RTM_NEWNEIGH, learned(22, 20, other))],
                    ..Default::default()
                }),
            );
            daemon_loop(&mut world, &mut syncer, &opts);
            assert!(
                world.fdb.added.is_empty(),
                "nothing here was ours to register"
            );
            assert_eq!(
                world.passes.iter().map(|d| secs(*d)).collect::<Vec<_>>(),
                vec![0],
                "an unrelated bridge's learning must not cost a forwarding dump"
            );
        }

        /// Lost notifications mean the world moved unseen: everything
        /// carried is distrusted and a pass runs now, on a fresh picture.
        #[test]
        fn lost_events_cost_a_fresh_picture_and_an_immediate_pass() {
            let (mut syncer, opts, _dir) = setup("lost", 300);
            let mut world = FakeWorld::new(8).at(5, Err(libc::ENOBUFS));
            daemon_loop(&mut world, &mut syncer, &opts);
            assert_eq!(
                world.passes.iter().map(|d| secs(*d)).collect::<Vec<_>>(),
                vec![0, 5],
                "losing events has to buy a pass right away"
            );
            assert_eq!(
                world.topo_calls, 2,
                "a picture from before the loss must not be believed"
            );
            assert!(
                world.fdb.vf_asked >= 2,
                "a VF answer from before the loss must not be believed either"
            );
        }

        /// A kernel that will not describe the interfaces is retried in
        /// seconds, not sat out for the whole interval - and no pass runs
        /// on the picture that is not there.
        #[test]
        fn a_refused_topology_is_retried_soon_and_reconciles_nothing() {
            let (mut syncer, opts, _dir) = setup("refused", 300);
            let mut world = FakeWorld::new(12);
            world.topo_fails = true;
            daemon_loop(&mut world, &mut syncer, &opts);
            assert!(
                world.passes.is_empty(),
                "a pass ran with no topology to judge by"
            );
            assert_eq!(
                world.topo_calls, 3,
                "the retry has to come at RETRY_AFTER (5 s), so 0, 5 and 10"
            );
        }

        /// An interface change spends the carried VF answer: the next pass
        /// asks the driver afresh. The interfaces are read afresh anyway.
        #[test]
        fn an_interface_change_re_reads_the_picture_and_re_asks_the_driver() {
            let (mut syncer, opts, _dir) = setup("links", 300);
            let mut world = FakeWorld::new(8).at(
                5,
                Ok(Events {
                    links_changed: true,
                    changed_links: vec![2], // nic1, which has functions
                    ..Default::default()
                }),
            );
            daemon_loop(&mut world, &mut syncer, &opts);
            assert_eq!(
                world.passes.iter().map(|d| secs(*d)).collect::<Vec<_>>(),
                vec![0, 5]
            );
            // The batch read one, the pass it bought read another: nothing
            // about the interfaces is ever carried.
            assert_eq!(world.topo_calls, 3, "batch and pass each read afresh");
            assert_eq!(
                world.fdb.vf_asked, 2,
                "a change on an interface with functions has to re-ask the driver"
            );
        }

        /// A refused pass keeps its rate bound, not just its deadline:
        /// `last_pass` is what `handle_batch` puts its 200 ms floor under,
        /// and left standing every notification bought another attempt at
        /// once.
        #[test]
        fn a_refused_pass_still_paces_the_batches_behind_it() {
            let (mut syncer, opts, _dir) = setup("retry-brake", 300);
            let mut world = FakeWorld::new(3);
            world.topo_fails = true;
            // Ten notifications inside one second, each one asking for a
            // pass that cannot run.
            for i in 1..=10 {
                world.script.push_back((
                    Duration::from_millis(i * 100),
                    Ok(Events {
                        fdb: vec![(
                            crate::netlink::RTM_NEWNEIGH,
                            crate::sync::tests::learned(4, 10, [2, 0, 0, 0, 0, 9]),
                        )],
                        links_changed: false,
                        changed_links: Vec::new(),
                    }),
                ));
            }
            daemon_loop(&mut world, &mut syncer, &opts);
            // Each batch reads the picture for itself (a failed read leaves
            // nothing to carry), so ten of these are the batches; the rest
            // are pass attempts. Measured: 16 with the bound, 21 without.
            assert!(
                world.topo_calls <= 18,
                "a refusal streak was answered {} times in three seconds",
                world.topo_calls
            );
        }

        /// A wait that keeps failing does not become a hot loop: the first
        /// failure buys a prompt recovery pass, from the second on the retry
        /// pace applies before the pass.
        #[test]
        fn a_wait_that_keeps_failing_is_paced() {
            let (mut syncer, opts, _dir) = setup("wait-brake", 300);
            let mut world = FakeWorld::new(30);
            world.fail_wait = Some(libc::ENOMEM);
            world.fail_wait_times = 3;
            daemon_loop(&mut world, &mut syncer, &opts);
            // Four failures: the first is prompt, the other three each wait
            // out RETRY_AFTER before their pass.
            assert!(
                world.passes.len() <= 5,
                "a failing wait spun into a hot loop: {} passes",
                world.passes.len()
            );
            let paced: Vec<u64> = world.passes.iter().map(|d| secs(*d)).collect();
            assert!(
                paced.windows(2).skip(1).all(|w| w[1] - w[0] >= 5),
                "the retry pace was not applied between failures: {paced:?}"
            );
        }

        /// Deadline rules only ever pull a pass earlier: `bring_forward`
        /// takes a `min` against what is scheduled. Assigning would push a
        /// pass due now into the future while a guest waits for its entry.
        #[test]
        fn a_deadline_is_only_ever_pulled_earlier() {
            let start = Instant::now();
            let mut sched = Schedule::new(start, Duration::from_secs(300));
            // A pass is due at once.
            sched.at_once(start, "recovery");
            assert!(sched.pass_due(start));
            // The timer comes round: it may not push that pass away.
            let later = start + Duration::from_secs(600);
            assert!(sched.pass_due(later), "a due pass stays due");
            // Neither may a batch that only wants one soon.
            sched.bring_forward(later + Duration::from_secs(60), "forwarding change");
            assert!(
                sched.pass_due(later),
                "a batch pushed a pass that was already due"
            );
        }

        /// The brake lets go once a wait works again: a counter that never
        /// reset would make every later failure - hours apart, on a recovered
        /// host - wait out the retry pace.
        #[test]
        fn a_wait_that_recovers_gets_its_prompt_pass_back() {
            // A short interval, so the loop really gets to its third wait.
            let (mut syncer, opts, _dir) = setup("wait-brake-reset", 2);
            let mut world = FakeWorld::new(12);
            // Fail, work, fail again.
            world.wait_fail_calls = vec![1, 3];
            daemon_loop(&mut world, &mut syncer, &opts);
            assert!(
                world.wait_calls >= 3,
                "the loop never reached its second failure"
            );
            assert!(
                world.paused.is_empty(),
                "a wait that had recovered was still paced: {:?}",
                world.paused
            );
        }

        /// A card that structurally cannot report a capacity is asked once,
        /// not for ever: ixgbe, i40e and mlx4 have no devlink `max_macs`
        /// parameter, and waiting for a number meant a full devlink parameter
        /// dump on every reloaded pass - a tap appearing when a VM starts
        /// bought one.
        #[test]
        fn a_card_that_reports_no_capacity_is_asked_only_once() {
            let (mut syncer, opts, _dir) = setup("capacity-silent-card", 300);
            let mut world = FakeWorld::new(20);
            // The card is there and answers - with nothing, the way an
            // ixgbe does. Several link batches follow.
            for at in [2, 4, 6, 8] {
                world.script.push_back((
                    Duration::from_secs(at),
                    Ok(Events {
                        fdb: Vec::new(),
                        links_changed: true,
                        changed_links: vec![2],
                    }),
                ));
            }
            daemon_loop(&mut world, &mut syncer, &opts);
            assert_eq!(
                world.capacity_asks.len(),
                1,
                "a card that answered nothing was asked again on every reloaded pass"
            );
        }

        /// One card answering does not settle the question for another:
        /// taking the first answer would measure the second card - possibly
        /// the smaller filter - against the first one's limit for life.
        #[test]
        fn one_card_s_answer_does_not_settle_another_s() {
            let dir = scratch("capacity-two-cards");
            let mut opts = Options {
                interval: 300,
                pairs: vec!["nic1:vmbr1".into(), "nic0:vmbr0".into()],
                ..Default::default()
            };
            opts.mode = Mode::Daemon;
            let mut syncer = Syncer::new(
                vec![
                    Pair {
                        dev: "nic1".into(),
                        bridge: "vmbr1".into(),
                    },
                    Pair {
                        dev: "nic0".into(),
                        bridge: "vmbr0".into(),
                    },
                ],
                dir.0.clone(),
            );
            let mut world = FakeWorld::new(8);
            world.capacities.insert("nic1".to_string(), 64);
            world.capacity_errors.push("nic0".to_string());
            for at in [2, 5] {
                world.script.push_back((
                    Duration::from_secs(at),
                    Ok(Events {
                        fdb: Vec::new(),
                        links_changed: true,
                        changed_links: vec![2],
                    }),
                ));
            }
            daemon_loop(&mut world, &mut syncer, &opts);
            assert!(
                world.capacity_asks.len() >= 2,
                "the unanswered card was written off because the other one answered"
            );
        }

        /// An uplink that is not there yet has not been asked at all - the
        /// pending state exists so a daemon started before its bridges picks
        /// the capacity up when the interface appears.
        #[test]
        fn an_uplink_that_appears_later_is_still_asked() {
            let (mut syncer, opts, _dir) = setup("capacity-late-uplink", 300);
            let mut world = FakeWorld::new(8);
            // Until second 3 the world has no nic1 at all.
            world.absent_until = Duration::from_secs(3);
            world.capacities.insert("nic1".to_string(), 64);
            for at in [1, 5] {
                world.script.push_back((
                    Duration::from_secs(at),
                    Ok(Events {
                        fdb: Vec::new(),
                        links_changed: true,
                        changed_links: vec![2],
                    }),
                ));
            }
            daemon_loop(&mut world, &mut syncer, &opts);
            assert!(
                world.capacity_asks.len() >= 2,
                "an uplink that did not exist yet was written off after one ask"
            );
            assert_eq!(
                syncer.max_macs, 64,
                "the late uplink's card never reached the pressure valve"
            );
        }

        /// A configured pair is not second class: without a re-ask a daemon
        /// started before its written-down uplink measured threshold and
        /// valve against the assumed number for life. Autodetection had the
        /// cure first; --pair was left out.
        #[test]
        fn a_configured_pair_brings_its_capacity_when_it_appears() {
            let (mut syncer, opts, _dir) = setup("conf-capacity", 300);
            let mut world = FakeWorld::new(5);
            world.bare_until = Duration::from_secs(1);
            world.capacities.insert("nic1".to_string(), 64);
            world.script.push_back((
                Duration::from_secs(2),
                Ok(Events {
                    fdb: Vec::new(),
                    links_changed: true,
                    changed_links: vec![2],
                }),
            ));
            daemon_loop(&mut world, &mut syncer, &opts);
            assert!(
                !world.capacity_asks.is_empty(),
                "the configured pair was never asked for its capacity"
            );
            assert_eq!(
                syncer.max_macs, 64,
                "the card's answer has to reach the pressure valve"
            );
        }

        /// When the filter is filling up, even an ageing burst is answered
        /// at the fast rate: entries that should be gone are taking room
        /// from entries that should be there.
        #[test]
        fn a_filling_filter_turns_deletions_urgent() {
            let (mut syncer, opts, _dir) = setup("filling", 300);
            // The wiring run() does: the one capacity number lives in the
            // syncer, where the valve and the batch heuristic read it.
            syncer.max_macs = 1;
            // One address already on record. The file is the truth, so the
            // file is what the test writes.
            std::fs::create_dir_all(&syncer.state_dir).unwrap();
            std::fs::write(syncer.state_dir.join("nic1.owned"), "02:00:00:00:00:60\n").unwrap();
            let gone = [0xaa, 0, 0, 0, 0, 0x54];
            let kept = [0x02, 0, 0, 0, 0, 0x60];
            let mut world = FakeWorld::new(4).at(
                1,
                Ok(Events {
                    fdb: vec![(RTM_DELNEIGH, learned(3, 10, gone))],
                    ..Default::default()
                }),
            );
            // The recorded address is still wanted - it is learnt behind the
            // bridge - or the first pass would settle the note back to
            // nothing and the filter would not be filling any more.
            world.fdb.fdb = vec![learned(3, 10, kept)];
            daemon_loop(&mut world, &mut syncer, &opts);
            assert_eq!(
                world.passes.iter().map(|d| secs(*d)).collect::<Vec<_>>(),
                vec![0, 1],
                "with the filter nine tenths full, a deletion is worth a prompt pass"
            );
        }

        /// A stop is a stop: the loop ends without unregistering anything,
        /// which is what makes a restart invisible to the guests. There has
        /// to BE a registration for the claim to mean anything.
        #[test]
        fn stopping_leaves_every_registration_in_place() {
            let (mut syncer, opts, _dir) = setup("stop", 300);
            let guest = [0x02u8, 0, 0, 0, 0, 0x71];
            let mut world = FakeWorld::new(4).at(
                1,
                Ok(Events {
                    fdb: vec![(RTM_NEWNEIGH, learned(3, 10, guest))],
                    ..Default::default()
                }),
            );
            world.fdb.fdb = vec![learned(3, 10, guest)];
            daemon_loop(&mut world, &mut syncer, &opts);
            assert!(
                world.fdb.added.iter().any(|(_, m)| *m == guest),
                "the fixture never registered anything to leave in place"
            );
            assert!(world.fdb.removed.is_empty(), "a stop must not flush");
            assert!(
                std::fs::read_to_string(syncer.state_dir.join("nic1.owned"))
                    .unwrap_or_default()
                    .contains("02:00:00:00:00:71"),
                "the note has to survive the stop"
            );
        }

        /// The topology figure is measured at the World seam, from the
        /// pass's own reading: a real-clock measurement saturates to zero
        /// under a scripted world and no loop test could assert it.
        #[test]
        fn the_pass_reports_what_its_reading_cost() {
            let (mut syncer, opts, _dir) = setup("topo-cost", 300);
            let mut world = FakeWorld::new(1);
            world.read_cost = Duration::from_millis(7);
            daemon_loop(&mut world, &mut syncer, &opts);
            assert_eq!(
                syncer.timings.topology,
                Duration::from_millis(7),
                "the topology cost did not come from the world's clock"
            );
        }

        /// A batch whose reading fails can judge nothing: the carried driver
        /// answer is spent, the fast path is skipped, and a pass is bought
        /// - which reads again.
        #[test]
        fn a_batch_without_a_reading_spends_the_driver_answer_and_buys_a_pass() {
            let (mut syncer, _opts, _dir) = setup("blind-batch", 300);
            let mut world = FakeWorld::new(5);
            // The reading before says index 2 has no functions.
            let mut last = Some(
                crate::topology::fixture::Builder::new()
                    .add("nic1", 2, Some(mac(1)))
                    .build(),
            );
            syncer.vf_stale = false;
            world.topo_fails = true;
            let started = world.base;
            let bought = handle_batch(
                &mut world,
                &mut syncer,
                &mut last,
                &netlink::Events {
                    links_changed: true,
                    changed_links: vec![2],
                    ..Default::default()
                },
                started,
            );
            assert!(
                syncer.vf_stale,
                "a link change nothing could judge kept the carried answer"
            );
            assert!(
                bought.is_some(),
                "a batch nothing could judge has to buy a pass"
            );
            // And a learning batch without a reading registers nothing but
            // still buys the pass that will.
            let bought = handle_batch(
                &mut world,
                &mut syncer,
                &mut last,
                &netlink::Events {
                    fdb: vec![(RTM_NEWNEIGH, learned(3, 10, [0x02, 0, 0, 0, 0, 0x77]))],
                    ..Default::default()
                },
                started,
            );
            assert!(bought.is_some());
            assert!(
                world.fdb.added.is_empty(),
                "nothing may be registered blind"
            );
        }
    }
}
