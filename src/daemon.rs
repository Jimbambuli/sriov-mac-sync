//! The daemon: what happens between events, and when.
//!
//! Everything here is a decision about time or about what the world said; the
//! world arrives as a trait so the tests can hand in a scripted one. `main`
//! keeps the command line, the configuration file and the one-shot modes.

use crate::netlink::Socket;
use crate::sync::{self, Pair, Syncer};
use crate::topology::Topology;
use crate::Options;
use crate::{drivers, netlink, note, pair_names, report_changes, stopping};
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
    fn dump_fdb_of(&mut self, ifindex: u32) -> std::io::Result<Vec<netlink::FdbEntry>> {
        self.sock.dump_fdb_of(ifindex)
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
        // A poll on the stop pipe rather than a sleep, so SIGTERM during the
        // wait-failure brake does not wait the brake out. The brake is used
        // when poll itself may be what fails, so a failing poll falls back
        // to sleeping, and a byte that is not a stop (SIGHUP) is drained
        // and the wait goes on - or the brake would be void exactly when it
        // is needed.
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            let Some(stop_rx) = &self.stop_rx else {
                std::thread::sleep(left);
                return;
            };
            let mut pfd = libc::pollfd {
                fd: stop_rx.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let millis = left.as_millis().min(i32::MAX as u128) as i32;
            let rc = unsafe { libc::poll(&mut pfd, 1, millis) };
            if rc < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                std::thread::sleep(left);
                return;
            }
            if rc > 0 {
                let mut sink = [0u8; 16];
                while unsafe { libc::read(pfd.fd, sink.as_mut_ptr().cast(), sink.len()) } > 0 {}
                if crate::stopping() {
                    return;
                }
            }
        }
    }
    fn read_topology(&mut self) -> Result<Topology, String> {
        read_topology(&mut self.sock)
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
    /// Which reason for a pass produced work is the only way to tell whether
    /// the timed one earns its keep.
    trigger: Trigger,
    interval: Duration,
}

/// Why a pass runs. The label is what the journal shows and what the trial
/// harness greps for; the variant is what the code compares, so a typo in
/// a label cannot silently disable a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trigger {
    Start,
    Timed,
    Operator,
    Recovery,
    LostEvents,
    InterfaceChange,
    ForwardingChange,
    Once,
}

impl Trigger {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Trigger::Start => "start",
            Trigger::Timed => "timed",
            Trigger::Operator => "operator",
            Trigger::Recovery => "recovery",
            Trigger::LostEvents => "lost events",
            Trigger::InterfaceChange => "interface change",
            Trigger::ForwardingChange => "forwarding change",
            Trigger::Once => "once",
        }
    }
}

impl Schedule {
    fn new(now: Instant, interval: Duration) -> Self {
        Self {
            next_full: now,
            last_pass: now - interval,
            trigger: Trigger::Start,
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
        self.trigger = Trigger::Timed;
    }

    /// A batch wants a pass sooner. Everything that does goes through here.
    fn bring_forward(&mut self, due: Instant, trigger: Trigger) {
        self.next_full = self.next_full.min(due);
        self.trigger = trigger;
    }

    /// Nothing carried over may be believed and the pass cannot wait: a failed
    /// wait, or notifications the kernel dropped.
    fn at_once(&mut self, now: Instant, trigger: Trigger) {
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
    let interval = Duration::from_secs(opts.interval);
    let mut schedule = Schedule::new(world.now(), interval);
    // When the driver's VF answer was last read fresh. A carried answer is
    // good for one interval, whatever the passes were called: on a busy
    // host no pass is ever "timed", and staleness has to be a matter of age.
    let mut vf_fresh = world.now();
    // The previous reading, kept for one question only: what a link message
    // was about. An interface that has just gone is in no fresh reading.
    let mut last: Option<Topology> = None;
    let mut wait_failures = 0u32;
    let mut state = LoopState {
        said_empty: false,
        said_cards: crate::hash::set(),
    };

    loop {
        if world.stopping() {
            break;
        }
        // The operator knocked: now, and believe nothing.
        if world.resync_wanted() {
            syncer.vf_stale = true;
            schedule.at_once(world.now(), Trigger::Operator);
        }
        let now = world.now();
        if now.saturating_duration_since(vf_fresh) >= interval {
            syncer.vf_stale = true;
        }
        if schedule.pass_due(now) {
            match run_pass(world, syncer, &mut last, opts, schedule.trigger, &mut state) {
                Pass::Done => {
                    if !syncer.timings.vf_carried {
                        vf_fresh = now;
                    }
                    schedule.completed(world.now())
                }
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
                schedule.at_once(world.now(), Trigger::Recovery);
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
                schedule.at_once(world.now(), Trigger::LostEvents);
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

/// The loop's say-once marks, threaded through the passes as one thing
/// because they live exactly as long as the loop.
struct LoopState {
    said_empty: bool,
    /// Cards whose limit has been said.
    said_cards: crate::hash::Set<String>,
}

fn run_pass<W: World>(
    world: &mut W,
    syncer: &mut Syncer,
    last: &mut Option<Topology>,
    opts: &Options,
    trigger: Trigger,
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
        }
    }
    // Every pass, because it is map lookups: a card that appears later
    // gets its number when it does.
    apply_card_limits(syncer, &topo, opts.max_macs_set, &mut state.said_cards);
    if syncer.pairs.is_empty() && !state.said_empty {
        note!("waiting for an SR-IOV interface to appear in a bridge");
        state.said_empty = true;
    }

    let outcome = match syncer.reconcile(world, true, &topo, topo_load) {
        Ok(reports) => {
            report_changes(&reports, opts.dry_run, trigger);
            if opts.timings {
                note!(
                    "pass [{}]\n{}",
                    trigger.label(),
                    syncer.timings.report().trim_end()
                );
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
) -> Option<(Instant, Trigger)> {
    if events.fdb.is_empty() && !events.links_changed {
        return None; // something else's neighbour, not a bridge's
    }
    // A batch carrying both kinds is called a forwarding change.
    let trigger = if events.fdb.is_empty() {
        Trigger::InterfaceChange
    } else {
        Trigger::ForwardingChange
    };
    // Whether the batch left anything for a pass. A pass dumps the whole
    // forwarding table, so a batch that was entirely somebody else's must not
    // buy one. Link changes always do.
    let mut urgency = if events.links_changed {
        sync::Urgency::Now
    } else {
        sync::Urgency::Nothing
    };

    // A fresh reading for every batch that could register or that changed
    // an interface. What the batch's link messages were about is judged
    // against the reading before it as well, because an interface that has
    // just gone is only in that one. A deletions-only batch - the commonest
    // kind on a quiet host, an ageing table by the hundred - only dates the
    // silence, and the reading before is good enough for that: a bridge's
    // ageing time and any restacking arrive as link messages, which force
    // the read.
    let needs_reading = events.links_changed
        || events
            .fdb
            .iter()
            .any(|(kind, _)| *kind == netlink::RTM_NEWNEIGH);
    let fresh = if needs_reading {
        match read_picture(world) {
            Ok((topo, _)) => Some(topo),
            Err(e) => {
                eprintln!("warning: {e}");
                None
            }
        }
    } else {
        None
    };
    if !events.changed_links.is_empty()
        && (fresh.is_none()
            || sync::vf_may_have_changed(last.as_ref(), fresh.as_ref(), &events.changed_links))
    {
        // Nothing readable to judge with spends the carried answer too.
        syncer.vf_stale = true;
    }
    let judged_by = if needs_reading {
        fresh.as_ref()
    } else {
        last.as_ref()
    };
    match judged_by {
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
    // those by the hundred and each would buy a whole-table dump - unless a
    // filter is filling up, when entries that should be gone take room from
    // entries that should be there.
    let filling = syncer.any_filter_filling();
    let wait = if urgency == sync::Urgency::Now || filling {
        Duration::from_millis(200)
    } else {
        AGEING_SETTLE
    };
    Some(((last_pass + wait).max(world.now()), trigger))
}

/// The interfaces that really hold the uplinks' filters: the uplink itself,
/// or for a VLAN the interface below - the only one with a list of its own.
pub(crate) fn filter_carriers(devs: &[String], topo: &Topology) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in devs {
        let name = topo
            .index_of(d)
            .map(|i| topo.filter_carrier(i))
            .and_then(|c| topo.name_of(c))
            .unwrap_or(d)
            .to_string();
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// The driver behind an interface, and what the table says about it. A
/// bond has no driver: its list is copied to every member, so the members
/// answer, and the smallest of them binds.
fn card_filter(
    topo: &Topology,
    link: &crate::topology::Link,
) -> (Option<String>, Option<drivers::Filter>) {
    let vf = link.is_vf || link.physfn.is_some();
    if let Some(d) = link.driver.as_deref() {
        return (Some(d.to_string()), drivers::filter_of(d, vf));
    }
    if link.is_bridge || link.slaves.is_empty() {
        return (None, None);
    }
    let mut stack: Vec<u32> = link.slaves.clone();
    let mut seen = crate::hash::set();
    let mut best: Option<(String, drivers::Filter)> = None;
    while let Some(i) = stack.pop() {
        if !seen.insert(i) {
            continue;
        }
        let Some(l) = topo.at(i) else { continue };
        match l.driver.as_deref() {
            Some(d) => {
                if let Some(f) = drivers::filter_of(d, l.is_vf || l.physfn.is_some()) {
                    let smaller = match &best {
                        None => true,
                        Some((_, b)) => {
                            f.holds.unwrap_or(usize::MAX) < b.holds.unwrap_or(usize::MAX)
                        }
                    };
                    if smaller {
                        best = Some((format!("{d} behind {}", link.name), f));
                    }
                }
            }
            None => {
                stack.extend(l.slaves.iter().copied());
                stack.extend(l.filter_below);
            }
        }
    }
    match best {
        Some((d, f)) => (Some(d), Some(f)),
        None => (None, None),
    }
}

/// What each card holds, by the interface holding the filter: what the
/// kernel source says its driver does (see `drivers`), the assumed number
/// where it names none. Applied to the syncer as the per-card limit and, as
/// the smallest of them, the number to warn at - unless the operator set
/// --max, which the numbers yield to and the warnings do not. A card absent
/// from this reading keeps its last number. Each card is said once, when its
/// driver is known; a driver that never programs the list on this role is a
/// warning, because nothing registered there takes effect.
pub(crate) fn apply_card_limits(
    syncer: &mut Syncer,
    topo: &Topology,
    max_set: bool,
    said: &mut crate::hash::Set<String>,
) {
    let devs: Vec<String> = syncer.pairs.iter().map(|p| p.dev.clone()).collect();
    let assumed = sync::DEFAULT_MAX_MACS;
    let mut limits: crate::hash::Map<String, usize> = crate::hash::map();
    for card in filter_carriers(&devs, topo) {
        let Some(link) = topo.index_of(&card).and_then(|i| topo.at(i)) else {
            if let Some(n) = syncer.max_macs_per_card.get(&card) {
                limits.insert(card, *n);
            }
            continue;
        };
        let (driver, filter) = card_filter(topo, link);
        let first = driver.is_some() && said.insert(card.clone());
        let mut holds = assumed;
        match (driver, filter) {
            (Some(d), Some(f)) => match f.past {
                drivers::Past::Ignored => {
                    if first {
                        eprintln!(
                            "warning: {card}: the {d} driver never programs a unicast \
                             list on this interface - nothing registered here takes effect"
                        );
                    }
                }
                drivers::Past::PromiscFromFirst => {
                    if first {
                        note!(
                            "{card}: the {d} driver has no unicast filter - the kernel makes \
                             the interface promiscuous at the first entry, traffic flows and \
                             the list is moot"
                        );
                    }
                }
                _ => {
                    let past = match f.past {
                        drivers::Past::Drops => "drops silently",
                        drivers::Past::Promisc => "goes unicast-promiscuous",
                        drivers::Past::Hashes => "falls back to a hash filter",
                        _ => unreachable!(),
                    };
                    match f.holds {
                        Some(n) => {
                            holds = n;
                            if first {
                                note!(
                                    "{card}: the {d} driver holds {n} addresses by the kernel \
                                     source and {past} past that"
                                );
                            }
                        }
                        None if first => note!(
                            "{card}: the {d} driver's limit lives in firmware; assuming \
                             {assumed}, and it {past} past its real one"
                        ),
                        None => {}
                    }
                }
            },
            (Some(d), None) if first => {
                note!("{card}: the {d} driver is not in the table; assuming {assumed} addresses");
            }
            _ => {} // no driver known in this reading: the next may know
        }
        limits.insert(card, holds);
    }
    if max_set {
        return; // the operator's number governs every card
    }
    let limit = limits.values().copied().min().unwrap_or(assumed);
    syncer.max_macs_per_card = limits;
    if limit != syncer.max_macs {
        note!(
            "the number to warn at is {limit} addresses; quiet addresses are released \
             as a list comes near its card's limit"
        );
        syncer.max_macs = limit;
    }
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
        assert_eq!(
            s.trigger,
            Trigger::Start,
            "the first pass is the restart catch-up"
        );
        s.completed(now);
        assert_eq!(s.trigger, Trigger::Timed, "the default between events");
        assert!(
            !s.pass_due(now + interval / 2),
            "a completed pass pushes the timer a whole interval out"
        );
        assert!(
            s.pass_due(now + interval),
            "and after an interval of silence it fires"
        );
        s.bring_forward(now, Trigger::ForwardingChange);
        assert_eq!(
            s.trigger,
            Trigger::ForwardingChange,
            "an event keeps its own label"
        );
        s.retry_soon(now);
        assert_eq!(
            s.trigger,
            Trigger::ForwardingChange,
            "the retried pass forgot whose pass it was"
        );
        s.at_once(now, Trigger::Recovery);
        assert_eq!(s.trigger, Trigger::Recovery);
        s.completed(now);
        assert_eq!(s.trigger, Trigger::Timed);
    }

    /// The kernel source answers for each card by driver and role; the
    /// smallest number is the one to warn at; a card the table cannot number
    /// keeps the assumed number rather than inheriting the smallest card's;
    /// a card absent from a reading keeps its last number; a bond answers
    /// with its smallest member; the operator's --max leaves every number
    /// alone.
    #[test]
    fn the_driver_table_sets_the_limits() {
        use crate::topology::fixture::{mac, Builder};
        let topo = Builder::new()
            .add("be", 2, Some(mac(1)))
            .driver("be2net")
            .add("bev", 3, Some(mac(2)))
            .driver("be2net")
            .physfn("be")
            .add("i40", 4, Some(mac(3)))
            .driver("i40e")
            .add("ena0", 5, Some(mac(4)))
            .driver("ena")
            .add("veth", 6, Some(mac(5)))
            .add("av0", 7, Some(mac(6)))
            .driver("iavf")
            .physfn("i40")
            .master("bond0")
            .add("av1", 8, Some(mac(7)))
            .driver("iavf")
            .physfn("i40")
            .master("bond0")
            .add("bond0", 9, Some(mac(6)))
            .lower("av0")
            .lower("av1")
            .build();
        let pair = |d: &str| Pair {
            dev: d.into(),
            bridge: "br".into(),
        };
        let dir =
            std::env::temp_dir().join(format!("sriov-mac-sync-limits-{}", std::process::id()));
        let mut syncer = Syncer::new(
            vec![pair("i40"), pair("ena0"), pair("veth"), pair("later")],
            dir.clone(),
        );
        let mut said = crate::hash::set();
        apply_card_limits(&mut syncer, &topo, false, &mut said);
        assert_eq!(
            syncer.max_macs, 128,
            "firmware-limited, ignored and unknown cards set no number"
        );
        assert_eq!(
            syncer.max_macs_per_card.get("i40"),
            Some(&128),
            "the assumed number, per card"
        );
        assert_eq!(syncer.max_macs_per_card.get("ena0"), Some(&128));
        assert!(
            !said.contains("later"),
            "an absent card is not said, it is asked again"
        );

        // Roles: the PF and the VF of one driver hold different numbers.
        syncer.pairs = vec![pair("be"), pair("bev"), pair("i40")];
        apply_card_limits(&mut syncer, &topo, false, &mut said);
        assert_eq!(syncer.max_macs_per_card.get("be"), Some(&30));
        assert_eq!(
            syncer.max_macs_per_card.get("bev"),
            Some(&2),
            "the VF role, by physfn"
        );
        assert_eq!(syncer.max_macs, 2, "the smallest card governs the warning");
        assert_eq!(
            syncer.limit_of("i40"),
            128,
            "a card without a number keeps the assumed one, not the smallest card's"
        );

        // A bond of VFs answers with its smallest member.
        syncer.pairs = vec![pair("bond0")];
        apply_card_limits(&mut syncer, &topo, false, &mut said);
        assert_eq!(
            syncer.max_macs_per_card.get("bond0"),
            Some(&12),
            "iavf behind the bond"
        );

        // A card that drops out of one reading keeps its number.
        let bare = Builder::new().add("lo", 1, None).build();
        apply_card_limits(&mut syncer, &bare, false, &mut said);
        assert_eq!(
            syncer.max_macs_per_card.get("bond0"),
            Some(&12),
            "kept while absent"
        );

        // --max: the numbers are the operator's, the table only warns.
        let mut fixed = Syncer::new(vec![pair("bev")], dir.clone());
        fixed.max_macs = 200;
        apply_card_limits(&mut fixed, &topo, true, &mut crate::hash::set());
        assert_eq!(fixed.max_macs, 200);
        assert!(fixed.max_macs_per_card.is_empty());
        assert_eq!(fixed.limit_of("bev"), 200);
        let _ = std::fs::remove_dir_all(&dir);
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
            /// the reading to hand out instead of the fixtures, when set
            topo_override: Option<Topology>,
            /// when the operator knocks (--resync), if at all
            resync_at: Option<Duration>,
            /// every pause the loop asked for
            paused: Vec<Duration>,
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
                    topo_override: None,
                    resync_at: None,
                    paused: Vec::new(),
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
            fn resync_wanted(&mut self) -> bool {
                if self.resync_at.is_some_and(|t| self.offset >= t) {
                    self.resync_at = None;
                    return true;
                }
                false
            }
            fn read_topology(&mut self) -> Result<Topology, String> {
                self.topo_calls += 1;
                self.offset += self.read_cost;
                if self.topo_fails {
                    Err("no picture today".into())
                } else if let Some(t) = &self.topo_override {
                    Ok(t.clone())
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
        /// link event buys, not by the next timed pass: autodetection runs
        /// on every pass's own reading.
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
            sched.at_once(start, Trigger::Recovery);
            assert!(sched.pass_due(start));
            // The timer comes round: it may not push that pass away.
            let later = start + Duration::from_secs(600);
            assert!(sched.pass_due(later), "a due pass stays due");
            // Neither may a batch that only wants one soon.
            sched.bring_forward(later + Duration::from_secs(60), Trigger::ForwardingChange);
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

        /// When the filter is filling up, even an ageing burst is answered
        /// at the fast rate: entries that should be gone are taking room
        /// from entries that should be there.
        #[test]
        fn a_filling_filter_turns_deletions_urgent() {
            let (mut syncer, mut opts, _dir) = setup("filling", 300);
            // The operator's --max, the way run() wires it: the loop then
            // leaves the number alone.
            // Ten slots, nine held: exactly nine tenths, the edge the rule
            // is written at.
            opts.max_macs = 10;
            opts.max_macs_set = true;
            syncer.max_macs = 10;
            let guests: Vec<[u8; 6]> = (1..=9u8).map(|i| [0x02, 0, 0, 0, 0, 0x60 + i]).collect();
            // The addresses are on record. The file is the truth, so the
            // file is what the test writes.
            std::fs::create_dir_all(&syncer.state_dir).unwrap();
            let lines: String = guests
                .iter()
                .map(|m| format!("{}\n", crate::netlink::format_mac(m)))
                .collect();
            std::fs::write(syncer.state_dir.join("nic1.owned"), lines).unwrap();
            let gone = [0xaa, 0, 0, 0, 0, 0x54];
            let mut world = FakeWorld::new(4).at(
                1,
                Ok(Events {
                    fdb: vec![(RTM_DELNEIGH, learned(3, 10, gone))],
                    ..Default::default()
                }),
            );
            // The recorded addresses are still wanted - learnt behind the
            // bridge - or the first pass would settle the note back to
            // nothing and the filter would not be filling any more. Nine of
            // ten: the bridge's own address is the uplink's and drops out.
            world.fdb.fdb = guests.iter().map(|m| learned(3, 10, *m)).collect();
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
            assert_eq!(
                bought.map(|(_, t)| t),
                Some(Trigger::InterfaceChange),
                "a batch nothing could judge has to buy a pass, under its own name"
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
            assert_eq!(bought.map(|(_, t)| t), Some(Trigger::ForwardingChange));
            assert!(
                world.fdb.added.is_empty(),
                "nothing may be registered blind"
            );
        }

        /// The operator's knock buys a pass at once, under its own name, and
        /// that pass asks the driver afresh.
        #[test]
        fn a_resync_buys_a_distrusting_pass_at_once() {
            let (mut syncer, opts, _dir) = setup("resync", 300);
            let mut world = FakeWorld::new(8).at(3, Ok(Events::default()));
            world.resync_at = Some(Duration::from_secs(3));
            daemon_loop(&mut world, &mut syncer, &opts);
            assert_eq!(
                world.passes.iter().map(|d| secs(*d)).collect::<Vec<_>>(),
                vec![0, 3],
                "the knock has to buy a pass now"
            );
            assert_eq!(
                world.fdb.vf_asked, 2,
                "and that pass believes nothing carried"
            );
        }

        /// A link message is judged against the reading BEFORE the batch as
        /// well as the fresh one: an interface that lost its functions is
        /// only known to have had any by the reading before.
        #[test]
        fn a_link_change_is_judged_against_the_reading_before_it() {
            let (mut syncer, _opts, _dir) = setup("before-picture", 300);
            let mut world = FakeWorld::new(5);
            // The reading before: nic1 hands out functions.
            let mut last = Some(host(mac(1)));
            // The fresh reading: nic1 is there, with nothing behind it.
            world.topo_override = Some(
                crate::topology::fixture::Builder::new()
                    .add("nic1", 2, Some(mac(1)))
                    .build(),
            );
            syncer.vf_stale = false;
            let started = world.base;
            handle_batch(
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
                "the functions nic1 just lost were only in the reading before"
            );
        }

        /// A fast path that fails - the driver would not answer - buys the
        /// pass that will do its work, rather than ending the batch quietly.
        #[test]
        fn a_batch_whose_fast_path_fails_buys_a_pass() {
            let (mut syncer, _opts, _dir) = setup("fast-path-fails", 300);
            let mut world = FakeWorld::new(5);
            let mut last = Some(host(mac(1)));
            syncer.vf_stale = true; // the batch has to ask the driver ...
            world.fdb.fail_vf = Some(libc::EIO); // ... and the driver refuses
            let started = world.base;
            let bought = handle_batch(
                &mut world,
                &mut syncer,
                &mut last,
                &netlink::Events {
                    fdb: vec![(RTM_NEWNEIGH, learned(3, 10, [0x02, 0, 0, 0, 0, 0x78]))],
                    ..Default::default()
                },
                started,
            );
            assert!(bought.is_some(), "a failed fast path has to buy a pass");
        }
    }
}
