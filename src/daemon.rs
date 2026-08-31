//! The daemon: what happens between events, and when.
//!
//! Everything here is a decision about time or about what the world said -
//! the pass cadence and what a pass calls itself, the picture of the
//! interfaces and how long it may be believed, the capacity a card
//! reports. The world arrives as a trait so the tests can hand in a
//! scripted one and this code cannot tell the difference; `main` keeps the
//! command line, the configuration file and the one-shot modes.

use crate::netlink::Socket;
use crate::sync::{self, Pair, Syncer};
use crate::topology::Topology;
use crate::{clamp_max_macs, devlink, netlink, note, pair_names, report_changes, stopping};
use crate::{Options, AGEING_SETTLE, RETRY_AFTER};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

/// The interface picture, from the kernel in one dump.
pub(crate) fn read_topology(sock: &mut Socket) -> Result<Topology, String> {
    let links = sock
        .dump_links()
        .map_err(|e| format!("cannot ask the kernel about the interfaces: {e}"))?;
    Ok(Topology::from_links(links))
}

/// Everything the daemon loop reaches for outside itself: the clock, the
/// two sockets and the stop flag.
///
/// The loop is where the scheduling lives - when a pass is due, what a
/// batch is worth, how a failure is retried - and every one of those
/// decisions is a function of time and of what the sockets said. Reaching
/// for `Instant::now()` and the sockets directly put all of it beyond any
/// test's reach: the loop was the one piece of this daemon whose behaviour
/// only a live kernel could confirm. This trait is the seam. `Live`
/// forwards to the real clock and sockets and adds nothing; the tests
/// stand in a scripted world and watch what the loop decides.
///
/// `FdbWriter` as the supertrait, because the pass and the fast path
/// already take their socket through it - the loop hands itself over.
/// (A trait object would need trait upcasting, which is newer Rust than
/// this builds with; the loop is generic instead, and the compiler folds
/// the one production instantiation flat.)
pub(crate) trait World: sync::FdbWriter {
    fn now(&self) -> Instant;
    fn stopping(&self) -> bool;
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

/// When the next pass is due, when the picture is read again regardless of
/// what anybody says, and what to call the pass that results.
///
/// These were three locals, and their coupling was the subtlest thing in this
/// file: the refresh was once gated on what the pass called itself, every
/// batch renames the pass, and so on a host whose bridges age entries - which
/// is every host - the condition stopped being true and the daemon never
/// refreshed at all. The `[timed]` line the trial looks for went with it.
/// Holding them together means every rule about them is one of these methods.
pub(crate) struct Schedule {
    /// A deadline, not a sleep. Wake-ups that turn out to be none of our
    /// business must not push the full pass further away.
    next_full: Instant,
    next_refresh: Instant,
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
            // A whole interval out, not now: the first pass is the catch-up
            // after a restart and calls itself "start" - a refresh firing on
            // the first iteration used to rename it "timed", and the
            // canary's one job is that "timed" means the timer caught
            // something.
            next_refresh: now + interval,
            last_pass: now - interval,
            trigger: "start",
            interval,
        }
    }

    /// The refresh exists to catch what the events missed, an interface change
    /// whose notification never arrived included. It believes nothing it was
    /// told, and brings the pass forward so that what it reads is acted on.
    /// The caller invalidates what it holds; saying so is not this type's job.
    /// The trigger name is left alone: after a quiet interval it already
    /// says "timed" (completed() set the default), and a pending batch
    /// label must not be stolen - the pass does that batch's work too, and
    /// a correction reported as `[timed]` is the canary's false alarm.
    fn refresh_due(&mut self, now: Instant) -> bool {
        if now < self.next_refresh {
            return false;
        }
        self.next_full = self.next_full.min(now);
        self.next_refresh = now + self.interval;
        true
    }

    fn pass_due(&self, now: Instant) -> bool {
        now >= self.next_full
    }

    /// A pass that could not run - no picture, or reconciliation refused. Come
    /// back soon rather than sitting out the whole interval: one refused dump
    /// used to cost five minutes of not looking at the host at all.
    /// The retried pass keeps the name of the pass that failed - a
    /// forwarding change whose pass hit a transient rtnl error is still a
    /// forwarding change five seconds later.
    fn retry_soon(&mut self, now: Instant) {
        self.next_full = now + RETRY_AFTER;
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
        self.next_full
            .min(self.next_refresh)
            .saturating_duration_since(now)
    }
}

/// The topology carried over from the last pass, and whether it can still be
/// believed. A forwarding entry appearing or going says nothing about which
/// interfaces exist or what they are enslaved to, so a pass woken by one works
/// from the picture it already has. Anything that touches interfaces marks it
/// stale, as does losing notifications and the timed refresh, whose whole
/// purpose is to find what the events missed.
pub(crate) struct Picture {
    held: Option<Topology>,
    stale: bool,
    /// Whether a read replaced the picture since the last pass consumed one.
    /// The pass needs this to know that autodetection's answer may have
    /// changed: a batch reads the fresh picture *before* the pass it buys,
    /// so by the time that pass runs, needs_reading() is already false.
    replaced_since_pass: bool,
    /// What reading the picture cost when an event read it, so the pass that
    /// uses it can account for it. Without this a pass whose topology was read
    /// moments earlier reports "0.000 ms" for it, which reads as "not read at
    /// all" - it misled the author of this line for an hour.
    carried_load: Duration,
}

impl Picture {
    fn new() -> Self {
        Self {
            held: None,
            stale: true,
            replaced_since_pass: false,
            carried_load: Duration::ZERO,
        }
    }

    fn invalidate(&mut self) {
        self.stale = true;
    }

    fn needs_reading(&self) -> bool {
        self.stale || self.held.is_none()
    }

    /// The read itself. What it cost, and the picture it replaced.
    fn read<W: World>(&mut self, world: &mut W) -> Result<(Duration, Option<Topology>), String> {
        let started = world.now();
        let fresh = world.read_topology()?;
        self.stale = false;
        self.replaced_since_pass = true;
        Ok((started.elapsed(), self.held.replace(fresh)))
    }

    /// Before a pass, which **fails closed**: a pass on a picture that may be
    /// wrong is worse than no pass at all, so a refused read throws away what
    /// was held and the caller schedules the retry. The cost reported is the
    /// fresh read's, superseding anything an event carried.
    fn for_pass<W: World>(&mut self, world: &mut W) -> Duration {
        let carried = std::mem::take(&mut self.carried_load);
        let cost = if !self.needs_reading() {
            carried
        } else {
            match self.read(world) {
                Ok((cost, _)) => cost,
                Err(e) => {
                    eprintln!("warning: {e}");
                    self.held = None;
                    carried
                }
            }
        };
        // Cleared after the read, not before: read() marks the picture
        // replaced, and a pass that read for itself has consumed that
        // replacement in the same breath. Cleared first, the flag came
        // back up and bought every fresh-read pass a redundant
        // autodetect on its next event.
        self.replaced_since_pass = false;
        cost
    }

    /// Before the fast path, which **keeps what it had**: answering a batch
    /// from a picture one link message out of date still beats not answering
    /// it. The cost is carried to the pass a few milliseconds later, which
    /// works from this same reading rather than paying for its own.
    fn for_batch<W: World>(&mut self, world: &mut W) -> Option<Topology> {
        if !self.needs_reading() {
            return None;
        }
        match self.read(world) {
            Ok((cost, previous)) => {
                self.carried_load += cost;
                previous
            }
            Err(e) => {
                eprintln!("warning: {e}");
                None
            }
        }
    }
}

/// "Believe nothing carried": the picture and the driver's VF answer go
/// stale together, always - the history knows exactly the bug where one
/// of the two was forgotten on one path.
pub(crate) fn distrust_carried(picture: &mut Picture, syncer: &mut Syncer) {
    picture.invalidate();
    syncer.vf_stale = true;
}

/// The daemon: answer batches through the fast path, keep the pass rate
/// bounded, and never trust a picture longer than the interval. Everything
/// here is a decision about time or about what the world said, which is why
/// the world arrives as a parameter - the tests hand in a scripted one and
/// this function cannot tell.
pub(crate) fn daemon_loop<W: World>(world: &mut W, syncer: &mut Syncer, opts: &Options) {
    let mut schedule = Schedule::new(world.now(), Duration::from_secs(opts.interval));
    let mut picture = Picture::new();
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
        if schedule.refresh_due(world.now()) {
            distrust_carried(&mut picture, syncer);
        }
        if schedule.pass_due(world.now()) {
            match run_pass(
                world,
                syncer,
                &mut picture,
                opts,
                schedule.trigger,
                &mut state,
            ) {
                Pass::Done => schedule.completed(world.now()),
                Pass::Refused => {
                    schedule.retry_soon(world.now());
                    continue;
                }
            }
        }

        let due = schedule.wait_for(world.now());
        // Rounded up, not truncated: poll sleeps at most what it is told,
        // so a truncated wait woke just before the deadline and the loop
        // then spun through poll(0) for the last millisecond. Oversleeping
        // by under a millisecond is harmless - the deadline is re-checked
        // at the top.
        let millis = due.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32;
        let woken = match world.wait(millis) {
            Ok(w) => {
                wait_failures = 0;
                w
            }
            Err(e) => {
                eprintln!("warning: waiting for events failed: {e}");
                // The first failure buys a prompt recovery pass. A wait
                // that KEEPS failing (sustained ENOMEM) must not turn the
                // daemon into a hot loop of full-table dumps, each paying
                // a dump to learn nothing - so from the second failure on,
                // the retry pace applies before the pass.
                if wait_failures > 0 {
                    world.pause(RETRY_AFTER);
                }
                wait_failures = wait_failures.saturating_add(1);
                schedule.at_once(world.now(), "recovery");
                distrust_carried(&mut picture, syncer);
                continue;
            }
        };
        if !woken {
            continue; // the deadline came round; the pass happens above
        }

        let events = match world.recv_events() {
            Ok(events) => events,
            // ENOBUFS means the kernel dropped notifications because we could
            // not keep up. Losing them is survivable - a full pass reads the
            // real state - but exiting over it would not be. What was in the
            // messages that never arrived is not knowable, so nothing carried
            // over may be believed.
            Err(e) => {
                eprintln!("warning: lost neighbour notifications: {e}");
                schedule.at_once(world.now(), "lost events");
                distrust_carried(&mut picture, syncer);
                continue;
            }
        };

        if let Some((due, trigger)) =
            handle_batch(world, syncer, &mut picture, &events, schedule.last_pass)
        {
            schedule.bring_forward(due, trigger);
        }
    }
}

/// Whether a pass got as far as reconciling. It is the caller that owns the
/// clock, so a pass says what happened and schedules nothing itself.
pub(crate) enum Pass {
    Done,
    Refused,
}

/// One full pass: read the picture if it can no longer be believed, work out
/// which pairs there are, and reconcile every one of them against the kernel.
/// The daemon loop's accumulated say-once and adoption state, threaded
/// through the passes as one thing because it lives exactly as long as the
/// loop does.
pub(crate) struct LoopState {
    said_empty: bool,
    /// Whether a configured pair's card still owes its capacity answer.
    capacity_pending: bool,
}

pub(crate) fn run_pass<W: World>(
    world: &mut W,
    syncer: &mut Syncer,
    picture: &mut Picture,
    opts: &Options,
    trigger: &'static str,
    state: &mut LoopState,
) -> Pass {
    // One reading serves both the autodetection and the reconciliation: they
    // ask about the same moment, and reading it twice was work nobody asked
    // for. "Reloaded" includes a picture the batch read moments ago: the
    // batch reads *before* the pass it buys, so needs_reading() alone would
    // say false here and a bridge built at runtime waited for the timer.
    let reloaded = picture.needs_reading() || picture.replaced_since_pass;
    let topo_load = picture.for_pass(world);

    // Autodetection is redone every pass. A NIC that gets its VFs later, or a
    // bridge built after boot, must not need a restart to be noticed - and
    // starting before the network is up must not turn into a crash loop. But
    // it is a pure function of the picture, so on a pass that carried the
    // picture unchanged its answer cannot have changed either: a new NIC or
    // bridge arrives as a link message, whose batch replaces the picture -
    // which is exactly what sets `reloaded`.
    let auto = opts.pairs.is_empty();
    if let (true, true, Some(topo)) = (auto, reloaded, picture.held.as_ref()) {
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
            // that started before its bridges - the "waiting for an SR-IOV
            // interface" flow - would otherwise warn against the assumed
            // number for the rest of its life. The operator's --max still
            // wins; the gate is the same one.
            if !opts.max_macs_set && !syncer.pairs.is_empty() {
                let devs: Vec<String> = syncer.pairs.iter().map(|p| p.dev.clone()).collect();
                let answers = world.filter_capacities(&devs);
                if let Some(v) = adopt_reported_capacity(answers, opts.verbose, syncer.max_macs) {
                    // One number, one home: the warning threshold and the
                    // quiet-keep's pressure valve read the same field. The
                    // operator's --max never moves - the max_macs_set gate
                    // above is what enforces that, not a second copy.
                    syncer.max_macs = v;
                }
            }
        }
    }
    // The same cure for pairs the operator wrote down: a daemon started
    // before its configured uplink exists gets no devlink answer at start,
    // and pairs that never change never re-asked - the warning threshold
    // and the quiet-keep's pressure valve then measured against the
    // assumed number for the rest of the process. Asked again on every
    // reloaded picture until a card answers; the operator's --max still
    // wins, the gate is the same one.
    // `capacity_pending` already implies configured pairs and no operator
    // --max (it is initialised from exactly those two and only ever
    // cleared), so it carries the gate alone.
    if reloaded && state.capacity_pending {
        // Non-empty by construction: capacity_pending is only set when the
        // operator wrote pairs down, and resolve_pairs keeps every one of
        // them even before its interface exists.
        let devs: Vec<String> = syncer.pairs.iter().map(|p| p.dev.clone()).collect();
        {
            let answers = world.filter_capacities(&devs);
            // Settled only when EVERY written-down device has answered: the
            // first card's answer must not orphan a second, later-appearing
            // one - possibly the smaller filter - for the process's life.
            if answers.iter().all(|(_, a)| matches!(a, Ok(Some(_)))) {
                state.capacity_pending = false;
            }
            if let Some(v) = adopt_reported_capacity(answers, opts.verbose, syncer.max_macs) {
                syncer.max_macs = v;
            }
        }
    }
    if syncer.pairs.is_empty() && !state.said_empty {
        note!("waiting for an SR-IOV interface to appear in a bridge");
        state.said_empty = true;
    }

    // Nothing to work from. Fail closed; the caller comes back soon.
    let Some(topo) = picture.held.as_ref() else {
        return Pass::Refused;
    };
    match syncer.reconcile(world, true, topo, topo_load) {
        Ok(reports) => {
            report_changes(&reports, opts.dry_run, opts.verbose, trigger);
            if opts.timings {
                note!("pass [{}]\n{}", trigger, syncer.timings.report().trim_end());
            }
            Pass::Done
        }
        Err(e) => {
            eprintln!("warning: reconciliation failed: {e}");
            Pass::Refused
        }
    }
}

/// One batch of notifications: register what just appeared, before anything
/// else, so the first reply to it is not sent into the void. Says when a full
/// pass has to follow and what to call it.
///
/// `None` means the batch bought nothing - and buys no name either: a pass that
/// runs on the timer has to say "timed", or the one line that tells whether the
/// timer ever catches anything stops meaning it.
pub(crate) fn handle_batch<W: World>(
    world: &mut W,
    syncer: &mut Syncer,
    picture: &mut Picture,
    events: &netlink::Events,
    last_pass: Instant,
) -> Option<(Instant, &'static str)> {
    if events.fdb.is_empty() && !events.links_changed {
        return None; // something else's neighbour, not a bridge's
    }
    if events.links_changed {
        picture.invalidate();
    }
    // The invalidation above keys on links_changed, not on this name: a batch
    // carrying both kinds is called a forwarding change, and keying on the
    // name would have kept a topology its own link messages just invalidated.
    let trigger = if events.fdb.is_empty() {
        "interface change"
    } else {
        "forwarding change"
    };

    // What the batch's link messages were about is judged against the picture
    // as it stands - before it is read again, because an interface that has
    // just gone is only in that one.
    let previous = picture.for_batch(world);
    if !events.changed_links.is_empty()
        && sync::vf_may_have_changed(
            previous.as_ref(),
            picture.held.as_ref(),
            &events.changed_links,
        )
    {
        syncer.vf_stale = true;
    }

    // Whether the batch left anything for a pass to do. A pass dumps the
    // host's whole forwarding table, so a batch that was entirely somebody
    // else's - learning on the wire that was never ours, entries on unrelated
    // bridges - must not buy one. Link changes always do.
    let mut urgency = if events.links_changed {
        sync::Urgency::Now
    } else {
        sync::Urgency::Nothing
    };
    match picture.held.as_ref() {
        // The whole batch, both kinds. What each means is the fast path's
        // business: an address learnt behind the bridge is registered, one
        // learnt on the uplink's own port is taken back out if it was ours,
        // and a deletion is left to the pass that follows - one entry going
        // does not mean the address is gone.
        Some(topo) => match syncer.fast_apply(world, topo, &events.fdb) {
            Ok(u) => urgency = urgency.max(u),
            // It could not do its work, so the pass has to.
            Err(e) => {
                eprintln!("warning: answering the batch failed: {e}");
                urgency = sync::Urgency::Now;
            }
        },
        None => urgency = sync::Urgency::Now, // no picture to judge it by
    }
    if urgency == sync::Urgency::Nothing {
        return None;
    }

    // The full pass still has to follow - it is what removes stale entries and
    // reconciles the notes - but nothing waits for it any more. Its
    // predecessor waited for a 200 ms lull, which held every second address of
    // a burst back by exactly that, and unrelated neighbour chatter stretched
    // the wait towards its two-second bound. A pass rate bound does the same
    // job without making anything later than it has to be.
    //
    // Registrations and interface changes get the ordinary bound; a batch that
    // only reported deletions waits longer, because an ageing table produces
    // those by the hundred and each would otherwise buy a dump of the whole
    // table - unless the filter is filling up, when entries that should be
    // gone are taking room from entries that should be there. Asked lazily:
    // at Urgency::Now the wait is already decided, and registered() lists the
    // state directory and reads every note.
    let wait = if urgency == sync::Urgency::Now || syncer.registered() * 10 >= syncer.max_macs * 9 {
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

/// Take the smallest capacity the uplinks report as the threshold to warn
/// at. The smallest, because one number governs every uplink and the
/// filter that fills first is the one that drops addresses. A card that
/// says nothing changes nothing; so does a number this program would
/// refuse from a person, because a driver is not more trustworthy than an
/// operator - and it must not veto another card's good answer either.
///
/// `None` means the assumed threshold stands. The `--max`/`MAX_MACS` gate
/// lives at the call sites: an operator's instruction is never moved.
pub(crate) fn adopt_reported_capacity(
    answers: Vec<(String, CapacityAnswer)>,
    verbose: bool,
    assumed: usize,
) -> Option<usize> {
    let mut usable: Vec<(String, usize)> = Vec::new();
    for (dev, answer) in answers {
        match answer {
            Ok(Some(v)) => match clamp_max_macs(v as usize) {
                Ok(v) => usable.push((dev, v)),
                Err(_) => {
                    if verbose {
                        note!("{dev}: reported capacity {v} is unusable, ignored");
                    }
                }
            },
            Ok(None) => {
                if verbose {
                    note!("{dev}: no filter capacity reported; keeping the assumed {assumed}");
                }
            }
            Err(e) => {
                if verbose {
                    note!("{dev}: could not ask for the filter capacity: {e}");
                }
            }
        }
    }
    let (dev, value) = usable.into_iter().min_by_key(|(_, v)| *v)?;
    if value == assumed {
        // Worth saying only to somebody who asked what was skipped: the
        // number moved nowhere, but that it was *asked for* is the
        // difference between a card that agrees and a card that is silent.
        if verbose {
            note!("{dev} says its filter holds {value} addresses, which is what was assumed");
        }
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

    /// The trigger labels are what bench/trial.py's quiescence check and
    /// the [timed] canary read; internals.md promises recovery passes name
    /// themselves. Nothing pinned the renaming rules before, and a refresh
    /// or retry that stole a batch's label made the canary cry wolf.
    #[test]
    fn the_trigger_labels_survive_what_the_schedule_does() {
        let now = Instant::now();
        let interval = Duration::from_secs(300);
        let mut s = Schedule::new(now, interval);
        assert_eq!(s.trigger, "start", "the first pass is the restart catch-up");
        assert!(
            !s.refresh_due(now),
            "a refresh on the very first iteration would rename [start]"
        );
        s.completed(now);
        assert_eq!(s.trigger, "timed", "the default between events");
        s.bring_forward(now, "forwarding change");
        assert!(s.refresh_due(now + interval));
        assert_eq!(
            s.trigger, "forwarding change",
            "the refresh stole the batch's label"
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
                false,
                128
            ),
            Some(64)
        );
        // A card reporting nonsense is ignored, not a veto on the good one.
        assert_eq!(
            adopt_reported_capacity(
                vec![dev("nic0", Ok(Some(0))), dev("nic1", Ok(Some(64)))],
                false,
                128
            ),
            Some(64)
        );
        // Nothing usable at all leaves the default standing.
        assert_eq!(
            adopt_reported_capacity(vec![dev("nic0", Ok(Some(0)))], false, 128),
            None
        );
        // Agreement is not a change.
        assert_eq!(
            adopt_reported_capacity(vec![dev("nic0", Ok(Some(128)))], false, 128),
            None
        );
        // Silence and failure leave the default standing.
        assert_eq!(
            adopt_reported_capacity(
                vec![dev("nic0", Ok(None)), dev("nic1", Err("no".into()))],
                false,
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
        /// events arrive when the script says, and the clock cannot drift.
        /// Everything the loop decides is then a pure function of the
        /// script, which is what makes the schedule assertable at all.
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
            topo_fails: bool,
            topo_calls: usize,
            fdb: FakeSock,
            /// when each full pass ran - the dump is what a pass is
            passes: Vec<Duration>,
            /// errno the next wait() answers with, taken once
            fail_wait: Option<i32>,
            /// what filter_capacities answers, per netdev
            capacities: crate::hash::Map<String, u32>,
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
                    topo_fails: false,
                    topo_calls: 0,
                    fdb: FakeSock::default(),
                    passes: Vec::new(),
                    fail_wait: None,
                    capacities: crate::hash::map(),
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
                if let Some(errno) = self.fail_wait.take() {
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
                self.offset += wait;
            }
            fn filter_capacities(&mut self, devs: &[String]) -> Vec<(String, CapacityAnswer)> {
                self.capacity_asks.push(devs.to_vec());
                devs.iter()
                    .map(|d| (d.clone(), Ok(self.capacities.get(d).copied())))
                    .collect()
            }
            fn read_topology(&mut self) -> Result<Topology, String> {
                self.topo_calls += 1;
                if self.topo_fails {
                    Err("no picture today".into())
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
        /// autodetect and the pair set stays put.
        /// The guard comes back with the syncer and MUST be bound at the
        /// call site: dropped early, the directory vanishes while the
        /// daemon is still writing into it.
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

        /// A bridge built at runtime - the hotplug flow the "waiting for an
        /// SR-IOV interface" note promises - is adopted by the prompt pass
        /// its own link event buys, not by the next timed refresh. The batch
        /// reads the fresh picture *before* the pass it buys, so the pass
        /// cannot tell by needs_reading() alone; replaced_since_pass is what
        /// carries the news. Without it, a pair appearing at runtime waited
        /// out the whole interval - here 300 s - while the loop had already
        /// run a pass for exactly that event.
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

        /// The timed refresh's documented job is "it believes nothing it
        /// was told" - and until now nothing asserted that it actually
        /// distrusts both carried things. Deleting the distrust left every
        /// loop test green.
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

        /// A pair adopted at runtime brings its card's capacity with it.
        /// The start-time devlink question never saw this uplink; without
        /// the re-ask, a daemon started before its bridges warned against
        /// the assumed 128 for the rest of its life.
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

        /// An interface change invalidates the picture and the virtual
        /// functions' addresses with it: the next pass reads both afresh.
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
            assert_eq!(world.topo_calls, 2, "the picture was not read afresh");
            assert_eq!(
                world.fdb.vf_asked, 2,
                "a change on an interface with functions has to re-ask the driver"
            );
        }

        /// A configured pair is not second class: a daemon started before
        /// its written-down uplink exists gets no devlink answer at start,
        /// and without a re-ask the warning threshold and the quiet-keep's
        /// pressure valve would measure against the assumed number for the
        /// life of the process. Autodetection had this cure first; --pair
        /// was left out.
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

        /// A stop is a stop: the loop ends without unregistering anything.
        /// The registrations and the notes outliving the process is what
        /// makes a daemon restart invisible to the guests. There has to BE
        /// a registration for the claim to mean anything - stopping an
        /// empty world proved only that nothing removes nothing.
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
    }
}
