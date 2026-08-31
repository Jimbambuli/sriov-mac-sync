//! Deciding which addresses belong in an uplink's unicast filter, and putting
//! them there.

use crate::hash::{Map, Set};
use crate::note;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::netlink::{format_mac, FdbEntry, Socket};
use crate::topology::Topology;

pub type Mac = [u8; 6];

#[derive(Debug, Clone)]
pub struct Pair {
    pub dev: String,
    pub bridge: String,
}

/// One pair as the fast path needs it: the structural questions answered
/// once for the whole batch, because a batch describes a single moment.
/// The two halves of fast_apply's grow-only driver refresh. They never
/// vary independently: deciding collects what would be registered - stale
/// carried VF exclusions included - so the fresh driver question can be
/// paid only when something would grow; committing collects the batch's
/// real candidates, trusting the (by then fresh) skip sets. Neither
/// phase writes - the caller writes the decided batch through, note first.
#[derive(Clone, Copy, PartialEq)]
enum FastPhase {
    Decide,
    Commit,
}

struct FastPair {
    /// kept for the messages a person reads
    dev: String,
    bridge: u32,
    /// the interface of the bridge this uplink is enslaved through
    port: u32,
    /// the uplink's own interface index, which the filter is written to
    index: u32,
    /// addresses that may not be registered for this uplink: the host's own,
    /// the virtual functions', the configured exclusions
    skip: Set<Mac>,
    /// what this very batch saw on the uplink's own port. Held apart from
    /// `skip` because a refusal on its account has to count as ours: the
    /// kernel's end state may be "behind the bridge" - wire first, inner
    /// learn later in the same drained burst - and a refusal that bought no
    /// pass would suppress its own correction.
    reflected: Set<Mac>,
    /// the share of `skip` that came from the carried driver answer. A
    /// refusal owed only to that share may be stale news - a VF address
    /// freed without any link message - so with a carried answer such a hit
    /// goes through the decide phase and the fresh question settles it.
    vf_own: Set<Mac>,
}

mod notes;
use notes::Note;

/// How soon a batch of notifications needs a full pass.
///
/// A pass dumps the host's whole forwarding table, so what a batch is worth
/// decides how often that happens. Deletions are the case that matters: a
/// bridge ages its entries out, and on a large table that arrives as a burst
/// of hundreds. Each of them may mean an address is gone and its registration
/// should follow - but none of them is urgent, and answering each burst at the
/// full rate is how a quiet host turns into a busy one for no reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Urgency {
    /// The batch was somebody else's entirely.
    Nothing,
    /// Something may need removing, but nothing is waiting on it.
    WhenConvenient,
    /// Registrations, removals or interfaces changed.
    Now,
}

/// What a registration attempt actually achieved.
struct Registered {
    /// Addresses this call put into the card.
    put: Vec<Mac>,
    /// Addresses the card is now known to hold because of this call - the
    /// ones it took, plus the ones it refused with EEXIST because they
    /// were already there. Anything else was NOT written: a hard error
    /// leaves the note naming it and the card without it, and recording
    /// it as present would make the next re-learn look like a re-learn of
    /// something already in - which skips the fresh driver question that
    /// keeps a VF's own address out of the filter.
    held: Vec<Mac>,
    /// What went wrong, for a caller that reports.
    failures: Vec<String>,
}

/// What one pass left behind about an uplink's filter.
#[derive(Default)]
struct Carried {
    /// WHICH addresses the card holds, foreign entries included - and
    /// therefore, by its length, how many slots. A separate count lived
    /// here and was written at exactly the same three places as this set,
    /// never once from anywhere else; two names for one fact are two
    /// things to keep in step. The note is not a substitute: it says
    /// what is ours, this says what is in the card, and the two part
    /// company exactly where it hurts - a driver that cleared its list on
    /// link-down leaves addresses noted but absent, and putting one back
    /// is a growth that must ask the driver afresh.
    present: Set<Mac>,
    /// The addresses that pass decided to keep: ours, aged out of the
    /// bridge, and held because their port lives. The one pool BOTH
    /// valves surrender from - the pass's own and the event path's - so
    /// the event path cannot reach anything the pass would not. Being
    /// built from the pass's `kept` it is by construction free of
    /// everything that must never be shed: pinned EXTRA addresses and
    /// anything else still wanted, foreign entries, and addresses the
    /// note does not name. A pass that could not read its note keeps
    /// nothing, so the set is empty and the event path shed nothing
    /// either - which is the honest answer when the ledger is unreadable.
    quiet: Set<Mac>,
    /// When that pass ran, in the same boot-clock the addresses are
    /// stamped in. This is what makes "quiet" a fact rather than a
    /// guess: every pass refreshes the stamp of everything the bridge
    /// holds at that moment, so an address whose stamp predates the last
    /// pass is one the last pass did not see.
    passed_at: u64,
}

/// What a ConnectX-4 Lx vport list holds - the assumption when neither the
/// operator nor devlink says otherwise. The one spelling; main.rs and the
/// help text both read it.
pub const DEFAULT_MAX_MACS: usize = 128;

/// Slots deliberately left free below `max_macs`: an allowance for counting
/// drift, not a working reserve. The occupancy the valve and the fast path
/// act on is read back from the card's own list each pass and carried
/// between passes, so the old blind tenth shrank to a few slots that cover
/// what a count can still miss - a parallel writer's entries between two
/// passes, an add in flight while a batch decides.
const CAPACITY_HEADROOM: usize = 4;

pub struct Report {
    pub dev: String,
    pub bridge: String,
    pub port: String,
    pub driver: String,
    /// how many addresses this uplink's filter should hold
    pub wanted: usize,
    pub owned: usize,
    pub present: usize,
    pub stacked: Vec<String>,
    pub added: usize,
    pub removed: usize,
    pub foreign: usize,
    /// aged out of the bridge, kept because their guest ports live on
    pub quiet: usize,
    /// Only built when somebody is going to print it. On the daemon path
    /// this was a copy of the whole desired set and a silence walk, per
    /// uplink per pass, for numbers nothing prints - on a host with a
    /// thousand learnt addresses that is the pass's largest allocation.
    pub detail: Option<Detail>,
}

/// The per-address half of a report, for `--status -v` and nothing else.
/// Built from the same sets the pass decided on, so there is no second
/// spelling of "what this uplink wants" to drift from the first.
pub struct Detail {
    pub wanted: Vec<Mac>,
    /// the kept addresses, with how long each has been silent -
    /// milliseconds since the bridge last held it
    pub quiet_ages: Vec<(Mac, u64)>,
}

/// What the syncer needs from the kernel, as a trait so the bookkeeping can
/// be tested against a fake. The real one is the netlink socket; the fake
/// records what would be written and answers with whatever a test injects.
/// reconcile had no test at all for exactly this reason - its second argument
/// was the concrete socket, and the concrete socket needs a kernel.
pub trait FdbWriter {
    fn dump_fdb(&mut self) -> io::Result<Vec<FdbEntry>>;
    fn dump_links(&mut self) -> io::Result<Vec<crate::netlink::LinkInfo>>;
    fn vf_macs_of(&mut self, indices: &[u32]) -> io::Result<Vec<(u32, Mac)>>;
    fn set_self_fdb(&mut self, ifindex: u32, mac: &Mac, add: bool) -> io::Result<()>;
}

impl FdbWriter for Socket {
    fn dump_fdb(&mut self) -> io::Result<Vec<FdbEntry>> {
        Socket::dump_fdb(self)
    }
    fn dump_links(&mut self) -> io::Result<Vec<crate::netlink::LinkInfo>> {
        Socket::dump_links(self)
    }
    fn vf_macs_of(&mut self, indices: &[u32]) -> io::Result<Vec<(u32, Mac)>> {
        Socket::vf_macs_of(self, indices)
    }
    fn set_self_fdb(&mut self, ifindex: u32, mac: &Mac, add: bool) -> io::Result<()> {
        Socket::set_self_fdb(self, ifindex, mac, add)
    }
}

/// The virtual functions' addresses, remembered together with the physical
/// functions they were read for.
type CarriedVf = (Vec<u32>, Vec<(u32, Mac)>);

pub struct Syncer {
    pub pairs: Vec<Pair>,
    pub exclude: Set<Mac>,
    /// addresses to register whether or not a bridge has learnt them
    pub extra: Set<Mac>,
    pub dry_run: bool,
    /// Whether each pass should also build the per-address half of its
    /// report. Only `--status` prints it, and only that sets this.
    pub detail: bool,
    /// Whether the pair list is the whole picture. It is when autodetection
    /// drew it, and it is not when somebody named pairs by hand - and only
    /// something that knows every uplink may decide that a note belongs to
    /// none of them.
    pub authoritative: bool,
    pub state_dir: PathBuf,
    /// What the most recent pass cost.
    pub timings: Timings,
    /// The virtual functions' addresses from the last pass, together with
    /// the physical functions they were read for. They are set
    /// administratively and announced as link messages, so a pass that no
    /// interface message preceded works from these rather than asking the
    /// driver again - which is the most expensive thing a pass does. The PF
    /// list is kept so a pass over different pairs cannot inherit answers
    /// that were never about them.
    carried_vf: Option<CarriedVf>,
    /// Whether the carried answer can still be believed. Set by whoever
    /// notices an interface with virtual functions changing, cleared in the
    /// one place a fresh answer is read - so the full pass and the fast path
    /// cannot disagree about it. They did: main worked this out, passed it to
    /// the pass and not to the fast path, and a batch arriving between the
    /// change and the pass built its exclusions from the old list.
    pub vf_stale: bool,
    /// How long a device has to have been absent from the pair list before
    /// its note counts as an orphan. Zero for one-shot commands, which mean
    /// now; the daemon sets it to something that outlives an interface
    /// reload.
    pub orphan_grace: Duration,
    /// When each noted device was first seen to be missing.
    absent_since: Map<String, Instant>,
    /// Uplinks already told about, so the warning appears when the situation
    /// arises rather than once per pass for ever.
    warned_unknown_vf: Set<String>,
    /// Devices whose note could not be read. Not "owns nothing" - nothing may
    /// overwrite or unlink one of these.
    unreadable: std::cell::RefCell<Set<String>>,
    /// Devices whose lock file could not be opened, already said once. The
    /// note is still written, unlocked; what this stops is a line about it on
    /// every address of every burst.
    lock_warned: std::cell::RefCell<Set<String>>,
    /// Devices whose quiet-keep memory could not be written, already said
    /// once - the keeps still work in this process, they just will not
    /// outlive it, and that is one warning, not one per pass.
    ports_warned: std::cell::RefCell<Set<String>>,
    /// Whether an unlistable state directory has been said out loud. Once:
    /// the list is asked for on every batch, and the condition does not
    /// come and go.
    dir_list_warned: std::cell::Cell<bool>,
    /// Whether the state directory has been looked at this run. Its mode is
    /// only ours to decide when we are the ones who made it, and the one in
    /// /run outlives the process: a run under an older build, or under a
    /// umask that let it through wide open, leaves it that way for this run
    /// to write into. Looked at once, on the first write.
    dir_checked: std::cell::Cell<bool>,
    /// Pinned addresses already warned about, per uplink, so the warning
    /// appears when the situation arises and not once per pass forever -
    /// seventeen thousand identical journal lines a day teach an operator
    /// to stop reading warnings.
    warned_extra: Map<String, Set<Mac>>,
    /// The notes as they were last read, so reading them again costs a stat
    /// rather than an open-read-close. The file stays the truth: the copy is
    /// used only while identity, size and timestamp all say the file has not
    /// moved since - a --flush from a second process replaces it through
    /// rename, which changes the inode, and any other writer changes at
    /// least the timestamp.
    notes: std::cell::RefCell<Map<String, Note>>,
    /// The interface index last recorded beside each note, so the record
    /// is written when the answer changes rather than once per pass.
    indices: std::cell::RefCell<Map<String, u32>>,
    /// Which addresses the last pass saw out on the wire, per uplink. The
    /// fast path has no forwarding dump to work this out from, and an address
    /// that lives on the wire in one VLAN and behind the bridge in another
    /// must not flap in and out of the filter on every learning event.
    carried_wire: Map<String, Set<Mac>>,
    /// The bridge port each owned address was last learnt behind, per
    /// uplink. What it buys: a guest that goes quiet outlives the bridge's
    /// ageing as long as its port does - the kernel deletes a veth or a tap
    /// with its endpoint, so the port existing is the guest existing. A
    /// router that caches ARP longer than the bridge ages (FreeBSD holds
    /// 1200 s against the bridge's 300) keeps sending unicast without asking
    /// again, and without this those frames went out on the wire.
    ///
    /// Written down beside the note, because a daemon that restarts is
    /// mostly a daemon being updated - and forgetting the keeps there would
    /// unregister every quiet guest on the next pass, which is the very
    /// outage this exists to prevent, caused by our own package. The file
    /// lives in the same tmpfs as the notes, so a reboot still starts from
    /// nothing: then the addresses are gone from the card too, and there is
    /// nothing to keep.
    ///
    /// The value is the port and when the bridge was last seen holding
    /// the address, in milliseconds since boot. Every pass refreshes the
    /// stamp of everything it finds learnt, and so does every learn on
    /// the event path - so "quiet" needs no guessed window: an address
    /// whose stamp predates the last pass is one the last pass did not
    /// see. The stamp also orders the pressure valve's evictions, which
    /// is why it records when the guest last SPOKE rather than when we
    /// noticed the silence: two addresses that fall out between the same
    /// two passes are told apart by their traffic, not by their names.
    carried_ports: Map<String, Map<Mac, (u32, u64)>>,
    /// Uplinks whose written-down memory has already been read this run. The
    /// file is the previous process's word and is believed once, at the
    /// first pass that needs it; after that this process's own map is ahead
    /// of it.
    ports_loaded: Set<String>,
    /// What was last written to each uplink's memory file, so an idle pass
    /// writes nothing at all.
    ports_written: Map<String, Vec<String>>,
    /// The filter capacity the quiet-keep must respect. Kept addresses cost
    /// filter slots, and past its capacity the card drops entries silently -
    /// so keeps are the first surrendered as the list nears this limit.
    pub max_macs: usize,
    /// Which addresses each uplink was last said to be keeping, so the
    /// quiet-keep is announced once per entry into that state rather than
    /// once per pass forever.
    noted_quiet: Map<String, Set<Mac>>,
    /// What the last pass measured about each uplink's filter, carried
    /// between passes so the event path can be capacity-aware without
    /// paying a dump per batch. Corrected against the read-back every
    /// pass; the fast path adjusts it as it adds and removes.
    carried: Map<String, Carried>,
    /// The stamp the last pass wrote, whichever uplink it was for. Two
    /// passes must never share one - "quiet" means "stamped before the
    /// last pass", so a shared stamp would make every address read as
    /// loud and the valve would find nothing to shed. The clock alone
    /// cannot promise that: milliseconds are the right resolution for
    /// something observed once per pass, and two passes of a busy daemon
    /// can land in one tick. So the pass stamp is nudged past its
    /// predecessor when it has to be - at most a millisecond of drift,
    /// gone again the moment real time catches up.
    last_pass_at: u64,
    /// Uplinks already warned about exceeding the filter capacity, re-armed
    /// when the count drops back under: an overloaded bridge buys passes at
    /// the event rate, and the same warning five times a second is how an
    /// operator learns to stop reading exactly the journal that matters.
    warned_over: Set<String>,
    /// The fast path's own say-once mark. Separate from `warned_over` on
    /// purpose: the two speak at different thresholds - the pass at "past
    /// max_macs", the batch at "past max_macs minus the headroom" - so one
    /// shared mark meant the pass cleared, in the four-slot band between
    /// them, exactly what the batch had just set, and "once per uplink per
    /// stay" became once per batch.
    warned_tight: Set<String>,
}

/// Where a pass spent its time, and what it found on the way.
///
/// Filled in on every pass: it is six clock reads and a handful of counters,
/// far below the cost of the work being measured. Reported only when asked,
/// because a daemon that says nothing while nothing changes is the point.
#[derive(Debug, Default, Clone)]
pub struct Timings {
    pub topology: Duration,
    pub fdb: Duration,
    pub vf_macs: Duration,
    pub orphans: Duration,
    pub pairs: Duration,
    pub total: Duration,
    pub links: usize,
    pub fdb_entries: usize,
    pub vf_addresses: usize,
    /// whether the addresses came from the previous pass rather than the driver
    pub vf_carried: bool,
    pub added: usize,
    pub removed: usize,
    /// Anything that went wrong without stopping the pass. These are the
    /// places that used to fail in silence.
    pub failures: Vec<String>,
}

impl Timings {
    /// One line per phase, widest first, so the expensive one is obvious.
    pub fn report(&self) -> String {
        let ms = |d: Duration| d.as_secs_f64() * 1000.0;
        let mut out = format!("  pass total {:.3} ms\n", ms(self.total));
        out += &format!(
            "    topology  {:7.3} ms  {} links\n",
            ms(self.topology),
            self.links
        );
        out += &format!(
            "    fdb dump  {:7.3} ms  {} entries\n",
            ms(self.fdb),
            self.fdb_entries
        );
        out += &format!(
            "    vf macs   {:7.3} ms  {} addresses{}\n",
            ms(self.vf_macs),
            self.vf_addresses,
            if self.vf_carried {
                " (carried over)"
            } else {
                ""
            }
        );
        out += &format!("    orphans   {:7.3} ms\n", ms(self.orphans));
        out += &format!(
            "    pairs     {:7.3} ms  +{} -{}\n",
            ms(self.pairs),
            self.added,
            self.removed
        );
        for f in &self.failures {
            out += &format!("    failure: {f}\n");
        }
        out
    }
}

/// Whether an address may appear in a unicast filter at all: unicast, and
/// not the all-zero address a never-configured interface reports.
fn is_registerable(mac: &Mac) -> bool {
    mac[0] & 1 == 0 && *mac != [0u8; 6]
}

/// Could a link message about this interface have changed a virtual
/// function's address? `None` when this picture does not have the interface
/// and so cannot say.
///
/// Asking the driver is the most expensive thing a pass does, and the answer
/// only changes when somebody sets a virtual function's address - from the
/// host, or from inside a guest that holds one. Neither has anything to do
/// with a container's veth appearing, which on a busy host is what link
/// messages mostly are.
pub fn touches_virtual_functions(topo: &Topology, index: u32) -> Option<bool> {
    topo.at(index)
        .map(|link| link.numvfs > 0 || link.physfn.is_some())
}

/// The same question for a batch, against the picture as it was and the
/// picture as it is.
///
/// Both are needed, and the first attempt at this used only the second: an
/// interface that has just *gone* is not in the new picture, so every
/// deletion counted as a reason to ask - which is every second event when
/// containers come and go. The old picture still knows what it was. An
/// interface neither picture has is a reason to ask, because nothing here can
/// say what it was.
pub fn vf_may_have_changed(
    before: Option<&Topology>,
    after: Option<&Topology>,
    changed: &[u32],
) -> bool {
    changed.iter().any(|i| {
        // Either picture saying yes is a yes: a PF whose numvfs went from 0
        // to N inside this very batch is invisible to the old picture, and
        // letting the old answer win was how exactly that change slipped
        // past the exclusions. Only when neither picture knows the
        // interface is caution the answer.
        let b = before.and_then(|t| touches_virtual_functions(t, *i));
        let a = after.and_then(|t| touches_virtual_functions(t, *i));
        match (b, a) {
            (None, None) => true,
            _ => b.unwrap_or(false) || a.unwrap_or(false),
        }
    })
}

/// Every physical function whose VF addresses must be excluded for `dev`.
///
/// Usually one - a VF has a PF, a PF is its own. A multiport card that shares
/// one PCI function across its ports is the exception: each port's netdev
/// reports only its own port's VF addresses, so a VF there has a PF netdev per
/// port and all of them must be asked, or a sibling VF on the other port is
/// left out of the exclusion set and its address registered past its guest.
fn physical_functions(topo: &Topology, dev: u32) -> Vec<u32> {
    match topo.at(dev) {
        Some(l) if !l.pf_netdevs.is_empty() => l.pf_netdevs.clone(),
        // `physfn` is only ever the first of `pf_netdevs` (every Link
        // constructor derives it so), hence empty pf_netdevs means no
        // physfn either: the uplink is its own function.
        _ => vec![dev],
    }
}

impl Syncer {
    pub fn new(pairs: Vec<Pair>, state_dir: PathBuf) -> Self {
        Syncer {
            pairs,
            exclude: crate::hash::set(),
            extra: crate::hash::set(),
            dry_run: false,
            detail: false,
            authoritative: false,
            state_dir,
            timings: Timings::default(),
            carried_vf: None,
            vf_stale: true,
            orphan_grace: Duration::ZERO,
            absent_since: crate::hash::map(),
            warned_unknown_vf: crate::hash::set(),
            unreadable: std::cell::RefCell::new(crate::hash::set()),
            lock_warned: std::cell::RefCell::new(crate::hash::set()),
            ports_warned: std::cell::RefCell::new(crate::hash::set()),
            dir_checked: std::cell::Cell::new(false),
            dir_list_warned: std::cell::Cell::new(false),
            carried_wire: crate::hash::map(),
            carried_ports: crate::hash::map(),
            ports_loaded: crate::hash::set(),
            ports_written: crate::hash::map(),
            max_macs: DEFAULT_MAX_MACS,
            noted_quiet: crate::hash::map(),
            last_pass_at: 0,
            warned_over: crate::hash::set(),
            warned_tight: crate::hash::set(),
            carried: crate::hash::map(),
            warned_extra: crate::hash::map(),
            notes: std::cell::RefCell::new(crate::hash::map()),
            indices: std::cell::RefCell::new(crate::hash::map()),
        }
    }

    /// Record the driver's answer about the virtual functions, and that it
    /// is current. One function, so the answer and "is it still true" cannot
    /// be set apart from each other.
    fn remember_vf(&mut self, pfs: Vec<u32>, macs: Vec<(u32, Mac)>) {
        self.carried_vf = Some((pfs, macs));
        self.vf_stale = false;
    }

    /// Devices with a note that are no longer uplinks - and have not been for
    /// long enough to believe it.
    ///
    /// The grace period is the whole point. A device drops out of one reading
    /// for reasons that have nothing to do with it being gone: `ifreload -a`
    /// or `ifdown vmbr1 && ifup vmbr1` takes a Proxmox node's bridge away for
    /// a moment, and every registered address would be deleted from a live
    /// uplink's filter within 200 ms of a routine network reload - the exact
    /// outage this daemon exists to prevent, caused by the daemon.
    ///
    /// Zero grace is the one-shot behaviour: somebody running --once or
    /// --flush by hand means now, and there is no earlier reading to compare
    /// against anyway.
    fn orphaned(&mut self) -> Vec<String> {
        if !self.authoritative {
            self.absent_since.clear();
            return Vec::new();
        }
        let now = Instant::now();
        let live: Set<String> = self.pairs.iter().map(|p| p.dev.clone()).collect();
        let noted = self.noted_devices_or_none();
        // Forget devices whose note is gone, or that came back.
        self.absent_since
            .retain(|dev, _| noted.contains(dev) && !live.contains(dev));
        let mut out = Vec::new();
        for dev in noted {
            if live.contains(&dev) {
                continue;
            }
            let since = *self.absent_since.entry(dev.clone()).or_insert_with(|| {
                if !self.orphan_grace.is_zero() {
                    note!(
                        "{dev}: no longer among the uplinks; waiting {:?} before \
                         taking its addresses back out",
                        self.orphan_grace
                    );
                }
                now
            });
            if now.duration_since(since) >= self.orphan_grace {
                out.push(dev);
            }
        }
        out
    }

    /// Take back what was registered for a device that is no longer an uplink.
    /// Left alone, the card goes on steering those addresses to a port that
    /// leads nowhere, and nothing short of a reboot undoes it.
    fn drop_orphans(
        &mut self,
        sock: &mut dyn FdbWriter,
        topo: &Topology,
        apply: bool,
        failures: &mut Vec<String>,
    ) {
        for dev in self.orphaned() {
            // A name that is gone while its interface lives on is a rename,
            // not a disappearance. The filter entries survived it, under the
            // new name; reading the old name as "the device is gone" would
            // unlink the note and leave every one of them in the card owned
            // by nobody. The note follows the interface instead. (Identity
            // is the recorded index, which a boot never re-uses; two
            // interfaces swapping names in one breath is the residual case
            // this cannot tell apart, and the index still points each note
            // at the right interface then.)
            if topo.get(&dev).is_none() {
                if let Some((index, new_name)) = self.renamed_target(&dev, topo) {
                    if !apply || self.dry_run {
                        note!("{dev}: now called {new_name}; its note would follow");
                    } else {
                        // Read the old name's memory BEFORE the note moves.
                        // `migrate_note` unlinks the old note and, with it,
                        // `.<old>.owned.ports` - and in a fresh process
                        // nothing is carried in RAM to move instead, because
                        // `load_ports` only ever runs for a name that is
                        // still a pair. Without this the warm case (rename
                        // while the daemon watched) carried the keeps and
                        // the cold one (rename while it was stopped) lost
                        // them, which is the case a rename actually happens
                        // in. Reading is enough: the lines land in
                        // `carried_ports` under the old name and the move
                        // below picks them up.
                        self.load_ports(&dev, topo, false);
                        let moved = self.migrate_note(&dev, &new_name, index);
                        if moved {
                            note!("{dev}: now called {new_name}, its note follows the interface");
                            // The port memory follows the note, or a rename
                            // would silently forget exactly the quiet guests.
                            if let Some(ports) = self.carried_ports.remove(&dev) {
                                self.carried_ports.insert(new_name.clone(), ports);
                                // And the new name counts as read, or the fast
                                // path stops stamping a map it fully owns while
                                // the valve goes on judging it. Inside this
                                // block on purpose: marking a name whose memory
                                // was NOT migrated would suppress the real read
                                // and lose the file the line above exists for.
                                self.ports_loaded.insert(new_name.clone());
                            }
                            // The written-down copy went with the old note; the
                            // new name has nothing on file yet, so forget what
                            // was written there and let the next pass put the
                            // carried map down under the new name.
                            self.ports_loaded.remove(&dev);
                            self.ports_written.remove(&dev);
                            self.ports_written.remove(&new_name);
                            // The said-once mark travels too, or the same keeps
                            // are announced a second time under the new name.
                            if let Some(said) = self.noted_quiet.remove(&dev) {
                                self.noted_quiet.insert(new_name.clone(), said);
                            }
                            // The wire set follows for the same reason: the fast
                            // path would otherwise judge the renamed uplink
                            // against an empty set - or the old name's set
                            // against whoever inherits it.
                            if let Some(wire) = self.carried_wire.remove(&dev) {
                                self.carried_wire.insert(new_name.clone(), wire);
                            }
                            if self.warned_over.remove(&dev) {
                                self.warned_over.insert(new_name.clone());
                            }
                            if self.warned_tight.remove(&dev) {
                                self.warned_tight.insert(new_name.clone());
                            }
                            // The capacity arithmetic follows too. Usually
                            // moot - the pass that migrates the note also
                            // reconciles the new name and writes both of these
                            // fresh - but not when that pass skips the pair
                            // (no bridge, no port in this reading) while the
                            // event path keeps registering for it.
                            if let Some(c) = self.carried.remove(&dev) {
                                self.carried.insert(new_name.clone(), c);
                            }
                            // The two say-once sets follow as well. Nothing
                            // decides anything on them - they only keep a
                            // warning from being repeated every pass - but a
                            // rename made the daemon say both again, once, for
                            // a device that had not changed.
                            if self.warned_unknown_vf.remove(&dev) {
                                self.warned_unknown_vf.insert(new_name.clone());
                            }
                            if let Some(said) = self.warned_extra.remove(&dev) {
                                self.warned_extra.insert(new_name.clone(), said);
                            }
                            // And onto disk under the new name at once: the old
                            // file went with the old note, and a crash before
                            // the pair's next pass would otherwise forget the
                            // very keeps the migration carried over.
                            // The pass stamp, like every other caller: a
                            // fresh clock reading here is later than every
                            // stamp in the map, so the memo recorded each line
                            // as quiet and the next pass rewrote the file for
                            // nothing.
                            self.save_ports(&new_name, topo, self.last_pass_at);
                        }
                    }
                    // Worked, or waits (an unreadable note, an unwritable
                    // new one - both said out loud where they happened, and
                    // looked at again next sweep). Either way there is
                    // nothing to unregister: the device lives.
                    continue;
                }
            }
            if !apply || self.dry_run {
                let owned = self.load_owned(&dev);
                if !owned.is_empty() {
                    note!(
                        "{dev}: no longer an uplink, {} address(es) still registered",
                        owned.len()
                    );
                }
                continue;
            }
            // Under the note's lock, for the same reason flush works under
            // it: between reading the note and unlinking it, somebody else's
            // append would otherwise vanish with the file.
            self.locked(&dev, || {
                let owned = self.load_owned(&dev);
                if owned.is_empty() {
                    // Empty because it says so, or empty because it could not
                    // be read? The two arrive here looking identical, and only
                    // the first is a note this may unlink: removing an
                    // unreadable note abandons every entry it names, still in
                    // the card, with nothing left on record - the orphan the
                    // notes exist to prevent. Unreadable is left alone until
                    // it can be read, the same answer read_owned already gave
                    // out loud.
                    if self.note_is_readable(&dev) {
                        self.remove_note(&dev);
                    }
                    return;
                }
                let (gone, kept) = match topo.get(&dev) {
                    Some(link) => self.unregister_all(sock, &dev, link.index, &owned),
                    // The device itself is gone - a rename was told apart
                    // above - and a unicast filter does not outlive its
                    // netdev: the entries died with it.
                    None => (owned.len(), crate::hash::set()),
                };
                if kept.is_empty() && self.note_is_readable(&dev) {
                    note!("{dev}: no longer an uplink, removed {gone} address(es)");
                    self.remove_note(&dev);
                } else {
                    // What could not be removed is still in the card;
                    // forgetting it here is how a registration becomes
                    // permanent. write_owned, because the lock is already
                    // held.
                    note!(
                        "{dev}: no longer an uplink, removed {gone} address(es), \
                         {} could not be removed and stay on record",
                        kept.len()
                    );
                    // A oneshot asked to take orphans out and could not; its
                    // exit code has to say so, not just its scrollback.
                    failures.push(format!(
                        "{dev}: {} orphaned address(es) could not be removed",
                        kept.len()
                    ));
                    let _ = self.write_owned(&dev, &kept);
                }
            });
            // Whatever the sweep decided, the port memory of a device that
            // stopped being an uplink is over; a device that returns as a
            // pair records afresh from its first dump. The said-once mark
            // goes with it, so a return also announces afresh.
            self.carried_ports.remove(&dev);
            self.noted_quiet.remove(&dev);
            // Neither a month-old wire set nor a stale capacity warning
            // greets a device that returns.
            self.carried_wire.remove(&dev);
            self.warned_over.remove(&dev);
            self.warned_tight.remove(&dev);
            self.carried.remove(&dev);
            // remove_note took the file; a device that returns as a pair
            // reads afresh rather than believing this run's leftovers.
            self.ports_loaded.remove(&dev);
            self.ports_written.remove(&dev);
        }
    }

    /// Where a noted device's interface lives now, when the name is gone
    /// but the recorded index is not: the rename case. `None` where no
    /// index was ever recorded (a note from an older build) or the
    /// interface really is gone - and then the caller's old answer stands.
    fn renamed_target(&self, dev: &str, topo: &Topology) -> Option<(u32, String)> {
        let index = self.noted_index(dev)?;
        let link = topo.at(index)?;
        if link.name == dev {
            // Cannot happen when the name lookup already failed, but the
            // honest answer to "renamed to itself" is that it was not.
            return None;
        }
        Some((index, link.name.clone()))
    }

    /// Takes every one of `owned` back out of the filter. Returns how many
    /// are gone - removed now, or found already absent - and the set that
    /// could not be removed and therefore stays owned.
    fn unregister_all(
        &self,
        sock: &mut dyn FdbWriter,
        dev: &str,
        ifindex: u32,
        owned: &Set<Mac>,
    ) -> (usize, Set<Mac>) {
        let mut gone = 0usize;
        let mut kept = crate::hash::set();
        for mac in owned {
            match sock.set_self_fdb(ifindex, mac, false) {
                Ok(()) => gone += 1,
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => gone += 1,
                Err(e) => {
                    eprintln!("warning: {dev}: cannot unregister {}: {e}", format_mac(mac));
                    kept.insert(*mac);
                }
            }
        }
        (gone, kept)
    }

    /// The addresses that must never be registered for `pair`, no matter
    /// where they were learnt: the operator's exclusions, everything stacked
    /// on the uplink's wire side, the uplink's and its physical function's
    /// own addresses, the addresses administratively given to the sister
    /// virtual functions, and those of VFs bound on the host.
    ///
    /// One function, used by the full pass and the fast path alike. The fast
    /// path once carried its own abbreviation of this list - it had none of
    /// it - and registered a guest VF's own address, which tells the eSwitch
    /// the guest lives behind the bridge and sends its traffic past it.
    fn exclusions(&self, topo: &Topology, dev: u32, port: u32, vf_macs: &[(u32, Mac)]) -> Set<Mac> {
        let mut skip: Set<Mac> = crate::hash::set();
        skip.extend(self.exclude.iter().copied());
        skip.extend(topo.subtree_macs(port));
        if let Some(l) = topo.at(dev) {
            if let Some(mac) = l.mac {
                skip.insert(mac);
            }
        }
        // The driver-reported VF addresses come through vf_reported, the
        // one canonical spelling: the fast path's stale-answer logic
        // DEPENDS on vf_own being a subset of skip, and two hand-kept
        // copies of this walk agreeing is exactly the kind of promise that
        // silently breaks. Subset by construction instead.
        skip.extend(Self::vf_reported(topo, dev, vf_macs));
        for pf in physical_functions(topo, dev) {
            if let Some(pf_link) = topo.at(pf) {
                if let Some(mac) = pf_link.mac {
                    skip.insert(mac);
                }
                for vf in &pf_link.vf_netdevs {
                    if let Some(l) = topo.at(*vf) {
                        if let Some(mac) = l.mac {
                            skip.insert(mac);
                        }
                    }
                }
            }
        }
        skip
    }

    /// The probe entry --check writes is owned from the moment it exists:
    /// noted BEFORE it is written, forgotten after it is taken back out. A
    /// check killed between the two then leaves an entry the daemon's next
    /// pass removes and heals - without this it left a foreign entry
    /// nothing would ever touch, until a reboot. The tiny cost: a pass
    /// racing a live check can take the probe out early and fail the check
    /// with "accepted but not listed" - a diagnostic re-run, not a harm.
    ///
    /// Whether the noting worked is the answer, and a probe the note could
    /// not take must not be written at all: "noted first" used to be true
    /// only when the write happened to succeed, and nothing said otherwise.
    pub fn note_check_probe(&self, dev: &str, index: u32, mac: &Mac) -> bool {
        self.note_index(dev, index);
        self.append_owned(dev, &[*mac])
    }

    pub fn forget_check_probe(&self, dev: &str, mac: &Mac) {
        if !self.load_owned(dev).contains(mac) {
            return;
        }
        // Under the lock and against the file, so whatever a parallel writer
        // noted meanwhile survives - same rule as every other write-back.
        // One line out, the rest byte for byte: a whole-set write would
        // sort the note, and reordering a file this had no business
        // changing is a trace where the point was to leave none. When the
        // probe was the only line, note and index came into being for the
        // probe and go with it - an empty leftover would read as a managed
        // device to --flush and to anyone listing the state directory.
        self.locked(dev, || self.drop_line_locked(dev, mac));
    }

    /// Say so when a virtual function's address cannot be known.
    ///
    /// The exclusion set can recognise a virtual function two ways: an
    /// address set from the host (`ip link set <pf> vf N mac ...`), which the
    /// driver reports, or a netdev still bound here. A function handed
    /// straight to a guest with neither - the address made up by the driver
    /// in the guest - is in no exclusion set at all, and invariant 2 then
    /// rests entirely on the wire rule: if anything ever makes the bridge
    /// learn that address on a port other than the uplink's, the daemon will
    /// register the guest's own address and its traffic is sent past it.
    ///
    /// Nothing can be done about it here - the address is not knowable - so
    /// the operator is told, once, with the two ways to close it.
    fn warn_about_unknowable_vfs(&mut self, topo: &Topology, dev: &str, vf_macs: &[(u32, Mac)]) {
        let Some(pfs) = topo.index_of(dev).map(|d| physical_functions(topo, d)) else {
            return;
        };
        // numvfs and host-bound netdevs are device-level - the same on every
        // port netdev of a shared function - so the first PF answers for them;
        // only the set addresses are per-port, and are counted across them all.
        // `topo.at` cannot fail for an index this topology produced; what
        // this really guards is the empty list, a device with no functions.
        let Some(pf_link) = pfs.first().and_then(|&pf| topo.at(pf)) else {
            return;
        };
        // An address of all zeroes is the driver saying "nobody set one".
        let named = vf_macs
            .iter()
            .filter(|(index, mac)| pfs.contains(index) && *mac != [0u8; 6])
            .count();
        let here = pf_link.vf_netdevs.len();
        let unknowable = pf_link.numvfs as usize > named.max(here);
        if !unknowable {
            // Nothing unknowable right now - including no functions at all.
            // The mark comes off, so a situation that arises later, or
            // arises again, gets its warning: "told once" means once per
            // situation, not once per process. It used to be set on the
            // way past this point, and an uplink whose first pass was
            // harmless could then never warn at all.
            self.warned_unknown_vf.remove(dev);
            return;
        }
        if self.warned_unknown_vf.insert(dev.to_string()) {
            eprintln!(
                "warning: {}: {} of {}'s {} virtual function(s) have no address set \
                 from this host and no interface here, so their addresses cannot be \
                 excluded - a guest holding one would have its own traffic sent past \
                 it if this bridge ever learns that address. Set them with \
                 `ip link set {} vf N mac ...`, or list them in EXCLUDE.",
                dev,
                pf_link.numvfs as usize - named.max(here),
                pf_link.name,
                pf_link.numvfs,
                pf_link.name
            );
        }
    }

    /// Take the previous process's written-down quiet memory, once per
    /// uplink per run.
    ///
    /// A daemon restarts most often because it is being updated, and an
    /// update that forgot the keeps would unregister every quiet guest on
    /// its first pass - the outage this feature exists to prevent, caused
    /// by our own package. So the file is believed, but only where it still
    /// describes this kernel: a line counts when the port it names still
    /// exists AND still carries the index it was written with. An interface
    /// replaced under the same name, or a name that has moved, therefore
    /// loses its memory rather than inheriting somebody else's - and losing
    /// it costs the keeps and nothing else, which is what every build
    /// before this one did.
    ///
    /// Read once: after this the running map is ahead of the file, and a
    /// second read would put back what this process has already pruned.
    fn load_ports(&mut self, dev: &str, topo: &Topology, apply: bool) {
        if !self.ports_loaded.insert(dev.to_string()) {
            return;
        }
        // A map already carried in RAM is ahead of any file - a rename just
        // migrated it here, and the file under this name is a previous
        // life's leftover that must not clobber it.
        if self.carried_ports.contains_key(dev) {
            return;
        }
        let mut ports: Map<Mac, (u32, u64)> = crate::hash::map();
        let now = Self::boot_millis();
        let read: Vec<(Mac, String, u32, u64)> = self
            .read_ports(dev)
            .into_iter()
            .filter(|(_, name, index, _)| topo.index_of(name) == Some(*index))
            .collect();
        // Stamps from the future are brought back. Not from a reboot: the
        // state directory is a tmpfs and the file dies with the clock it
        // was written against. What does reach here is the pass stamp's own
        // lead - `max(clock, previous + 1)` walks ahead of the clock when
        // passes crowd into one millisecond - read back by a process that
        // restarted inside the same boot. Left standing, such a
        // stamp says "spoke after the last pass" for the life of the
        // process, which is not merely the youngest: it is never quiet, so
        // the valve can never reach it and the slot is held until the
        // address leaves the bridge.
        //
        // Shifted as one, not clamped one by one. Clamping maps every
        // stamp ahead of now onto the same instant and loses the order
        // between them - which is the whole content of this file, and a
        // pass stamp is `max(clock, previous + 1)`, so ordinary stamps sit
        // a millisecond or two ahead of the clock quite legitimately. The
        // shift keeps every gap and puts the newest at now.
        let ahead = read
            .iter()
            .map(|&(_, _, _, seen)| seen)
            .max()
            .unwrap_or(0)
            .saturating_sub(now);
        for (mac, _, index, seen) in read {
            ports.insert(mac, (index, seen.saturating_sub(ahead)));
        }
        if ports.is_empty() {
            return;
        }
        // Said by the process that actually manages the card - a --status
        // or dry run beside the daemon takes nothing over.
        //
        // The total, and only the total. Quietness is a comparison against
        // the ground of the pass that wrote the stamps, and that ground is
        // not in the file; judging against the file's own newest stamp
        // gave `count(t < max(t))`, which is at most N-1 for any input - a
        // host with one kept guest said "1 address(es), 0 of them quiet"
        // and was contradicted by the very next line. This pass says how
        // many are held quiet, from what it actually kept.
        if apply && !self.dry_run {
            note!(
                "{dev}: took over the last run's memory of {} address(es)",
                ports.len()
            );
        }
        // Seeded in the vocabulary `save_ports` compares against - the
        // quiet-flag keys, not the raw lines. Seeding raw lines meant the
        // memo could never hit after a takeover, and the first save of
        // every restart rewrote a file that already said the right thing.
        // Judged against the takeover's own newest stamp, which is the
        // ground the first pass will replace anyway.
        let newest_seen = ports.values().map(|&(_, t)| t).max().unwrap_or(0);
        let mut keys: Vec<String> = ports
            .iter()
            .filter_map(|(m, &(index, seen))| {
                topo.name_of(index).map(|name| {
                    format!(
                        "{} {name} {index} {}",
                        format_mac(m),
                        u8::from(seen < newest_seen)
                    )
                })
            })
            .collect();
        self.carried_ports.insert(dev.to_string(), ports);
        keys.sort();
        self.ports_written.insert(dev.to_string(), keys);
    }

    fn ports_line(mac: &Mac, name: &str, index: u32, seen: u64) -> String {
        format!("{} {name} {index} {seen}", format_mac(mac))
    }

    /// Write the quiet memory down for whoever runs next, when it changed.
    ///
    /// Under the note's lock, like every other writer here: `--once` and
    /// `--flush` are run by hand while the daemon is running. An idle pass
    /// writes nothing - the lines are compared against what was last put
    /// there, so the file is touched when an address is learnt, goes quiet
    /// or leaves, and not once per pass.
    fn save_ports(&mut self, dev: &str, topo: &Topology, pass_at: u64) {
        // A dry run changes nothing on disk - the memory stays in RAM for
        // an honest report, the file belongs to whoever actually manages
        // the card. (--status never even reaches this: every caller is
        // behind an `apply` gate, and its pass carries apply=false.)
        if self.dry_run {
            return;
        }
        // "Nothing in the map" means two different things, and only one of
        // them is "nothing to remember". The other is "nobody has looked at
        // the file yet": `load_ports` runs at exactly one place, in the
        // pass's pair loop, behind three fail-closed `continue`s and behind
        // a refused pass - while the reflection path reaches here from a
        // batch. Told apart by the mark `load_ports` sets before it reads,
        // because otherwise the empty branch below unlinks the previous
        // process's memory unread, and the next pass unregisters every
        // guest that went quiet across the restart. That is the outage this
        // file exists to prevent. The learn path a few hundred lines down
        // carries the same guard for the same reason.
        if !self.ports_loaded.contains(dev) && !self.carried_ports.contains_key(dev) {
            return;
        }
        let (mut lines, mut keys): (Vec<String>, Vec<String>) = match self.carried_ports.get(dev) {
            // A port whose index no longer has a name is a port that
            // is gone: the keep is over for it anyway, and a line that
            // cannot be written honestly is better not written.
            Some(ports) => ports
                .iter()
                .filter_map(|(m, &(index, seen))| {
                    topo.name_of(index).map(|name| {
                        (
                            Self::ports_line(m, name, index, seen),
                            // What a rewrite is FOR, without the stamp
                            // itself: which addresses, behind which
                            // port, and whether each is quiet. Stamps
                            // move on every pass - comparing them
                            // would rewrite this file five times a
                            // second on a busy host, for a difference
                            // no reader can act on.
                            format!(
                                "{} {name} {index} {}",
                                format_mac(m),
                                u8::from(seen < pass_at)
                            ),
                        )
                    })
                })
                .unzip(),
            None => (Vec::new(), Vec::new()),
        };
        lines.sort();
        keys.sort();
        // The memo is only as good as the file it describes: a --flush from
        // a second terminal unlinks it, and believing the memo then freezes
        // this uplink's memory for the life of the process - the next
        // restart, which is usually an update, would unregister every quiet
        // guest on its first pass. One stat says whether the file is still
        // the shape the memo claims.
        // Nothing to remember is no file: an uplink with no quiet addresses
        // would otherwise keep an empty one around for the next process to
        // read nothing out of. The look and the write are one locked
        // stretch: asking outside it and writing inside meant a --flush
        // landing between the two decided against a file that no longer
        // existed by the time the write ran.
        let memo_holds = self.ports_written.get(dev) == Some(&keys);
        let empty = lines.is_empty();
        let mut skipped = false;
        let wrote = self.locked(dev, || {
            if memo_holds && self.ports_path(dev).exists() != empty {
                skipped = true;
                return true;
            }
            if empty {
                fs::remove_file(self.ports_path(dev)).is_ok() || !self.ports_path(dev).exists()
            } else {
                self.write_ports(dev, &lines)
            }
        });
        if skipped {
            return;
        }
        // Memoised only when the file really says this. A failed write that
        // counted as done would leave the running process believing a stale
        // file, and every later pass skipping the correction.
        if wrote {
            self.ports_written.insert(dev.to_string(), keys);
        } else {
            self.ports_written.remove(dev);
        }
    }

    /// Record what was just observed about an owned address: where the
    /// bridge holds it, and when it was last heard from.
    ///
    /// The one place a stamp is written, and it only ever moves forward.
    /// Every reader treats the number as "the most recent moment there is
    /// evidence for", so an older observation is not evidence against a
    /// newer one - it is simply nothing new. That has to hold whatever
    /// the source: the pass, a learn on the event path, or the bridge's
    /// own deletion dating a silence. It cannot be argued per site,
    /// because the sources do not share a clock reading - a pass stamp is
    /// nudged past its predecessor and can sit a millisecond ahead of the
    /// clock a learn moments later reads, and a deletion's date is
    /// deliberately older than now. A stamp that went backwards would
    /// make a live guest the pressure valve's first victim.
    ///
    /// `port` is what the observation knows: the pass and a learn name
    /// one, a deletion refines only the moment. An address nothing knows
    /// a port for is not recorded at all - the keep rests on the port.
    fn note_seen(ports: &mut Map<Mac, (u32, u64)>, mac: Mac, port: Option<u32>, at: u64) {
        match ports.get_mut(&mac) {
            Some(slot) => {
                if let Some(p) = port {
                    slot.0 = p;
                }
                slot.1 = slot.1.max(at);
            }
            None => {
                if let Some(p) = port {
                    ports.insert(mac, (p, at));
                }
            }
        }
    }

    /// Put a date on a silence the bridge has just announced.
    ///
    /// A bridge forgets an address exactly its ageing time after the last
    /// frame from it, so a deletion arriving now says the guest last spoke
    /// one ageing time ago - a fact, where the stamp otherwise holds only
    /// "the last pass still saw it", which can be a whole pass interval
    /// short of the truth. What the number is for is the order the
    /// pressure valve evicts in and the silence `--status -v` reports, and
    /// both get more honest for it.
    ///
    /// Never backwards: a vlan-aware bridge holds one entry per VLAN and
    /// ages them apart, so a deletion can arrive for an address that spoke
    /// in another VLAN a moment ago. The later stamp is the true one.
    ///
    /// Not every deletion is an ageing - a flush, a port going down and a
    /// hand-run `bridge fdb del` look the same from here - so this is an
    /// estimate. Because it is only ever taken when it moves the stamp
    /// forward, a wrong one can only make an address look *younger* than
    /// it is and be surrendered later than it deserves; it can never make
    /// one look older, and so can never cost a live guest its entry.
    /// Erring towards keeping is the direction to err in.
    fn date_the_silence(&mut self, topo: &Topology, events: &[(u16, FdbEntry)]) {
        let now = Self::boot_millis();
        for (kind, entry) in events {
            if *kind != crate::netlink::RTM_DELNEIGH {
                continue;
            }
            // The bridge that forgot it decides the interval; a stacked
            // vnet may age differently from the uplink's own bridge. This
            // is also what keeps our own filter entries out: a `self`
            // entry names no master, so a deletion from the card says
            // nothing here and is stepped over.
            let Some(master) = entry.master else {
                continue;
            };
            let Some(ageing) = topo.at(master).and_then(|l| l.ageing_ms) else {
                continue;
            };
            let spoke = now.saturating_sub(ageing);
            // Only the uplinks this bridge actually serves. The ageing
            // time is read from the bridge that forgot the address, so
            // handing the answer to every uplink's memory let one bridge's
            // interval date another's keeps: a dual-homed guest, or the
            // same segment bridged twice, drags an hour-old entry forward
            // to five minutes old, and the pressure valve then surrenders
            // a genuinely quieter guest instead.
            for pair in &self.pairs {
                let Some(bridge) = topo.index_of(&pair.bridge) else {
                    continue;
                };
                if !topo.leads_to(master, bridge) {
                    continue;
                }
                if let Some(ports) = self.carried_ports.get_mut(&pair.dev) {
                    Self::note_seen(ports, entry.mac, None, spoke);
                }
            }
        }
    }

    /// How long each of these has been silent, in milliseconds - the
    /// valve orders evictions by it and --status -v shows it. An address
    /// this process never saw learnt counts as silent since boot: nothing
    /// is known in its favour.
    fn silence_of(&self, dev: &str, macs: &Set<Mac>, now: u64) -> Vec<(u64, Mac)> {
        // `now` is the pass's own stamp, not a fresh clock reading: the
        // valve's ordering and what --status -v prints then describe the
        // same instant instead of two microseconds apart, and the clamp
        // below cannot be handed a moment the stamps were never judged
        // against.
        let ports = self.carried_ports.get(dev);
        macs.iter()
            .map(|m| {
                let seen = ports
                    .and_then(|ps| ps.get(m))
                    .map_or(0, |&(_, t)| t.min(now));
                (now.saturating_sub(seen), *m)
            })
            .collect()
    }

    /// Take addresses off a note as a difference against a fresh read.
    ///
    /// The three removal paths - the pass's stale loop, the reflection and
    /// the shedder - all reach this state: entries out of the card, the
    /// note still naming them. Written as a whole set instead, a line a
    /// parallel writer appended during the rtnl wait above would be lost,
    /// and its entry left in the card with nothing on record saying it is
    /// ours. Assumes the caller holds the lock.
    fn forget_locked(&self, dev: &str, dropped: &[Mac]) {
        if dropped.is_empty() {
            return;
        }
        let mut fin = self.read_owned(dev);
        for mac in dropped {
            fin.remove(mac);
        }
        self.write_owned(dev, &fin);
    }

    /// Register a batch the note-first way, under the note's lock. The
    /// one spelling of the ordering both the pass and the event path
    /// depend on - the two had it twice, and this repository's two worst
    /// bugs both grew in the gap between such twins.
    ///
    /// The note first, then the card: written the other way round, a
    /// crash between the two (an OOM kill, an abort) leaves an entry in
    /// the card that no note names - counted foreign from the next start
    /// on, and foreign entries are deliberately never touched. This way
    /// round the crash leaves a note naming an entry that is not there,
    /// and the ordinary paths heal it: the add is retried while the
    /// address is wanted, and the removal's ENOENT settles the note once
    /// it is not. A note that cannot be written keeps the card untouched
    /// entirely - which also covers the note that cannot be read.
    ///
    /// Under the lock because `--flush` reads, unregisters and unlinks
    /// under it: an intent appended outside would meet exactly that
    /// window - the flush's removal answers ENOENT for the not-yet-written
    /// entry, the note is settled away, and the add lands owned by nobody.
    ///
    /// Returns what really went into the card and what went wrong, for a
    /// caller that counts or reports. `None` means the note refused the
    /// batch and the card was not touched at all.
    fn register_batch_locked(
        &self,
        sock: &mut dyn FdbWriter,
        dev: &str,
        index: u32,
        macs: &[Mac],
    ) -> Option<Registered> {
        let mut put: Vec<Mac> = Vec::new();
        let mut held: Vec<Mac> = Vec::new();
        let mut failures: Vec<String> = Vec::new();
        let refused = self.locked(dev, || {
            let Some(fresh) = self.append_owned_locked(dev, macs) else {
                return true;
            };
            let fresh: Set<Mac> = fresh.into_iter().collect();
            let mut unclaim: Vec<Mac> = Vec::new();
            for mac in macs {
                match sock.set_self_fdb(index, mac, true) {
                    Ok(()) => {
                        put.push(*mac);
                        held.push(*mac);
                    }
                    // The dump a moment ago said it was absent, so somebody
                    // else put it there in between - the same call from a
                    // --once in a second terminal is somebody else.
                    // Claiming it would mean deleting their entry later, so
                    // the intent this call noted comes back out; a line
                    // that predates it stays, because it was ours all
                    // along.
                    Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                        // Somebody else's entry, but an entry: it fills a
                        // slot, and the next batch must not read it as
                        // room.
                        held.push(*mac);
                        if fresh.contains(mac) {
                            unclaim.push(*mac);
                        }
                    }
                    // The entry does not exist and the note names it: the
                    // crash posture, reached while running. Kept on record
                    // on purpose - the retry and the ENOENT settling
                    // depend on it.
                    Err(e) => {
                        eprintln!("warning: {dev}: cannot register {}: {e}", format_mac(mac));
                        failures.push(format!("{dev}: register {}: {e}", format_mac(mac)));
                    }
                }
            }
            if !unclaim.is_empty() && !self.unnote_locked(dev, &unclaim) {
                eprintln!(
                    "warning: {dev}: {} refused address(es) could not be taken back \
                     off the ownership note - they are somebody else's entries and \
                     would be removed when they stop being wanted",
                    unclaim.len()
                );
            }
            false
        });
        if refused {
            return None;
        }
        Some(Registered {
            put,
            held,
            failures,
        })
    }

    /// How full the fullest uplink's filter is, as the last pass measured
    /// it against the card itself.
    ///
    /// The limit applies to one card's unicast list, so the question is
    /// the fullest list, not the total across uplinks. This used to count
    /// the notes instead - our own registrations, summed - which both
    /// missed every foreign entry taking a real slot and listed the state
    /// directory and read every note to find out, on a path that an
    /// ageing table walks hundreds of times.
    pub fn fullest_filter(&self) -> usize {
        self.carried
            .values()
            .map(|c| c.present.len())
            .max()
            .unwrap_or(0)
    }

    /// The card is now known to hold these.
    ///
    /// Idempotent: an address already counted stays counted once. Only
    /// ever called with what the card really took or really had - an
    /// address a hard error left out must not be recorded as present,
    /// because the grow-gate reads owned-and-present as "re-learning this
    /// grows nothing" and would then skip the fresh driver question that
    /// keeps a virtual function's own address out of the filter.
    fn card_now_holds(&mut self, dev: &str, macs: impl IntoIterator<Item = Mac>) {
        let c = self.carried.entry(dev.to_string()).or_default();
        for mac in macs {
            c.present.insert(mac);
        }
    }

    /// The card is known not to hold these any anymore - it took them out,
    /// or it turned out never to have had them.
    ///
    /// Both free the slot, and a slot the count still claims is a slot the
    /// next burst will not use: the valve would shed again, and again, one
    /// guest per burst, while the card never gets any emptier. Surrendered
    /// is also no longer kept, or a second batch in the same window counts
    /// it as room it can free a second time.
    fn card_no_longer_holds(&mut self, dev: &str, macs: &[Mac]) {
        let Some(c) = self.carried.get_mut(dev) else {
            return;
        };
        for mac in macs {
            c.present.remove(mac);
            c.quiet.remove(mac);
        }
    }

    /// Surrender up to `need` kept addresses, longest-silent first -
    /// card, note and memory in the same breath, under the note's lock
    /// like every other removal. The fast path's arm of the pressure
    /// valve: a burst that would overflow the card cannot wait the 200 ms
    /// for a pass, because past its limit the card drops arbitrarily -
    /// possibly the very guest that is speaking. Returns how many slots
    /// were really freed.
    fn shed_keeps(
        &mut self,
        sock: &mut dyn FdbWriter,
        dev: &str,
        index: u32,
        need: usize,
        topo: &Topology,
    ) -> usize {
        // A note that cannot be read is a device to leave alone - every
        // other removal path says so, and this one would otherwise delete
        // entries while the batch that asked for the room is refused.
        // Asked by reading, not by consulting the mark: the mark is only
        // set once a read has failed, and on the fast path this may be the
        // first read of the pass.
        self.load_owned(dev);
        if !self.note_is_readable(dev) {
            return 0;
        }
        // No pass yet, no ground to judge quietness on - and nothing was
        // registered by this process either, so there is nothing to shed.
        // No pass yet, no ground to judge on - and nothing this process
        // registered either, so there is nothing to shed.
        let Some(carried) = self.carried.get(dev) else {
            return 0;
        };
        let (passed_at, quiet) = (carried.passed_at, &carried.quiet);
        let Some(ports) = self.carried_ports.get(dev) else {
            return 0;
        };
        // The pass's own keeps, and nothing else. That set is what the
        // pass's valve surrenders from, so both valves reach exactly the
        // same addresses: never a pinned EXTRA or anything else still
        // wanted, never a foreign entry, never one the note does not
        // name. On top of it, the freshness test - a stamp older than the
        // last pass means the last pass did not find the address, so it
        // is still quiet now; a learn since then has stamped it forward
        // and taken it out of reach, which is also why an address this
        // very batch is registering can never be its own victim.
        let mut cands: Vec<(u64, Mac)> = quiet
            .iter()
            .filter_map(|m| ports.get(m).map(|&(_, seen)| (seen, *m)))
            .filter(|(seen, _)| *seen < passed_at)
            .collect();
        // Smallest stamp = longest since it last spoke; the address is
        // the tiebreak, as in the pass's valve.
        cands.sort_unstable();
        cands.truncate(need);
        if cands.is_empty() {
            return 0;
        }
        let mut dropped: Vec<Mac> = Vec::new();
        self.locked(dev, || {
            for (_, mac) in &cands {
                match sock.set_self_fdb(index, mac, false) {
                    Ok(()) => dropped.push(*mac),
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) => dropped.push(*mac),
                    Err(e) => eprintln!(
                        "warning: {dev}: cannot release quiet {}: {e}",
                        format_mac(mac)
                    ),
                }
            }
            self.forget_locked(dev, &dropped);
        });
        if dropped.is_empty() {
            return 0;
        }
        if let Some(ports) = self.carried_ports.get_mut(dev) {
            for mac in &dropped {
                ports.remove(mac);
            }
        }
        self.save_ports(dev, topo, passed_at);
        // Counted BEFORE the bookkeeping is told, because that is what the
        // answer is about: how many slots this really freed. Candidates come
        // from the pass's keeps, which are read off the note - and the note
        // deliberately keeps an address whose registration failed outright.
        // Such an address is not in the card, so deleting it frees nothing,
        // and reporting it as freed let the caller believe it had made room
        // and skip the warning that says the card is being written past its
        // limit.
        //
        // They are still deleted, all of them: filtering the candidates
        // against what the card holds would make an address the card never
        // took unsheddable for ever - it would stay owned, stay kept, be
        // loudly re-registered by every pass, and the pass's own valve would
        // surrender real keeps for a slot nobody occupies.
        let freed = self.carried.get(dev).map_or(0, |c| {
            dropped.iter().filter(|m| c.present.contains(*m)).count()
        });
        self.card_no_longer_holds(dev, &dropped);
        note!(
            "{dev}: filter nearing its {} limit, released {} quiet \
             address(es) [pressure]",
            self.max_macs,
            dropped.len()
        );
        freed
    }

    /// One spelling of "what the filter should hold": the desired set with
    /// the quiet survivors already folded in. Asked twice per pass - once
    /// up front, once against the fresh driver answer after a grow-refresh -
    /// and having both callers share it is what keeps the two askings from
    /// drifting apart. Returns (want, stacked, wire, learnt_at, kept).
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    fn wanted_with_keeps(
        &self,
        topo: &Topology,
        bridge: u32,
        dev: u32,
        port: u32,
        fdb: &[FdbEntry],
        vf_macs: &[(u32, Mac)],
        owned_before: &Set<Mac>,
    ) -> (Set<Mac>, Vec<String>, Set<Mac>, Map<Mac, u32>, Set<Mac>) {
        let (mut want, stacked, wire, learnt_at) =
            self.desired(topo, bridge, dev, port, fdb, vf_macs);
        let kept =
            self.quiet_survivors(topo, bridge, dev, port, &want, &wire, vf_macs, owned_before);
        want.extend(kept.iter().copied());
        (want, stacked, wire, learnt_at, kept)
    }

    /// The owned addresses that aged out of the bridge but should stay:
    /// those whose learn-port still exists and still hangs under this
    /// bridge. Ageing is the bridge managing its own table, not news about
    /// the device - a router that caches ARP longer than the bridge ages
    /// keeps sending unicast without asking again, and a miss only delivers
    /// to the uplink port's own wire. Anything the bridge must carry - a
    /// device on another NIC as much as a guest - blackholes. So an aged
    /// address is simply kept; the honest limit is filter capacity, and the
    /// pressure valve collects it from the longest-silent entries first.
    ///
    /// A port that is GONE keeps nothing: the kernel deletes a veth or tap
    /// with its endpoint, and a vanished physical port took its segment
    /// with it. An address that moved to the wire is not asked here at all
    /// - the wire set wins before this runs.
    ///
    /// Pure over its inputs, because the grow-refresh recomputes `desired`
    /// and this has to be askable twice with a straight face.
    #[allow(clippy::too_many_arguments)]
    fn quiet_survivors(
        &self,
        topo: &Topology,
        bridge: u32,
        dev: u32,
        port: u32,
        want: &Set<Mac>,
        wire: &Set<Mac>,
        vf_macs: &[(u32, Mac)],
        owned_before: &Set<Mac>,
    ) -> Set<Mac> {
        let mut kept = crate::hash::set();
        let Some(name) = topo.name_of(dev) else {
            return kept;
        };
        let Some(ports) = self.carried_ports.get(name) else {
            return kept;
        };
        if ports.is_empty() {
            return kept;
        }
        // The one canonical exclusion set, asked again rather than re-spelt.
        let skip = self.exclusions(topo, dev, port, vf_macs);
        // Everything under the uplink port is the wire's side of the fence,
        // the port itself included: a learn-port later re-enslaved beneath
        // the uplink (two NICs folded into a bond uplink) now leads out,
        // and keeping its addresses would steer wire traffic into the
        // bridge.
        let wireward = topo.subtree_of(&[port]);
        for m in owned_before {
            if want.contains(m) || wire.contains(m) || skip.contains(m) {
                continue;
            }
            if !is_registerable(m) {
                continue;
            }
            let Some(&(p, _)) = ports.get(m) else {
                continue;
            };
            if wireward.contains(&p) {
                continue;
            }
            // A vanished port keeps nothing either: `bridge_above` answers
            // None for an index the topology no longer knows, so the
            // reachability question below covers gone and moved alike.
            // Still a port of this bridge, or of a vnet stacked above it:
            // the inverse walk of the same edges desired() takes downward
            // through `uplink_ward` and `relevant`.
            let reachable = match topo.bridge_above(p) {
                Some((br, _)) => topo.leads_to(br, bridge),
                None => false,
            };
            if !reachable {
                continue;
            }
            kept.insert(*m);
        }
        kept
    }

    /// The addresses that belong in `pair`'s filter list, and the ones that
    /// must stay out of it.
    fn desired(
        &self,
        topo: &Topology,
        bridge: u32,
        dev: u32,
        port: u32,
        fdb: &[FdbEntry],
        vf_macs: &[(u32, Mac)],
    ) -> (Set<Mac>, Vec<String>, Set<Mac>, Map<Mac, u32>) {
        let Some(bridge_link) = topo.at(bridge) else {
            return (
                crate::hash::set(),
                Vec::new(),
                crate::hash::set(),
                crate::hash::map(),
            );
        };

        // Which interfaces sit on top of the uplink bridge. One walk up from
        // the bridge, rather than asking every interface on the host whether
        // it leads down to it: same edges, walked once instead of once per
        // interface. A busy host has thousands of forwarding entries and a
        // few dozen interfaces, and asking the same structural question over
        // and over is what made this daemon show up in `top` at all.
        let uplink_ward: Set<u32> = topo.stacked_above(bridge);

        // Bridges stacked on the uplink bridge. Their tables hold the guests
        // whose addresses the lower bridge never learns: that traffic enters it
        // from the bridge's own local port, and a bridge does not learn from
        // itself.
        let mut relevant: Map<u32, String> = crate::hash::map();
        for b in topo.bridges() {
            if b.index == bridge {
                continue;
            }
            if b.slaves.iter().any(|p| uplink_ward.contains(p)) {
                relevant.insert(b.index, b.name.clone());
            }
        }

        let mut wire: Set<Mac> = crate::hash::set();
        let mut want: Set<Mac> = crate::hash::set();

        // Where each learnt address was seen, alongside what is wanted. The
        // structural entries below - the bridge's own address, the uplink-ward
        // interfaces, the pinned extras - record no port on purpose: they do
        // not age out of `want` while the topology knows them, so there is
        // nothing for the quiet-keep to remember.
        let mut learnt_at: Map<Mac, u32> = crate::hash::map();
        for e in fdb {
            if !e.is_learned() || !e.is_unicast() {
                continue;
            }
            let Some(master) = e.master else { continue };
            if master == bridge_link.index {
                if e.ifindex == port {
                    // out on the wire: registering it would divert its traffic
                    // to the bridge, which cannot send it back out of the port
                    // it arrived on
                    wire.insert(e.mac);
                } else {
                    want.insert(e.mac);
                    learnt_at.insert(e.mac, e.ifindex);
                }
            } else if relevant.contains_key(&master) && !uplink_ward.contains(&e.ifindex) {
                want.insert(e.mac);
                learnt_at.insert(e.mac, e.ifindex);
            }
        }

        // The host's own addresses on this bridge. Usually the uplink's own,
        // in which case they drop out again below - but not on a host where
        // the bridge carries a different address, and there the host would
        // otherwise be unreachable from the VF.
        if let Some(mac) = bridge_link.mac {
            want.insert(mac);
        }
        for index in &uplink_ward {
            if *index == bridge {
                continue;
            }
            if let Some(mac) = topo.at(*index).and_then(|l| l.mac) {
                want.insert(mac);
            }
        }

        // Everything the host owns on this side of the uplink, plus what the
        // wire already carries.
        let mut skip: Set<Mac> = self.exclusions(topo, dev, port, vf_macs);
        skip.extend(wire.iter().copied());

        // Addresses pinned by configuration are registered even when nothing
        // has been heard from them yet - for a device that never speaks first,
        // or to close the gap before a guest's first frame.
        want.extend(self.extra.iter().copied());

        want.retain(|m| !skip.contains(m) && is_registerable(m));

        let mut stacked: Vec<String> = relevant.into_values().collect();
        stacked.sort();
        (want, stacked, wire, learnt_at)
    }

    /// Bring the filter in line with the bridge.
    ///
    /// The physical functions behind these uplinks, alive in this reading.
    /// Only they contribute exclusions, so only they are asked about - a
    /// dump would describe every interface on the host to reach them.
    ///
    /// One function on purpose: the exclusion set invariant 2 hangs on is
    /// built from exactly this list, and it used to be spelled three times.
    /// The pf_netdevs-union fix was the class of bug where one of several
    /// copies of a rule goes stale.
    fn live_pfs<'a>(topo: &Topology, devs: impl Iterator<Item = &'a str>) -> Vec<u32> {
        let mut pfs: Vec<u32> = Vec::new();
        for dev in devs {
            let Some(idx) = topo.index_of(dev) else {
                continue;
            };
            // No existence check: every index `physical_functions` can
            // return came out of a link this very topology holds, so one
            // here would ask whether the reading contains what the reading
            // just said. It was there, and it never fired.
            for pf in physical_functions(topo, idx) {
                if !pfs.contains(&pf) {
                    pfs.push(pf);
                }
            }
        }
        pfs
    }

    /// The addresses the driver reports for the virtual functions behind
    /// this uplink - the share of the exclusion set that can go stale when
    /// the answer is carried, which is why the fast path keeps it apart.
    fn vf_reported(topo: &Topology, dev: u32, vf_macs: &[(u32, Mac)]) -> Set<Mac> {
        let mut own = crate::hash::set();
        for pf in physical_functions(topo, dev) {
            if let Some(pf_link) = topo.at(pf) {
                for (ifindex, mac) in vf_macs {
                    if *ifindex == pf_link.index {
                        own.insert(*mac);
                    }
                }
            }
        }
        own
    }

    /// The carried answer, if it may be used for these very physical
    /// functions - the staleness rule invariant 2 hangs on, written once
    /// for the pass and the fast path alike. Carried answers count only
    /// when they were collected for these very functions: a pass over a
    /// different pair list must not inherit what was never about it.
    fn carried_vf_for(&self, pfs: &[u32]) -> Option<Vec<(u32, Mac)>> {
        match (&self.carried_vf, self.vf_stale) {
            (Some((for_pfs, kept)), false) if *for_pfs == pfs => Some(kept.clone()),
            _ => None,
        }
    }

    /// The topology is handed in rather than read here. The caller needs it
    /// anyway - autodetection runs off the same picture - and reading it twice
    /// for one pass is work nobody asked for. `topo_load` is how long the
    /// caller took over it, so the report still accounts for the whole pass.
    pub fn reconcile(
        &mut self,
        sock: &mut dyn FdbWriter,
        apply: bool,
        topo: &Topology,
        topo_load: Duration,
    ) -> io::Result<Vec<Report>> {
        let started = Instant::now();
        let mut timings = Timings {
            topology: topo_load,
            links: topo.links.len(),
            ..Default::default()
        };

        // No pairs is not nothing to do: notes can outlive the last pair -
        // a bridge taken apart leaves its uplink's filter full - and this is
        // the only place that ever takes those entries back out. The dumps
        // serve the pairs and are skipped.
        if self.pairs.is_empty() {
            self.drop_orphans(sock, topo, apply, &mut timings.failures);
            timings.total = topo_load + started.elapsed();
            self.timings = timings;
            return Ok(Vec::new());
        }

        let mark = Instant::now();
        let fdb = sock.dump_fdb()?;
        timings.fdb = mark.elapsed();
        timings.fdb_entries = fdb.len();
        // Not `unwrap_or_default`: an empty list here does not mean "no virtual
        // functions", it means we failed to ask. Carrying on with it would drop
        // the VFs' own addresses out of the exclusions, and registering a VF's
        // address in the uplink's filter tells the switch that the guest
        // holding it lives behind the bridge - which sends its traffic past it.
        // A failed pass is harmless; a pass on incomplete information is not.
        let pfs = Self::live_pfs(topo, self.pairs.iter().map(|p| p.dev.as_str()));
        let (mut vf_macs, mut vf_carried) = match self.carried_vf_for(&pfs) {
            Some(kept) => {
                timings.vf_carried = true;
                (kept, true)
            }
            None => {
                let mark = Instant::now();
                let fresh = sock.vf_macs_of(&pfs)?;
                timings.vf_macs = mark.elapsed();
                self.remember_vf(pfs.clone(), fresh.clone());
                (fresh, false)
            }
        };
        timings.vf_addresses = vf_macs.len();

        // One reading for the whole pass: the ground every stamp written
        // here is judged against later, and what makes "quiet" a fact
        // rather than a guess. Strictly after the last pass's, so no two
        // passes can share a stamp.
        let pass_at = Self::boot_millis().max(self.last_pass_at + 1);
        self.last_pass_at = pass_at;
        let mut reports = Vec::new();
        let mark = Instant::now();
        self.drop_orphans(sock, topo, apply, &mut timings.failures);
        timings.orphans = mark.elapsed();

        let mark = Instant::now();
        for pair in self.pairs.clone() {
            let Some(dev_link) = topo.get(&pair.dev) else {
                // The device is gone; its filter went with it. Nothing can be
                // done here, and pretending otherwise by working from an
                // empty picture would only produce removals.
                continue;
            };
            // Fail closed: a bridge that is missing from this reading makes
            // every wanted address disappear, and the pass would take that
            // for "remove everything". An ifreload rebuilding the bridge is
            // a moment to wait out, not a state to act on.
            let Some(bridge_index) = topo.index_of(&pair.bridge) else {
                eprintln!(
                    "warning: {}: bridge {} not found, leaving the filter alone",
                    pair.dev, pair.bridge
                );
                continue;
            };
            let dev_index = dev_link.index;
            let driver = dev_link.driver.clone().unwrap_or_default();
            // Fail closed for the same reason as the missing bridge: a
            // detached device taken for the wire port makes every cable-side
            // peer look registrable.
            let Some(port) = topo.uplink_port(dev_index, bridge_index) else {
                eprintln!(
                    "warning: {}: not under bridge {} in this reading, leaving the filter alone",
                    pair.dev, pair.bridge
                );
                continue;
            };
            let port_name = topo.name_of(port).unwrap_or(&pair.dev).to_string();
            // Loaded before the grow-refresh decides, because the quiet
            // survivors have to be in `want` by then: a kept address missing
            // from the filter is a growth, and growing on a carried VF
            // answer is exactly the bug class the refresh exists for.
            // Before the survivors are asked for: the previous run's memory
            // is what makes an update invisible to a quiet guest.
            self.load_ports(&pair.dev, topo, apply);
            let owned_before = self.load_owned(&pair.dev);
            // The readability that matters for the memory prune below is the
            // one at THIS read: a note that turns readable again mid-pass
            // (a parallel writer healed it) makes `note_is_readable` true
            // while `owned` still descends from the could-not-tell empty
            // set - and pruning against that would erase the very memory
            // the gate exists to protect.
            let owned_was_readable = self.note_is_readable(&pair.dev);
            let (mut want, mut stacked, mut wire, mut learnt_at, mut kept) = self
                .wanted_with_keeps(
                    topo,
                    bridge_index,
                    dev_index,
                    port,
                    &fdb,
                    &vf_macs,
                    &owned_before,
                );

            let present: Set<Mac> = fdb
                .iter()
                .filter(|e| e.is_self() && e.ifindex == dev_index && e.is_unicast())
                .map(|e| e.mac)
                .collect();

            // The same rule as the fast path, for the same reason: a carried
            // answer decides nothing that grows a filter. A pass gets here
            // with additions pending in several real flows - a returner the
            // fast path refused on the carried wire set and bought this pass
            // for, a retry after a failed registration - and a VF's address
            // can have changed without any link message in the meantime. One
            // fresh question per growth-bearing pass, exactly the fast
            // path's price.
            //
            // An address ENTERING the kept state buys the question too, even
            // when the card already holds it: the keep re-asserts an address
            // the bridge no longer vouches for, and a guest may meanwhile
            // have claimed it as its VF's own over the driver mailbox - the
            // path that emits no link message. Asked once per entry into
            // the state, not per pass: the say-once set is exactly what
            // the last pass kept, so anything kept now and not in it has
            // just gone quiet. Between entries the timed refresh bounds
            // the window.
            let newly_quiet = match self.noted_quiet.get(&pair.dev) {
                Some(said) => kept.iter().any(|m| !said.contains(m)),
                None => !kept.is_empty(),
            };
            if vf_carried && (newly_quiet || want.iter().any(|m| !present.contains(m))) {
                // If the question fails, the next pass must not trust the
                // carried answer either; remember_vf clears this on success.
                self.vf_stale = true;
                let mark = Instant::now();
                let fresh = sock.vf_macs_of(&pfs)?;
                timings.vf_macs += mark.elapsed();
                self.remember_vf(pfs.clone(), fresh.clone());
                vf_macs = fresh;
                vf_carried = false;
                timings.vf_carried = false;
                timings.vf_addresses = vf_macs.len();
                // The same asking again, against the fresh answer: an
                // address the driver now calls a VF's own must not be kept.
                let again = self.wanted_with_keeps(
                    topo,
                    bridge_index,
                    dev_index,
                    port,
                    &fdb,
                    &vf_macs,
                    &owned_before,
                );
                (want, stacked, wire, learnt_at, kept) = again;
            }
            self.warn_about_unknowable_vfs(topo, &pair.dev, &vf_macs);

            // Pinned addresses that did not make it, said once per change.
            let unpinned: Set<Mac> = self
                .extra
                .iter()
                .filter(|m| !want.contains(*m))
                .copied()
                .collect();
            let warned = self.warned_extra.entry(pair.dev.clone()).or_default();
            for m in &unpinned {
                if !warned.contains(m) {
                    eprintln!(
                        "warning: {}: pinned address {} not registered - it is excluded, \
                         multicast, the host's own, or the bridge has it out on the wire",
                        pair.dev,
                        format_mac(m)
                    );
                }
            }
            *warned = unpinned;

            self.carried_wire.insert(pair.dev.clone(), wire);

            // Kept addresses cost filter slots, and past its capacity the
            // card drops entries silently - so they are the first
            // surrendered as the list nears the limit, longest-silent
            // first: every entry carries the stamp of when the bridge was
            // last seen holding it, so what goes is what has not been
            // heard from for the longest. A
            // surrendered keep is exactly the old behaviour, never worse.
            //
            // The limit is measured, not assumed: the pass reads the card's
            // own unicast list back anyway, so foreign entries occupy real
            // slots HERE too, instead of eating an invisible margin. What
            // the pass will leave behind is `want` plus the present entries
            // that are neither wanted nor ours to remove.
            let foreign_extra = present
                .iter()
                .filter(|m| !want.contains(*m) && !owned_before.contains(*m))
                .count();
            let mut occupied = want.len() + foreign_extra;
            if !kept.is_empty() && occupied + CAPACITY_HEADROOM > self.max_macs {
                let mut order = self.silence_of(&pair.dev, &kept, pass_at);
                // Longest silent first; the address is the tiebreak.
                order.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
                let mut shed = 0usize;
                for (_, m) in order {
                    if occupied + CAPACITY_HEADROOM <= self.max_macs {
                        break;
                    }
                    // A shed keep leaves `want`; the stale loop below takes
                    // it out of the card in this same pass, so the slot
                    // really frees.
                    want.remove(&m);
                    kept.remove(&m);
                    occupied -= 1;
                    shed += 1;
                }
                if apply && shed > 0 {
                    note!(
                        "{}: filter nearing its {} limit, released {shed} quiet \
                         address(es) [pressure]",
                        pair.dev,
                        self.max_macs
                    );
                }
            }

            // Said once per entry into the quiet state, not once per pass
            // forever - ageing comes in bursts, and seventeen thousand
            // identical journal lines a day teach an operator to stop
            // reading.
            let said = self.noted_quiet.entry(pair.dev.clone()).or_default();
            let fresh_quiet = kept.iter().filter(|m| !said.contains(*m)).count();
            if apply && fresh_quiet > 0 {
                note!(
                    "{}: {fresh_quiet} address(es) aged out of the bridge but \
                     their ports live on; kept [quiet]",
                    pair.dev
                );
            }
            *said = kept.clone();

            let mut owned = owned_before.clone();
            let mut added = 0usize;
            let mut removed = 0usize;
            let mut foreign = 0usize;

            // What the card is known to hold because of this pass's own
            // additions - the ones it took and the ones it refused as
            // already there. What a hard error left out is deliberately
            // absent.
            let mut landed: Vec<Mac> = Vec::new();
            let mut to_add: Vec<Mac> = Vec::new();
            for mac in &want {
                if present.contains(mac) {
                    if !owned.contains(mac) {
                        foreign += 1;
                    }
                } else {
                    to_add.push(*mac);
                }
            }

            // Which interface these notes are about, recorded so a rename
            // can be followed. Only where a note exists or is about to.
            if apply && !self.dry_run && !(owned_before.is_empty() && to_add.is_empty()) {
                self.note_index(&pair.dev, dev_index);
            }

            if !apply || self.dry_run {
                added = to_add.len();
            } else if !to_add.is_empty() {
                match self.register_batch_locked(sock, &pair.dev, dev_index, &to_add) {
                    Some(mut r) => {
                        added = r.put.len();
                        owned.extend(r.put);
                        landed = r.held;
                        timings.failures.append(&mut r.failures);
                    }
                    None => {
                        eprintln!(
                            "warning: {}: {} address(es) not registered - the \
                             ownership note has to take them first and could not",
                            pair.dev,
                            to_add.len()
                        );
                        timings.failures.push(format!(
                            "{}: note unusable, {} registration(s) held back",
                            pair.dev,
                            to_add.len()
                        ));
                    }
                }
            }

            let stale: Vec<Mac> = owned
                .iter()
                .filter(|m| !want.contains(*m))
                .copied()
                .collect();
            // Card and note under ONE lock, the flush's pattern: with the
            // delete outside it, a parallel --once whose older dump still
            // wants one of these could re-add the entry between our delete
            // and our merge, and the merge would then take its line back
            // off - an entry in the card that no note names, the permanent
            // orphan. `stale` was computed from THIS pass's reading, so a
            // line somebody appends meanwhile is not in it and survives.
            // Outlives the block: what the card really let go decides what
            // the next batch may count as room.
            let mut dropped: Vec<Mac> = Vec::new();
            if apply && !self.dry_run && !stale.is_empty() {
                let mut evict: Vec<Mac> = Vec::new();
                let mut failures: Vec<String> = Vec::new();
                self.locked(&pair.dev, || {
                    for mac in &stale {
                        removed += 1;
                        // Forgetting the note while the entry is still in
                        // the card is how a registration turns into an
                        // orphan: nothing owns it any more, so nothing will
                        // ever take it out. Keep the note when the removal
                        // fails and let the next pass retry.
                        match sock.set_self_fdb(dev_index, mac, false) {
                            Ok(()) => {
                                owned.remove(mac);
                                dropped.push(*mac);
                            }
                            // Already gone - a driver that cleared its list
                            // on link-down, or a flush from a second
                            // process. The point was for it not to be
                            // there, and warning about it on every pass
                            // forever is how a daemon trains its operator
                            // to stop reading warnings.
                            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                                owned.remove(mac);
                                dropped.push(*mac);
                            }
                            Err(e) => {
                                // The note stays for the retry - the memory
                                // must not: an address pending removal whose
                                // port memory survives would be re-adopted
                                // by the quiet keep once its wire evidence
                                // fades, and a one-off EBUSY would harden
                                // into a permanent keep. Losing memory is
                                // always the old behaviour, never worse.
                                evict.push(*mac);
                                eprintln!(
                                    "warning: {}: cannot unregister {}: {e}",
                                    pair.dev,
                                    format_mac(mac)
                                );
                                failures.push(format!(
                                    "{}: unregister {}: {e}",
                                    pair.dev,
                                    format_mac(mac)
                                ));
                                removed -= 1;
                            }
                        }
                    }
                    self.forget_locked(&pair.dev, &dropped);
                });
                if let Some(ports) = self.carried_ports.get_mut(&pair.dev) {
                    for mac in &evict {
                        ports.remove(mac);
                    }
                }
                timings.failures.extend(failures);
            } else {
                // A pass that may not touch the card still counts what a
                // real one would have removed, so dry-run reports stay
                // honest; `owned` stays as read, like it always did.
                removed += stale.len();
            }

            // Only when this pass changed something beyond what the locked
            // removal block above already wrote: the merge takes the note's
            // lock and reads the file past the stat cache, which an idle
            // pass has no reason to pay - and an empty difference can never
            // change what is merged. Removals already on file merge as a
            // no-op; what this still records is the EEXIST un-claims from
            // the addition loop. Failing to record is the safe direction:
            // the note then still names entries that are out of the card,
            // and a later pass settles them through ENOENT.
            if apply && owned != owned_before {
                self.save_owned_merged(&pair.dev, &owned_before, &owned);
            }

            // The memory follows the pass, under the same readability rule
            // the notes live by: while the note cannot be read, `owned` is
            // the empty could-not-tell set, and pruning against it would
            // erase the whole memory of this uplink - the quiet guests with
            // it. Judged by the readability of the read `owned` came from,
            // not by now. Merge what this dump saw, keep only what is still
            // owned.
            if owned_was_readable {
                let ports = self.carried_ports.entry(pair.dev.clone()).or_default();
                // Everything this dump found learnt was seen just now.
                // What it did not find keeps the stamp it had, and that
                // stamp - now older than this pass - is what makes it
                // quiet. Nothing has to be decided here; the two numbers
                // say it.
                for (m, p) in learnt_at {
                    Self::note_seen(ports, m, Some(p), pass_at);
                }
                ports.retain(|m, _| owned.contains(m));
                if apply {
                    self.save_ports(&pair.dev, topo, pass_at);
                }
            }

            // Said once per stay above the limit, by the process that acts:
            // a --status predicting the same number is not the daemon's
            // journal line.
            if apply {
                if occupied > self.max_macs {
                    if self.warned_over.insert(pair.dev.clone()) {
                        eprintln!(
                            "warning: {}: {} unicast entries against the {} the \
                             vport list holds - some will be dropped silently, \
                             and not by choice",
                            pair.dev, occupied, self.max_macs
                        );
                    }
                } else {
                    self.warned_over.remove(&pair.dev);
                }
                // The tight-fit mark re-arms only once the list is back
                // under the headroom the batch measures against, or the
                // pass would clear it while the batch is still in the band
                // that set it.
                if occupied + CAPACITY_HEADROOM <= self.max_macs {
                    self.warned_tight.remove(&pair.dev);
                }
            }
            // What the fast path counts from until the next pass corrects
            // it: how many slots, and which addresses fill them. `want` is
            // what this pass leaves behind - the additions below land, the
            // stale loop above took its removals out - plus the foreign
            // entries nobody here may touch.
            // What the card holds when this pass is done, observed rather
            // than intended: what the dump found, plus what this pass's
            // own additions really landed, minus what its removals really
            // took out. An address a hard error left out of the card is
            // absent from all three and so stays absent here - the
            // grow-gate must ask the driver afresh when it comes back.
            let mut holds: Set<Mac> = present.iter().copied().collect();
            holds.extend(landed);
            for mac in &dropped {
                holds.remove(mac);
            }
            self.carried.insert(
                pair.dev.clone(),
                Carried {
                    present: holds,
                    quiet: kept.clone(),
                    // A pass that could not read its note refreshed no
                    // stamp, so it must not advance the ground they are
                    // judged against either: every live guest would read
                    // as quiet afterwards.
                    passed_at: if owned_was_readable {
                        pass_at
                    } else {
                        self.carried.get(&pair.dev).map_or(0, |c| c.passed_at)
                    },
                },
            );

            // Unsorted on purpose: the status page sorts for display
            // itself, and nothing else looks at the addresses at all.
            let detail = self.detail.then(|| Detail {
                wanted: want.iter().copied().collect(),
                quiet_ages: self
                    .silence_of(&pair.dev, &kept, pass_at)
                    .into_iter()
                    .map(|(silent, m)| (m, silent))
                    .collect(),
            });
            reports.push(Report {
                dev: pair.dev.clone(),
                bridge: pair.bridge.clone(),
                port: port_name,
                driver,
                owned: owned.len(),
                present: present.len(),
                wanted: want.len(),
                stacked,
                added,
                removed,
                foreign,
                quiet: kept.len(),
                detail,
            });
        }
        timings.pairs = mark.elapsed();
        timings.added = reports.iter().map(|r| r.added).sum();
        timings.removed = reports.iter().map(|r| r.removed).sum();
        timings.total = topo_load + started.elapsed();
        self.timings = timings;
        Ok(reports)
    }

    /// Answer a batch of forwarding notifications straight away, before the
    /// pass that follows gets to it. A device that has only just appeared
    /// would otherwise miss the first reply sent to it.
    ///
    /// Two things are done here, and they are the same rule read in both
    /// directions. An address learnt behind the bridge is registered. An
    /// address learnt on the uplink's own port is *out on the wire*, and if
    /// it is one of ours it comes back out of the filter at once: that is a
    /// guest that has moved to another host, and until the entry goes, the
    /// eSwitch keeps handing its traffic to the uplink, where the bridge
    /// cannot send it back out of the port it arrived on. It is dropped.
    ///
    /// A `RTM_DELNEIGH` is deliberately not treated as a reason to remove
    /// anything. One entry going says nothing about the address: a
    /// vlan-aware bridge learns the same address once per VLAN and the
    /// filter holds one entry for all of them, so only a full dump can tell
    /// that the last one is gone. The pass that follows this batch does
    /// exactly that.
    ///
    /// The ownership notes are read once per device, and each device's
    /// additions are appended in one piece - before its card is written,
    /// the same note-first order the full pass keeps. Doing it per address
    /// meant rewriting a growing file for every entry of a burst - work
    /// that squares with the size of the burst, which is exactly when there
    /// is least of it to spare.
    /// Returns whether the batch is worth a full pass. A batch of learning
    /// that turns out to be entirely somebody else's - addresses appearing on
    /// the wire that were never ours, entries on bridges that have nothing to
    /// do with any uplink - leaves nothing for a pass to reconcile, and a
    /// pass is the expensive thing here: it dumps the host's whole forwarding
    /// table. On a busy host that is the difference between answering an
    /// event and being flattened by it.
    pub fn fast_apply(
        &mut self,
        sock: &mut dyn FdbWriter,
        topo: &Topology,
        events: &[(u16, FdbEntry)],
    ) -> io::Result<Urgency> {
        if events.is_empty() {
            return Ok(Urgency::Nothing);
        }
        // A dry run changes nothing, so nothing here can decide a pass is
        // unnecessary - and the pass is where a dry run does its reporting.
        if self.dry_run {
            return Ok(Urgency::Now);
        }
        // A deletion is a reason to look, never to hurry: a registration that
        // outlives its guest by a few seconds costs nothing but a filter slot.
        let mut urgency = if events
            .iter()
            .any(|(kind, _)| *kind == crate::netlink::RTM_DELNEIGH)
        {
            self.date_the_silence(topo, events);
            Urgency::WhenConvenient
        } else {
            Urgency::Nothing
        };
        // Everything below - reflection, decide, commit - acts only on
        // RTM_NEWNEIGH. A deletions-only batch has bought its pass above and
        // has no use for skip sets, and in a vf_stale window it would pay a
        // driver question (0.6-0.9 ms on mlx5) for answers nothing reads;
        // ageing bursts right after an interface change are exactly that.
        if !events
            .iter()
            .any(|(kind, _)| *kind == crate::netlink::RTM_NEWNEIGH)
        {
            return Ok(urgency);
        }
        // Where each uplink sits in its bridge, and which addresses may never
        // be registered for it, are properties of the topology - the same for
        // every entry in the batch. Worked out once instead of once per entry
        // per pair, and taken from the very rule the full pass uses - the
        // doc on exclusions says why there may be no second spelling.
        //
        // The virtual functions' addresses come carried from the last pass
        // where they fit, else they are asked for now - never assumed empty.
        let pfs = Self::live_pfs(topo, self.pairs.iter().map(|p| p.dev.as_str()));
        // Whether the answer is carried is kept, because a carried answer is
        // only good enough to shrink on: growing consults the driver first,
        // below.
        let (vf_macs, vf_carried) = match self.carried_vf_for(&pfs) {
            Some(kept) => (kept, true),
            None => {
                let fresh = sock.vf_macs_of(&pfs)?;
                self.remember_vf(pfs.clone(), fresh.clone());
                (fresh, false)
            }
        };
        let mut pairs: Vec<FastPair> = self
            .pairs
            .iter()
            .filter_map(|p| {
                let dev = topo.index_of(&p.dev)?;
                let bridge = topo.index_of(&p.bridge)?;
                // A pair whose device is not under its bridge right now is
                // skipped here too; the link event that detached it buys the
                // full pass, which says so out loud.
                let port = topo.uplink_port(dev, bridge)?;
                let skip = self.exclusions(topo, dev, port, &vf_macs);
                Some(FastPair {
                    dev: p.dev.clone(),
                    bridge,
                    index: dev,
                    port,
                    skip,
                    reflected: crate::hash::set(),
                    // Only the carried path reads this: it is what turns a
                    // learn of a VF's own address into a candidate, so the
                    // fresh question can settle it. On a freshly-asked
                    // answer there is nothing to settle, and building the
                    // set would be a walk per pair per batch for nobody.
                    vf_own: if vf_carried {
                        Self::vf_reported(topo, dev, &vf_macs)
                    } else {
                        crate::hash::set()
                    },
                })
            })
            .collect();

        // What this batch saw arrive on an uplink's own port, per uplink.
        // Read before anything is registered, because within one batch the
        // wire has the last word - the same reason the full pass subtracts
        // its wire set from what it wants.
        let mut reflected: Map<String, Set<Mac>> = crate::hash::map();
        for (kind, e) in events {
            if *kind != crate::netlink::RTM_NEWNEIGH || !e.is_learned() || !e.is_unicast() {
                continue;
            }
            for fp in &pairs {
                if e.ifindex == fp.port {
                    reflected.entry(fp.dev.clone()).or_default().insert(e.mac);
                }
            }
        }

        for fp in &mut pairs {
            let Some(macs) = reflected.get(&fp.dev) else {
                continue;
            };
            // For the rest of this batch these are wire addresses - the whole
            // batch is one moment, and in it the wire has the last word.
            fp.reflected.extend(macs.iter().copied());
            // Nothing of ours among them is the ordinary case on a busy
            // segment: every address the switch carries is learnt here
            // sooner or later. Establishing it without copying the record of
            // what we own is the difference between answering that traffic
            // and being buried by it.
            // One look at the note answers for the whole batch. Asking per
            // address would be a stat per address, on the path whose whole
            // point is that it is cheap when the answer is no.
            if !self.with_owned(&fp.dev, |o| macs.iter().any(|m| o.contains(m))) {
                continue;
            }
            // Card and note under ONE lock, the flush's pattern: with the
            // delete outside it, a parallel --once whose dump predates the
            // move could re-add the entry between our delete and our note
            // write, and the merge would then take its line back off - an
            // entry in the card that no note names, the permanent orphan.
            // The removals wait on rtnl while the lock is held; that wait
            // is precisely what the parallel writer's append has to sit
            // out. Only what THIS process owned before the window is
            // touched - a line somebody appends meanwhile is not ours to
            // judge and survives the write untouched.
            let owned_here = self.load_owned(&fp.dev);
            let mut evict: Vec<Mac> = Vec::new();
            let mut taken_back: Vec<Mac> = Vec::new();
            let mut dropped: Vec<Mac> = Vec::new();
            self.locked(&fp.dev, || {
                for mac in macs {
                    // Only ever our own registrations. An address somebody
                    // else put in the filter is theirs to remove, on the
                    // wire or not.
                    if !owned_here.contains(mac) {
                        continue;
                    }
                    // The port memory goes with the entry - mandatory, not
                    // tidiness: should the note write below fail, the
                    // address stays on the note, and a later pass whose
                    // dump no longer shows the wire entry would otherwise
                    // keep alive the very address this reflection just
                    // took out. In the Err arm the eviction is what
                    // re-arms the stale-removal retry: with the memory
                    // alive, the quiet keep would re-adopt this address as
                    // soon as its wire evidence ages, and a one-off
                    // failure would harden into a permanent keep.
                    match sock.set_self_fdb(fp.index, mac, false) {
                        Ok(()) => {
                            dropped.push(*mac);
                            evict.push(*mac);
                            urgency = Urgency::Now;
                            taken_back.push(*mac);
                            note!(
                                "{}: {} moved out onto the wire, unregistered [reflection]",
                                fp.dev,
                                format_mac(mac)
                            );
                        }
                        // Already gone. The point was for it not to be there.
                        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                            dropped.push(*mac);
                            evict.push(*mac);
                        }
                        // Keep the note: an entry still in the card that
                        // nothing owns is the orphan the notes exist to
                        // prevent. And buy a pass: the guest's traffic is
                        // being misdirected right now, and a batch made
                        // only of this failure would otherwise end quiet
                        // and retry nothing.
                        Err(e) => {
                            evict.push(*mac);
                            urgency = Urgency::Now;
                            eprintln!(
                                "warning: {}: cannot unregister {}: {e}",
                                fp.dev,
                                format_mac(mac)
                            );
                        }
                    }
                }
                self.forget_locked(&fp.dev, &dropped);
            });
            if !evict.is_empty() {
                if let Some(ports) = self.carried_ports.get_mut(&fp.dev) {
                    for mac in &evict {
                        ports.remove(mac);
                    }
                }
                // Every slot this really freed leaves the carried count -
                // the ENOENT arm's as much as the Ok arm's. An entry the
                // card says it does not have is not occupying anything,
                // and leaving it counted made the next burst measure its
                // room against a slot that was already free.
                self.card_no_longer_holds(&fp.dev, &dropped);
                // And out of the written-down memory too: an eviction that
                // lived only in RAM could come back through the file after
                // a crash, once the wire evidence has aged - re-registering
                // the very address this reflection took out.
                let passed = self.carried.get(&fp.dev).map_or(0, |c| c.passed_at);
                self.save_ports(&fp.dev, topo, passed);
            }
            // Beyond the batch, only the ones actually taken out of the
            // filter are remembered, so that the next batch does not put back
            // what this one removed. Remembering every address ever seen on
            // the wire would be a set that only grows: the full pass replaces
            // this set from the real forwarding table, and a run of wire-side
            // learning no longer schedules one - which is precisely when the
            // growth would be unbounded, and each batch would then be paying
            // to copy it.
            if !taken_back.is_empty() {
                self.carried_wire
                    .entry(fp.dev.clone())
                    .or_default()
                    .extend(taken_back);
            }
        }

        // A carried answer decides nothing that grows a filter. A virtual
        // function's address can change without any link message: a PF that
        // is administratively down announces nothing (netdev_state_change()
        // on a down device is a no-op, seen on mlx4) - and even an up PF is
        // silent when the GUEST changes its address, because on ixgbe and
        // i40e that runs over the driver mailbox and the PF handler updates
        // vfinfo without telling rtnetlink. There was an "up PFs announce"
        // gate here once; the kernel source refuted it. So no event can be
        // relied on to mark the carried answer stale, and the only moment
        // left to catch the change is before an addition. Decided first with
        // the carried answer, and only a batch that would register something
        // asks the driver afresh and decides again: reflection and deletions
        // above still act on the carried answer, because shrinking on stale
        // news is healed by the next pass, while growing on stale news sends
        // a guest's traffic past it until the timed pass, up to the whole
        // interval. The price is one driver question per filter-growing
        // batch - ~0.9 ms on mlx5, whose firmware answers it, ~0.01 ms on
        // the Intel drivers and mlx4.
        if vf_carried {
            let mut would: Map<String, Vec<(Mac, u32)>> = crate::hash::map();
            for (kind, entry) in events {
                if *kind != crate::netlink::RTM_NEWNEIGH {
                    continue;
                }
                self.fast_add(topo, entry, &pairs, &mut would, FastPhase::Decide);
            }
            // An address that is ours AND still in the card was vetted by
            // the fresh answer that let it in; re-learning it grows
            // nothing. Without this, the tail of a burst - the prompt pass
            // has long registered everything, the queued learns arrive one
            // by one - bought one driver question per re-learn, invisible
            // to every latency figure because the addresses were already
            // in. Owned alone is not enough: a driver that cleared its
            // list on link-down leaves addresses noted but gone, and
            // putting one back IS a growth - it must ask the driver, or a
            // VF that meanwhile claimed that address gets it registered
            // past its guest, for as long as the interval.
            for (dev, macs) in would.iter_mut() {
                let present = self.carried.get(dev).map(|c| &c.present);
                self.with_owned(dev, |o| {
                    macs.retain(|(m, _)| !(o.contains(m) && present.is_some_and(|p| p.contains(m))))
                });
            }
            would.retain(|_, macs| !macs.is_empty());
            if !would.is_empty() {
                // If the question fails, whoever comes next must not believe
                // the carried answer either: main answers the error with a
                // prompt full pass, and that pass would otherwise take the
                // very answer this refresh distrusted. remember_vf clears
                // the mark again on success.
                self.vf_stale = true;
                // Only the functions of the pairs that would grow are asked:
                // the question is per-function firmware work (~0.35 ms each
                // on mlx5), and a pair that grows nothing reads no fresh
                // answer. The unasked functions keep their carried entries,
                // merged back under the full function list, so the carry
                // contract the next pass compares against still holds.
                let ask = Self::live_pfs(topo, would.keys().map(String::as_str));
                let mut fresh: Vec<(u32, Mac)> = vf_macs
                    .iter()
                    .filter(|(pf, _)| !ask.contains(pf))
                    .cloned()
                    .collect();
                fresh.extend(sock.vf_macs_of(&ask)?);
                self.remember_vf(pfs.clone(), fresh.clone());
                for fp in &mut pairs {
                    fp.skip = self.exclusions(topo, fp.index, fp.port, &fresh);
                    // fp.vf_own is deliberately NOT refreshed: its only
                    // reader is the Decide phase, which ran before this
                    // refresh - the Commit phase judges by `skip`, which
                    // the line above just rebuilt from the fresh answer.
                    // fp.reflected stands: within this batch the wire keeps
                    // the last word, fresh answer or not.
                }
                // The catch this exists for is rare enough to be told about.
                for (dev, macs) in &would {
                    let Some(fp) = pairs.iter().find(|f| &f.dev == dev) else {
                        continue;
                    };
                    for (mac, _) in macs {
                        if fp.skip.contains(mac) {
                            note!(
                                "{}: {} is a virtual function's address by the \
                                 driver's fresh answer, kept out [vf refresh]",
                                dev,
                                format_mac(mac)
                            );
                        }
                    }
                }
            }
        }

        // What this batch would register, per uplink - decided first,
        // written after, because the note has to take every address before
        // the card does. The pass explains the order; it is the same one,
        // for the same crash.
        let mut to_register: Map<String, Vec<(Mac, u32)>> = crate::hash::map();
        for (kind, entry) in events {
            if *kind != crate::netlink::RTM_NEWNEIGH {
                continue;
            }
            if self.fast_add(topo, entry, &pairs, &mut to_register, FastPhase::Commit) {
                urgency = Urgency::Now;
            }
        }
        for (dev, learns) in to_register {
            // The same address can arrive several times in one drained
            // burst - once per VLAN on a vlan-aware bridge - and both the
            // note and the card want it once. When the ports differ too,
            // the last learn wins: the events are drained in the order the
            // kernel sent them, so the last one is where the address is
            // now.
            let mut learnt_on: Map<Mac, u32> = crate::hash::map();
            for (m, port) in &learns {
                learnt_on.insert(*m, *port);
            }
            let mut macs: Vec<Mac> = learnt_on.keys().copied().collect();
            macs.sort_unstable();
            let Some(fp) = pairs.iter().find(|f| f.dev == dev) else {
                continue;
            };
            // The batch counts against the occupancy the last pass measured
            // plus this process's own effect since. A burst that would not
            // fit surrenders keeps first - new learns outrank the quiet.
            // A guest that speaks is seen now - the rule the valve's
            // ordering rests on, and until this the pass alone kept it:
            // one that spoke seconds ago still wore the stamp of its last
            // silence, and the shedder would name it first, deleting an
            // entry the very next line puts back.
            let now = Self::boot_millis();
            // Only once the file has been consulted for this uplink:
            // making the map here before that would look to `load_ports`
            // like a memory already carried in RAM, and the previous
            // process's keeps would be thrown away unread.
            if self.ports_loaded.contains(&dev) {
                let ports = self.carried_ports.entry(dev.clone()).or_default();
                for mac in &macs {
                    Self::note_seen(ports, *mac, learnt_on.get(mac).copied(), now);
                }
            }
            let allowed = self.max_macs.saturating_sub(CAPACITY_HEADROOM);
            let est = self.carried.get(&dev).map_or(0, |c| c.present.len());
            // Only what would take a NEW slot. An address the card already
            // holds costs nothing to re-register - counting it would shed
            // keeps to make room for something that is already in.
            let fresh_slots = match self.carried.get(&dev) {
                Some(c) => macs.iter().filter(|m| !c.present.contains(*m)).count(),
                None => macs.len(),
            };
            let over = (est + fresh_slots).saturating_sub(allowed);
            if over > 0 && self.shed_keeps(sock, &dev, fp.index, over, topo) < over {
                // The one moment the daemon knowingly writes past the
                // filter's limit. Said once per uplink per stay: past the
                // limit the card drops silently and arbitrarily, and an
                // operator who never hears about it looks for the fault in
                // the guest.
                if self.warned_tight.insert(dev.clone()) {
                    eprintln!(
                        "warning: {dev}: no room for {} new address(es) and no \
                         quiet ones left to release - the list is within {} \
                         of the {} the card holds, and past that it drops \
                         silently",
                        fresh_slots, CAPACITY_HEADROOM, self.max_macs
                    );
                }
            }
            self.note_index(&dev, fp.index);
            let held = match self.register_batch_locked(sock, &dev, fp.index, &macs) {
                Some(r) => r.held,
                None => {
                    // A batch of ours already bought the pass, which says
                    // the held-back count out loud and retries.
                    eprintln!(
                        "warning: {dev}: {} address(es) not registered - the \
                         ownership note has to take them first and could not",
                        macs.len()
                    );
                    Vec::new()
                }
            };
            // Only what the card is now KNOWN to hold: what it took, and
            // what it refused as already there. An address a hard error
            // left out must not be recorded as present - the grow-gate
            // reads owned-and-present as "re-learning this grows nothing"
            // and would then skip the fresh driver question that keeps a
            // virtual function's own address out of the filter. The next
            // pass's read-back corrects any drift.
            self.card_now_holds(&dev, held);
        }
        Ok(urgency)
    }

    /// Returns whether this entry was any of our business - a candidate to
    /// register, refused, or something the full pass will have to look at.
    /// An entry that concerns none of the pairs returns false, and a batch
    /// made entirely of those does not earn a pass.
    ///
    /// Nothing is written here, in either phase: what would be registered
    /// lands in `registered`, and the caller writes the batch through -
    /// note first - once it is decided. The commit phase used to write the
    /// card itself, which is what made "note the batch afterwards" the
    /// only possible order.
    fn fast_add(
        &self,
        topo: &Topology,
        entry: &FdbEntry,
        pairs: &[FastPair],
        registered: &mut Map<String, Vec<(Mac, u32)>>,
        phase: FastPhase,
    ) -> bool {
        if !entry.is_learned() || !is_registerable(&entry.mac) {
            return false;
        }
        let Some(master) = entry.master else {
            return false;
        };
        if topo.at(entry.ifindex).is_none() {
            return false; // an interface this reading does not have
        }
        let mut ours = false;
        for fp in pairs {
            if fp.skip.contains(&entry.mac) {
                // A hit owed only to the carried driver answer may be stale
                // news - a VF address freed without any link message, on a
                // down PF or over the ixgbe/i40e mailbox. In the decide
                // phase such a hit becomes a candidate, so the fresh
                // question settles it; every other refusal stays passless,
                // which is what keeps the wire-load optimisation standing.
                if phase == FastPhase::Decide && fp.vf_own.contains(&entry.mac) {
                    registered
                        .entry(fp.dev.clone())
                        .or_default()
                        .push((entry.mac, entry.ifindex));
                }
                continue; // excluded, the host's own, or a VF's
            }

            // What the last full pass saw out on the wire. An address on the
            // wire in one VLAN and behind the bridge in another must not flap
            // into the filter on every learning event.
            //
            // Looked up here rather than folded into `skip` when the batch is
            // prepared: on a busy segment that set holds every address the
            // switch carries and copying it into the skip set cost 550 us per
            // batch, which is to say per address learnt anywhere on the
            // bridge. Two lookups are two lookups whatever the set holds.
            //
            // The batch counts as ours all the same. Only a full pass ever
            // replaces this set from the real forwarding table, so a refusal
            // that bought no pass would suppress its own correction: a guest
            // that moved away and came back would stay unregistered until an
            // unrelated event or the timer, up to the whole interval, while
            // address resolution for it succeeds and the unicast disappears.
            if self
                .carried_wire
                .get(&fp.dev)
                .is_some_and(|w| w.contains(&entry.mac))
            {
                ours = true;
                continue;
            }
            if entry.ifindex == fp.port {
                continue; // on the wire; handled before any of this
            }
            // An inner learn of an address this very batch saw on the wire:
            // the wire has the last word, so it is not registered - but the
            // batch counts as ours. The kernel's end state may be "behind
            // the bridge" (wire first, inner learn later in the same drained
            // burst), and a refusal that bought no pass would suppress its
            // own correction - the same rule as the carried wire set above.
            // The wire learn itself took the port exit a line up, so a batch
            // that is wire and nothing else stays passless.
            if fp.reflected.contains(&entry.mac) {
                ours = true;
                continue;
            }
            if master != fp.bridge {
                // only bridges stacked on the uplink bridge are of interest
                let Some(master_link) = topo.at(master) else {
                    continue;
                };
                if !master_link
                    .slaves
                    .iter()
                    .any(|p| topo.leads_to(*p, fp.bridge))
                {
                    continue;
                }
            }
            if topo.leads_to(entry.ifindex, fp.bridge) {
                continue;
            }
            ours = true;
            // With the port it was learnt on. The pass would put that on
            // record at its next dump, but a daemon that dies in between
            // leaves the address on the note with no port - and the
            // restart, finding no port to check, unregisters it as soon as
            // it falls quiet. Which is the outage the memory exists for.
            registered
                .entry(fp.dev.clone())
                .or_default()
                .push((entry.mac, entry.ifindex));
        }
        ours
    }

    /// Over the notes rather than over the pairs: `--flush` promises to remove
    /// every address this daemon registered, and some of them belong to
    /// devices that have since stopped being an uplink.
    pub fn flush(&mut self, sock: &mut dyn FdbWriter) -> io::Result<bool> {
        let topo = Topology::from_links(sock.dump_links()?);
        let mut clean = true;
        // A directory that cannot be listed fails the flush outright: the
        // promise here is "everything comes back out", and claiming it for
        // notes nobody could even enumerate would be the lie an operator
        // acts on.
        for dev in self.noted_devices()? {
            if self.dry_run {
                // The preview has to give the same answer the real flush
                // would: an unreadable note reads as the empty set, and
                // "would remove 0" with exit 0 is the opposite of the
                // refusal the real run answers this state with.
                if !self.note_is_readable(&dev) {
                    println!("{dev}: note unreadable, a real flush would fail here");
                    clean = false;
                    continue;
                }
                let owned = self.load_owned(&dev);
                println!("{dev}: would remove {} address(es)", owned.len());
                continue;
            }
            // Read, unregister and unlink under the note's lock. A daemon
            // appends to this note the moment it registers, and a line
            // appended into this window used to be destroyed by the rename
            // or unlink below - leaving that entry in the card with no owner
            // on record. The removals wait on rtnl while the lock is held;
            // that wait is precisely what the daemon's append has to sit out.
            let settled = self.locked(&dev, || {
                let owned = self.load_owned(&dev);
                // The name is how a note is found, the index is what the
                // entries are attached to - and a rename moves only the
                // name. The recorded index reaches the entries anyway.
                let index = topo.get(&dev).map(|l| l.index).or_else(|| {
                    let (index, new_name) = self.renamed_target(&dev, &topo)?;
                    println!("{dev}: now called {new_name}, removing through it");
                    Some(index)
                });
                let (gone, kept) = match index {
                    Some(index) => self.unregister_all(sock, &dev, index, &owned),
                    None => (owned.len(), crate::hash::set()),
                };
                if kept.is_empty() && self.note_is_readable(&dev) {
                    self.remove_note(&dev);
                    println!("{dev}: removed {gone} address(es)");
                    true
                } else {
                    // write_owned, not save_owned: the lock is already held,
                    // and taking it again on a second descriptor would wait
                    // on itself.
                    self.write_owned(&dev, &kept);
                    println!(
                        "{dev}: removed {gone} address(es), {} could not be removed \
                         and stay on record",
                        kept.len()
                    );
                    false
                }
            });
            clean &= settled;
        }
        Ok(clean)
    }
}

#[cfg(test)]
mod extra_tests;
#[cfg(test)]
mod state_tests;
#[cfg(test)]
pub(crate) mod tests;
