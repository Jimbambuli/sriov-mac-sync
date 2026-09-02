//! Deciding which addresses belong in an uplink's unicast filter, and putting
//! them there.
//!
//! # The three invariants
//!
//! Cited by number throughout the tree. Each is enforced where named, so this
//! list cannot go stale against the mechanism.
//!
//! 1. **An address learnt on the wire is never registered.** Enforced in
//!    `fast_add` (the port exit and the carried wire set) and by the pass
//!    judging every learn through `Reach`.
//! 2. **A virtual function's own address is never registered** - on ixgbe
//!    the guest goes deaf, on i40e the eSwitch duplicates. Enforced by
//!    `exclusions` and the grow-only driver refresh in the decide phase.
//! 3. **Only what this daemon registered is ever removed** - the note is
//!    written before the card. Enforced in `register_batch_locked` and by
//!    every removal path reading the note first.
//!
//! # Vocabulary
//!
//! One word per thing - code, tests, journal, man page:
//!
//! * **note** - the ownership file per uplink (`<dev>.owned`): what WE put in
//!   the card.
//! * **wire** - the uplink port's own side; addresses learnt there are peers,
//!   never guests.
//! * **keep** / **quiet** - an address aged out of the bridge but kept while
//!   its learn port lives; "quiet" is the state, "keep" the decision.
//! * **shed** / **release** - the pressure valve surrendering keeps near
//!   capacity.
//! * **pass** - one full reconciliation against a fresh dump.
//! * **batch** - one drained set of kernel notifications, answered by the
//!   fast path.
//! * **reflection** - one of our addresses turning up on the wire, and the
//!   removal that answers it.
//! * **ward** - the uplink's own address, registered so the host stays
//!   reachable.
//! * **orphan** - a note whose uplink is gone; only autodetection may
//!   conclude that.
//! * **carried** - state kept between passes, always revalidated before
//!   growth.

use crate::hash::{Map, Set};
use crate::note;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::netlink::{format_mac, FdbEntry, Socket};
use crate::topology::{Anatomy, Learn, Reach, Topology};

pub type Mac = [u8; 6];

/// Everything said once, per device, in one place: a device that leaves or is
/// renamed loses every mark in one call (`forget`, `rename`). A new mark goes
/// here; the test holds `forget` to leaving nothing behind.
#[derive(Debug, Default, PartialEq)]
pub(super) struct Said {
    /// a virtual function whose address cannot be known
    pub unknown_vf: Set<String>,
    /// pinned addresses that could not be registered, per device
    pub extra: Map<String, Set<Mac>>,
    /// the filter is over its limit
    pub over: Set<String>,
    /// a batch found no room
    pub tight: Set<String>,
    /// which addresses are being kept quiet, per device
    pub quiet: Map<String, Set<Mac>>,
    /// the note could not be read
    pub unreadable: Set<String>,
    /// the note's lock could not be taken
    pub lock: Set<String>,
    /// the port memory could not be written
    pub ports: Set<String>,
}

impl Said {
    /// A device that stopped being an uplink: a return announces afresh.
    pub fn forget(&mut self, dev: &str) {
        let Said {
            unknown_vf,
            extra,
            over,
            tight,
            quiet,
            unreadable,
            lock,
            ports,
        } = self;
        unknown_vf.remove(dev);
        extra.remove(dev);
        over.remove(dev);
        tight.remove(dev);
        quiet.remove(dev);
        unreadable.remove(dev);
        lock.remove(dev);
        ports.remove(dev);
    }

    /// A device renamed: what was said stays said under the new name.
    pub fn rename(&mut self, old: &str, new: &str) {
        let Said {
            unknown_vf,
            extra,
            over,
            tight,
            quiet,
            unreadable,
            lock,
            ports,
        } = self;
        for set in [unknown_vf, over, tight, unreadable, lock, ports] {
            if set.remove(old) {
                set.insert(new.to_string());
            }
        }
        for map in [extra, quiet] {
            if let Some(v) = map.remove(old) {
                map.insert(new.to_string(), v);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Pair {
    pub dev: String,
    pub bridge: String,
}

/// One pair as the fast path needs it: the structural questions answered once
/// per batch, which describes a single moment.
/// The two halves of fast_apply's grow-only driver refresh. Deciding collects
/// what would be registered - stale carried VF exclusions included - so the
/// fresh driver question is paid only when something would grow; committing
/// collects the real candidates against the by-then fresh skip sets. Neither
/// phase writes; the caller writes the decided batch through, note first.
#[derive(Clone, Copy, PartialEq)]
enum FastPhase {
    Decide,
    Commit,
}

struct FastPair {
    anat: Anatomy,
    reach: Reach,
    /// kept for the messages a person reads
    dev: String,
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
/// A pass dumps the host's whole forwarding table. Deletions arrive as bursts
/// of hundreds when a bridge ages its entries out, and none is urgent -
/// answering each burst at the full rate turns a quiet host busy for nothing.
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
    /// Addresses the card is now known to hold because of this call: taken,
    /// or refused with EEXIST. An address a hard error left out must NOT be
    /// recorded as present - the grow-gate reads owned-and-present as
    /// "re-learning grows nothing" and would skip the fresh driver question
    /// that keeps a VF's own address out of the filter (invariant 2).
    held: Vec<Mac>,
    /// What went wrong, for a caller that reports.
    failures: Vec<String>,
}

/// What one pass left behind about an uplink's filter.
#[derive(Default)]
struct Carried {
    /// WHICH addresses the card holds, foreign entries included; its length
    /// is the occupancy. The note is no substitute: it says what is ours,
    /// this what is in the card. A driver that cleared its list on link-down
    /// leaves addresses noted but absent, and putting one back is a growth
    /// that must ask the driver afresh.
    present: Set<Mac>,
    /// The addresses the pass decided to keep. The one pool BOTH valves
    /// surrender from, so the event path can reach nothing the pass would
    /// not: by construction free of pinned EXTRA addresses, anything still
    /// wanted, foreign entries and addresses the note does not name. A pass
    /// that could not read its note keeps nothing, so the event path sheds
    /// nothing either.
    quiet: Set<Mac>,
    /// When that pass ran, in the boot-clock the addresses are stamped in: an
    /// address whose stamp predates the last pass is one the last pass did
    /// not see.
    passed_at: u64,
}

/// What a ConnectX-4 Lx vport list holds - the assumption when neither the
/// operator nor devlink says otherwise. The one spelling; main.rs and the
/// help text both read it.
pub const DEFAULT_MAX_MACS: usize = 128;

/// Slots left free below `max_macs`: an allowance for counting drift (a
/// parallel writer's entries between two passes, an add in flight while a
/// batch decides), not a working reserve.
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
    /// Only built when somebody prints it: on the daemon path it was a copy
    /// of the whole desired set per uplink per pass, the pass's largest
    /// allocation.
    pub detail: Option<Detail>,
}

/// The per-address half of a report, for --status and --once and never the
/// daemon. Built from the sets the pass decided on, so there is no second
/// spelling of "what this uplink wants".
pub struct Detail {
    pub wanted: Vec<Mac>,
    /// the kept addresses, with how long each has been silent -
    /// milliseconds since the bridge last held it
    pub quiet_ages: Vec<(Mac, u64)>,
    /// The bridge port each address was last learnt behind, where known. The
    /// quiet memory records it per address, and on a virtualisation host it
    /// names the guest: `veth106i0` is container 106, `tap210i0` VM 210.
    /// Addresses without a port are structural (bridge's own, ward, EXTRA) or
    /// predate this process's memory.
    pub learnt_behind: Vec<(Mac, String)>,
}

/// What the syncer needs from the kernel, as a trait so the bookkeeping can
/// be tested against a fake: the real one is the netlink socket, the fake
/// records what would be written and answers what a test injects.
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
    /// Whether each pass also builds the per-address half of its report:
    /// --status and --once, never the daemon, which would pay the copy for
    /// numbers nothing prints.
    pub detail: bool,
    /// Whether the pair list is the whole picture: yes when autodetection
    /// drew it, no when pairs were named by hand - and only something that
    /// knows every uplink may declare a note an orphan.
    pub authoritative: bool,
    pub state_dir: PathBuf,
    /// What the most recent pass cost.
    pub timings: Timings,
    /// The VFs' addresses from the last pass, with the PFs they were read
    /// for. A pass that no link message preceded works from these instead of
    /// asking the driver again - the most expensive thing a pass does. The PF
    /// list keeps a pass over different pairs from inheriting answers that
    /// were never about them.
    carried_vf: Option<CarriedVf>,
    /// Whether the carried answer can still be believed. Set by whoever
    /// notices an interface with VFs changing, cleared in the one place a
    /// fresh answer is read - one flag for the pass and the fast path, or a
    /// batch between the change and the pass builds its exclusions from the
    /// old list.
    pub vf_stale: bool,
    /// How long a device must be absent from the pair list before its note
    /// counts as an orphan. Zero for one-shot commands; the daemon sets it to
    /// outlive an interface reload.
    pub orphan_grace: Duration,
    /// When each noted device was first seen to be missing.
    absent_since: Map<String, Instant>,
    /// Whether an unlistable state directory has been said out loud. Once:
    /// the list is asked for on every batch, and the condition does not
    /// come and go.
    dir_list_warned: std::cell::Cell<bool>,
    /// Whether the state directory has been looked at this run: the one in
    /// /run outlives the process, and an older build or a wide umask may have
    /// left it open, so the mode is checked once, on the first write.
    dir_checked: std::cell::Cell<bool>,
    /// The notes as last read, so re-reading costs a stat. Used only while
    /// inode, size and timestamp all match: a --flush replaces the file
    /// through rename (new inode), any other writer changes the timestamp.
    notes: std::cell::RefCell<Map<String, Note>>,
    /// The interface index last recorded beside each note, so the record
    /// is written when the answer changes rather than once per pass.
    indices: std::cell::RefCell<Map<String, u32>>,
    /// Which addresses the last pass saw on the wire, per uplink: the fast
    /// path has no dump, and an address on the wire in one VLAN and behind
    /// the bridge in another must not flap in and out on every learn.
    carried_wire: Map<String, Set<Mac>>,
    /// The bridge port each owned address was last learnt behind, per uplink,
    /// with when the bridge was last seen holding it (milliseconds since
    /// boot).
    ///
    /// What it buys: a guest that goes quiet outlives the bridge's ageing as
    /// long as its port does - the kernel deletes a veth or tap with its
    /// endpoint. A router that caches ARP longer than the bridge ages
    /// (FreeBSD holds 1200 s against the bridge's 300) keeps sending unicast
    /// without asking again, and without this those frames went out on the
    /// wire.
    ///
    /// Written down beside the note because a restarting daemon is mostly one
    /// being updated, and forgetting the keeps would unregister every quiet
    /// guest on the next pass. Same tmpfs as the notes, so a reboot starts
    /// from nothing
    /// - as it must, the card is empty too.
    ///
    /// Every pass and every learn refresh the stamp, so "quiet" needs no
    /// guessed window: a stamp older than the last pass means the last pass
    /// did not see the address. The stamp also orders the valve's evictions,
    /// which is why it records when the guest last SPOKE, not when we noticed
    /// the silence.
    carried_ports: Map<String, Map<Mac, (u32, u64)>>,
    /// Uplinks whose written-down memory has been read this run: the file is
    /// believed once, at the first pass that needs it; after that this
    /// process's map is ahead of it.
    ports_loaded: Set<String>,
    /// What was last written to each uplink's memory file, so an idle pass
    /// writes nothing at all.
    ports_written: Map<String, Vec<String>>,
    /// Everything said once per device - see `Said`.
    pub(super) said: std::cell::RefCell<Said>,
    /// The filter capacity the quiet-keep must respect, for any card that
    /// did not report a number: past it the card drops entries silently, so
    /// keeps are the first surrendered as the list nears the limit.
    pub max_macs: usize,
    /// Which interface holds the filter an uplink writes into, filled by each
    /// pass from the picture: the event path has no topology, and a burst on
    /// a VLAN uplink measures against the card below.
    karte_von: Map<String, String>,
    /// What single cards reported, by the interface holding the filter. Two
    /// cards in one host can differ, and taking the smaller number for both
    /// sheds keeps on the larger for nothing. Empty until devlink answers -
    /// never on ixgbe, i40e and mlx4.
    pub max_macs_je_karte: Map<String, usize>,
    /// Set by the event path when a learn named a port or a bridge the
    /// picture does not know: the picture is old, and the daemon reads it
    /// afresh before the next pass. A Cell because fast_add works on &self.
    pub disputed: std::cell::Cell<bool>,
    /// Whether the last capacity question reached every configured device
    /// and got an answer - read by the daemon to stop asking.
    pub capacity_settled: bool,
    /// What the last pass measured about each uplink's filter, carried so the
    /// event path is capacity-aware without a dump per batch; corrected
    /// against the read-back every pass.
    carried: Map<String, Carried>,
    /// The stamp the last pass wrote. Two passes must never share one -
    /// "quiet" means "stamped before the last pass" - and milliseconds cannot
    /// promise it on a busy daemon, so the stamp is nudged past its
    /// predecessor: at most a millisecond of drift, gone once real time
    /// catches up.
    last_pass_at: u64,
}

/// Where a pass spent its time, and what it found. Filled every pass (six
/// clock reads and a few counters), reported only when asked.
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

/// Could a link message about this interface have changed a VF's address?
/// `None` when this picture does not know the interface.
///
/// Asking the driver is the most expensive thing a pass does, and the answer
/// changes only when somebody sets a VF's address - not when a container's
/// veth appears, which is what link messages mostly are.
pub fn touches_virtual_functions(topo: &Topology, index: u32) -> Option<bool> {
    topo.at(index)
        .map(|link| link.numvfs > 0 || link.physfn.is_some())
}

/// The same question for a batch, against the old and the new picture. Both:
/// an interface that has just gone is not in the new picture, and judging by
/// that alone made every deletion a reason to ask. An interface neither
/// picture knows is a reason to ask.
pub fn vf_may_have_changed(
    before: Option<&Topology>,
    after: Option<&Topology>,
    changed: &[u32],
) -> bool {
    changed.iter().any(|i| {
        // Either picture saying yes is a yes: a PF whose numvfs went 0 -> N
        // inside this batch is invisible to the old picture, and letting the
        // old answer win slipped exactly that past the exclusions.
        let b = before.and_then(|t| touches_virtual_functions(t, *i));
        let a = after.and_then(|t| touches_virtual_functions(t, *i));
        match (b, a) {
            (None, None) => true,
            _ => b.unwrap_or(false) || a.unwrap_or(false),
        }
    })
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
            dir_checked: std::cell::Cell::new(false),
            dir_list_warned: std::cell::Cell::new(false),
            carried_wire: crate::hash::map(),
            carried_ports: crate::hash::map(),
            ports_loaded: crate::hash::set(),
            ports_written: crate::hash::map(),
            said: std::cell::RefCell::new(Said::default()),
            max_macs: DEFAULT_MAX_MACS,
            karte_von: crate::hash::map(),
            max_macs_je_karte: crate::hash::map(),
            capacity_settled: false,
            disputed: std::cell::Cell::new(false),
            last_pass_at: 0,
            carried: crate::hash::map(),
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

    /// Devices with a note that are no longer uplinks, and have not been for
    /// long enough to believe it.
    ///
    /// The grace period is the point: `ifreload -a` takes a Proxmox bridge
    /// away for a moment, and without it every registered address would be
    /// deleted from a live uplink within 200 ms of a routine reload. Zero
    /// grace is the one-shot behaviour (--once, --flush): now, with no
    /// earlier reading to compare against.
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
            // A name gone while its interface lives on is a rename: the
            // filter entries survived under the new name, and reading it as
            // "gone" would unlink the note and leave every entry owned by
            // nobody. Identity is the recorded index, which a boot never
            // re-uses; two interfaces swapping names in one breath is the
            // residual case.
            if topo.get(&dev).is_none() {
                if let Some((index, new_name)) = self.renamed_target(&dev, topo) {
                    if !apply || self.dry_run {
                        note!("{dev}: now called {new_name}; its note would follow");
                    } else {
                        // Read the old name's memory BEFORE the note moves:
                        // `migrate_note` unlinks the old note with its
                        // `.ports` file, and a fresh process has nothing in
                        // RAM to move instead (`load_ports` only runs for a
                        // name that is still a pair). Without this a rename
                        // while the daemon was stopped - the usual kind -
                        // lost the keeps. The lines land in `carried_ports`
                        // under the old name and move below.
                        self.load_ports(&dev, topo, false);
                        let moved = self.migrate_note(&dev, &new_name, index);
                        if moved {
                            note!("{dev}: now called {new_name}, its note follows the interface");
                            // Deliberately field by field, not a struct move.
                            // Three reviews proposed one UplinkState so a
                            // rename becomes remove+insert, refuted each
                            // time: these collections carry three lifecycles
                            // (file caches follow the note, absent_since
                            // measures the missing, the rest is uplink state)
                            // and several must NOT move uniformly -
                            // ports_written is discarded for both names,
                            // ports_loaded only set when the memory really
                            // migrated. A struct move would turn "forgot to
                            // move one" (cold start, benign) into "moved one
                            // that must not" (stale state under the new
                            // name). Each line below is a policy. The port
                            // memory follows the note, or a rename would
                            // forget exactly the quiet guests.
                            if let Some(ports) = self.carried_ports.remove(&dev) {
                                self.carried_ports.insert(new_name.clone(), ports);
                                // And the new name counts as read, or the
                                // fast path stops stamping a map it owns
                                // while the valve judges it. Inside this
                                // block on purpose: marking a name whose
                                // memory was NOT migrated would suppress the
                                // real read.
                                self.ports_loaded.insert(new_name.clone());
                            }
                            // The written-down copy went with the old note;
                            // the new name has nothing on file yet, so the
                            // next pass puts the carried map down under it.
                            self.ports_loaded.remove(&dev);
                            self.ports_written.remove(&dev);
                            self.ports_written.remove(&new_name);
                            // Every said-once mark in one call - see Said.
                            self.said.borrow_mut().rename(&dev, &new_name);
                            // The wire set follows for the same reason: the fast
                            // path would otherwise judge the renamed uplink
                            // against an empty set - or the old name's set
                            // against whoever inherits it.
                            if let Some(wire) = self.carried_wire.remove(&dev) {
                                self.carried_wire.insert(new_name.clone(), wire);
                            }
                            // The capacity arithmetic follows too - moot when
                            // the migrating pass also reconciles the new
                            // name, not when it skips the pair while the
                            // event path keeps registering for it.
                            if let Some(c) = self.carried.remove(&dev) {
                                self.carried.insert(new_name.clone(), c);
                            }
                            // The say-once marks follow too, or a rename
                            // repeats both warnings for a device that did not
                            // change. Onto disk under the new name at once:
                            // the old file went with the old note, and a
                            // crash before the next pass would forget the
                            // keeps just carried over. The pass stamp like
                            // every other caller: a fresh clock reading is
                            // later than every stamp, so the memo would
                            // record each line as quiet and the next pass
                            // rewrite the file for nothing.
                            self.save_ports(&new_name, topo, self.last_pass_at);
                        }
                    }
                    // Worked, or waits (an unreadable or unwritable note,
                    // said where it happened, looked at again next sweep).
                    // Either way nothing to unregister: the device lives.
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
                    // Empty because it says so, or because it could not be
                    // read? Only the first may be unlinked: removing an
                    // unreadable note abandons every entry it names in the
                    // card - the orphan the notes exist to prevent.
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
            // The port memory of a device that stopped being an uplink is
            // over; one that returns records afresh. The said-once mark goes
            // with it, so a return also announces afresh.
            self.carried_ports.remove(&dev);
            self.said.borrow_mut().forget(&dev);
            // Neither a month-old wire set nor a stale capacity warning
            // greets a device that returns.
            self.carried_wire.remove(&dev);
            self.carried.remove(&dev);
            // remove_note took the file; a device that returns as a pair
            // reads afresh rather than believing this run's leftovers.
            self.ports_loaded.remove(&dev);
            self.ports_written.remove(&dev);
            // The remaining say-once marks go by the same rule: a return
            // announces afresh. Named here so the next field added to the
            // Syncer finds the complete list in one place.
        }
    }

    /// Where a noted device's interface lives now, when the name is gone but
    /// the recorded index is not (the rename case). `None` for a note without
    /// index or an interface really gone - the caller's old answer stands.
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

    /// The addresses that must never be registered for `pair`, wherever
    /// learnt: the operator's exclusions, everything stacked on the wire
    /// side, the uplink's and its PFs' own addresses, the sister VFs'
    /// administrative addresses, and those of VFs bound on the host.
    ///
    /// One function for the pass and the fast path alike (invariant 2): a
    /// second spelling once lacked all of it and registered a guest VF's own
    /// address, sending its traffic past it.
    fn exclusions(&self, topo: &Topology, anat: &Anatomy, vf_macs: &[(u32, Mac)]) -> Set<Mac> {
        let mut skip: Set<Mac> = crate::hash::set();
        skip.extend(self.exclude.iter().copied());
        skip.extend(topo.subtree_macs(anat.port));
        if let Some(l) = topo.at(anat.dev) {
            if let Some(mac) = l.mac {
                skip.insert(mac);
            }
        }
        // The driver-reported VF addresses come through vf_reported, the one
        // spelling: the fast path's stale-answer logic DEPENDS on vf_own
        // being a subset of skip - subset by construction, not by two copies
        // agreeing.
        skip.extend(Self::vf_reported(&anat.functions, vf_macs));
        for pf in &anat.functions {
            if let Some(pf_link) = topo.at(*pf) {
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
    /// noted BEFORE it is written, forgotten after it is taken out. A check
    /// killed between the two then leaves an entry the next pass heals, not a
    /// foreign entry nothing touches until reboot. A pass racing a live check
    /// can take the probe out early and fail it with "accepted but not
    /// listed" - a re-run, not a harm. A probe the note could not take must
    /// not be written at all.
    pub fn note_check_probe(&self, dev: &str, index: u32, mac: &Mac) -> bool {
        self.note_index(dev, index);
        self.append_owned(dev, &[*mac])
    }

    pub fn forget_check_probe(&self, dev: &str, mac: &Mac) {
        if !self.load_owned(dev).contains(mac) {
            return;
        }
        // Under the lock and against the file, so a parallel writer's lines
        // survive. One line out, the rest byte for byte: a whole-set write
        // would sort the note, a trace where the point was to leave none.
        // When the probe was the only line, note and index go with it - an
        // empty leftover would read as a managed device to --flush.
        self.locked(dev, || self.drop_line_locked(dev, mac));
    }

    /// Say so when a VF's address cannot be known.
    ///
    /// The exclusion set recognises a VF by an address set from the host (`ip
    /// link set <pf> vf N mac ...`) or by a netdev still bound here. A
    /// function handed to a guest with neither is in no exclusion set, and
    /// invariant 2 then rests on the wire rule alone: should the bridge ever
    /// learn that address on another port, the guest's own address gets
    /// registered and its traffic sent past it. Not fixable here, so the
    /// operator is told once, with the two ways to close it.
    fn warn_about_unknowable_vfs(&mut self, topo: &Topology, dev: &str, vf_macs: &[(u32, Mac)]) {
        let Some(pfs) = topo
            .index_of(dev)
            .map(|d| topo.physical_functions(topo.filter_carrier(d)))
        else {
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
            // Nothing unknowable right now, including no functions at all:
            // the mark comes off, so a situation that arises later or again
            // warns again - "once" is per situation, not per process.
            self.said.borrow_mut().unknown_vf.remove(dev);
            return;
        }
        if self.said.borrow_mut().unknown_vf.insert(dev.to_string()) {
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

    /// Take the previous process's quiet memory, once per uplink per run.
    ///
    /// A daemon restarts mostly to be updated, and forgetting the keeps would
    /// unregister every quiet guest on the first pass. Believed only where it
    /// still describes this kernel: a line counts when its port still exists
    /// AND still carries the recorded index; a replaced or moved interface
    /// loses its memory rather than inheriting somebody else's. Read once:
    /// afterwards the running map is ahead of the file.
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
        // Stamps from the future are shifted back, as one. Not from a reboot
        // (the tmpfs dies with the clock) but from the pass stamp's own lead
        // - `max(clock, previous + 1)` - read back by a process restarted in
        // the same boot. Left standing, such a stamp is never quiet and holds
        // its slot until the address leaves the bridge. Shifted, not clamped:
        // clamping maps every stamp ahead of now onto one instant and loses
        // the order between them, which is the whole content of this file.
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
        // Said by the process that manages the card - a --status or dry run
        // beside the daemon takes nothing over. The total only: quietness is
        // a comparison against the pass that wrote the stamps, which the file
        // does not contain; judged against its own newest stamp it gave
        // `count(t < max(t))`, at most N-1 for any input. This pass says how
        // many it kept quiet.
        if apply && !self.dry_run {
            note!(
                "{dev}: took over the last run's memory of {} address(es)",
                ports.len()
            );
        }
        // Seeded in the vocabulary `save_ports` compares against - quiet-flag
        // keys, not raw lines - or the memo never hits after a takeover and
        // the first save of every restart rewrites a file that already said
        // the right thing.
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
    /// Under the note's lock: --once and --flush run by hand beside the
    /// daemon. An idle pass writes nothing - the lines are compared against
    /// what was last put there.
    fn save_ports(&mut self, dev: &str, topo: &Topology, pass_at: u64) {
        // A dry run changes nothing on disk: the memory stays in RAM for an
        // honest report, the file belongs to whoever manages the card.
        // (--status never reaches this: every caller is behind an `apply`
        // gate.)
        if self.dry_run {
            return;
        }
        // Nothing in the map means either nothing to remember or nobody has
        // looked at the file yet: `load_ports` runs in the pass's pair loop
        // behind fail-closed `continue`s, while the reflection path reaches
        // here from a batch. Told apart by the mark `load_ports` sets before
        // it reads - otherwise the empty branch unlinks the previous
        // process's memory unread, and the next pass unregisters every guest
        // that went quiet across the restart. The learn path carries the same
        // guard.
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
                            // What a rewrite is FOR, without the stamp: which
                            // addresses, behind which port, quiet or not.
                            // Stamps move every pass - comparing them would
                            // rewrite this file five times a second on a busy
                            // host.
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
        // The memo is only as good as the file: a --flush from a second
        // terminal unlinks it, and believing the memo then freezes this
        // uplink's memory for the life of the process. One stat says whether
        // the file is still the shape the memo claims. Nothing to remember is
        // no file. Look and write are one locked stretch: asking outside it
        // meant a --flush between the two decided against a file that no
        // longer existed.
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

    /// Record an observation about an owned address: where the bridge holds
    /// it, and when it was last heard from.
    ///
    /// The one place a stamp is written, and it only moves forward: an older
    /// observation is not evidence against a newer one, whatever the source -
    /// a pass stamp nudged past its predecessor can sit ahead of the clock a
    /// learn reads moments later, and a deletion's date is deliberately older
    /// than now. A stamp that went backwards would make a live guest the
    /// valve's first victim.
    ///
    /// `port` is what the observation knows: pass and learn name one, a
    /// deletion refines only the moment. An address nothing knows a port for
    /// is not recorded - the keep rests on the port.
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

    /// Put a date on a silence the bridge has just announced: a deletion
    /// arriving now says the guest last spoke one ageing time ago, where the
    /// stamp otherwise holds only "the last pass still saw it". That orders
    /// the valve more honestly.
    ///
    /// Never backwards: a vlan-aware bridge ages per VLAN, and a deletion can
    /// arrive for an address that spoke in another VLAN a moment ago.
    ///
    /// Not every deletion is an ageing - a flush, a port down and a hand-run
    /// `bridge fdb del` look the same - so this is an estimate. Taken only
    /// when it moves the stamp forward, a wrong one can only make an address
    /// look younger and be surrendered later; it can never cost a live guest
    /// its entry.
    fn date_the_silence(&mut self, topo: &Topology, events: &[(u16, FdbEntry)]) {
        let now = Self::boot_millis();
        // Bridge indices are batch-constant; the reachability is NOT
        // (`master` varies per event, a batch carries deletions from several
        // bridges), so it is memoised per deleting bridge rather than hoisted
        // whole - hoisting would date across bridges again. Measured: 0.42 ms
        // -> 0.007 ms at 60 ports and two pairs.
        let pair_bridges: Vec<(usize, u32)> = self
            .pairs
            .iter()
            .enumerate()
            .filter_map(|(i, p)| topo.index_of(&p.bridge).map(|b| (i, b)))
            .collect();
        let mut serves: Map<u32, Vec<usize>> = crate::hash::map();
        for (kind, entry) in events {
            if *kind != crate::netlink::RTM_DELNEIGH {
                continue;
            }
            // The bridge that forgot it decides the interval; a stacked vnet
            // may age differently from the uplink's bridge. This also keeps
            // our own filter entries out: a `self` entry names no master and
            // is stepped over.
            let Some(master) = entry.master else {
                continue;
            };
            let Some(ageing) = topo.at(master).and_then(|l| l.ageing_ms) else {
                continue;
            };
            let spoke = now.saturating_sub(ageing);
            // Only the uplinks this bridge serves: one bridge's ageing time
            // must not date another's keeps (a dual-homed guest would drag an
            // hour-old entry forward to five minutes, and the valve then
            // surrenders a genuinely quieter guest).
            let served = serves.entry(master).or_insert_with(|| {
                pair_bridges
                    .iter()
                    .filter(|&&(_, b)| topo.leads_to(master, b))
                    .map(|&(i, _)| i)
                    .collect()
            });
            for &i in served.iter() {
                let dev = &self.pairs[i].dev;
                if let Some(ports) = self.carried_ports.get_mut(dev) {
                    Self::note_seen(ports, entry.mac, None, spoke);
                }
            }
        }
    }

    /// How long each has been silent, in milliseconds - the valve orders by
    /// it and --status shows it. An address never seen learnt counts as
    /// silent since boot.
    fn silence_of(&self, dev: &str, macs: &Set<Mac>, now: u64) -> Vec<(u64, Mac)> {
        // `now` is the pass's own stamp, not a fresh clock reading, so the
        // valve's ordering and --status describe the same instant, and the
        // clamp below cannot be handed a moment the stamps were never judged
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
    /// All three removal paths - stale loop, reflection, shedder - reach this
    /// state: entries out of the card, the note still naming them. A
    /// whole-set write would lose a line a parallel writer appended during
    /// the rtnl wait, leaving its entry in the card with nothing on record.
    /// Caller holds the lock.
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

    /// Register a batch note-first, under the note's lock - the one spelling
    /// of the ordering the pass and the event path share.
    ///
    /// Note first: written the other way round, a crash between the two
    /// leaves an entry in the card that no note names - foreign from the next
    /// start on, and never touched. This way round it leaves a note naming an
    /// absent entry, which heals: the add is retried while the address is
    /// wanted, the removal's ENOENT settles the note once it is not. A note
    /// that cannot be written keeps the card untouched.
    ///
    /// Under the lock because --flush reads, unregisters and unlinks under
    /// it: an intent appended outside would land owned by nobody.
    ///
    /// Returns what really went into the card and what went wrong. `None`
    /// means the note refused the batch and the card was not touched.
    ///
    /// On the `_locked` suffix: this one TAKES the lock, `forget_locked`
    /// expects the caller to hold it - the suffix marks involvement with the
    /// lock, not which side of it you are on.
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
                    // The dump a moment ago said absent, so somebody else - a
                    // --once in a second terminal - put it there in between.
                    // Claiming it would mean deleting their entry later, so
                    // this call's intent comes back out; a line that predates
                    // it was ours all along.
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
                    // crash posture. Kept on record on purpose - the retry
                    // and the ENOENT settling depend on it.
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

    /// How full the fullest uplink's filter is, as the last pass measured it
    /// against the card. The limit applies per card, so the fullest list
    /// counts, not the total - and foreign entries take real slots, which
    /// counting the notes missed.
    /// The capacity of the card this uplink writes into: what it reported, or
    /// the assumed number where it reported nothing (ixgbe, i40e and mlx4:
    /// every card there is).
    pub fn limit_of(&self, dev: &str) -> usize {
        let karte = self.karte_von.get(dev).map(String::as_str).unwrap_or(dev);
        self.max_macs_je_karte
            .get(karte)
            .copied()
            .unwrap_or(self.max_macs)
    }

    pub fn fullest_filter(&self) -> usize {
        self.carried
            .values()
            .map(|c| c.present.len())
            .max()
            .unwrap_or(0)
    }

    /// The card is now known to hold these. Idempotent. Only ever called with
    /// what the card really took or really had - an address a hard error left
    /// out must not count as present, or the grow-gate skips the fresh driver
    /// question (invariant 2).
    fn card_now_holds(&mut self, dev: &str, macs: impl IntoIterator<Item = Mac>) {
        let c = self.carried.entry(dev.to_string()).or_default();
        for mac in macs {
            c.present.insert(mac);
        }
    }

    /// The card no longer holds these - taken out, or never had. Both free
    /// the slot: a slot the count still claims is one the next burst will not
    /// use, and the valve would shed one guest per burst while the card never
    /// gets emptier. Surrendered is no longer kept either, or a second batch
    /// counts the room twice.
    fn card_no_longer_holds(&mut self, dev: &str, macs: &[Mac]) {
        let Some(c) = self.carried.get_mut(dev) else {
            return;
        };
        for mac in macs {
            c.present.remove(mac);
            c.quiet.remove(mac);
        }
    }

    /// Surrender up to `need` kept addresses, longest-silent first - card,
    /// note and memory together, under the note's lock. The fast path's arm
    /// of the valve: a burst that would overflow the card cannot wait for a
    /// pass, because past its limit the card drops arbitrarily. Returns how
    /// many slots were really freed.
    fn shed_keeps(
        &mut self,
        sock: &mut dyn FdbWriter,
        dev: &str,
        index: u32,
        need: usize,
        topo: &Topology,
    ) -> usize {
        // An unreadable note is a device to leave alone, as on every removal
        // path. Asked by reading, not by the mark: the mark is set only once
        // a read has failed, and this may be the pass's first read.
        self.load_owned(dev);
        if !self.note_is_readable(dev) {
            return 0;
        }
        // No pass yet, no ground to judge quietness on - and nothing was
        // registered by this process either, so there is nothing to shed.
        let Some(carried) = self.carried.get(dev) else {
            return 0;
        };
        let (passed_at, quiet) = (carried.passed_at, &carried.quiet);
        let Some(ports) = self.carried_ports.get(dev) else {
            return 0;
        };
        // The pass's own keeps and nothing else, so both valves reach the
        // same addresses. Plus the freshness test: a stamp older than the
        // last pass means still quiet; a learn since then has stamped it out
        // of reach - which is why an address this batch registers can never
        // be its own victim.
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
        // Counted BEFORE the bookkeeping is told: how many slots this really
        // freed. Candidates come from the note, which deliberately keeps an
        // address whose registration failed - deleting it frees nothing, and
        // reporting it freed let the caller skip the over-limit warning.
        //
        // Still deleted, all of them: filtering against what the card holds
        // would make an address the card never took unsheddable for ever -
        // re-registered by every pass while the valve surrenders real keeps
        // for a slot nobody occupies.
        let freed = self.carried.get(dev).map_or(0, |c| {
            dropped.iter().filter(|m| c.present.contains(*m)).count()
        });
        self.card_no_longer_holds(dev, &dropped);
        note!(
            "{dev}: filter nearing its {} limit, released {} quiet \
             address(es) [pressure]",
            self.limit_of(dev),
            dropped.len()
        );
        freed
    }

    /// One spelling of "what the filter should hold": the desired set with
    /// the quiet survivors folded in. Asked twice per pass - up front, and
    /// against the fresh driver answer after a grow-refresh. Returns (want,
    /// stacked, wire, learnt_at, kept).
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    fn wanted_with_keeps(
        &self,
        topo: &Topology,
        anat: &Anatomy,
        fdb: &[FdbEntry],
        vf_macs: &[(u32, Mac)],
        owned_before: &Set<Mac>,
    ) -> (Set<Mac>, Vec<String>, Set<Mac>, Map<Mac, u32>, Set<Mac>) {
        let (mut want, stacked, wire, learnt_at) = self.desired(topo, anat, fdb, vf_macs);
        let kept = self.quiet_survivors(topo, anat, &want, &wire, vf_macs, owned_before);
        want.extend(kept.iter().copied());
        (want, stacked, wire, learnt_at, kept)
    }

    /// The owned addresses that aged out of the bridge but should stay: those
    /// whose learn-port still exists and still hangs under this bridge.
    /// Ageing is the bridge managing its table, not news about the device - a
    /// router that caches ARP longer than the bridge ages keeps sending
    /// unicast without asking, and a miss delivers only to the wire. So an
    /// aged address is kept; the limit is filter capacity, and the valve
    /// collects longest-silent first.
    ///
    /// A GONE port keeps nothing: the kernel deletes a veth or tap with its
    /// endpoint. The wire set wins before this runs.
    ///
    /// Pure over its inputs: the grow-refresh recomputes `desired` and asks
    /// twice.
    #[allow(clippy::too_many_arguments)]
    fn quiet_survivors(
        &self,
        topo: &Topology,
        anat: &Anatomy,
        want: &Set<Mac>,
        wire: &Set<Mac>,
        vf_macs: &[(u32, Mac)],
        owned_before: &Set<Mac>,
    ) -> Set<Mac> {
        let mut kept = crate::hash::set();
        let Some(name) = topo.name_of(anat.dev) else {
            return kept;
        };
        let Some(ports) = self.carried_ports.get(name) else {
            return kept;
        };
        if ports.is_empty() {
            return kept;
        }
        // The one canonical exclusion set, asked again rather than re-spelt.
        let skip = self.exclusions(topo, anat, vf_macs);
        // Everything under the uplink port is the wire's side, the port
        // included: a learn-port later re-enslaved beneath the uplink (two
        // NICs folded into a bond uplink) now leads out, and keeping its
        // addresses would steer wire traffic into the bridge.
        let wireward = topo.subtree_of(&[anat.port]);
        let reach = topo.reach(anat.bridge);
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
            // A vanished port keeps nothing: `bridge_above` answers None for
            // an index the topology no longer knows, so the reachability
            // question covers gone and moved alike. Still a port of this
            // bridge, or of a vnet above it - the same edges `Reach` walks.
            let reachable = match topo.bridge_above(p) {
                Some((br, _)) => reach.reaches(br),
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
        anat: &Anatomy,
        fdb: &[FdbEntry],
        vf_macs: &[(u32, Mac)],
    ) -> (Set<Mac>, Vec<String>, Set<Mac>, Map<Mac, u32>) {
        let bridge = anat.bridge;
        let Some(bridge_link) = topo.at(bridge) else {
            return (
                crate::hash::set(),
                Vec::new(),
                crate::hash::set(),
                crate::hash::map(),
            );
        };

        // Which interfaces sit on top of the uplink bridge: one walk up from
        // the bridge instead of asking every interface whether it leads down.
        // A busy host has thousands of forwarding entries, and asking the
        // structural question per entry is what made this daemon show up in
        // `top`.
        let reach = topo.reach(bridge);

        let mut wire: Set<Mac> = crate::hash::set();
        let mut want: Set<Mac> = crate::hash::set();

        // Where each learnt address was seen, alongside what is wanted. The
        // structural entries below (bridge's own, uplink-ward, pinned extras)
        // record no port on purpose: they do not age out of `want`, so the
        // quiet-keep has nothing to remember.
        let mut learnt_at: Map<Mac, u32> = crate::hash::map();
        for e in fdb {
            if !e.is_learned() || !e.is_unicast() {
                continue;
            }
            let Some(master) = e.master else { continue };
            match reach.classify(e.ifindex, master, anat.port) {
                // out on the wire: registering it would divert its traffic
                // to the bridge, which cannot send it back out of the port
                // it arrived on
                Learn::Wire => {
                    wire.insert(e.mac);
                }
                Learn::Behind => {
                    want.insert(e.mac);
                    learnt_at.insert(e.mac, e.ifindex);
                }
                Learn::NotOurs => {}
            }
        }

        // The host's own addresses on this bridge - usually the uplink's own,
        // which drop out again below, but a bridge carrying a different
        // address would leave the host unreachable from the VF.
        if let Some(mac) = bridge_link.mac {
            want.insert(mac);
        }
        for index in topo.stacked_above(bridge) {
            if index == bridge {
                continue;
            }
            if let Some(mac) = topo.at(index).and_then(|l| l.mac) {
                want.insert(mac);
            }
        }

        // Everything the host owns on this side of the uplink, plus what the
        // wire already carries.
        let mut skip: Set<Mac> = self.exclusions(topo, anat, vf_macs);
        skip.extend(wire.iter().copied());

        // Addresses pinned by configuration are registered even when nothing
        // has been heard from them yet - for a device that never speaks first,
        // or to close the gap before a guest's first frame.
        want.extend(self.extra.iter().copied());

        want.retain(|m| !skip.contains(m) && is_registerable(m));

        let mut stacked: Vec<String> = reach
            .stacked_bridges()
            .filter_map(|b| topo.name_of(b).map(str::to_string))
            .collect();
        stacked.sort();
        (want, stacked, wire, learnt_at)
    }

    /// The physical functions behind these uplinks, alive in this reading -
    /// only they contribute exclusions. One function on purpose: invariant
    /// 2's exclusion set is built from exactly this list, and a rule spelled
    /// several times goes stale in one copy (the pf_netdevs-union bug).
    fn live_pfs<'a>(topo: &Topology, devs: impl Iterator<Item = &'a str>) -> Vec<u32> {
        let mut pfs: Vec<u32> = Vec::new();
        for dev in devs {
            let Some(idx) = topo.index_of(dev) else {
                continue;
            };
            // No existence check: every index `physical_functions` returns
            // came out of this very topology. It was there, and it never
            // fired.
            for pf in topo.physical_functions(topo.filter_carrier(idx)) {
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
    fn vf_reported(functions: &[u32], vf_macs: &[(u32, Mac)]) -> Set<Mac> {
        vf_macs
            .iter()
            .filter(|(pf, _)| functions.contains(pf))
            .map(|(_, mac)| *mac)
            .collect()
    }

    /// The carried answer, if it may be used for these very physical
    /// functions
    /// - invariant 2's staleness rule, written once for pass and fast path. A
    ///   pass over a different pair list must not inherit what was never
    ///   about it.
    fn carried_vf_for(&self, pfs: &[u32]) -> Option<Vec<(u32, Mac)>> {
        match (&self.carried_vf, self.vf_stale) {
            (Some((for_pfs, kept)), false) if *for_pfs == pfs => Some(kept.clone()),
            _ => None,
        }
    }

    /// The topology is handed in: the caller needs it for autodetection
    /// anyway, and `topo_load` keeps the report honest about the whole pass.
    ///
    /// Deliberately one function. Three reviews proposed phase methods and
    /// were refuted: the mechanics live in named helpers, what remains is
    /// orchestration whose ORDER is the content, and def-before-use of the
    /// locals is the compiler checking that order - a context struct would
    /// compile disorder. Precedent daemon.rs (8609f1f): types where
    /// invariants outlive an iteration; these locals die inside one.
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

        // No pairs is not nothing to do: notes outlive the last pair (a
        // bridge taken apart leaves its uplink's filter full), and this is
        // the only place that takes those entries back out. The dumps serve
        // the pairs and are skipped.
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
        // Not `unwrap_or_default`: an empty list means we failed to ask, not
        // "no VFs". Carrying on would drop the VFs' own addresses from the
        // exclusions (invariant 2). A failed pass is harmless; a pass on
        // incomplete information is not.
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

        // One reading for the whole pass: the ground every stamp written here
        // is judged against. Strictly after the last pass's, so no two passes
        // share a stamp.
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
            // Fail closed: a bridge missing from this reading makes every
            // wanted address disappear, and the pass would take that for
            // "remove everything". An ifreload is a moment to wait out.
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
            let Some(anat) = topo.anatomy(dev_index, bridge_index) else {
                eprintln!(
                    "warning: {}: not under bridge {} in this reading, leaving the filter alone",
                    pair.dev, pair.bridge
                );
                continue;
            };
            let port = anat.port;
            let port_name = topo.name_of(port).unwrap_or(&pair.dev).to_string();
            // Loaded before the grow-refresh decides: the quiet survivors
            // must be in `want` by then, since a kept address missing from
            // the filter is a growth, and growing on a carried VF answer is
            // the bug class the refresh exists for. The previous run's memory
            // is what makes an update invisible to a quiet guest.
            self.load_ports(&pair.dev, topo, apply);
            let owned_before = self.load_owned(&pair.dev);
            // Readability as of THIS read: a note that turns readable
            // mid-pass makes `note_is_readable` true while `owned` still
            // descends from the could-not-tell empty set, and pruning against
            // that would erase the memory the gate protects.
            let owned_was_readable = self.note_is_readable(&pair.dev);
            let (mut want, mut stacked, mut wire, mut learnt_at, mut kept) =
                self.wanted_with_keeps(topo, &anat, &fdb, &vf_macs, &owned_before);

            let present: Set<Mac> = fdb
                .iter()
                .filter(|e| e.is_self() && e.ifindex == dev_index && e.is_unicast())
                .map(|e| e.mac)
                .collect();

            // Same rule as the fast path: a carried answer decides nothing
            // that grows a filter. Additions reach a pass in real flows - a
            // returner the fast path refused on the carried wire set, a retry
            // after a failed registration - and a VF's address can change
            // without a link message. One fresh question per growth-bearing
            // pass.
            //
            // An address ENTERING the kept state buys the question too, even
            // when the card holds it: the keep re-asserts an address the
            // bridge no longer vouches for, and a guest may have claimed it
            // as its VF's own over the driver mailbox. Asked once per entry
            // into the state: the say-once set is what the last pass kept, so
            // anything kept now and not in it has just gone quiet.
            let newly_quiet = match self.said.borrow().quiet.get(&pair.dev) {
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
                let again = self.wanted_with_keeps(topo, &anat, &fdb, &vf_macs, &owned_before);
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
            let mut said = self.said.borrow_mut();
            let warned = said.extra.entry(pair.dev.clone()).or_default();
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
            drop(said);

            self.carried_wire.insert(pair.dev.clone(), wire);

            // Kept addresses cost slots, and past capacity the card drops
            // silently - so they are surrendered first as the list nears the
            // limit, longest-silent first. A surrendered keep is the old
            // behaviour, never worse.
            //
            // The limit is measured: the pass reads the card's list back
            // anyway, so foreign entries occupy real slots here too. What the
            // pass leaves behind is `want` plus the present entries that are
            // neither wanted nor ours to remove.
            //
            // Asked of the card that holds the filter, not of the uplink:
            // three VLANs of one function are three uplinks but ONE list of
            // slots, and an uplink counting only its own share would let the
            // card overflow.
            let carrier = anat.card;
            let on_card: Set<Mac> = if carrier == dev_index {
                present.clone()
            } else {
                fdb.iter()
                    .filter(|e| e.is_self() && e.ifindex == carrier && e.is_unicast())
                    .map(|e| e.mac)
                    .collect()
            };
            let foreign_extra = on_card
                .iter()
                .filter(|m| !want.contains(*m) && !owned_before.contains(*m))
                .count();
            let mut occupied = want.len() + foreign_extra;
            if let Some(n) = topo.name_of(carrier) {
                if n != pair.dev {
                    self.karte_von.insert(pair.dev.clone(), n.to_string());
                } else {
                    self.karte_von.remove(&pair.dev);
                }
            }
            let limit = self.limit_of(&pair.dev);
            if !kept.is_empty() && occupied + CAPACITY_HEADROOM > limit {
                // Ordered by the RAW stamp, as shed_keeps orders - one
                // spelling for both valves. Not by `silence_of`: that view
                // clamps a stamp ahead of the pass mark to "just now" for
                // display, so two keeps a millisecond apart could tie and the
                // address decide.
                let ports = self.carried_ports.get(&pair.dev);
                let mut order: Vec<(u64, Mac)> = kept
                    .iter()
                    .map(|m| (ports.and_then(|ps| ps.get(m)).map_or(0, |&(_, t)| t), *m))
                    .collect();
                // Smallest stamp = longest since it last spoke; the
                // address is the tiebreak.
                order.sort_unstable();
                let mut shed = 0usize;
                for (_, m) in order {
                    if occupied + CAPACITY_HEADROOM <= limit {
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
                        limit
                    );
                }
            }

            // Said once per entry into the quiet state: ageing comes in
            // bursts, and seventeen thousand identical journal lines a day
            // teach an operator to stop reading.
            let mut marks = self.said.borrow_mut();
            let said = marks.quiet.entry(pair.dev.clone()).or_default();
            let fresh_quiet = kept.iter().filter(|m| !said.contains(*m)).count();
            if apply && fresh_quiet > 0 {
                note!(
                    "{}: {fresh_quiet} address(es) aged out of the bridge but \
                     their ports live on; kept [quiet]",
                    pair.dev
                );
            }
            *said = kept.clone();
            drop(marks);

            let mut owned = owned_before.clone();
            let mut added = 0usize;
            let mut removed = 0usize;
            let mut foreign = 0usize;

            // What the card holds because of this pass's additions - taken,
            // or refused as already there. What a hard error left out is
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
            // delete outside it, a parallel --once with an older dump could
            // re-add the entry between delete and merge, and the merge would
            // take its line off - the permanent orphan. `stale` came from
            // THIS pass's reading, so a line appended meanwhile survives.
            // Outlives the block: what the card really let go decides the
            // next batch's room.
            let mut dropped: Vec<Mac> = Vec::new();
            if apply && !self.dry_run && !stale.is_empty() {
                let mut evict: Vec<Mac> = Vec::new();
                let mut failures: Vec<String> = Vec::new();
                self.locked(&pair.dev, || {
                    for mac in &stale {
                        removed += 1;
                        // Forgetting the note while the entry is still in the
                        // card makes an orphan nothing will ever take out.
                        // Keep the note when the removal fails; the next pass
                        // retries.
                        match sock.set_self_fdb(dev_index, mac, false) {
                            Ok(()) => {
                                owned.remove(mac);
                                dropped.push(*mac);
                            }
                            // Already gone - a driver that cleared its list
                            // on link-down, or a second process's flush.
                            // Warning about it every pass forever trains the
                            // operator to stop reading warnings.
                            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                                owned.remove(mac);
                                dropped.push(*mac);
                            }
                            Err(e) => {
                                // The note stays for the retry, the memory
                                // must not: with its port memory alive the
                                // address would be re-adopted by the quiet
                                // keep once its wire evidence fades, and a
                                // one-off EBUSY would harden into a permanent
                                // keep.
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

            // Only when this pass changed something beyond the locked removal
            // above: the merge takes the lock and reads past the stat cache,
            // which an idle pass need not pay. What this records is the
            // EEXIST un-claims from the addition loop. Failing to record is
            // the safe direction: the note then still names entries out of
            // the card, settled later through ENOENT.
            if apply && owned != owned_before {
                self.save_owned_merged(&pair.dev, &owned_before, &owned);
            }

            // The memory follows the pass, under the note's readability rule:
            // while the note cannot be read, `owned` is the empty
            // could-not-tell set, and pruning against it would erase the
            // uplink's whole memory. Judged by the readability of the read
            // `owned` came from, not by now.
            if owned_was_readable {
                let ports = self.carried_ports.entry(pair.dev.clone()).or_default();
                // Everything this dump found learnt was seen just now; what
                // it did not find keeps its stamp, now older than this pass -
                // which is what makes it quiet.
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
                if occupied > limit {
                    if self.said.borrow_mut().over.insert(pair.dev.clone()) {
                        eprintln!(
                            "warning: {}: {} unicast entries against the {} the \
                             vport list holds - some will be dropped silently, \
                             and not by choice",
                            pair.dev, occupied, limit
                        );
                    }
                } else {
                    self.said.borrow_mut().over.remove(&pair.dev);
                }
                // The tight-fit mark re-arms only once the list is back under
                // the headroom the batch measures against, or the pass would
                // clear it while the batch is still in the band that set it.
                if occupied + CAPACITY_HEADROOM <= limit {
                    self.said.borrow_mut().tight.remove(&pair.dev);
                }
            }
            // What the fast path counts from until the next pass: `want` plus
            // the foreign entries nobody here may touch.
            // What the card holds when this pass is done, observed: the dump,
            // plus the additions that really landed, minus the removals that
            // really took. An address a hard error left out stays absent -
            // the grow-gate must ask the driver afresh when it comes back.
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
                    // A pass that could not read its note refreshed no stamp,
                    // so it must not advance the ground either: every live
                    // guest would read as quiet.
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
                learnt_behind: self
                    .carried_ports
                    .get(&pair.dev)
                    .map(|ports| {
                        ports
                            .iter()
                            .filter(|(m, _)| want.contains(*m))
                            .filter_map(|(m, &(index, _))| {
                                topo.name_of(index).map(|n| (*m, n.to_string()))
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
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

    /// Answer a batch of forwarding notifications before the pass that
    /// follows, or a device that has only just appeared misses the first
    /// reply sent to it.
    ///
    /// One rule read both ways: an address learnt behind the bridge is
    /// registered; one of ours learnt on the uplink's own port has moved to
    /// another host and comes out of the filter at once - until then the
    /// eSwitch hands its traffic to the uplink, where the bridge cannot send
    /// it back out of the port it arrived on.
    ///
    /// `RTM_DELNEIGH` removes nothing: a vlan-aware bridge learns an address
    /// once per VLAN and the filter holds one entry for all of them, so only
    /// a full dump can tell that the last one is gone.
    ///
    /// Notes are read once per device and additions appended in one piece,
    /// note first; per address meant rewriting a growing file for every entry
    /// of a burst.
    /// Returns whether the batch is worth a full pass: a batch that is
    /// entirely somebody else's leaves nothing to reconcile, and a pass dumps
    /// the whole forwarding table - on a busy host the difference between
    /// answering an event and being flattened by it.
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
        // Everything below acts only on RTM_NEWNEIGH: a deletions-only batch
        // has bought its pass above, and in a vf_stale window it would pay a
        // driver question (0.6-0.9 ms on mlx5) for answers nothing reads -
        // ageing bursts right after an interface change are exactly that.
        if !events
            .iter()
            .any(|(kind, _)| *kind == crate::netlink::RTM_NEWNEIGH)
        {
            return Ok(urgency);
        }
        // Where each uplink sits in its bridge and what may never be
        // registered for it are topology - worked out once per batch, from
        // the same rule the pass uses (see `exclusions`). The VFs' addresses
        // come carried where they fit, else asked for now - never assumed
        // empty.
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
                let anat = topo.anatomy(dev, bridge)?;
                let skip = self.exclusions(topo, &anat, &vf_macs);
                let reach = topo.reach(bridge);
                Some(FastPair {
                    reach,
                    dev: p.dev.clone(),
                    index: dev,
                    port: anat.port,
                    skip,
                    reflected: crate::hash::set(),
                    // Only the carried path reads this: it turns a learn of a
                    // VF's own address into a candidate so the fresh question
                    // settles it. On a fresh answer there is nothing to
                    // settle, and the walk per pair would serve nobody.
                    vf_own: if vf_carried {
                        Self::vf_reported(&anat.functions, &vf_macs)
                    } else {
                        crate::hash::set()
                    },
                    anat,
                })
            })
            .collect();

        // What this batch saw arrive on an uplink's own port, per uplink.
        // Read before anything is registered: within one batch the wire has
        // the last word, as in the full pass.
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
            // segment. One look at the note answers for the whole batch; per
            // address would be a stat each, on the path whose point is being
            // cheap when the answer is no.
            if !self.with_owned(&fp.dev, |o| macs.iter().any(|m| o.contains(m))) {
                continue;
            }
            // Card and note under ONE lock, the flush's pattern (see the
            // pass's stale loop): a parallel --once whose dump predates the
            // move could re-add the entry between delete and note write - the
            // permanent orphan. Only what THIS process owned before the
            // window is touched; a line appended meanwhile survives.
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
                    // The port memory goes with the entry - mandatory: should
                    // the note write fail, the address stays on the note, and
                    // a later pass whose dump no longer shows the wire entry
                    // would keep alive the address this reflection took out.
                    // In the Err arm the eviction re-arms the retry: with the
                    // memory alive, a one-off failure would harden into a
                    // permanent keep.
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
                        // Keep the note - an entry in the card nothing owns
                        // is the orphan. And buy a pass: the guest's traffic
                        // is misdirected right now, and a batch of only this
                        // failure would otherwise end quiet and retry
                        // nothing.
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
                // ENOENT as much as Ok: an entry the card says it does not
                // have occupies nothing, and leaving it counted made the next
                // burst measure against a free slot.
                self.card_no_longer_holds(&fp.dev, &dropped);
                // And out of the written-down memory: an eviction only in RAM
                // could come back through the file after a crash once the
                // wire evidence has aged, re-registering the address this
                // reflection took out.
                let passed = self.carried.get(&fp.dev).map_or(0, |c| c.passed_at);
                self.save_ports(&fp.dev, topo, passed);
            }
            // Beyond the batch only what was actually taken out is
            // remembered, so the next batch does not put it back. Remembering
            // every wire address would grow without bound: only a full pass
            // replaces this set, and wire-side learning no longer schedules
            // one.
            if !taken_back.is_empty() {
                self.carried_wire
                    .entry(fp.dev.clone())
                    .or_default()
                    .extend(taken_back);
            }
        }

        // A carried answer decides nothing that grows a filter. A VF's
        // address can change without a link message: a down PF announces
        // nothing (netdev_state_change() is a no-op on a down device, seen on
        // mlx4), and on ixgbe/i40e a GUEST changing its address runs over the
        // driver mailbox without telling rtnetlink - an "up PFs announce"
        // gate stood here once and the kernel source refuted it. So the only
        // moment to catch the change is before an addition: decided first
        // with the carried answer, and only a batch that would register
        // something asks afresh and decides again. Shrinking on stale news is
        // healed by the next pass; growing on it sends a guest's traffic past
        // it for up to the whole interval. Price: one driver question per
        // growing batch - ~0.9 ms on mlx5, ~0.01 ms on Intel and mlx4.
        if vf_carried {
            let mut would: Map<String, Vec<(Mac, u32)>> = crate::hash::map();
            for (kind, entry) in events {
                if *kind != crate::netlink::RTM_NEWNEIGH {
                    continue;
                }
                self.fast_add(topo, entry, &pairs, &mut would, FastPhase::Decide);
            }
            // Ours AND still in the card was vetted by the fresh answer that
            // let it in; re-learning it grows nothing - without this the tail
            // of a burst bought one driver question per re-learn. Owned alone
            // is not enough: a driver that cleared its list on link-down
            // leaves addresses noted but gone, and putting one back IS a
            // growth that must ask, or a VF that meanwhile claimed the
            // address gets it registered past its guest.
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
                // prompt pass, which would otherwise take the very answer
                // this refresh distrusted. remember_vf clears the mark on
                // success.
                self.vf_stale = true;
                // Only the functions of the pairs that would grow are asked
                // (~0.35 ms per function on mlx5). The unasked keep their
                // carried entries, merged back under the full function list,
                // so the carry contract the next pass compares against holds.
                let ask = Self::live_pfs(topo, would.keys().map(String::as_str));
                let mut fresh: Vec<(u32, Mac)> = vf_macs
                    .iter()
                    .filter(|(pf, _)| !ask.contains(pf))
                    .cloned()
                    .collect();
                fresh.extend(sock.vf_macs_of(&ask)?);
                self.remember_vf(pfs.clone(), fresh.clone());
                for fp in &mut pairs {
                    fp.skip = self.exclusions(topo, &fp.anat, &fresh);
                    // fp.vf_own is NOT refreshed: its only reader is the
                    // Decide phase, already run - Commit judges by `skip`,
                    // just rebuilt from the fresh answer. fp.reflected
                    // stands: within this batch the wire keeps the last word.
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

        // What this batch would register, per uplink - decided first, written
        // after: the note takes every address before the card does (see
        // `register_batch_locked`).
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
            // The same address can arrive several times in one burst (once
            // per VLAN on a vlan-aware bridge); note and card want it once.
            // When the ports differ, the last learn wins - events are drained
            // in kernel order.
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
            // fit surrenders keeps first - new learns outrank the quiet. A
            // guest that speaks is stamped now, or one that spoke seconds ago
            // still wears its last silence and the shedder would name it
            // first, deleting what the next line puts back.
            let now = Self::boot_millis();
            // Only once the file has been consulted for this uplink: a map
            // made earlier would look to `load_ports` like memory already
            // carried, and the previous process's keeps would be thrown away
            // unread.
            if self.ports_loaded.contains(&dev) {
                let ports = self.carried_ports.entry(dev.clone()).or_default();
                for mac in &macs {
                    Self::note_seen(ports, *mac, learnt_on.get(mac).copied(), now);
                }
            }
            let allowed = self.limit_of(&dev).saturating_sub(CAPACITY_HEADROOM);
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
                // filter's limit. Said once per stay: past the limit the card
                // drops silently, and an operator who never hears looks for
                // the fault in the guest.
                if self.said.borrow_mut().tight.insert(dev.clone()) {
                    eprintln!(
                        "warning: {dev}: no room for {} new address(es) and no \
                         quiet ones left to release - the list is within {} \
                         of the {} the card holds, and past that it drops \
                         silently",
                        fresh_slots,
                        CAPACITY_HEADROOM,
                        self.limit_of(&dev)
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
            // Only what the card is KNOWN to hold: taken, or refused as
            // already there. An address a hard error left out must not count
            // as present, or the grow-gate skips the fresh driver question
            // (invariant 2). The next pass's read-back corrects drift.
            self.card_now_holds(&dev, held);
        }
        Ok(urgency)
    }

    /// Returns whether this entry was any of our business - a candidate,
    /// refused, or something the pass must look at. An entry concerning no
    /// pair returns false, and a batch of those earns no pass.
    ///
    /// Nothing is written in either phase: candidates land in `registered`
    /// and the caller writes the batch through, note first.
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
        // The learn is a witness: it names a port and the bridge that
        // recorded it, now. A port the picture does not know, or one it
        // knows under another master, says the picture is old.
        match topo.at(entry.ifindex) {
            None => {
                self.disputed.set(true);
                return false;
            }
            Some(l) if l.master != Some(master) => {
                self.disputed.set(true);
            }
            _ => {}
        }
        let mut ours = false;
        for fp in pairs {
            if fp.skip.contains(&entry.mac) {
                // A hit owed only to the carried driver answer may be stale -
                // a VF address freed without a link message. In the decide
                // phase it becomes a candidate so the fresh question settles
                // it; every other refusal stays passless, which keeps the
                // wire-load optimisation standing.
                if phase == FastPhase::Decide && fp.vf_own.contains(&entry.mac) {
                    registered
                        .entry(fp.dev.clone())
                        .or_default()
                        .push((entry.mac, entry.ifindex));
                }
                continue; // excluded, the host's own, or a VF's
            }

            // What the last pass saw on the wire: an address on the wire in
            // one VLAN and behind the bridge in another must not flap into
            // the filter on every learn.
            //
            // Looked up here rather than folded into `skip`: on a busy
            // segment that set holds every address the switch carries, and
            // copying it cost 550 us per batch.
            //
            // The batch counts as ours all the same: only a full pass
            // replaces this set, and a refusal that bought no pass would
            // suppress its own correction
            // - a guest that moved away and came back would stay unregistered
            //   until
            // the timer.
            if self
                .carried_wire
                .get(&fp.dev)
                .is_some_and(|w| w.contains(&entry.mac))
            {
                ours = true;
                continue;
            }
            match fp.reach.classify(entry.ifindex, master, fp.port) {
                Learn::Wire => continue, // on the wire; handled before any of this
                Learn::NotOurs => continue,
                Learn::Behind => {}
            }
            // An inner learn of an address this batch saw on the wire: the
            // wire has the last word, but the batch counts as ours - the
            // kernel's end state may be "behind the bridge" (wire first,
            // inner learn later in the same burst), the same rule as the
            // carried wire set above. The wire learn itself took the port
            // exit, so a wire-only batch stays passless.
            if fp.reflected.contains(&entry.mac) {
                ours = true;
                continue;
            }
            ours = true;
            // With the port it was learnt on: a daemon that dies before the
            // next dump would leave the address on the note with no port, and
            // the restart unregisters it as soon as it falls quiet - the
            // outage the memory exists for.
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
        // A directory that cannot be listed fails the flush outright:
        // "everything comes back out" claimed for notes nobody could
        // enumerate would be the lie an operator acts on.
        for dev in self.noted_devices()? {
            if self.dry_run {
                // The preview must answer as the real flush would: an
                // unreadable note reads as the empty set, and "would remove
                // 0" with exit 0 is the opposite of the refusal the real run
                // gives.
                //
                // Read FIRST, ask the mark second: the mark is set only once
                // a read has failed, and in this fresh process nothing has
                // read yet.
                let owned = self.load_owned(&dev);
                if !self.note_is_readable(&dev) {
                    note!("{dev}: note unreadable, a real flush would fail here");
                    clean = false;
                    continue;
                }
                note!("{dev}: would remove {} address(es)", owned.len());
                continue;
            }
            // Read, unregister and unlink under the note's lock: a daemon
            // appends the moment it registers, and a line appended into this
            // window would be destroyed by the rename or unlink - an entry
            // with no owner on record. The removals wait on rtnl under the
            // lock; that wait is what the append sits out.
            let settled = self.locked(&dev, || {
                let owned = self.load_owned(&dev);
                // The name is how a note is found, the index is what the
                // entries are attached to - and a rename moves only the
                // name. The recorded index reaches the entries anyway.
                let index = topo.get(&dev).map(|l| l.index).or_else(|| {
                    let (index, new_name) = self.renamed_target(&dev, &topo)?;
                    note!("{dev}: now called {new_name}, removing through it");
                    Some(index)
                });
                let (gone, kept) = match index {
                    Some(index) => self.unregister_all(sock, &dev, index, &owned),
                    None => (owned.len(), crate::hash::set()),
                };
                if kept.is_empty() && self.note_is_readable(&dev) {
                    self.remove_note(&dev);
                    note!("{dev}: removed {gone} address(es)");
                    true
                } else {
                    // write_owned, not save_owned: the lock is already held,
                    // and taking it again on a second descriptor would wait
                    // on itself.
                    self.write_owned(&dev, &kept);
                    note!(
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
