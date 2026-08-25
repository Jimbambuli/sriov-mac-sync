//! Deciding which addresses belong in an uplink's unicast filter, and putting
//! them there.

use crate::hash::{Map, Set};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::netlink::{format_mac, FdbEntry, Socket};
use crate::sysfs::Topology;

pub type Mac = [u8; 6];

#[derive(Debug, Clone)]
pub struct Pair {
    pub dev: String,
    pub bridge: String,
}

/// One pair as the fast path needs it: the structural questions answered
/// once for the whole batch, because a batch describes a single moment.
struct FastPair {
    /// kept for the messages a person reads
    dev: String,
    bridge: u32,
    /// the interface of the bridge this uplink is enslaved through
    port: u32,
    /// the uplink's own interface index, which the filter is written to
    index: u32,
    /// addresses that may not be registered for this uplink: the host's own,
    /// the virtual functions', the configured exclusions, and whatever this
    /// batch has just seen out on the wire
    skip: Set<Mac>,
}

/// A note as it was last read, with what it takes to tell whether the file
/// is still the same one, unchanged.
struct Note {
    macs: Set<Mac>,
    ino: u64,
    len: u64,
    mtime: (i64, i64),
    /// When this was read. A file written in the same clock tick as the read
    /// cannot be told from one written before it, so a note whose timestamp
    /// is not strictly older than the moment we read it is never believed.
    read_at: (i64, i64),
}

impl Note {
    /// Is the file still the one this was read from, untouched since?
    fn is_still(&self, meta: &fs::Metadata) -> bool {
        self.ino == meta.ino()
            && self.len == meta.len()
            && self.mtime == (meta.mtime(), meta.mtime_nsec())
            && self.mtime < self.read_at
    }
}

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

pub struct Report {
    pub dev: String,
    pub bridge: String,
    pub port: String,
    pub driver: String,
    pub wanted: Vec<Mac>,
    pub owned: usize,
    pub present: usize,
    pub stacked: Vec<String>,
    pub added: usize,
    pub removed: usize,
    pub foreign: usize,
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
    /// Which addresses the last pass saw out on the wire, per uplink. The
    /// fast path has no forwarding dump to work this out from, and an address
    /// that lives on the wire in one VLAN and behind the bridge in another
    /// must not flap in and out of the filter on every learning event.
    carried_wire: Map<String, Set<Mac>>,
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

/// The physical function behind an uplink, or the uplink itself when it is
/// not a virtual function.
///
/// Both the pass and the exclusion set have to arrive at the same answer: the
/// pass asks the kernel about this interface's virtual functions, and the
/// exclusion set looks the results up by its index. Two spellings of the same
/// rule would silently stop excluding anything.
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
        before
            .and_then(|t| touches_virtual_functions(t, *i))
            .or_else(|| after.and_then(|t| touches_virtual_functions(t, *i)))
            .unwrap_or(true)
    })
}

fn physical_function(topo: &Topology, dev: u32) -> u32 {
    topo.at(dev).and_then(|l| l.physfn).unwrap_or(dev)
}

impl Syncer {
    pub fn new(pairs: Vec<Pair>, state_dir: PathBuf) -> Self {
        Syncer {
            pairs,
            exclude: crate::hash::set(),
            extra: crate::hash::set(),
            dry_run: false,
            authoritative: false,
            state_dir,
            timings: Timings::default(),
            carried_vf: None,
            vf_stale: true,
            orphan_grace: Duration::ZERO,
            absent_since: crate::hash::map(),
            carried_wire: crate::hash::map(),
            warned_extra: crate::hash::map(),
            notes: std::cell::RefCell::new(crate::hash::map()),
        }
    }

    /// Record the driver's answer about the virtual functions, and that it
    /// is current. One function, so the answer and "is it still true" cannot
    /// be set apart from each other.
    fn remember_vf(&mut self, pfs: Vec<u32>, macs: Vec<(u32, Mac)>) {
        self.carried_vf = Some((pfs, macs));
        self.vf_stale = false;
    }

    fn state_path(&self, dev: &str) -> PathBuf {
        self.state_dir.join(format!("{dev}.owned"))
    }

    /// What this daemon put there itself. Kept on disk so a restart does not
    /// have to choose between forgetting its entries and claiming everybody
    /// else's.
    ///
    /// The file is the truth, and it has to be: `--once` and `--flush` write
    /// these same files while the daemon runs, and a daemon working from a
    /// remembered copy would carry on believing it owns entries somebody has
    /// since taken from it - and never clean them up again. That was a real
    /// bug once and is not being reintroduced.
    ///
    /// What is remembered is the file's identity - inode, size, timestamp -
    /// so *checking* the copy costs one stat instead of an open, a read and a
    /// close. Any writer changes at least one of the three: this daemon and
    /// --flush both replace the file through rename, which changes the inode.
    /// A note whose timestamp is not strictly older than the moment it was
    /// read is never believed either, since a write in the same clock tick as
    /// the read cannot be told from one before it.
    fn load_owned(&self, dev: &str) -> Set<Mac> {
        self.with_owned(dev, |s| s.clone())
    }

    /// The note, without copying it. One check of the file, then the answer.
    fn with_owned<R>(&self, dev: &str, f: impl FnOnce(&Set<Mac>) -> R) -> R {
        let usable = match fs::metadata(self.state_path(dev)) {
            Ok(meta) => self
                .notes
                .borrow()
                .get(dev)
                .is_some_and(|note| note.is_still(&meta)),
            Err(_) => false,
        };
        if !usable {
            let set = self.read_owned(dev);
            self.remember(dev, &set);
        }
        match self.notes.borrow().get(dev) {
            Some(note) => f(&note.macs),
            // Nothing on record: no file, or one that could not be read.
            None => f(&crate::hash::set()),
        }
    }

    /// Note what was just read or written, together with what the file looks
    /// like now, so the next read can be a stat.
    fn remember(&self, dev: &str, set: &Set<Mac>) {
        let Ok(meta) = fs::metadata(self.state_path(dev)) else {
            // No file: nothing to recognise later. Forget any older copy
            // rather than keep one that describes a file that is gone.
            self.notes.borrow_mut().remove(dev);
            return;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| (d.as_secs() as i64, d.subsec_nanos() as i64))
            .unwrap_or((0, 0));
        self.notes.borrow_mut().insert(
            dev.to_string(),
            Note {
                macs: set.clone(),
                ino: meta.ino(),
                len: meta.len(),
                mtime: (meta.mtime(), meta.mtime_nsec()),
                read_at: now,
            },
        );
    }

    fn read_owned(&self, dev: &str) -> Set<Mac> {
        let mut set = crate::hash::set();
        match fs::read_to_string(self.state_path(dev)) {
            Ok(text) => {
                for line in text.lines() {
                    match crate::netlink::parse_mac(line.trim()) {
                        Some(mac) => {
                            set.insert(mac);
                        }
                        None if line.trim().is_empty() => {}
                        // A line nobody can read is an entry nobody will ever
                        // take back out of the card. Saying so is all that can
                        // be done, but silence would look like health.
                        None => eprintln!(
                            "warning: {}: unreadable line in the ownership note, \
                             the entry it named is now nobody's: {line}",
                            self.state_path(dev).display()
                        ),
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => eprintln!(
                "warning: cannot read {}: {e} - treating every entry there as foreign",
                self.state_path(dev).display()
            ),
        }
        set
    }

    fn save_owned(&self, dev: &str, set: &Set<Mac>) {
        if self.dry_run {
            return;
        }
        // Most passes change nothing, and rewriting the note every time would
        // be pointless work on a host that is simply idle. The remembered
        // copy answers this without reading the file - and when it cannot be
        // believed, load_owned reads it and the comparison is against what is
        // really there either way.
        if self.load_owned(dev) == *set {
            return;
        }
        let mut lines: Vec<String> = set.iter().map(format_mac).collect();
        lines.sort();
        let text = lines.join("\n") + "\n";
        // A note that cannot be written strands every entry it should have
        // named: the next pass reads nothing and counts them as foreign,
        // forever. That must not happen in silence.
        //
        // Through a temporary file: a note truncated by a crash mid-write
        // would read as "we own nothing" just the same. The name is a hidden
        // prefix, not a suffix - "eth0.new" is a perfectly legal interface
        // name whose own note would otherwise be this file - and it carries
        // the process id, because the daemon is not the only thing that
        // writes these. `--once` and `--flush` are run by hand while it is
        // running; two of them sharing one temporary file means one truncates
        // what the other is writing and then renames it into place, and the
        // note that results is neither's.
        let write = || -> io::Result<()> {
            let tmp = self
                .state_dir
                .join(format!(".{dev}.owned.{}.tmp", std::process::id()));
            if let Err(e) = fs::write(&tmp, &text) {
                // The directory is created by the unit and survives a
                // restart; asking for it on every write was a syscall per
                // write for a thing that is already there.
                if e.kind() != io::ErrorKind::NotFound {
                    return Err(e);
                }
                fs::create_dir_all(&self.state_dir)?;
                fs::write(&tmp, &text)?;
            }
            fs::rename(&tmp, self.state_path(dev)).map_err(|e| {
                let _ = fs::remove_file(&tmp);
                e
            })
        };
        match write() {
            Ok(()) => self.remember(dev, set),
            Err(e) => {
                // The file and the copy have to agree, and neither is now
                // known to hold what was asked for.
                self.notes.borrow_mut().remove(dev);
                eprintln!(
                    "warning: cannot write the ownership note for {dev}: {e} - \
                     what was just registered has no owner on record"
                );
            }
        }
    }

    /// Add addresses to a note without rewriting it.
    ///
    /// The fast path only ever adds, and a note is a list of addresses in no
    /// particular order, so an addition is a line at the end. Rewriting the
    /// whole file instead means formatting and sorting every address it holds,
    /// once per batch - which is once per address learnt. Measured on a host
    /// learning 200 addresses a second: 1878 rewrites of a growing file in ten
    /// seconds, and the sorting was the single largest thing the daemon did.
    ///
    /// The file stops being sorted, which nothing reads it for - it is read
    /// into a set. A full pass rewrites it in order only when the set of
    /// addresses has changed, so an unsorted file can stay unsorted for a
    /// long time; that is fine, and saying so here is better than implying
    /// somebody tidies up afterwards. What matters is that a line, once
    /// written, is in the file before the entry it names is anybody's to
    /// remove.
    fn append_owned(&self, dev: &str, added: &[Mac]) {
        if self.dry_run || added.is_empty() {
            return;
        }
        use std::io::Write;
        // Only what the note does not already name. A line that is already
        // there would never be taken out again: a full pass rewrites the file
        // only when the set of addresses changed, and a duplicate does not
        // change the set - so the file would grow by a line every time an
        // address was registered afresh, for ever.
        let mut set = self.load_owned(dev);
        let fresh: Vec<Mac> = added
            .iter()
            .filter(|m| !set.contains(*m))
            .copied()
            .collect();
        if fresh.is_empty() {
            return;
        }
        let mut text = String::with_capacity(fresh.len() * 18);
        for mac in &fresh {
            text.push_str(&format_mac(mac));
            text.push('\n');
        }
        let path = self.state_path(dev);
        let opened = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .or_else(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    fs::create_dir_all(&self.state_dir)?;
                    fs::OpenOptions::new().create(true).append(true).open(&path)
                } else {
                    Err(e)
                }
            });
        // What the file held when it was read, so that somebody else writing
        // it in between can be told from nothing having happened. A --flush
        // from a second process replaces this file, and appending to what it
        // left is right - but the copy in memory would then describe a file
        // that no longer exists, and its size is how that shows.
        let was = self.notes.borrow().get(dev).map(|n| n.len);
        let wrote = opened.and_then(|mut f| f.write_all(text.as_bytes()));
        match wrote {
            Ok(()) => {
                let expected = was.map(|w| w + text.len() as u64);
                set.extend(fresh);
                self.remember(dev, &set);
                let agrees = match (expected, self.notes.borrow().get(dev)) {
                    (Some(want), Some(now)) => now.len == want,
                    // Nothing was remembered, so there is nothing to check
                    // against; what was just written is all this knows.
                    _ => true,
                };
                if !agrees {
                    // Somebody wrote the file between the read and the
                    // append. What it holds now is not what this thinks, so
                    // stop thinking it - the next read goes to the file.
                    self.notes.borrow_mut().remove(dev);
                }
            }
            Err(e) => {
                self.notes.borrow_mut().remove(dev);
                eprintln!(
                    "warning: cannot add to the ownership note for {dev}: {e} - \
                     what was just registered has no owner on record"
                );
            }
        }
    }

    /// Devices this daemon has a note for. A note outlives the pair it was
    /// made for on purpose: when a bridge is taken apart, what we put in that
    /// device's filter still has to come back out.
    /// How many addresses this daemon currently has on record as its own,
    /// across every device it has a note for. Read from the notes rather than
    /// from memory, for the same reason everything else here is: a --flush
    /// from a second process is a thing that happens.
    pub fn registered(&self) -> usize {
        self.noted_devices()
            .iter()
            .map(|dev| self.load_owned(dev).len())
            .sum()
    }

    fn noted_devices(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(rd) = fs::read_dir(&self.state_dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if let Some(dev) = name.strip_suffix(".owned") {
                    out.push(dev.to_string());
                }
            }
        }
        out.sort();
        out
    }

    /// Take back what was registered for a device that is no longer an uplink.
    /// Left alone, the card goes on steering those addresses to a port that
    /// leads nowhere, and nothing short of a reboot undoes it.
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
        let noted = self.noted_devices();
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
                    eprintln!(
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

    fn drop_orphans(&mut self, sock: &mut dyn FdbWriter, topo: &Topology, apply: bool) {
        for dev in self.orphaned() {
            let owned = self.load_owned(&dev);
            if !apply || self.dry_run {
                if !owned.is_empty() {
                    eprintln!(
                        "{dev}: no longer an uplink, {} address(es) still registered",
                        owned.len()
                    );
                }
                continue;
            }
            if owned.is_empty() {
                let _ = fs::remove_file(self.state_path(&dev));
                continue;
            }
            let (gone, kept) = match topo.get(&dev) {
                Some(link) => self.unregister_all(sock, &dev, link.index, &owned),
                // The device itself is gone, and a unicast filter does not
                // outlive its netdev - the entries died with it. (A device
                // that was merely renamed keeps its entries under the new
                // name, but a note under the old name could never reach them
                // anyway.)
                None => (owned.len(), crate::hash::set()),
            };
            if kept.is_empty() {
                eprintln!("{dev}: no longer an uplink, removed {gone} address(es)");
                let _ = fs::remove_file(self.state_path(&dev));
            } else {
                // What could not be removed is still in the card; forgetting
                // it here is how a registration becomes permanent.
                eprintln!(
                    "{dev}: no longer an uplink, removed {gone} address(es), \
                     {} could not be removed and stay on record",
                    kept.len()
                );
                self.save_owned(&dev, &kept);
            }
        }
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

    /// The addresses that belong in `pair`'s filter list, and the ones that
    /// must stay out of it.
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
        let pf = physical_function(topo, dev);
        if let Some(pf_link) = topo.at(pf) {
            if let Some(mac) = pf_link.mac {
                skip.insert(mac);
            }
            for (ifindex, mac) in vf_macs {
                if *ifindex == pf_link.index {
                    skip.insert(*mac);
                }
            }
            for vf in &pf_link.vf_netdevs {
                if let Some(l) = topo.at(*vf) {
                    if let Some(mac) = l.mac {
                        skip.insert(mac);
                    }
                }
            }
        }
        skip
    }

    fn desired(
        &self,
        topo: &Topology,
        bridge: u32,
        dev: u32,
        port: u32,
        fdb: &[FdbEntry],
        vf_macs: &[(u32, Mac)],
    ) -> (Set<Mac>, Vec<String>, Set<Mac>) {
        let Some(bridge_link) = topo.at(bridge) else {
            return (crate::hash::set(), Vec::new(), crate::hash::set());
        };
        let port_index = port;

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

        for e in fdb {
            if !e.is_learned() || !e.is_unicast() {
                continue;
            }
            let Some(master) = e.master else { continue };
            if master == bridge_link.index {
                if e.ifindex == port_index {
                    // out on the wire: registering it would divert its traffic
                    // to the bridge, which cannot send it back out of the port
                    // it arrived on
                    wire.insert(e.mac);
                } else {
                    want.insert(e.mac);
                }
            } else if relevant.contains_key(&master) && !uplink_ward.contains(&e.ifindex) {
                want.insert(e.mac);
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
        (want, stacked, wire)
    }

    /// Bring the filter in line with the bridge.
    ///
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
            self.drop_orphans(sock, topo, apply);
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
        // Only each pair's physical function contributes exclusions, so ask
        // about those. A dump would describe every interface on the host to
        // reach them.
        let mut pfs: Vec<u32> = Vec::new();
        for pair in &self.pairs {
            let Some(dev) = topo.index_of(&pair.dev) else {
                continue;
            };
            let pf = physical_function(topo, dev);
            if topo.at(pf).is_some() && !pfs.contains(&pf) {
                pfs.push(pf);
            }
        }
        // Carried answers count only when they were collected for these very
        // physical functions - a pass over a different pair list must not
        // inherit what was never about it.
        let vf_macs = match (&self.carried_vf, self.vf_stale) {
            (Some((for_pfs, kept)), false) if *for_pfs == pfs => {
                timings.vf_carried = true;
                kept.clone()
            }
            _ => {
                let mark = Instant::now();
                let fresh = sock.vf_macs_of(&pfs)?;
                timings.vf_macs = mark.elapsed();
                self.remember_vf(pfs.clone(), fresh.clone());
                fresh
            }
        };
        timings.vf_addresses = vf_macs.len();

        let mut reports = Vec::new();
        let mark = Instant::now();
        self.drop_orphans(sock, topo, apply);
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
            if topo.get(&pair.bridge).is_none() {
                eprintln!(
                    "warning: {}: bridge {} not found, leaving the filter alone",
                    pair.dev, pair.bridge
                );
                continue;
            }
            let dev_index = dev_link.index;
            let driver = dev_link.driver.clone().unwrap_or_default();
            let bridge_index = match topo.index_of(&pair.bridge) {
                Some(i) => i,
                None => continue,
            };
            let port = topo.uplink_port(dev_index, bridge_index);
            let port_name = topo.name_of(port).unwrap_or(&pair.dev).to_string();
            let (want, stacked, wire) =
                self.desired(topo, bridge_index, dev_index, port, &fdb, &vf_macs);

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

            let present: Set<Mac> = fdb
                .iter()
                .filter(|e| e.is_self() && e.ifindex == dev_index && e.is_unicast())
                .map(|e| e.mac)
                .collect();

            let mut owned = self.load_owned(&pair.dev);
            let mut added = 0usize;
            let mut removed = 0usize;
            let mut foreign = 0usize;

            for mac in &want {
                if present.contains(mac) {
                    if !owned.contains(mac) {
                        foreign += 1;
                    }
                    continue;
                }
                added += 1;
                if apply && !self.dry_run {
                    match sock.set_self_fdb(dev_index, mac, true) {
                        Ok(()) => {
                            owned.insert(*mac);
                        }
                        // The dump a moment ago said it was absent, so
                        // somebody else put it there in between. Claiming it
                        // would mean deleting somebody else's entry later -
                        // the same call as --once from a second terminal is
                        // somebody else. The next pass counts it as foreign.
                        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                            added -= 1;
                        }
                        Err(e) => {
                            eprintln!(
                                "warning: {}: cannot register {}: {e}",
                                pair.dev,
                                format_mac(mac)
                            );
                            timings.failures.push(format!(
                                "{}: register {}: {e}",
                                pair.dev,
                                format_mac(mac)
                            ));
                            added -= 1;
                        }
                    }
                }
            }

            let stale: Vec<Mac> = owned
                .iter()
                .filter(|m| !want.contains(*m))
                .copied()
                .collect();
            for mac in stale {
                removed += 1;
                if apply && !self.dry_run {
                    // Forgetting the note while the entry is still in the card
                    // is how a registration turns into an orphan: nothing owns
                    // it any more, so nothing will ever take it out. Keep the
                    // note when the removal fails and let the next pass retry.
                    match sock.set_self_fdb(dev_index, &mac, false) {
                        Ok(()) => {
                            owned.remove(&mac);
                        }
                        // Already gone - a driver that cleared its list on
                        // link-down, or a flush from a second process. The
                        // point was for it not to be there, and warning about
                        // it on every pass forever is how a daemon trains its
                        // operator to stop reading warnings.
                        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                            owned.remove(&mac);
                        }
                        Err(e) => {
                            eprintln!(
                                "warning: {}: cannot unregister {}: {e}",
                                pair.dev,
                                format_mac(&mac)
                            );
                            timings.failures.push(format!(
                                "{}: unregister {}: {e}",
                                pair.dev,
                                format_mac(&mac)
                            ));
                            removed -= 1;
                        }
                    }
                }
            }

            if apply {
                self.save_owned(&pair.dev, &owned);
            }

            // Unsorted on purpose: outside --status only its length is read,
            // and the status page sorts for display itself.
            let wanted: Vec<Mac> = want.into_iter().collect();
            reports.push(Report {
                dev: pair.dev.clone(),
                bridge: pair.bridge.clone(),
                port: port_name,
                driver,
                owned: owned.len(),
                present: present.len(),
                wanted,
                stacked,
                added,
                removed,
                foreign,
            });
        }
        timings.pairs = mark.elapsed();
        timings.added = reports.iter().map(|r| r.added).sum();
        timings.removed = reports.iter().map(|r| r.removed).sum();
        // The caller's reading of /sys belongs to this pass even though it
        // happened before the clock below started.
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
    /// The ownership notes are read once per device and written once at the
    /// end. Doing it per address meant rewriting a growing file for every
    /// entry of a burst - work that squares with the size of the burst, which
    /// is exactly when there is least of it to spare.
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
        // A deletion is not acted on here, but it is a reason to look: it may
        // have been the last copy of an address that is now to come out, and
        // only a full dump can tell. It is never a reason to hurry - an
        // ageing table produces these in bursts of hundreds, and a
        // registration that outlives its guest by a few seconds costs nothing
        // but a filter slot.
        let mut urgency = if events
            .iter()
            .any(|(kind, _)| *kind == crate::netlink::RTM_DELNEIGH)
        {
            Urgency::WhenConvenient
        } else {
            Urgency::Nothing
        };
        // Where each uplink sits in its bridge, and which addresses may never
        // be registered for it, are properties of the topology - the same for
        // every entry in the batch. Worked out once instead of once per entry
        // per pair, and taken from the very rule the full pass uses: the fast
        // path once carried its own abbreviation and registered a guest VF's
        // own address, which sends that guest's traffic past it.
        //
        // The virtual functions' addresses come carried from the last pass
        // where they fit, else they are asked for now - never assumed empty.
        let mut pfs: Vec<u32> = Vec::new();
        for pair in &self.pairs {
            let Some(dev) = topo.index_of(&pair.dev) else {
                continue;
            };
            let pf = physical_function(topo, dev);
            if topo.at(pf).is_some() && !pfs.contains(&pf) {
                pfs.push(pf);
            }
        }
        // The same rule as the pass, from the same flag. The fast path used
        // to reuse the carried answer whenever the physical functions
        // matched, which is not the question: the addresses change without
        // the list of functions changing at all.
        let vf_macs = match (&self.carried_vf, self.vf_stale) {
            (Some((for_pfs, kept)), false) if *for_pfs == pfs => kept.clone(),
            _ => {
                let fresh = sock.vf_macs_of(&pfs)?;
                self.remember_vf(pfs.clone(), fresh.clone());
                fresh
            }
        };
        let mut pairs: Vec<FastPair> = self
            .pairs
            .iter()
            .filter_map(|p| {
                let dev = topo.index_of(&p.dev)?;
                let bridge = topo.index_of(&p.bridge)?;
                let port = topo.uplink_port(dev, bridge);
                let skip = self.exclusions(topo, dev, port, &vf_macs);
                Some(FastPair {
                    dev: p.dev.clone(),
                    bridge,
                    index: dev,
                    port,
                    skip,
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
            fp.skip.extend(macs.iter().copied());
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
            let mut owned = self.load_owned(&fp.dev);
            let mut changed = false;
            let mut taken_back: Vec<Mac> = Vec::new();
            for mac in macs {
                // Only ever our own registrations. An address somebody else
                // put in the filter is theirs to remove, on the wire or not.
                if !owned.contains(mac) {
                    continue;
                }
                match sock.set_self_fdb(fp.index, mac, false) {
                    Ok(()) => {
                        owned.remove(mac);
                        changed = true;
                        urgency = Urgency::Now;
                        taken_back.push(*mac);
                        eprintln!(
                            "{}: {} moved out onto the wire, unregistered [reflection]",
                            fp.dev,
                            format_mac(mac)
                        );
                    }
                    // Already gone. The point was for it not to be there.
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                        owned.remove(mac);
                        changed = true;
                    }
                    // Keep the note: an entry still in the card that nothing
                    // owns is the orphan the notes exist to prevent.
                    Err(e) => eprintln!(
                        "warning: {}: cannot unregister {}: {e}",
                        fp.dev,
                        format_mac(mac)
                    ),
                }
            }
            if changed {
                self.save_owned(&fp.dev, &owned);
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

        let mut registered: Map<String, Vec<Mac>> = crate::hash::map();
        for (kind, entry) in events {
            if *kind != crate::netlink::RTM_NEWNEIGH {
                continue;
            }
            if self.fast_add(sock, topo, entry, &pairs, &mut registered) {
                urgency = Urgency::Now;
            }
        }
        for (dev, added) in registered {
            self.append_owned(&dev, &added);
        }
        Ok(urgency)
    }

    /// Returns whether this entry was any of our business - registered,
    /// refused, or something the full pass will have to look at. An entry
    /// that concerns none of the pairs returns false, and a batch made
    /// entirely of those does not earn a pass.
    fn fast_add(
        &self,
        sock: &mut dyn FdbWriter,
        topo: &Topology,
        entry: &FdbEntry,
        pairs: &[FastPair],
        registered: &mut Map<String, Vec<Mac>>,
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
                continue; // excluded, the host's own, a VF's, or out on the wire
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
            match sock.set_self_fdb(fp.index, &entry.mac, true) {
                Ok(()) => {
                    registered
                        .entry(fp.dev.clone())
                        .or_default()
                        .push(entry.mac);
                }
                // Already there, and unlike in a full pass nothing checked
                // beforehand whether it was ours. Claiming it now could mean
                // deleting somebody else's entry later, so leave the note be;
                // the next full pass classifies it properly.
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
                Err(e) => eprintln!(
                    "warning: {}: cannot register {}: {e}",
                    fp.dev,
                    format_mac(&entry.mac)
                ),
            }
        }
        ours
    }

    /// Over the notes rather than over the pairs: `--flush` promises to remove
    /// every address this daemon registered, and some of them belong to
    /// devices that have since stopped being an uplink.
    pub fn flush(&mut self, sock: &mut dyn FdbWriter) -> io::Result<bool> {
        let topo = Topology::from_links(&sock.dump_links()?);
        let mut clean = true;
        for dev in self.noted_devices() {
            let owned = self.load_owned(&dev);
            if self.dry_run {
                println!("{dev}: would remove {} address(es)", owned.len());
                continue;
            }
            let (gone, kept) = match topo.get(&dev) {
                Some(link) => self.unregister_all(sock, &dev, link.index, &owned),
                None => (owned.len(), crate::hash::set()),
            };
            if kept.is_empty() {
                let _ = fs::remove_file(self.state_path(&dev));
                println!("{dev}: removed {gone} address(es)");
            } else {
                self.save_owned(&dev, &kept);
                println!(
                    "{dev}: removed {gone} address(es), {} could not be removed \
                     and stay on record",
                    kept.len()
                );
                clean = false;
            }
        }
        Ok(clean)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::netlink::FdbEntry;
    use crate::sysfs::fixture::{mac, Builder};

    pub(crate) const WIRE: Mac = [0xaa, 0, 0, 0, 0, 1]; // a peer out on the switch
    pub(crate) const BEHIND_NIC: Mac = [0xaa, 0, 0, 0, 0, 2]; // on the bridge's other NIC
    pub(crate) const BEHIND_GUEST: Mac = [0xaa, 0, 0, 0, 0, 3]; // a container, seen by a vnet
    pub(crate) const UPLINK_WARD: Mac = [0xaa, 0, 0, 0, 0, 4]; // seen by a vnet on its way down
    pub(crate) const OTHER_BRIDGE: Mac = [0xaa, 0, 0, 0, 0, 5]; // nothing to do with this uplink
    pub(crate) const VF_ADMIN: Mac = [0x02, 0x11, 0x22, 0x33, 0x44, 1];
    pub(crate) const MCAST: Mac = [0x01, 0x00, 0x5e, 0, 0, 1];

    /// A learnt entry: not permanent, not `self`, so the bridge picked it up
    /// from traffic.
    pub(crate) fn learned(ifindex: u32, master: u32, mac: Mac) -> FdbEntry {
        FdbEntry {
            ifindex,
            master: Some(master),
            mac,
            state: 0x02, // NUD_REACHABLE
            flags: 0,
        }
    }

    /// nic1 and nic2 in vmbr1, a vnet bridge IOT stacked on vmbr1.44 with a
    /// container on it, and an unrelated vmbr0 carrying a VM tap.
    pub(crate) fn host(bridge_mac: [u8; 6]) -> crate::sysfs::Topology {
        Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .master("vmbr1")
            .vfs(1)
            .add("nic2", 3, Some(mac(2)))
            .master("vmbr1")
            .add("vmbr1", 10, Some(bridge_mac))
            .bridge()
            .lower("nic1")
            .lower("nic2")
            .add("vmbr1.44", 11, Some(bridge_mac))
            .master("IOT")
            .lower("vmbr1")
            .add("IOT", 12, Some(bridge_mac))
            .bridge()
            .lower("vmbr1.44")
            .lower("veth0")
            .add("veth0", 13, Some(mac(0x13)))
            .master("IOT")
            .add("vmbr0", 20, Some(mac(0xaa)))
            .bridge()
            .lower("nic0")
            .lower("tap0")
            .add("nic0", 21, Some(mac(0xaa)))
            .master("vmbr0")
            .vfs(1)
            .add("tap0", 22, Some(mac(0xa0)))
            .master("vmbr0")
            .build()
    }

    pub(crate) fn fdb() -> Vec<FdbEntry> {
        vec![
            learned(2, 10, WIRE),          // on the uplink itself
            learned(3, 10, BEHIND_NIC),    // on the bridge's other NIC
            learned(13, 12, BEHIND_GUEST), // on the vnet's container port
            learned(11, 12, UPLINK_WARD),  // on the vnet's way back to vmbr1
            learned(22, 20, OTHER_BRIDGE), // on an unrelated bridge
            learned(3, 10, MCAST),         // multicast is not a destination to register
            learned(3, 10, VF_ADMIN),      // our own VF, seen from the other side
            FdbEntry {
                ifindex: 3,
                master: Some(10),
                mac: mac(2),
                state: 0x80, // NUD_PERMANENT - the port's own address
                flags: 0,
            },
        ]
    }

    /// `desired` as the tests think about it: by name. The production callers
    /// hold indices already, having just looked the pair up.
    pub(crate) fn desired_named(
        s: &Syncer,
        topo: &crate::sysfs::Topology,
        pair: &Pair,
        port: &str,
        fdb: &[FdbEntry],
        vf_macs: &[(u32, Mac)],
    ) -> (Set<Mac>, Vec<String>, Set<Mac>) {
        let dev = topo
            .index_of(&pair.dev)
            .expect("fixture has no such device");
        let bridge = topo.index_of(&pair.bridge).unwrap_or(0);
        let port = topo.index_of(port).unwrap_or(dev);
        s.desired(topo, bridge, dev, port, fdb, vf_macs)
    }

    pub(crate) fn syncer() -> Syncer {
        Syncer::new(Vec::new(), PathBuf::from("/nonexistent"))
    }

    pub(crate) fn pair() -> Pair {
        Pair {
            dev: "nic1".into(),
            bridge: "vmbr1".into(),
        }
    }

    #[test]
    fn registers_what_is_behind_the_bridge_and_nothing_else() {
        let topo = host(mac(1));
        let (want, stacked, _) =
            desired_named(&syncer(), &topo, &pair(), "nic1", &fdb(), &[(2, VF_ADMIN)]);

        assert!(want.contains(&BEHIND_NIC), "the bridge's other NIC");
        assert!(
            want.contains(&BEHIND_GUEST),
            "a container behind a stacked vnet"
        );

        assert!(!want.contains(&WIRE), "peers on the wire must stay out");
        assert!(
            !want.contains(&UPLINK_WARD),
            "entries pointing back at the uplink"
        );
        assert!(
            !want.contains(&OTHER_BRIDGE),
            "a bridge that is not stacked on this one is none of our business"
        );
        assert!(!want.contains(&MCAST), "multicast");
        assert!(!want.contains(&VF_ADMIN), "our own VF");
        assert!(
            !want.contains(&mac(2)),
            "a port's own address is not learnt"
        );
        assert!(!want.contains(&mac(1)), "the uplink's own address");

        assert_eq!(stacked, vec!["IOT".to_string()]);
    }

    /// The host's own address on the bridge is normally the uplink's, and then
    /// the internal switch knows it anyway. When it differs it has to be
    /// registered, or the VF cannot reach the host at all. Checked on a plain
    /// bridge with nothing stacked on it, so only the bridge's own address can
    /// account for the result.
    #[test]
    fn a_bridge_with_its_own_address_gets_registered() {
        let plain = |bridge_mac: [u8; 6]| {
            Builder::new()
                .add("nic1", 2, Some(mac(1)))
                .master("br0")
                .vfs(1)
                .add("nic2", 3, Some(mac(2)))
                .master("br0")
                .add("br0", 10, Some(bridge_mac))
                .bridge()
                .lower("nic1")
                .lower("nic2")
                .build()
        };
        let p = Pair {
            dev: "nic1".into(),
            bridge: "br0".into(),
        };

        let odd = mac(0x99);
        let (want, stacked, _) = desired_named(&syncer(), &plain(odd), &p, "nic1", &[], &[]);
        assert!(
            want.contains(&odd),
            "a bridge address that is not the uplink's must be registered"
        );
        assert!(stacked.is_empty(), "nothing is stacked on this one");

        let (want, _, _) = desired_named(&syncer(), &plain(mac(1)), &p, "nic1", &[], &[]);
        assert!(
            !want.contains(&mac(1)),
            "when it is the uplink's address there is nothing to do"
        );
    }

    /// The same for interfaces stacked on the bridge - a VLAN interface the
    /// host routes from is reachable only through the bridge.
    #[test]
    fn stacked_interfaces_of_the_host_get_registered_too() {
        let vlan_mac = mac(0x77);
        let topo = Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .master("br0")
            .vfs(1)
            .add("br0", 10, Some(mac(1)))
            .bridge()
            .lower("nic1")
            .add("br0.44", 11, Some(vlan_mac))
            .lower("br0")
            .build();
        let p = Pair {
            dev: "nic1".into(),
            bridge: "br0".into(),
        };
        let (want, _, _) = desired_named(&syncer(), &topo, &p, "nic1", &[], &[]);
        assert!(want.contains(&vlan_mac));
    }

    #[test]
    fn excluded_addresses_stay_out() {
        let topo = host(mac(1));
        let mut s = syncer();
        s.exclude.insert(BEHIND_GUEST);
        let (want, _, _) = desired_named(&s, &topo, &pair(), "nic1", &fdb(), &[]);
        assert!(!want.contains(&BEHIND_GUEST));
        assert!(want.contains(&BEHIND_NIC));
    }

    /// With a bond in between, the wire side is the whole bond: entries learnt
    /// on it belong out there, and every member's address is the host's own.
    #[test]
    fn a_bond_counts_as_the_wire_side_in_full() {
        let topo = Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .master("bond0")
            .vfs(1)
            .add("nic1b", 3, Some(mac(2)))
            .master("bond0")
            .add("bond0", 4, Some(mac(1)))
            .master("br0")
            .lower("nic1")
            .lower("nic1b")
            .add("br0", 10, Some(mac(1)))
            .bridge()
            .lower("bond0")
            .lower("tap0")
            .add("tap0", 5, Some(mac(5)))
            .master("br0")
            .build();
        let entries = vec![
            learned(4, 10, WIRE),       // arrived over the bond
            learned(5, 10, BEHIND_NIC), // a local guest
            learned(5, 10, mac(2)),     // a bond member's address, oddly placed
        ];
        let p = Pair {
            dev: "nic1".into(),
            bridge: "br0".into(),
        };
        let (want, _, _) = desired_named(&syncer(), &topo, &p, "bond0", &entries, &[]);
        assert!(want.contains(&BEHIND_NIC));
        assert!(
            !want.contains(&WIRE),
            "learnt on the bond, so it is on the wire"
        );
        assert!(
            !want.contains(&mac(2)),
            "a bond member's address is the host's own"
        );
    }
}

#[cfg(test)]
mod extra_tests {
    use super::tests::*;
    use super::*;
    use crate::sysfs::fixture::mac;

    #[test]
    fn pinned_addresses_are_registered_without_being_learnt() {
        let unheard: Mac = [0xaa, 0, 0, 0, 0, 0x42];
        let topo = host(mac(1));
        let mut s = syncer();
        s.extra.insert(unheard);
        let (want, _, _) = desired_named(&s, &topo, &pair(), "nic1", &fdb(), &[]);
        assert!(
            want.contains(&unheard),
            "nothing has ever been heard from it"
        );
    }

    /// Pinning must not become a way to break the wire.
    #[test]
    fn pinning_cannot_override_the_wire_side() {
        let topo = host(mac(1));
        let mut s = syncer();
        s.extra.insert(WIRE);
        s.extra.insert(mac(1));
        let (want, _, _) = desired_named(&s, &topo, &pair(), "nic1", &fdb(), &[]);
        assert!(!want.contains(&WIRE), "it lives out on the wire");
        assert!(!want.contains(&mac(1)), "it is the uplink's own address");
    }
}

#[cfg(test)]
mod state_tests {
    use super::tests::*;
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sriov-mac-sync-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    /// The note in /run is what keeps the daemon from deleting entries it never
    /// made, so it has to survive a restart.
    #[test]
    fn ownership_survives_a_restart() {
        let dir = scratch("restart");
        let mut set = crate::hash::set();
        set.insert(BEHIND_NIC);
        set.insert(BEHIND_GUEST);

        let before = Syncer::new(Vec::new(), dir.clone());
        before.save_owned("nic1", &set);
        assert!(dir.join("nic1.owned").exists());

        let after = Syncer::new(Vec::new(), dir.clone());
        assert_eq!(after.load_owned("nic1"), set);
        assert!(
            after.load_owned("nic0").is_empty(),
            "an uplink with no note owns nothing"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Most passes change nothing; those must not touch the disk.
    fn set_mtime(path: &std::path::Path, secs: i64) {
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let t = libc::timeval {
            tv_sec: secs as libc::time_t,
            tv_usec: 0,
        };
        assert_eq!(unsafe { libc::utimes(c.as_ptr(), [t, t].as_ptr()) }, 0);
    }

    fn mtime(path: &std::path::Path) -> i64 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(path).unwrap().mtime()
    }

    #[test]
    fn a_device_that_stopped_being_an_uplink_is_noticed() {
        let dir = scratch("orphan");
        let mut set = crate::hash::set();
        set.insert(BEHIND_NIC);

        let mut s = Syncer::new(
            vec![Pair {
                dev: "nic1".into(),
                bridge: "br0".into(),
            }],
            dir.clone(),
        );
        s.authoritative = true;
        s.save_owned("nic1", &set);
        s.save_owned("nic0", &set); // was an uplink once, is not one now
        assert_eq!(
            s.orphaned(),
            vec!["nic0".to_string()],
            "a note without a pair is an orphan; one with a pair is not"
        );

        let mut none = Syncer::new(Vec::new(), dir.clone());
        none.authoritative = true;
        assert_eq!(
            none.orphaned(),
            vec!["nic0".to_string(), "nic1".to_string()],
            "with no pairs left, everything registered has to come back out"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn named_pairs_do_not_get_to_declare_anything_an_orphan() {
        let dir = scratch("no-authority");
        let mut set = crate::hash::set();
        set.insert(BEHIND_NIC);

        // `--once --pair nic0:vmbr0` next to a running daemon that also looks
        // after nic1 must not take nic1's addresses away.
        let mut s = Syncer::new(
            vec![Pair {
                dev: "nic0".into(),
                bridge: "vmbr0".into(),
            }],
            dir.clone(),
        );
        s.save_owned("nic1", &set);
        assert!(
            s.orphaned().is_empty(),
            "a hand-written pair list says nothing about the pairs it omits"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_note_changed_behind_our_back_is_put_right() {
        let dir = scratch("stale-note");
        let mut set = crate::hash::set();
        set.insert(BEHIND_NIC);

        let s = Syncer::new(Vec::new(), dir.clone());
        s.save_owned("nic1", &set);
        // What `--flush` from a second process leaves behind.
        fs::write(dir.join("nic1.owned"), "").unwrap();

        assert!(
            s.load_owned("nic1").is_empty(),
            "the file is the truth, not a copy in memory"
        );
        s.save_owned("nic1", &set);
        assert_eq!(
            s.load_owned("nic1"),
            set,
            "and a note that disagrees with the set gets written again"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unchanged_set_is_not_written_again() {
        let dir = scratch("idle");
        let mut set = crate::hash::set();
        set.insert(BEHIND_NIC);

        let s = Syncer::new(Vec::new(), dir.clone());
        s.save_owned("nic1", &set);
        let path = dir.join("nic1.owned");
        // Backdated, so a rewrite cannot hide in the clock's resolution.
        set_mtime(&path, 1_000_000_000);
        s.save_owned("nic1", &set);
        assert_eq!(mtime(&path), 1_000_000_000, "unchanged means untouched");

        set.insert(BEHIND_GUEST);
        s.save_owned("nic1", &set);
        assert_eq!(
            fs::read_to_string(&path).unwrap().lines().count(),
            2,
            "a changed set is written"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A note whose file was removed underneath us must be written again.
    #[test]
    fn a_vanished_note_is_recreated() {
        let dir = scratch("vanish");
        let mut set = crate::hash::set();
        set.insert(BEHIND_NIC);
        let s = Syncer::new(Vec::new(), dir.clone());
        s.save_owned("nic1", &set);
        fs::remove_file(dir.join("nic1.owned")).unwrap();
        s.save_owned("nic1", &set);
        assert!(dir.join("nic1.owned").exists());
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn the_timing_report_names_every_phase_and_what_it_found() {
        let t = Timings {
            topology: Duration::from_micros(8100),
            fdb: Duration::from_micros(3200),
            vf_macs: Duration::from_micros(400),
            orphans: Duration::from_micros(100),
            pairs: Duration::from_micros(600),
            total: Duration::from_micros(12400),
            links: 37,
            fdb_entries: 8707,
            vf_addresses: 4,
            vf_carried: false,
            added: 1,
            removed: 2,
            failures: vec!["nic1v0: unregister 02:00:00:00:00:01: no space".into()],
        };
        let r = t.report();
        for phase in ["topology", "fdb dump", "vf macs", "orphans", "pairs"] {
            assert!(
                r.contains(phase),
                "the report hides the {phase} phase:\n{r}"
            );
        }
        assert!(r.contains("37 links"), "link count missing:\n{r}");
        assert!(r.contains("8707 entries"), "fdb size missing:\n{r}");
        assert!(r.contains("+1 -2"), "the change count is missing:\n{r}");
        assert!(
            r.contains("failure: nic1v0: unregister"),
            "a failure went unmentioned:\n{r}"
        );
    }

    #[test]
    fn a_carried_over_reading_says_so() {
        let fresh = Timings {
            vf_addresses: 4,
            ..Default::default()
        };
        assert!(
            !fresh.report().contains("carried over"),
            "a reading taken this pass claimed to be carried over"
        );
        let carried = Timings {
            vf_addresses: 4,
            vf_carried: true,
            ..Default::default()
        };
        assert!(
            carried.report().contains("carried over"),
            "a carried reading is indistinguishable from a fresh one:\n{}",
            carried.report()
        );
    }

    #[test]
    fn a_pass_without_trouble_reports_no_failures() {
        let r = Timings::default().report();
        assert!(
            !r.contains("failure"),
            "an untroubled pass claimed a failure:\n{r}"
        );
    }
    use crate::sysfs::fixture::{mac, Builder};

    /// The kernel, as far as the bookkeeping is concerned: answers with what
    /// a test injected and records what would have been written.
    #[derive(Default)]
    struct FakeSock {
        fdb: Vec<FdbEntry>,
        vf: Vec<(u32, Mac)>,
        added: Vec<(u32, Mac)>,
        removed: Vec<(u32, Mac)>,
        /// raw OS error to answer an add of this address with
        fail_add: Map<Mac, i32>,
        /// raw OS error to answer a removal of this address with
        fail_del: Map<Mac, i32>,
    }

    impl FdbWriter for FakeSock {
        fn dump_fdb(&mut self) -> io::Result<Vec<FdbEntry>> {
            Ok(self.fdb.clone())
        }
        // Only --flush reads the topology through the socket, and the tests
        // that use this hand it in directly.
        fn dump_links(&mut self) -> io::Result<Vec<crate::netlink::LinkInfo>> {
            Ok(Vec::new())
        }
        fn vf_macs_of(&mut self, _indices: &[u32]) -> io::Result<Vec<(u32, Mac)>> {
            Ok(self.vf.clone())
        }
        fn set_self_fdb(&mut self, ifindex: u32, mac: &Mac, add: bool) -> io::Result<()> {
            let table = if add { &self.fail_add } else { &self.fail_del };
            if let Some(code) = table.get(mac) {
                return Err(io::Error::from_raw_os_error(*code));
            }
            if add {
                self.added.push((ifindex, *mac));
            } else {
                self.removed.push((ifindex, *mac));
            }
            Ok(())
        }
    }

    fn ready_syncer(dir: &std::path::Path) -> Syncer {
        let mut s = Syncer::new(vec![pair()], dir.to_path_buf());
        s.authoritative = true;
        s
    }

    use std::time::Duration as Dur;

    #[test]
    fn a_full_pass_registers_exactly_what_is_wanted_and_notes_it() {
        let dir = scratch("pass");
        let topo = host(mac(1));
        let mut sock = FakeSock {
            fdb: fdb(),
            vf: vec![(2, VF_ADMIN)],
            ..Default::default()
        };
        let mut s = ready_syncer(&dir);
        let reports = s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();

        let registered: Set<Mac> = sock.added.iter().map(|(_, m)| *m).collect();
        let (want, _, _) = desired_named(&s, &topo, &pair(), "nic1", &fdb(), &[(2, VF_ADMIN)]);
        assert_eq!(
            registered, want,
            "the pass wrote something desired() does not want"
        );
        assert_eq!(reports[0].added, want.len());
        assert_eq!(
            s.load_owned("nic1"),
            want,
            "the note does not record what was registered"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The fast path once had its own abbreviation of the exclusion rules -
    /// none of them - and registered our own VF's address. This pins the two
    /// paths together: whatever arrives as an event may be registered exactly
    /// when the full pass would want it.
    #[test]
    fn the_fast_path_agrees_with_the_full_pass_on_every_fixture_entry() {
        let dir = scratch("parity");
        let topo = host(mac(1));
        let vf = vec![(2, VF_ADMIN)];
        let mut s = ready_syncer(&dir);
        let (want, _, wire) = desired_named(&s, &topo, &pair(), "nic1", &fdb(), &vf);
        s.carried_wire.insert("nic1".into(), wire);
        s.remember_vf(vec![2], vf.clone());

        for entry in fdb() {
            let mut sock = FakeSock::default();
            s.fast_apply(
                &mut sock,
                &topo,
                &[(crate::netlink::RTM_NEWNEIGH, entry.clone())],
            )
            .unwrap();
            let registered = !sock.added.is_empty();
            // Only learned entries reach the fast path at all; desired() also
            // wants the host's own addresses, which never arrive as events.
            let wanted = entry.is_learned() && want.contains(&entry.mac);
            assert_eq!(
                registered,
                wanted,
                "fast path and full pass disagree on {} (registered {registered}, wanted {wanted})",
                crate::netlink::format_mac(&entry.mac)
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn eexist_is_not_claimed_as_ours() {
        let dir = scratch("eexist");
        let topo = host(mac(1));
        let mut sock = FakeSock {
            fdb: fdb(),
            vf: vec![(2, VF_ADMIN)],
            fail_add: [(BEHIND_GUEST, libc::EEXIST)]
                .into_iter()
                .collect::<Map<_, _>>(),
            ..Default::default()
        };
        let mut s = ready_syncer(&dir);
        s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
        assert!(
            !s.load_owned("nic1").contains(&BEHIND_GUEST),
            "an entry somebody else created was claimed - it would be deleted later"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_removal_that_fails_keeps_its_note_and_enoent_counts_as_gone() {
        let dir = scratch("removal");
        let topo = host(mac(1));
        let mut s = ready_syncer(&dir);
        // Two addresses on record that the bridge no longer knows.
        let gone_mac = mac(0x51);
        let stuck_mac = mac(0x52);
        s.save_owned(
            "nic1",
            &[gone_mac, stuck_mac].into_iter().collect::<Set<_>>(),
        );
        let mut sock = FakeSock {
            fdb: fdb(),
            vf: vec![(2, VF_ADMIN)],
            fail_del: [(gone_mac, libc::ENOENT), (stuck_mac, libc::EPERM)]
                .into_iter()
                .collect::<Map<_, _>>(),
            ..Default::default()
        };
        s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
        let owned = s.load_owned("nic1");
        assert!(!owned.contains(&gone_mac), "ENOENT means gone, not stuck");
        assert!(
            owned.contains(&stuck_mac),
            "a failed removal lost its note - the entry is an orphan now"
        );
        assert!(
            s.timings.failures.iter().any(|f| f.contains("unregister")),
            "the failure went unrecorded"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_dry_run_leaves_the_notes_byte_identical() {
        let dir = scratch("dryrun");
        let topo = host(mac(1));
        let mut s = ready_syncer(&dir);
        s.save_owned("nic1", &[mac(0x61)].into_iter().collect::<Set<_>>());
        s.save_owned("gone0", &[mac(0x62)].into_iter().collect::<Set<_>>()); // an orphan
        let before: Vec<(String, String)> = {
            let mut v: Vec<_> = fs::read_dir(&dir)
                .unwrap()
                .map(|e| {
                    let p = e.unwrap().path();
                    (p.display().to_string(), fs::read_to_string(&p).unwrap())
                })
                .collect();
            v.sort();
            v
        };
        s.dry_run = true;
        let mut sock = FakeSock {
            fdb: fdb(),
            vf: vec![(2, VF_ADMIN)],
            ..Default::default()
        };
        s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
        s.flush(&mut sock).unwrap();
        assert!(
            sock.added.is_empty() && sock.removed.is_empty(),
            "a dry run wrote"
        );
        let after: Vec<(String, String)> = {
            let mut v: Vec<_> = fs::read_dir(&dir)
                .unwrap()
                .map(|e| {
                    let p = e.unwrap().path();
                    (p.display().to_string(), fs::read_to_string(&p).unwrap())
                })
                .collect();
            v.sort();
            v
        };
        assert_eq!(before, after, "a dry run changed the state directory");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_mangled_note_gives_up_only_the_mangled_lines() {
        let dir = scratch("mangled");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("nic1.owned"),
            "aa:bb:cc:dd:ee:01\r\nnot an address\nAA:BB:CC:DD:EE:02\naa:bb:cc:dd:ee:03\n",
        )
        .unwrap();
        let s = ready_syncer(&dir);
        let owned = s.load_owned("nic1");
        // CRLF is trimmed, uppercase is not an address to parse_mac, garbage is dropped.
        assert!(owned.contains(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]));
        assert!(owned.contains(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03]));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn with_no_pairs_left_the_pass_still_sweeps_orphans() {
        let dir = scratch("sweep");
        let topo = host(mac(1));
        let mut s = Syncer::new(Vec::new(), dir.clone());
        s.authoritative = true;
        s.save_owned("nic1", &[mac(0x71)].into_iter().collect::<Set<_>>());
        let mut sock = FakeSock::default();
        s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
        assert_eq!(
            sock.removed,
            vec![(2, mac(0x71))],
            "the orphaned registration was not taken back out"
        );
        assert!(!dir.join("nic1.owned").exists(), "the settled note lingers");
        let _ = fs::remove_dir_all(&dir);
    }

    /// The uplink may itself be a VF; the exclusions then belong to its PF -
    /// the sister VFs' addresses above all. All earlier tests ran with the
    /// device being its own physical function.
    #[test]
    fn a_vf_uplink_excludes_its_sisters_through_the_pf() {
        let sister: Mac = [0x02, 0x99, 0, 0, 0, 7];
        let topo = Builder::new()
            .add("pf0", 1, Some(mac(0x10)))
            .vfs(2)
            .add("pf0v1", 2, Some(mac(0x11)))
            .physfn("pf0")
            .master("br0")
            .add("br0", 10, Some(mac(0x11)))
            .bridge()
            .lower("pf0v1")
            .lower("tap1")
            .add("tap1", 11, Some(mac(0x12)))
            .master("br0")
            .build();
        let p = Pair {
            dev: "pf0v1".into(),
            bridge: "br0".into(),
        };
        // The sister's address was learnt behind the bridge; the PF's index
        // is 1 and the vf list is keyed by it.
        let entries = vec![learned(11, 10, sister)];
        let s = syncer();
        let (want, _, _) = desired_named(&s, &topo, &p, "pf0v1", &entries, &[(1, sister)]);
        assert!(
            !want.contains(&sister),
            "a sister VF's address made it past the PF-keyed exclusions"
        );
        let _ = &s;
    }
    /// The reading side of the bench: a pass that may not apply must leave
    /// the state directory byte-identical - including an orphan note, whose
    /// deletion path runs through the filesystem where no FdbWriter fake can
    /// see it. A watchdog counting fake writes alone guards the wrong door.
    #[test]
    fn a_non_applying_pass_leaves_the_state_directory_untouched() {
        let dir = scratch("readonly");
        let topo = host(mac(1));
        let mut s = ready_syncer(&dir);
        s.save_owned("nic1", &[mac(0x81)].into_iter().collect::<Set<_>>());
        s.save_owned("gone0", &[mac(0x82)].into_iter().collect::<Set<_>>()); // an orphan
        let snapshot = |d: &std::path::Path| -> Vec<(String, Vec<u8>)> {
            let mut v: Vec<_> = fs::read_dir(d)
                .unwrap()
                .map(|e| {
                    let p = e.unwrap().path();
                    (p.display().to_string(), fs::read(&p).unwrap())
                })
                .collect();
            v.sort();
            v
        };
        let before = snapshot(&dir);
        let mut sock = FakeSock {
            fdb: fdb(),
            vf: vec![(2, VF_ADMIN)],
            ..Default::default()
        };
        for _ in 0..3 {
            s.reconcile(&mut sock, false, &topo, Dur::ZERO).unwrap();
        }
        assert!(sock.added.is_empty() && sock.removed.is_empty());
        assert_eq!(
            before,
            snapshot(&dir),
            "a non-applying pass wrote to the state directory"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// How the pass scales, in the shape it actually meets: stacked vnet
    /// bridges the Proxmox way, a share of the entries out on the wire, two
    /// pairs. Run by hand when the question comes up:
    ///   cargo test --release scaling -- --ignored --nocapture
    /// It asserts rough linearity so it doubles as a regression tripwire.
    #[test]
    #[ignore]
    fn scaling_stays_roughly_linear_in_the_forwarding_table() {
        use crate::sysfs::fixture::Builder;
        use std::time::Instant;

        // An SDN-shaped host: uplink + second NIC under the bridge, VLAN
        // interfaces stacked on it, each carrying a vnet bridge with ports.
        fn build(vnets: u32) -> crate::sysfs::Topology {
            let mut b = Builder::new()
                .add("nic1", 2, Some(mac(1)))
                .master("vmbr1")
                .vfs(1)
                .add("nic2", 3, Some(mac(2)))
                .master("vmbr1");
            let mut bridge = b
                .add("vmbr1", 10, Some(mac(3)))
                .bridge()
                .lower("nic1")
                .lower("nic2");
            for v in 0..vnets {
                bridge = bridge.lower(&format!("vmbr1.{}", 100 + v));
            }
            b = bridge;
            for v in 0..vnets {
                let vid = 100 + v;
                b = b
                    .add(&format!("vmbr1.{vid}"), 100 + v * 3, Some(mac(3)))
                    .master(&format!("VNET{vid}"))
                    .lower("vmbr1")
                    .add(&format!("VNET{vid}"), 101 + v * 3, Some(mac(3)))
                    .bridge()
                    .lower(&format!("vmbr1.{vid}"))
                    .lower(&format!("veth{vid}"))
                    .add(&format!("veth{vid}"), 102 + v * 3, Some(mac(4)))
                    .master(&format!("VNET{vid}"));
            }
            b.build()
        }

        fn entries(n: usize, vnets: u32) -> Vec<FdbEntry> {
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                let m = [0xaa, 0x10, (i >> 16) as u8, (i >> 8) as u8, i as u8, 1];
                let e = if i % 10 < 3 {
                    learned(2, 10, m) // 30 % out on the wire
                } else if i % 10 < 6 {
                    let v = (i as u32) % vnets;
                    learned(102 + v * 3, 101 + v * 3, m) // behind a vnet
                } else {
                    learned(3, 10, m) // behind the second NIC
                };
                out.push(e);
            }
            out
        }

        let topo = build(8);
        let mut cost = Vec::new();
        for &n in &[500usize, 5_000, 20_000] {
            let dir = scratch(&format!("scale{n}"));
            let mut s = Syncer::new(
                vec![Pair {
                    dev: "nic1".into(),
                    bridge: "vmbr1".into(),
                }],
                dir.clone(),
            );
            s.authoritative = true;
            let mut sock = FakeSock {
                fdb: entries(n, 8),
                vf: vec![(2, VF_ADMIN)],
                ..Default::default()
            };
            // warm once, then measure the median of five
            let _ = s.reconcile(&mut sock, false, &topo, Dur::ZERO);
            let mut runs: Vec<u128> = (0..5)
                .map(|_| {
                    let t = Instant::now();
                    let _ = s.reconcile(&mut sock, false, &topo, Dur::ZERO);
                    t.elapsed().as_micros()
                })
                .collect();
            runs.sort();
            println!("  {n:6} entries: {} us", runs[2]);
            cost.push((n as u128, runs[2].max(1)));
            let _ = fs::remove_dir_all(&dir);
        }
        let (n0, t0) = cost[0];
        let (n2, t2) = cost[2];
        let work_ratio = n2 / n0; // 40x the entries
        assert!(
            t2 / t0 < work_ratio * 4,
            "the pass grew {}x over a {}x larger table - that is not linear",
            t2 / t0,
            work_ratio
        );
    }

    /// A guest that moves to another host takes its address with it, and the
    /// bridge learns that address on the uplink's own port from then on. The
    /// registration left behind is worse than useless: the eSwitch keeps
    /// handing that traffic to the uplink, and the bridge cannot send it back
    /// out of the port it came in on, so it is dropped. The batch that brings
    /// the news has to undo it.
    ///
    /// Verified by mutation: with the reflection loop removed, nothing is
    /// removed and the note keeps the address.
    #[test]
    fn an_address_that_reappears_on_the_wire_is_unregistered_at_once() {
        let dir = scratch("reflection");
        let topo = host(mac(1));
        let mut s = ready_syncer(&dir);
        s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
        // It was behind the bridge a moment ago, registered and noted.
        s.save_owned("nic1", &[BEHIND_NIC].into_iter().collect::<Set<_>>());

        let mut sock = FakeSock::default();
        // nic1 is the uplink and its own port in this fixture: index 2.
        s.fast_apply(
            &mut sock,
            &topo,
            &[(crate::netlink::RTM_NEWNEIGH, learned(2, 10, BEHIND_NIC))],
        )
        .unwrap();

        assert_eq!(
            sock.removed,
            vec![(2, BEHIND_NIC)],
            "the address is out on the wire now; the filter entry has to go"
        );
        assert!(
            !s.load_owned("nic1").contains(&BEHIND_NIC),
            "and the note with it, or the next pass counts it as somebody else's"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Only ever our own registrations. An address somebody else put in the
    /// filter stays there, wire or no wire - the same rule the full pass and
    /// --flush follow.
    #[test]
    fn a_reflection_of_an_address_we_never_registered_is_left_alone() {
        let dir = scratch("reflection-foreign");
        let topo = host(mac(1));
        let mut s = ready_syncer(&dir);
        s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);

        let mut sock = FakeSock::default();
        s.fast_apply(
            &mut sock,
            &topo,
            &[(crate::netlink::RTM_NEWNEIGH, learned(2, 10, BEHIND_NIC))],
        )
        .unwrap();

        assert!(
            sock.removed.is_empty(),
            "nothing of ours was there to remove: {:?}",
            sock.removed
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// One batch is one moment, and in it the wire has the last word. An
    /// address seen on the uplink port and behind the bridge in the same
    /// batch must not end up registered - which is what happens if the
    /// registrations are done first and the reflections after.
    #[test]
    fn within_one_batch_the_wire_wins() {
        let dir = scratch("reflection-order");
        let topo = host(mac(1));
        let mut s = ready_syncer(&dir);
        s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);

        let mut sock = FakeSock::default();
        s.fast_apply(
            &mut sock,
            &topo,
            &[
                // behind the bridge, on the other NIC ...
                (crate::netlink::RTM_NEWNEIGH, learned(3, 10, BEHIND_NIC)),
                // ... and on the uplink's own port in the same breath
                (crate::netlink::RTM_NEWNEIGH, learned(2, 10, BEHIND_NIC)),
            ],
        )
        .unwrap();

        assert!(
            sock.added.is_empty(),
            "the wire side of the same batch says this address is out there: {:?}",
            sock.added
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A deletion is not evidence. A vlan-aware bridge learns one address once
    /// per VLAN and the filter holds a single entry for all of them, so the
    /// last of them going is something only a full dump can establish. The
    /// fast path must not act on one notification - the pass that follows the
    /// batch is what removes.
    #[test]
    fn a_deletion_alone_does_not_remove_a_registration() {
        let dir = scratch("deletion");
        let topo = host(mac(1));
        let mut s = ready_syncer(&dir);
        s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
        s.save_owned("nic1", &[BEHIND_NIC].into_iter().collect::<Set<_>>());

        let mut sock = FakeSock::default();
        s.fast_apply(
            &mut sock,
            &topo,
            &[(crate::netlink::RTM_DELNEIGH, learned(3, 10, BEHIND_NIC))],
        )
        .unwrap();

        assert!(
            sock.removed.is_empty(),
            "one entry going is not the address going: {:?}",
            sock.removed
        );
        assert!(
            s.load_owned("nic1").contains(&BEHIND_NIC),
            "the note stays until a full dump says otherwise"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The remembered copy is a way to skip *reading* the file, never a way
    /// to skip believing it. A second process replacing the note through
    /// rename - which is what --flush and --once do - has to be seen.
    ///
    /// Verified by mutation: with `is_still` always true, this reads the old
    /// contents and fails.
    #[test]
    fn a_note_replaced_by_another_process_is_read_again() {
        let dir = scratch("note-replaced");
        let s = Syncer::new(Vec::new(), dir.clone());
        s.save_owned("nic1", &[BEHIND_NIC].into_iter().collect::<Set<_>>());
        assert_eq!(
            s.load_owned("nic1"),
            [BEHIND_NIC].into_iter().collect::<Set<_>>()
        );

        // What another process's save_owned leaves: a different file in the
        // same place, same length, written through rename.
        let other = dir.join("other");
        fs::write(&other, format!("{}\n", format_mac(&BEHIND_GUEST))).unwrap();
        fs::rename(&other, dir.join("nic1.owned")).unwrap();

        assert_eq!(
            s.load_owned("nic1"),
            [BEHIND_GUEST].into_iter().collect::<Set<_>>(),
            "the file is the truth; the copy only saves reading it"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A note written in the same instant it was read cannot be told from one
    /// written before it, and believing the copy then would mean believing
    /// something that was already out of date when it was made. The rule is
    /// that the timestamp has to be strictly older than the read.
    ///
    /// Verified by mutation: without the `mtime < read_at` condition this
    /// returns the stale set and fails.
    #[test]
    fn a_note_not_older_than_its_reading_is_never_believed() {
        let dir = scratch("note-instant");
        let path = dir.join("nic1.owned");
        let s = Syncer::new(Vec::new(), dir.clone());
        s.save_owned("nic1", &[BEHIND_NIC].into_iter().collect::<Set<_>>());

        // A timestamp in the future stands in for "the same instant": both
        // are timestamps that are not older than the moment of reading, and
        // the file can be changed afterwards without the timestamp moving.
        let ahead = 4_000_000_000; // 2096
        set_mtime(&path, ahead);
        assert_eq!(
            s.load_owned("nic1"),
            [BEHIND_NIC].into_iter().collect::<Set<_>>()
        );

        // Changed underneath, with identity, length and timestamp all left
        // looking exactly as they did.
        fs::write(&path, format!("{}\n", format_mac(&BEHIND_GUEST))).unwrap();
        set_mtime(&path, ahead);

        assert_eq!(
            s.load_owned("nic1"),
            [BEHIND_GUEST].into_iter().collect::<Set<_>>(),
            "a note whose timestamp is not older than the read has to be read"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A pass dumps the host's whole forwarding table, so what a batch is
    /// worth has to be decided before one is scheduled. These are the four
    /// answers - and the difference between the first two is what the eBPF
    /// experiment measured as 3.5 seconds of CPU for nothing.
    ///
    /// Verified by mutation: returning true unconditionally makes the
    /// wire-side cases fail; returning false makes the others fail.
    #[test]
    fn only_a_batch_with_something_in_it_earns_a_pass() {
        let dir = scratch("worth");
        let topo = host(mac(1));
        let vf = vec![(2, VF_ADMIN)];

        let mut s = ready_syncer(&dir);
        s.remember_vf(vec![2], vf.clone());
        let mut sock = FakeSock::default();

        // Somebody else's address, learnt out on the wire. Nothing of ours.
        assert!(
            s.fast_apply(
                &mut sock,
                &topo,
                &[(crate::netlink::RTM_NEWNEIGH, learned(2, 10, WIRE))]
            )
            .unwrap()
                == Urgency::Nothing,
            "learning on the wire that was never ours leaves nothing to reconcile"
        );

        // An entry on a bridge that has nothing to do with this uplink.
        assert!(
            s.fast_apply(
                &mut sock,
                &topo,
                &[(crate::netlink::RTM_NEWNEIGH, learned(22, 20, OTHER_BRIDGE))]
            )
            .unwrap()
                == Urgency::Nothing,
            "another bridge's forwarding is not this uplink's business"
        );

        // A guest behind the bridge: registered, and the pass reconciles.
        assert!(
            s.fast_apply(
                &mut sock,
                &topo,
                &[(crate::netlink::RTM_NEWNEIGH, learned(3, 10, BEHIND_NIC))]
            )
            .unwrap()
                == Urgency::Now,
            "an address behind the bridge is ours, and registering it is not \
             something to sit on"
        );

        // A deletion: only a full dump can say whether that was the last copy.
        assert!(
            s.fast_apply(
                &mut sock,
                &topo,
                &[(crate::netlink::RTM_DELNEIGH, learned(3, 10, BEHIND_NIC))]
            )
            .unwrap()
                == Urgency::WhenConvenient,
            "a deletion has to be looked at - but a table ageing out sends \
             hundreds, and none of them is urgent"
        );

        // One of ours turning up on the wire: unregistered here, reconciled there.
        let mut s2 = ready_syncer(&dir);
        s2.remember_vf(vec![2], vf);
        s2.save_owned("nic1", &[BEHIND_GUEST].into_iter().collect::<Set<_>>());
        assert!(
            s2.fast_apply(
                &mut sock,
                &topo,
                &[(crate::netlink::RTM_NEWNEIGH, learned(2, 10, BEHIND_GUEST))]
            )
            .unwrap()
                == Urgency::Now,
            "taking one of ours back out is a change the pass has to see"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The fast path adds to a note without rewriting it. What matters is
    /// that the address is in the note afterwards, whatever the file looks
    /// like - and that a note somebody else replaced meanwhile is not lost.
    #[test]
    fn a_note_is_added_to_rather_than_rewritten() {
        let dir = scratch("append");
        let s = Syncer::new(Vec::new(), dir.clone());
        s.save_owned("nic1", &[BEHIND_NIC].into_iter().collect::<Set<_>>());
        let before = fs::metadata(dir.join("nic1.owned")).unwrap().len();

        s.append_owned("nic1", &[BEHIND_GUEST, UPLINK_WARD]);

        assert_eq!(
            s.load_owned("nic1"),
            [BEHIND_NIC, BEHIND_GUEST, UPLINK_WARD]
                .into_iter()
                .collect::<Set<_>>(),
            "everything that was there, plus what was added"
        );
        let after = fs::metadata(dir.join("nic1.owned")).unwrap().len();
        assert!(after > before, "the file grew rather than being replaced");

        // A note with no file yet - the first registration after a reboot.
        s.append_owned("nic2", &[BEHIND_NIC]);
        assert_eq!(
            s.load_owned("nic2"),
            [BEHIND_NIC].into_iter().collect::<Set<_>>(),
            "a note that did not exist is created"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// An address the note already names is not written again. It sounds like
    /// tidiness and is not: a full pass rewrites the file only when the set of
    /// addresses changed, and a second copy of a line does not change the set -
    /// so the file would grow by a line every time an address was registered
    /// afresh, and nothing would ever shorten it again.
    ///
    /// Verified by mutation: appending unconditionally leaves two lines.
    #[test]
    fn a_note_does_not_collect_duplicate_lines() {
        let dir = scratch("append-dup");
        let s = Syncer::new(Vec::new(), dir.clone());
        s.append_owned("nic1", &[BEHIND_NIC]);
        s.append_owned("nic1", &[BEHIND_NIC]);
        s.append_owned("nic1", &[BEHIND_NIC, BEHIND_GUEST]);
        assert_eq!(
            s.load_owned("nic1"),
            [BEHIND_NIC, BEHIND_GUEST].into_iter().collect::<Set<_>>()
        );
        let text = fs::read_to_string(dir.join("nic1.owned")).unwrap();
        assert_eq!(
            text.lines().count(),
            2,
            "one line per address, however often it is registered:\n{text}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A --flush from a second process replaces the note while the daemon is
    /// adding to it. Appending to what it left behind is right; carrying on
    /// with a copy in memory that describes the file it replaced is not.
    ///
    /// This pins the ordinary case: the flush lands before the append reads
    /// the file, and the append works from what it found. It does *not*
    /// exercise the size check in `append_owned`, which covers the flush
    /// landing between that read and the write - a window this test cannot
    /// produce without a hook in the code to stop in. The check is kept
    /// because it is two comparisons and the alternative is a copy in memory
    /// that quietly disagrees with the file; its worth is argued, not
    /// measured.
    #[test]
    fn a_note_rewritten_between_read_and_append_is_not_remembered() {
        let dir = scratch("append-race");
        let path = dir.join("nic1.owned");
        let s = Syncer::new(Vec::new(), dir.clone());
        s.save_owned(
            "nic1",
            &[BEHIND_NIC, BEHIND_GUEST].into_iter().collect::<Set<_>>(),
        );
        assert_eq!(s.load_owned("nic1").len(), 2); // the copy is now warm

        // What --flush leaves: a different file, through rename, holding
        // nothing.
        let other = dir.join("flushed");
        fs::write(&other, "").unwrap();
        fs::rename(&other, &path).unwrap();

        s.append_owned("nic1", &[UPLINK_WARD]);

        assert_eq!(
            s.load_owned("nic1"),
            [UPLINK_WARD].into_iter().collect::<Set<_>>(),
            "the file is the truth: it holds what was appended and nothing else"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// What a link message is about decides whether the driver has to be
    /// asked about virtual function addresses again - the most expensive
    /// thing a pass does. A container's veth is not a reason; the interface
    /// that hands out the functions is.
    ///
    /// Verified by mutation: answering true always makes the veth case fail,
    /// answering false always makes the other three fail.
    #[test]
    fn only_an_interface_with_virtual_functions_makes_their_addresses_stale() {
        let topo = host(mac(1));
        let veth = topo.index_of("veth0").unwrap();
        let pf = topo.index_of("nic1").unwrap(); // has vfs(1) in the fixture
        let plain = topo.index_of("nic2").unwrap();

        let now = Some(&topo);
        assert!(
            !vf_may_have_changed(now, now, &[veth]),
            "a container's veth says nothing about virtual functions"
        );
        assert!(
            !vf_may_have_changed(now, now, &[plain, veth]),
            "nor does an ordinary NIC in the same bridge"
        );
        assert!(
            vf_may_have_changed(now, now, &[pf]),
            "the interface handing out virtual functions is a reason to ask"
        );
        assert!(
            vf_may_have_changed(now, now, &[veth, pf]),
            "one reason in the batch is enough"
        );
        assert!(
            vf_may_have_changed(now, now, &[9999]),
            "an interface neither picture has is a reason to ask"
        );

        // A veth that has just been destroyed: gone from the new picture,
        // still in the old one, and never a reason to ask. Judging by the new
        // picture alone made every deletion a reason - which on a host with
        // containers is every second link message.
        let gone = crate::sysfs::Topology::assemble(Vec::new(), crate::hash::map());
        assert!(
            !vf_may_have_changed(now, Some(&gone), &[veth]),
            "what it was is in the picture from before it went"
        );
        assert!(
            vf_may_have_changed(now, Some(&gone), &[pf]),
            "and a virtual function going is still a reason"
        );
    }

    /// The same rule for a virtual function itself: a guest setting its own
    /// address is announced as a link message about that interface, and it
    /// changes what must be excluded without moving a forwarding entry.
    #[test]
    fn a_virtual_function_of_its_own_counts_too() {
        let topo = Builder::new()
            .add("pf0", 2, Some(mac(1)))
            .vfs(2)
            .add("pf0v0", 3, Some(mac(2)))
            .physfn("pf0")
            .add("tap0", 4, Some(mac(3)))
            .build();
        let now = Some(&topo);
        assert!(vf_may_have_changed(
            now,
            now,
            &[topo.index_of("pf0v0").unwrap()]
        ));
        assert!(!vf_may_have_changed(
            now,
            now,
            &[topo.index_of("tap0").unwrap()]
        ));
    }

    /// Two processes writing the same note must not share a temporary file:
    /// one would truncate what the other is writing and rename the result
    /// into place. The name carries the process id for that reason.
    ///
    /// Verified by mutation: dropping the pid from the name fails this.
    #[test]
    fn the_temporary_note_is_this_process_alone() {
        let dir = scratch("tmp-name");
        let s = Syncer::new(Vec::new(), dir.clone());
        // A temporary file left by another process, mid-write.
        let theirs = dir.join(format!(".nic1.owned.{}.tmp", std::process::id() + 1));
        fs::create_dir_all(&dir).unwrap();
        fs::write(&theirs, "half a note").unwrap();

        s.save_owned("nic1", &[BEHIND_NIC].into_iter().collect::<Set<_>>());

        assert_eq!(
            s.load_owned("nic1"),
            [BEHIND_NIC].into_iter().collect::<Set<_>>(),
            "our write went through untouched"
        );
        assert_eq!(
            fs::read_to_string(&theirs).unwrap(),
            "half a note",
            "and did not go through the other process's temporary file"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A guest that moved away and came back: its address is in the set the
    /// last pass saw on the wire, so the fast path refuses to register it -
    /// rightly, because only a full dump can say where it is now. What it
    /// must not do is refuse *and* decide the batch was worth nothing: the
    /// full pass is the only thing that ever replaces that set, so the
    /// refusal would suppress its own correction and the guest would stay
    /// unreachable from the VFs until the timer, up to a full interval.
    ///
    /// Verified by mutation: without `ours = true` on that path this returns
    /// Nothing and no pass is bought.
    #[test]
    fn an_address_the_wire_set_still_holds_still_buys_a_pass() {
        let dir = scratch("wire-return");
        let topo = host(mac(1));
        let mut s = ready_syncer(&dir);
        s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
        // The last pass saw this address out on the wire.
        s.carried_wire
            .insert("nic1".into(), [BEHIND_NIC].into_iter().collect::<Set<_>>());

        let mut sock = FakeSock::default();
        let urgency = s
            .fast_apply(
                &mut sock,
                &topo,
                // ... and now it is learnt behind the bridge again.
                &[(crate::netlink::RTM_NEWNEIGH, learned(3, 10, BEHIND_NIC))],
            )
            .unwrap();

        assert!(
            sock.added.is_empty(),
            "the fast path cannot know it has really moved back; only a dump can"
        );
        assert_eq!(
            urgency,
            Urgency::Now,
            "but the pass that can find out has to be scheduled"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The fast path and the full pass have to agree about whether the
    /// carried answer on the virtual functions can still be believed. It used
    /// to be the pass's business alone: the fast path reused the answer
    /// whenever the list of physical functions matched, which is not the
    /// question - the addresses change without that list changing at all.
    ///
    /// Verified by mutation: reusing the answer on a PF-list match alone lets
    /// the fast path register a virtual function's own address here.
    #[test]
    fn the_fast_path_asks_again_when_the_answer_went_stale() {
        let dir = scratch("vf-stale");
        let topo = host(mac(1));
        let mut s = ready_syncer(&dir);
        // What the last pass was told, and then somebody set a VF's address.
        s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
        s.vf_stale = true;

        let fresh: Mac = [0x02, 0x99, 0x99, 0x99, 0x99, 0x99];
        let mut sock = FakeSock {
            vf: vec![(2, fresh)],
            ..Default::default()
        };
        s.fast_apply(
            &mut sock,
            &topo,
            &[(crate::netlink::RTM_NEWNEIGH, learned(3, 10, fresh))],
        )
        .unwrap();

        assert!(
            sock.added.is_empty(),
            "the address is a virtual function's own; registering it sends \
             that guest's traffic past it: {:?}",
            sock.added
        );
        assert!(!s.vf_stale, "and having asked, the answer is current again");
        let _ = fs::remove_dir_all(&dir);
    }

    /// An interface reload takes a bridge away for a moment. Deleting a live
    /// uplink's registrations over that - within 200 ms, on a routine
    /// `ifreload -a` - is the outage this daemon exists to prevent, performed
    /// by the daemon. A device has to stay gone before its note is believed
    /// to be an orphan.
    ///
    /// Verified by mutation: with the grace period ignored the first pass
    /// takes the addresses out.
    #[test]
    fn a_device_that_blinks_is_not_an_orphan() {
        let dir = scratch("orphan-grace");
        let topo = host(mac(1));
        let mut s = ready_syncer(&dir);
        s.orphan_grace = Dur::from_secs(60);
        s.save_owned("nic1", &[BEHIND_NIC].into_iter().collect::<Set<_>>());

        // The bridge went; autodetection finds nothing this pass.
        s.pairs.clear();
        let mut sock = FakeSock::default();
        s.drop_orphans(&mut sock, &topo, true);
        assert!(
            sock.removed.is_empty(),
            "an interface that has been gone for an instant is not gone: {:?}",
            sock.removed
        );
        assert_eq!(
            s.load_owned("nic1").len(),
            1,
            "and its note stays, or the entries become orphans nothing owns"
        );

        // It comes back, as it does after ifreload.
        s.pairs.push(pair());
        s.drop_orphans(&mut sock, &topo, true);
        assert!(sock.removed.is_empty(), "still nothing to remove");

        // A device that really is gone, with the grace period behind it.
        s.pairs.clear();
        s.orphan_grace = Dur::ZERO;
        s.drop_orphans(&mut sock, &topo, true);
        assert_eq!(
            sock.removed,
            vec![(2, BEHIND_NIC)],
            "what is genuinely gone still gets cleaned up"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
