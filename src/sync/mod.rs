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
use crate::sysfs::Topology;

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
/// carried VF exclusions included - and writes nothing; committing writes
/// and trusts the (by then fresh) skip sets.
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

/// The physical function behind an uplink, or the uplink itself when it is
/// not a virtual function.
///
/// Both the pass and the exclusion set have to arrive at the same answer: the
/// pass asks the kernel about this interface's virtual functions, and the
/// exclusion set looks the results up by its index. Two spellings of the same
/// rule would silently stop excluding anything.
fn physical_function(topo: &Topology, dev: u32) -> u32 {
    topo.at(dev).and_then(|l| l.physfn).unwrap_or(dev)
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
        _ => vec![physical_function(topo, dev)],
    }
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
            warned_unknown_vf: crate::hash::set(),
            unreadable: std::cell::RefCell::new(crate::hash::set()),
            lock_warned: std::cell::RefCell::new(crate::hash::set()),
            dir_checked: std::cell::Cell::new(false),
            dir_list_warned: std::cell::Cell::new(false),
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
                        let _ = fs::remove_file(self.state_path(&dev));
                    }
                    return;
                }
                let (gone, kept) = match topo.get(&dev) {
                    Some(link) => self.unregister_all(sock, &dev, link.index, &owned),
                    // The device itself is gone, and a unicast filter does not
                    // outlive its netdev - the entries died with it. (A device
                    // that was merely renamed keeps its entries under the new
                    // name, but a note under the old name could never reach
                    // them anyway.)
                    None => (owned.len(), crate::hash::set()),
                };
                if kept.is_empty() && self.note_is_readable(&dev) {
                    note!("{dev}: no longer an uplink, removed {gone} address(es)");
                    let _ = fs::remove_file(self.state_path(&dev));
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
        for pf in physical_functions(topo, dev) {
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
    pub fn note_check_probe(&self, dev: &str, mac: &Mac) {
        self.append_owned(dev, &[*mac]);
    }

    pub fn forget_check_probe(&self, dev: &str, mac: &Mac) {
        let before = self.load_owned(dev);
        if !before.contains(mac) {
            return;
        }
        let mut after = before.clone();
        after.remove(mac);
        // As a difference, so whatever a parallel writer noted meanwhile
        // survives - same rule as every other write-back.
        self.save_owned_merged(dev, &before, &after);
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
                if e.ifindex == port {
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
            for pf in physical_functions(topo, idx) {
                if topo.at(pf).is_some() && !pfs.contains(&pf) {
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
            let (mut want, mut stacked, mut wire) =
                self.desired(topo, bridge_index, dev_index, port, &fdb, &vf_macs);

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
            if vf_carried && want.iter().any(|m| !present.contains(m)) {
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
                let (w, st, wi) = self.desired(topo, bridge_index, dev_index, port, &fdb, &vf_macs);
                want = w;
                stacked = st;
                wire = wi;
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

            let owned_before = self.load_owned(&pair.dev);
            // While the note cannot be read, nothing new is registered for
            // this device: write_owned will refuse the note afterwards, and
            // an entry registered in that window would be permanently
            // ownerless - read_owned promised "leaving that device alone
            // until it can be read", and the register loop is part of that
            // promise. Removals need no guard: owned reads empty.
            let note_ok = self.note_is_readable(&pair.dev);
            let mut suppressed = 0usize;
            let mut owned = owned_before.clone();
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
                    if !note_ok {
                        added -= 1;
                        suppressed += 1;
                        continue;
                    }
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

            if suppressed > 0 {
                eprintln!(
                    "warning: {}: note unreadable, {suppressed} address(es) not \
                     registered until it can be read",
                    pair.dev
                );
                timings.failures.push(format!(
                    "{}: note unreadable, {suppressed} registration(s) held back",
                    pair.dev
                ));
            }

            // Only when this pass changed something: the merge takes the
            // note's lock and reads the file past the stat cache, which an
            // idle pass has no reason to pay - and an empty difference can
            // never change what is merged.
            if apply
                && owned != owned_before
                && !self.save_owned_merged(&pair.dev, &owned_before, &owned)
            {
                // The note does not name what was just registered, and an
                // entry no note names would never be removed again. Take the
                // fresh ones back out; the next pass retries them once the
                // note can be written.
                let unnoted: Vec<Mac> = owned.difference(&owned_before).copied().collect();
                for mac in &unnoted {
                    let _ = sock.set_self_fdb(dev_index, mac, false);
                }
                added -= unnoted.len();
                eprintln!(
                    "warning: {}: note write failed, unregistered {} fresh \
                     address(es) for retry",
                    pair.dev,
                    unnoted.len()
                );
                timings.failures.push(format!(
                    "{}: note write failed, {} registration(s) rolled back",
                    pair.dev,
                    unnoted.len()
                ));
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
        // A deletion is a reason to look, never to hurry: a registration that
        // outlives its guest by a few seconds costs nothing but a filter slot.
        let mut urgency = if events
            .iter()
            .any(|(kind, _)| *kind == crate::netlink::RTM_DELNEIGH)
        {
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
                    vf_own: Self::vf_reported(topo, dev, &vf_macs),
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
            // The snapshot is taken before a window that can stand on rtnl
            // for seconds; written back as a difference, not as the whole
            // set, or a parallel writer's additions in that window are lost.
            let owned_before = self.load_owned(&fp.dev);
            let mut owned = owned_before.clone();
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
                        note!(
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
                    // owns is the orphan the notes exist to prevent. And buy
                    // a pass: the guest's traffic is being misdirected right
                    // now, and a batch made only of this failure would
                    // otherwise end quiet and retry nothing.
                    Err(e) => {
                        urgency = Urgency::Now;
                        eprintln!(
                            "warning: {}: cannot unregister {}: {e}",
                            fp.dev,
                            format_mac(mac)
                        );
                    }
                }
            }
            if changed {
                self.save_owned_merged(&fp.dev, &owned_before, &owned);
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
            let mut would: Map<String, Vec<Mac>> = crate::hash::map();
            for (kind, entry) in events {
                if *kind != crate::netlink::RTM_NEWNEIGH {
                    continue;
                }
                self.fast_add(sock, topo, entry, &pairs, &mut would, FastPhase::Decide);
            }
            // An address already registered and ours was vetted by the
            // fresh answer that let it in; re-learning it grows nothing.
            // Without this, the tail of a burst - the prompt pass has long
            // registered everything, the queued learns arrive one by one -
            // bought one driver question per re-learn, invisible to every
            // latency figure because the addresses were already in.
            for (dev, macs) in would.iter_mut() {
                self.with_owned(dev, |o| macs.retain(|m| !o.contains(m)));
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
                    fp.vf_own = Self::vf_reported(topo, fp.index, &fresh);
                    // fp.reflected stands: within this batch the wire keeps
                    // the last word, fresh answer or not.
                }
                // The catch this exists for is rare enough to be told about.
                for (dev, macs) in &would {
                    let Some(fp) = pairs.iter().find(|f| &f.dev == dev) else {
                        continue;
                    };
                    for mac in macs {
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

        let mut registered: Map<String, Vec<Mac>> = crate::hash::map();
        for (kind, entry) in events {
            if *kind != crate::netlink::RTM_NEWNEIGH {
                continue;
            }
            if self.fast_add(
                sock,
                topo,
                entry,
                &pairs,
                &mut registered,
                FastPhase::Commit,
            ) {
                urgency = Urgency::Now;
            }
        }
        for (dev, added) in registered {
            if !self.append_owned(&dev, &added) {
                // The note does not name them, and an entry no note names
                // would never be removed again. Take them back out; the pass
                // this buys retries them once the note can be written.
                if let Some(fp) = pairs.iter().find(|f| f.dev == dev) {
                    for mac in &added {
                        let _ = sock.set_self_fdb(fp.index, mac, false);
                    }
                }
                eprintln!(
                    "warning: {dev}: note write failed, unregistered {} fresh \
                     address(es) for retry",
                    added.len()
                );
                urgency = Urgency::Now;
            }
        }
        Ok(urgency)
    }

    /// Returns whether this entry was any of our business - registered,
    /// refused, or something the full pass will have to look at. An entry
    /// that concerns none of the pairs returns false, and a batch made
    /// entirely of those does not earn a pass.
    ///
    /// In the decide phase nothing is written: what would have been
    /// registered lands in `registered` and the filter is left alone.
    fn fast_add(
        &self,
        sock: &mut dyn FdbWriter,
        topo: &Topology,
        entry: &FdbEntry,
        pairs: &[FastPair],
        registered: &mut Map<String, Vec<Mac>>,
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
                        .push(entry.mac);
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
            if phase == FastPhase::Decide {
                registered
                    .entry(fp.dev.clone())
                    .or_default()
                    .push(entry.mac);
                continue;
            }
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
                let (gone, kept) = match topo.get(&dev) {
                    Some(link) => self.unregister_all(sock, &dev, link.index, &owned),
                    None => (owned.len(), crate::hash::set()),
                };
                if kept.is_empty() && self.note_is_readable(&dev) {
                    let _ = fs::remove_file(self.state_path(&dev));
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
