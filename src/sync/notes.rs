//! The ownership notes: which addresses this daemon put into which card.
//!
//! One invariant: an entry this daemon added must always have a line on
//! record saying so, or nothing will ever take it back out. The files in the
//! state directory are the truth (a --once or --flush from a second process
//! writes them while the daemon runs), the in-memory copies a stat-checked
//! shortcut, and every writer holds the note's lock across its whole window;
//! the sweeps in the parent module read, unregister and unlink under that
//! same lock.
//!
//! pub(super), the lot of it: sync's inner organ, not an interface.

use super::*;
use crate::note;

/// A note as it was last read, with what it takes to tell whether the file
/// is still the same one, unchanged.
pub(super) struct Note {
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

/// Format marker of the quiet-keep memory file, bumped whenever the numbers'
/// meaning changes: an older or newer file is ignored, which costs the keeps
/// for one ARP cycle.
const PORTS_FORMAT: &str = "sriov-mac-sync ports 3";

impl Syncer {
    pub(super) fn state_path(&self, dev: &str) -> PathBuf {
        self.state_dir.join(format!("{dev}.owned"))
    }

    pub(super) fn index_path(&self, dev: &str) -> PathBuf {
        self.state_dir.join(format!(".{dev}.owned.index"))
    }

    pub(super) fn ports_path(&self, dev: &str) -> PathBuf {
        self.state_dir.join(format!(".{dev}.owned.ports"))
    }

    /// Milliseconds since boot, the clock the quiet memory is stamped in.
    ///
    /// `Instant` cannot be written down, a wall clock steps under NTP;
    /// `CLOCK_BOOTTIME` counts monotonically from boot, suspends included -
    /// and the memory lives in a tmpfs that starts empty after a reboot, so
    /// stamp and clock always come from the same boot. Milliseconds because
    /// between passes this daemon is blind anyway; two passes in one tick are
    /// told apart by the caller nudging the pass stamp, not by nanoseconds.
    pub(super) fn boot_millis() -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // CLOCK_BOOTTIME is read-only and the struct is ours; the call
        // cannot fail with these arguments on any kernel this runs on, and
        // a zero answer would only make everything look equally young.
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
        (ts.tv_sec.max(0) as u64)
            .saturating_mul(1000)
            .saturating_add(ts.tv_nsec.max(0) as u64 / 1_000_000)
    }

    /// The quiet memory as last written: which bridge port each owned address
    /// was learnt behind, and when the bridge last held it. Every owned
    /// learnt address has a line; quiet is the one whose stamp is older than
    /// the last pass.
    ///
    /// Beside the note, not in it, so the note stays a plain address list any
    /// build can read (as with the index record). The first line is the
    /// marker `sriov-mac-sync ports 3`; each line after it is
    ///
    /// <address> <port-name> <port-ifindex> <last-seen-millis>
    ///
    /// The port is written both ways: a line is believed only while the name
    /// still carries that very index, so a replaced or moved interface loses
    /// its memory instead of inheriting somebody else's.
    ///
    /// Evidence, never ownership: losing the file costs the keeps and nothing
    /// else.
    pub(super) fn read_ports(&self, dev: &str) -> Vec<(Mac, String, u32, u64)> {
        let Ok(text) = fs::read_to_string(self.ports_path(dev)) else {
            return Vec::new();
        };
        // The first line says what the numbers mean: an unrecognised file is
        // no memory. (An earlier format recorded a different quantity, and
        // reading it as this one made every carried entry look silent since
        // boot.)
        let mut lines = text.lines();
        if lines.next() != Some(PORTS_FORMAT) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for line in lines {
            let mut f = line.split_whitespace();
            let (Some(mac), Some(name), Some(index)) = (f.next(), f.next(), f.next()) else {
                continue;
            };
            let (Some(mac), Ok(index)) = (crate::netlink::parse_mac(mac), index.parse::<u32>())
            else {
                continue;
            };
            // Every line carries when the bridge was last seen holding
            // the address; a line without a readable one says nothing
            // this can use.
            let Some(Ok(seen)) = f.next().map(|v| v.parse::<u64>()) else {
                continue;
            };
            out.push((mac, name.to_string(), index, seen));
        }
        out
    }

    /// Write the quiet memory, under the note's lock and through a temporary
    /// file, like the note itself. Says so once per device when it cannot,
    /// then carries on: the memory still works in this process. Precondition:
    /// `lines` sorted and non-empty - the caller sorts for its change
    /// comparison and hands the empty case to removal.
    pub(super) fn write_ports(&self, dev: &str, lines: &[String]) -> bool {
        let text = format!("{PORTS_FORMAT}\n{}\n", lines.join("\n"));
        if let Err(e) = self.put_file(&self.ports_path(dev), &text) {
            if self.said.borrow_mut().ports.insert(dev.to_string()) {
                eprintln!(
                    "warning: cannot write the quiet-keep memory for {dev}: {e} - \
                     addresses held while their port lives will be forgotten if \
                     this daemon restarts"
                );
            }
            return false;
        }
        true
    }

    /// Record which interface a device's note is about - beside the note, so
    /// the note stays a plain address list.
    ///
    /// A note is found by name, and a name is the one thing a rename takes
    /// away while interface, entries and index live on; the recorded index
    /// lets the orphan sweep and --flush tell a rename from a device really
    /// gone. Within one boot an index identifies an interface outright: the
    /// kernel never re-uses one, and /run does not outlive a boot.
    ///
    /// Best-effort: without the record a rename is simply not followed.
    /// Cached so the write happens when the answer changes, and cached even
    /// on a failed write so the warning is said once.
    pub(super) fn note_index(&self, dev: &str, index: u32) {
        if self.indices.borrow().get(dev) == Some(&index) {
            return;
        }
        // Atomic like every other writer here: a second process's
        // renamed_target reading a torn index record would fail to follow
        // exactly the rename the record exists for.
        let wrote = self.put_file(&self.index_path(dev), &format!("{index}\n"));
        if let Err(e) = wrote {
            eprintln!(
                "warning: cannot record which interface {dev} is: {e} - \
                 a rename of it would not be followed"
            );
        }
        self.indices.borrow_mut().insert(dev.to_string(), index);
    }

    /// The index recorded for a device's note, if any run recorded one. Read
    /// from the file, not the cache: the rename paths mostly run in a process
    /// that never stamped it.
    pub(super) fn noted_index(&self, dev: &str) -> Option<u32> {
        fs::read_to_string(self.index_path(dev))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// A note that is settled: the file, its index record and the cached
    /// copies go together, or a later run reads a record about a note that
    /// no longer exists.
    pub(super) fn remove_note(&self, dev: &str) {
        let _ = fs::remove_file(self.state_path(dev));
        let _ = fs::remove_file(self.index_path(dev));
        // The quiet memory is about the addresses this note names; without
        // the note it says nothing, and a device that comes back records
        // afresh from its first dump.
        let _ = fs::remove_file(self.ports_path(dev));
        self.notes.borrow_mut().remove(dev);
        self.indices.borrow_mut().remove(dev);
    }

    /// The directory the notes live in, made if absent, reachable by nobody
    /// but the user running this.
    ///
    /// `create_dir_all` asks for 0777 minus umask, so the mode would depend
    /// on how the daemon was started; a umask of 0 leaves it world-writable,
    /// and any local user could replace a note or plant a symlink for a root
    /// daemon to write through. 0700 is asked for outright.
    ///
    /// An existing directory is looked at, not trusted: it outlives the
    /// process, so one made by an older build or by hand is the one this run
    /// writes into. Narrowed is only a directory others may *write*. One
    /// others may only read is left alone: a source install under a unit
    /// without `RuntimeDirectoryMode=` gets 0755 from systemd, and changing
    /// it back every start would be a warning a day. The notes themselves are
    /// 0600 either way.
    pub fn ensure_state_dir(&self) -> io::Result<()> {
        // `recursive` returns Ok for a directory that was already there, and
        // leaves its mode alone - hence the check that follows.
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.state_dir)?;
        let meta = fs::metadata(&self.state_dir)?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            match fs::set_permissions(&self.state_dir, perms) {
                Ok(()) => eprintln!(
                    "warning: {} was mode {mode:o}, which lets other users put \
                     what they like where the ownership notes go - narrowed to 700",
                    self.state_dir.display()
                ),
                Err(e) => eprintln!(
                    "warning: {} is mode {mode:o} and cannot be narrowed: {e} - \
                     another user can replace the ownership notes, and so decide \
                     what this removes from a card",
                    self.state_dir.display()
                ),
            }
        }
        Ok(())
    }

    /// What this daemon put there itself, on disk so a restart neither
    /// forgets its entries nor claims everybody else's.
    ///
    /// The file is the truth: --once and --flush write these files while the
    /// daemon runs, and a daemon believing a remembered copy would go on
    /// owning entries somebody has since taken - and never clean them up.
    /// What is remembered is the file's identity (inode, size, timestamp), so
    /// *checking* the copy costs a stat; any writer changes at least one of
    /// the three - this daemon and --flush replace through rename.
    pub(super) fn load_owned(&self, dev: &str) -> Set<Mac> {
        self.with_owned(dev, |s| s.clone())
    }

    /// The note, without copying it. One check of the file, then the answer.
    pub(super) fn with_owned<R>(&self, dev: &str, f: impl FnOnce(&Set<Mac>) -> R) -> R {
        let usable = match fs::metadata(self.state_path(dev)) {
            Ok(meta) => self
                .notes
                .borrow()
                .get(dev)
                .is_some_and(|note| note.is_still(&meta)),
            Err(_) => false,
        };
        if !usable {
            // Stat, read, stat again, and believe the copy only when the file
            // did not move under the read: a note replaced between read and
            // `remember` was otherwise cached with the NEW identity and OLD
            // contents, and the timestamp guard cannot see it (inode mtimes
            // come from the coarse clock). Not unit-pinned - the window needs
            // a second writer inside one read; the suite pins that a replaced
            // file is read again even under the old timestamp.
            let before = fs::metadata(self.state_path(dev)).ok();
            let set = self.read_owned(dev);
            let after = fs::metadata(self.state_path(dev)).ok();
            let steady = match (&before, &after) {
                (Some(a), Some(b)) => {
                    a.ino() == b.ino()
                        && a.len() == b.len()
                        && (a.mtime(), a.mtime_nsec()) == (b.mtime(), b.mtime_nsec())
                }
                _ => false,
            };
            if self.note_is_readable(dev) && steady {
                // `after` is Some here: `steady` cannot be true otherwise.
                self.remember(dev, &set, after.as_ref());
            } else if self.note_is_readable(dev) {
                // Readable, but it moved while we read it: the set is
                // whatever we got, the next look reads again. The cached
                // index goes too - the record lives beside the note and a
                // second-terminal --flush unlinks both - or note_index
                // short-circuits for the life of the process and a later
                // rename reads as a disappearance.
                self.notes.borrow_mut().remove(dev);
                self.indices.borrow_mut().remove(dev);
                return f(&set);
            } else {
                // The read failed: `read_owned` then returns "could not
                // tell", not "owns nothing". Remembering that would be worse
                // than the failure - the copy is believed while identity,
                // size and timestamp hold, and a file this could not read is
                // a file nothing changed, so one unreadable moment would
                // stand for good and every entry the note names would sit in
                // the card with nothing on record. Nothing on record instead,
                // so the next look reads again.
                self.notes.borrow_mut().remove(dev);
                // The index record goes with the note - a second-terminal
                // --flush unlinks both. Otherwise the cached index
                // short-circuits every later write and rename-following stays
                // dead for the life of the process.
                self.indices.borrow_mut().remove(dev);
            }
        }
        // The shared borrow of `notes` is held while `f` runs: a callback
        // that calls load_owned, read_owned or remember here is a
        // double-borrow panic, an abort in the release profile.
        match self.notes.borrow().get(dev) {
            Some(note) => f(&note.macs),
            // Nothing on record: no file, or one that could not be read.
            None => f(&crate::hash::set()),
        }
    }

    /// Note what was just read or written, with what the file looks like now,
    /// so the next read can be a stat.
    ///
    /// `meta` is what the caller knows the file to be: `with_owned` passes
    /// the stat it took *after* the read and proved identical to the one
    /// before - a third, later stat here would cache old contents under a
    /// newer identity, the window the steadiness check closes. Callers that
    /// just wrote pass `None`.
    pub(super) fn remember(&self, dev: &str, set: &Set<Mac>, meta: Option<&fs::Metadata>) {
        let looked;
        let meta = match meta {
            Some(m) => m,
            None => {
                looked = fs::metadata(self.state_path(dev)).ok();
                match &looked {
                    Some(m) => m,
                    None => {
                        // No file: nothing to recognise later. Forget any
                        // older copy rather than keep one that describes a
                        // file that is gone.
                        self.notes.borrow_mut().remove(dev);
                        return;
                    }
                }
            }
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

    pub(super) fn read_owned(&self, dev: &str) -> Set<Mac> {
        let mut set = crate::hash::set();
        match fs::read_to_string(self.state_path(dev)) {
            Ok(text) => {
                for (no, line) in text.lines().enumerate() {
                    match crate::netlink::parse_mac(line.trim()) {
                        Some(mac) => {
                            set.insert(mac);
                        }
                        None if line.trim().is_empty() => {}
                        // A line nobody can read is an entry nobody will ever
                        // take back out of the card. Saying so is all that can
                        // be done, but silence would look like health.
                        None => eprintln!(
                            // Its NUMBER and LENGTH, never its bytes:
                            // whatever file carries the device's name is read
                            // here, `noted_devices` does not ask what kind,
                            // and a symlink `zzz.owned` at /etc/shadow would
                            // otherwise have its contents copied into the
                            // journal by a root daemon.
                            "warning: {}: unreadable line {} ({} bytes) in the \
                             ownership note, the entry it named is now nobody's",
                            self.state_path(dev).display(),
                            no + 1,
                            line.len()
                        ),
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                // Not the same as owning nothing, and the difference is
                // destructive: a pass would rename a fresh note over it,
                // --flush and the orphan sweep would unlink it - abandoning
                // entries still in the card. Said when it starts, not per
                // attempt: the file is read again on every look for as long
                // as it cannot be read, and a look happens per batch.
                if self.said.borrow_mut().unreadable.insert(dev.to_string()) {
                    eprintln!(
                        "warning: cannot read {}: {e} - leaving that device alone \
                         until it can be read",
                        self.state_path(dev).display()
                    );
                }
                return set;
            }
        }
        if self.said.borrow_mut().unreadable.remove(dev) {
            note!(
                "{}: readable again, {dev} is back in the reckoning",
                self.state_path(dev).display()
            );
        }
        set
    }

    /// Whether the note for this device could be read at all. Everything that
    /// would replace or unlink it has to ask first.
    pub(super) fn note_is_readable(&self, dev: &str) -> bool {
        !self.said.borrow().unreadable.contains(dev)
    }

    /// Hold the note against everybody else while it is rewritten.
    ///
    /// --once and --flush run by hand beside the daemon, and a pass takes
    /// long enough for that to land inside one (a single filter write has
    /// waited seconds on rtnl); whoever renamed last kept only its own lines,
    /// and an address the other had registered ended up owned by nobody -
    /// which --flush cannot clean up, because it iterates the notes.
    pub(super) fn locked<R>(&self, dev: &str, f: impl FnOnce() -> R) -> R {
        use std::os::fd::AsRawFd;
        // Every write goes through here, so the directory gets its one look
        // per run. An error is not reported here: the open below runs into it
        // too and names the file.
        if !self.dir_checked.replace(true) {
            let _ = self.ensure_state_dir();
        }
        let path = self.state_dir.join(format!(".{dev}.owned.lock"));
        let open = || {
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                // Never through a symlink, like every opener here: nothing is
                // written to this file, but a directory that was
                // group-writable before `ensure_state_dir` narrowed it can
                // hold links planted earlier. A refusal is a degradation the
                // caller handles.
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)
        };
        let file = open().or_else(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                self.ensure_state_dir()?;
                open()
            } else {
                Err(e)
            }
        });
        let file = match file {
            Ok(file) => file,
            // No lock to be had. Refusing to write would strand what was just
            // registered, so the note is written unlocked and this says so -
            // once per device: a line per batch on the learning path would
            // bury the one that matters, and a permission or read-only
            // filesystem does not come and go.
            Err(e) => {
                if self.said.borrow_mut().lock.insert(dev.to_string()) {
                    eprintln!(
                        "warning: cannot lock {}: {e} - writing the ownership \
                         note for {dev} unlocked, so a --once or --flush run by \
                         hand at the same moment can lose entries from it",
                        path.display()
                    );
                }
                return f();
            }
        };
        let fd = file.as_raw_fd();
        // Taking the lock can fail - EINTR, since nothing sets SA_RESTART, is
        // the one that happens. It is retried; any other failure gets the
        // same warning as a failed open, rather than running on silently.
        loop {
            if unsafe { libc::flock(fd, libc::LOCK_EX) } == 0 {
                break;
            }
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if self.said.borrow_mut().lock.insert(dev.to_string()) {
                eprintln!(
                    "warning: cannot take the lock on {}: {e} - writing the \
                     ownership note for {dev} unlocked, so a --once or --flush \
                     run by hand at the same moment can lose entries from it",
                    path.display()
                );
            }
            break;
        }
        let out = f();
        // Dropping the file below releases the lock either way; the explicit
        // unlock only shortens the window, so its result changes nothing.
        unsafe { libc::flock(fd, libc::LOCK_UN) };
        out
    }

    /// Write the note as the difference this caller made, not as the set it
    /// started from: whatever else has been added meanwhile stays.
    pub(super) fn save_owned_merged(&self, dev: &str, before: &Set<Mac>, after: &Set<Mac>) {
        // No caller reaches this today (the one production site is gated on
        // the owned set changing, which a dry run cannot cause). It stays
        // because "a dry run writes nothing" is a promise to the operator,
        // kept where the writing happens.
        if self.dry_run {
            return;
        }
        self.locked(dev, || {
            let current = self.read_owned(dev);
            let mut merged = current;
            for mac in after.iter() {
                if !before.contains(mac) {
                    merged.insert(*mac);
                }
            }
            for mac in before.iter() {
                if !after.contains(mac) {
                    merged.remove(mac);
                }
            }
            self.write_owned(dev, &merged);
        })
    }

    /// Seed a note with exactly this set. No production path writes a whole
    /// set any more - pass and reflection write differences so a parallel
    /// writer's lines survive; the tests build starting states this way.
    #[cfg(test)]
    #[cfg(test)]
    pub(super) fn save_owned(&self, dev: &str, set: &Set<Mac>) {
        if self.dry_run {
            return;
        }
        self.locked(dev, || self.write_owned(dev, set));
    }

    /// The one atomic writer everything on disk goes through: a temporary
    /// file, then a rename onto `dest`.
    ///
    /// Through a temporary because a file truncated mid-write would read as
    /// "we own nothing" or as no memory. Its name is the destination's with a
    /// hidden prefix and this process's pid: a prefix because "eth0.new" is a
    /// legal interface name whose own note would otherwise be this file; the
    /// pid because --once and --flush write beside the daemon, and two
    /// writers sharing one temporary means one truncates what the other
    /// writes and renames it into place.
    ///
    /// 0600 rather than `fs::write`'s 0666-minus-umask: the renamed file
    /// keeps the temporary's mode, and state other users may write decides
    /// what this daemon takes out of a card. The second lock on the same door
    /// as the 0700 directory, for a directory made by something else.
    fn put_file(&self, dest: &std::path::Path, text: &str) -> io::Result<()> {
        let name = dest
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let tmp = self
            .state_dir
            .join(format!(".{name}.{}.tmp", std::process::id()));
        let put = |tmp: &PathBuf| -> io::Result<()> {
            use std::io::Write;
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                // Never through a symlink: `ensure_state_dir` narrows a
                // writable directory but cannot remove what was planted
                // before, and this daemon writes as root.
                .custom_flags(libc::O_NOFOLLOW)
                .open(tmp)?
                .write_all(text.as_bytes())
        };
        if let Err(e) = put(&tmp) {
            // The directory is created by the unit and survives a restart;
            // asking for it on every write was a syscall per write for a
            // thing that is already there.
            if e.kind() != io::ErrorKind::NotFound {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
            self.ensure_state_dir()?;
            if let Err(e) = put(&tmp) {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
        }
        // Both error paths take the temporary with them: a half-written
        // `.<dev>.owned.<pid>.tmp` left in the state directory is a file the
        // next reader has to guess about.
        fs::rename(&tmp, dest).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            e
        })
    }

    /// Take one address out of a note without touching the rest: a `--check`
    /// that reordered a note is a trace where the point was to leave none.
    /// The other lines keep their bytes and order. Under the caller's lock.
    pub(super) fn drop_line_locked(&self, dev: &str, mac: &Mac) {
        let Ok(text) = fs::read_to_string(self.state_path(dev)) else {
            return;
        };
        let wanted = format_mac(mac);
        let kept: Vec<&str> = text
            .lines()
            .filter(|l| l.trim() != wanted && !l.trim().is_empty())
            .collect();
        if kept.is_empty() {
            // The note existed for this address alone - it came into being
            // with the probe and goes with it, index record and all.
            self.remove_note(dev);
            return;
        }
        let text = kept.join("\n") + "\n";
        // Either way the remembered copy is about a file that changed, or
        // that is no longer known to hold what it claims.
        self.notes.borrow_mut().remove(dev);
        if let Err(e) = self.put_file(&self.state_path(dev), &text) {
            eprintln!("warning: cannot write the ownership note for {dev}: {e}");
        }
    }

    /// The write itself, every caller holding the lock. Returns whether the
    /// note now records the set: a caller that registered on the strength of
    /// it has to know, or an entry no note names is never removed again.
    pub(super) fn write_owned(&self, dev: &str, set: &Set<Mac>) -> bool {
        if !self.note_is_readable(dev) {
            eprintln!(
                "warning: not writing the ownership note for {dev}: it could not \
                 be read, and replacing it would abandon whatever it names"
            );
            return false;
        }
        // Most passes change nothing, and rewriting the note every time is
        // pointless work on an idle host. The remembered copy answers without
        // reading; when it cannot be believed, load_owned reads, and the
        // comparison is against what is really there either way.
        if self.load_owned(dev) == *set {
            return true;
        }
        let mut lines: Vec<String> = set.iter().map(format_mac).collect();
        lines.sort();
        // An empty set is an empty file: `join + newline` wrote a lone
        // newline, and the next append produced a phantom blank first line -
        // harmless to the parser, visible to anything comparing notes.
        let text = if lines.is_empty() {
            String::new()
        } else {
            lines.join("\n") + "\n"
        };
        // A note that cannot be written strands every entry it should have
        // named
        // - the next pass counts them as foreign, forever - and must not fail
        //   in silence. The how (temporary, hidden pid name, 0600) lives on
        //   put_file.
        match self.put_file(&self.state_path(dev), &text) {
            Ok(()) => {
                self.remember(dev, set, None);
                true
            }
            Err(e) => {
                // The file and the copy have to agree, and neither is now
                // known to hold what was asked for.
                self.notes.borrow_mut().remove(dev);
                eprintln!("warning: cannot write the ownership note for {dev}: {e}");
                false
            }
        }
    }

    /// Add addresses to a note without rewriting it.
    ///
    /// The fast path only adds, and a note is an unordered list, so an
    /// addition is a line at the end. Rewriting meant formatting and sorting
    /// every address once per batch - measured at 200 addresses a second:
    /// 1878 rewrites in ten seconds, the sorting the single largest thing the
    /// daemon did. The file stops being sorted, which nothing reads it for; a
    /// full pass rewrites it in order only when the set changed, and an
    /// unsorted file may stay so for a long time. What matters: a line, once
    /// written, is in the file before the entry it names is anybody's to
    /// remove.
    pub(super) fn append_owned(&self, dev: &str, added: &[Mac]) -> bool {
        // The dry-run half is unreachable as the modes stand - `--check`
        // is the only reader that could get here and it refuses
        // `--dry-run` - and stays for the reason `save_owned_merged` gives.
        if self.dry_run || added.is_empty() {
            return true;
        }
        // Only what the note does not already name: a duplicate line does not
        // change the set, so a full pass would never rewrite it away and the
        // file would grow by a line per re-registration for ever. Read and
        // write under one lock, or two writers both decide "not there yet".
        self.locked(dev, || self.append_owned_locked(dev, added).is_some())
    }

    /// The addresses actually appended - only a line this call added may be
    /// taken back out when the card refuses the address as somebody else's.
    /// `None` when the note could not take them; the caller then writes none
    /// of them into the card.
    /// Cut back a line a previous write did not finish, before adding to it.
    ///
    /// This is the one writer working in place; everything else goes through
    /// `put_file`. A `write_all` that stops mid-address (a full /run) leaves
    /// the file ending without a newline, the next append glues two addresses
    /// together, and the card holds an entry no note names - neither a pass
    /// nor --flush can reach it: the permanent orphan invariant 3 exists
    /// against, out of one full filesystem.
    ///
    /// Cutting back rather than rolling back on the error path: the pre-write
    /// length is not always known, a stale one would cut a parallel writer's
    /// lines, and neither helps against a write that never returned
    /// (SIGKILL). The next append under this lock tidies whatever left the
    /// file unfinished.
    fn finish_the_last_line(dev: &str, f: &mut fs::File) -> io::Result<()> {
        use std::io::{Read, Seek, SeekFrom};
        let mut all = Vec::new();
        f.seek(SeekFrom::Start(0))?;
        f.read_to_end(&mut all)?;
        if all.is_empty() || all.last() == Some(&b'\n') {
            return Ok(());
        }
        // Back to the end of the last line that IS finished. A file with no
        // newline at all was cut in its first line and keeps nothing.
        let keep = all.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        eprintln!(
            "warning: {dev}: the ownership note ended mid-line, {} byte(s) \
             from a write that did not finish - cut back before appending",
            all.len() - keep
        );
        f.set_len(keep as u64)
    }

    pub(super) fn append_owned_locked(&self, dev: &str, added: &[Mac]) -> Option<Vec<Mac>> {
        use std::io::Write;
        let mut set = self.load_owned(dev);
        // A note that cannot be read cannot be added to: what it holds is
        // unknown, read_owned has put the device on hold, and appending would
        // let a caller register on the strength of a note nobody can believe.
        if !self.note_is_readable(dev) {
            return None;
        }
        let fresh: Vec<Mac> = added
            .iter()
            .filter(|m| !set.contains(*m))
            .copied()
            .collect();
        if fresh.is_empty() {
            return Some(fresh);
        }
        let mut text = String::with_capacity(fresh.len() * 18);
        for mac in &fresh {
            text.push_str(&format_mac(mac));
            text.push('\n');
        }
        let path = self.state_path(dev);
        let opened = fs::OpenOptions::new()
            .read(true)
            .append(true)
            // Never through a symlink, for the reason `put_file` gives.
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .or_else(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    self.ensure_state_dir()?;
                    fs::OpenOptions::new()
                        .read(true)
                        .create(true)
                        .append(true)
                        .mode(0o600)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(&path)
                } else {
                    Err(e)
                }
            });
        // What the file held when read, so somebody else's write in between
        // can be told from nothing having happened: a second-process --flush
        // replaces the file, appending to what it left is right, but the copy
        // in memory then describes a file that no longer exists - its size
        // shows it.
        let was = self.notes.borrow().get(dev).map(|n| n.len);
        let wrote = opened.and_then(|mut f| {
            Self::finish_the_last_line(dev, &mut f)?;
            f.write_all(text.as_bytes())
        });
        match wrote {
            Ok(()) => {
                let expected = was.map(|w| w + text.len() as u64);
                set.extend(fresh.iter().copied());
                self.remember(dev, &set, None);
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
                Some(fresh)
            }
            Err(e) => {
                self.notes.borrow_mut().remove(dev);
                eprintln!("warning: cannot add to the ownership note for {dev}: {e}");
                None
            }
        }
    }

    /// Take addresses back out of the note, the lock already held - for the
    /// intent that turned out to be somebody else's entry (EEXIST): a line
    /// left standing would have that entry deleted the day its address stops
    /// being wanted. Returns whether the note agrees; a caller that cannot
    /// un-note has claimed a foreign entry and has to say so.
    pub(super) fn unnote_locked(&self, dev: &str, macs: &[Mac]) -> bool {
        // Unreadable is not "removed": the empty could-not-tell set would
        // read as "nothing to do" and swallow the caller's warning about
        // lines it could not take back.
        if !self.note_is_readable(dev) {
            return false;
        }
        let before = self.load_owned(dev);
        let mut after = before.clone();
        for mac in macs {
            after.remove(mac);
        }
        if after.len() == before.len() {
            return true;
        }
        self.write_owned(dev, &after)
    }

    /// Move a note and its index record to the interface's new name. Both
    /// locks in name order, so two processes migrating a swapped pair cannot
    /// deadlock; append before unlink, so a crash between leaves the
    /// addresses named twice (the next sweep settles it) rather than nowhere.
    pub(super) fn migrate_note(&self, old: &str, new: &str, index: u32) -> bool {
        // Two locked() sections on one name would block on the second
        // descriptor and hang the daemon for good. Unreachable today -
        // renamed_target answers None for an unchanged name - but the guard
        // belongs where the hazard is.
        if old == new {
            return true;
        }
        let (first, second) = if old <= new { (old, new) } else { (new, old) };
        self.locked(first, || {
            self.locked(second, || {
                let macs: Vec<Mac> = self.load_owned(old).iter().copied().collect();
                if !self.note_is_readable(old) {
                    // Unreadable is not "owns nothing": moving nothing and
                    // unlinking would abandon whatever the note names. It
                    // stays an orphan and is looked at again.
                    return false;
                }
                if macs.is_empty() {
                    // A note that was already settled: nothing to move, and
                    // stamping the new name would leave an index record with
                    // no note beside it.
                    self.remove_note(old);
                    return true;
                }
                if self.append_owned_locked(new, &macs).is_none() {
                    return false; // the new note would not take them; keep the old
                }
                self.note_index(new, index);
                self.remove_note(old);
                true
            })
        })
    }

    /// How many addresses this daemon has on record as its own, across every
    /// note. Read from the notes, not memory: a second-process --flush is a
    /// thing that happens.
    pub fn registered(&self) -> usize {
        self.noted_devices_or_none()
            .iter()
            .map(|dev| self.with_owned(dev, |o| o.len()))
            .sum()
    }

    /// Every device with a note. A missing directory means none; any other
    /// listing failure means unknown - the difference --flush's exit code
    /// stands on.
    pub(super) fn noted_devices(&self) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        match fs::read_dir(&self.state_dir) {
            Ok(rd) => {
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
                    // Only ordinary files: a symlink named `<x>.owned` is not
                    // a note this program wrote, and treating it as one reads
                    // and possibly rewrites whatever it points at, as root.
                    // `file_type` on the entry does not follow the link.
                    if !e.file_type().is_ok_and(|t| t.is_file()) {
                        continue;
                    }
                    if let Some(dev) = name.strip_suffix(".owned") {
                        out.push(dev.to_string());
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        out.sort();
        Ok(out)
    }

    /// The same list for callers that can only shrug at a failure - a
    /// scheduling heuristic and the orphan sweep. They act on "none" the
    /// harmless way, so an unlistable directory costs a warning, once, not an
    /// invented answer.
    pub(super) fn noted_devices_or_none(&self) -> Vec<String> {
        match self.noted_devices() {
            Ok(v) => v,
            Err(e) => {
                if !self.dir_list_warned.replace(true) {
                    eprintln!(
                        "warning: cannot list {}: {e} - the notes in it, if any, \
                         are out of reach until it can be listed",
                        self.state_dir.display()
                    );
                }
                Vec::new()
            }
        }
    }
}
