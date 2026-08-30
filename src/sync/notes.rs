//! The ownership notes: which addresses this daemon put into which card.
//!
//! Everything here serves one invariant - an entry in a card's filter that
//! this daemon added must always have a line on record saying so, or nothing
//! will ever take it back out. The note files in the state directory are the
//! truth (a --once or --flush from a second process writes them while the
//! daemon runs), the in-memory copies are only ever a stat-checked shortcut
//! to them, and every writer holds the note's lock across its whole window.
//! The sweeps in the parent module lean on that: they read, unregister and
//! unlink under the same lock, through the write that assumes it rather than
//! the one that takes it.
//!
//! pub(super), the lot of it: this is sync's inner organ, not an interface.

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

    /// Milliseconds since this boot, the clock the quiet memory is stamped
    /// in.
    ///
    /// `Instant` cannot be written down and read back, and a wall clock can
    /// step backwards under NTP. `CLOCK_BOOTTIME` counts monotonically from
    /// boot, suspends included, which is exactly as long as the memory is
    /// allowed to mean anything: the state directory lives in a tmpfs and
    /// starts empty after a reboot, so a stamp and the clock that reads it
    /// always come from the same boot.
    ///
    /// Milliseconds rather than seconds because the valve orders by this,
    /// and two addresses that went quiet in the same second are still one
    /// after the other - at whole seconds the order fell back to the
    /// addresses themselves.
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

    /// The quiet memory as it was last written: which bridge port each owned
    /// address was learnt behind, and since when it has been missing from
    /// the forwarding table.
    ///
    /// Beside the note rather than in it, so the note stays a plain list of
    /// addresses that any build of this program can read - the same
    /// reasoning as the index record. A line is
    ///
    ///     <address> <port-name> <port-ifindex> <missing-since|->
    ///
    /// and the port is written both ways on purpose: the index is what the
    /// pass works in, and the caller only believes a line whose name still
    /// carries that very index. An interface that was replaced under the
    /// same name, or a name that moved, therefore loses its memory rather
    /// than inheriting somebody else's.
    ///
    /// Best-effort in both directions. This file is evidence, never
    /// ownership: losing it costs the keeps and nothing else, which is
    /// exactly what every build before it did.
    pub(super) fn read_ports(&self, dev: &str) -> Vec<(Mac, String, u32, Option<u64>)> {
        let Ok(text) = fs::read_to_string(self.ports_path(dev)) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for line in text.lines() {
            let mut f = line.split_whitespace();
            let (Some(mac), Some(name), Some(index)) = (f.next(), f.next(), f.next()) else {
                continue;
            };
            let (Some(mac), Ok(index)) = (crate::netlink::parse_mac(mac), index.parse::<u32>())
            else {
                continue;
            };
            // A missing clock is written as a dash: the address was in the
            // table when this was written, so it has not started ageing.
            let since = match f.next() {
                Some("-") | None => None,
                Some(v) => match v.parse::<u64>() {
                    Ok(v) => Some(v),
                    Err(_) => continue,
                },
            };
            out.push((mac, name.to_string(), index, since));
        }
        out
    }

    /// Write the quiet memory, under the note's lock and through a temporary
    /// file - the same rules the note itself is written by, for the same
    /// reasons. Says so once per device when it cannot, and then carries on:
    /// the memory still works in this process, it just will not outlive it.
    /// Precondition: `lines` sorted and non-empty - the one caller sorts
    /// for its change comparison anyway, and hands the empty case to the
    /// file's removal instead.
    pub(super) fn write_ports(&self, dev: &str, lines: &[String]) {
        let text = lines.join("\n") + "\n";
        if let Err(e) = self.put_file(&self.ports_path(dev), &text) {
            if self.ports_warned.borrow_mut().insert(dev.to_string()) {
                eprintln!(
                    "warning: cannot write the quiet-keep memory for {dev}: {e} - \
                     addresses held while their port lives will be forgotten if \
                     this daemon restarts"
                );
            }
        }
    }

    /// Record which interface a device's note is about - beside the note,
    /// not in it, so the note stays a plain list of addresses that any
    /// build of this program can read.
    ///
    /// A note is found by interface name, and a name is the one thing a
    /// rename takes away while the interface, its filter entries and its
    /// index all live on. The recorded index is what lets the orphan sweep
    /// and --flush tell that case from a device that is really gone.
    /// Within one boot an index identifies an interface outright: the
    /// kernel hands them out from a per-namespace counter that does not
    /// re-use one, and /run does not outlive a boot either.
    ///
    /// Best-effort, on purpose: without the record a rename is simply not
    /// followed, which is all this program ever did. The value is cached
    /// so the write happens when the answer changes, not once per pass -
    /// and cached even when the write fails, so the warning is said once
    /// rather than becoming a line per pass forever.
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

    /// The interface index recorded for a device's note, if any run of
    /// this program ever recorded one. Read from the file, not the cache:
    /// the callers are the rename paths, which mostly run in a process
    /// that never stamped the record itself.
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

    /// The directory the notes live in, made if it is not there - and made
    /// reachable by nobody but the user that runs this.
    ///
    /// `create_dir_all` asks for 0777 and lets the process umask take bits
    /// off it, so the mode of this directory would be decided by whatever the
    /// daemon happened to be started with. A umask of 0 - which is what a
    /// process started by a unit that does not set one inherits on some
    /// systems - leaves it writable by everybody, and then any local user can
    /// replace a note, or put a symlink where one goes and have this daemon,
    /// which is root, write through it. 0700 is asked for outright.
    ///
    /// A directory that is already there is looked at rather than trusted,
    /// because it outlives the process that made it: the packaged unit keeps
    /// it across restarts on purpose, so a directory made by an older build,
    /// or by a hand, is the one this run writes into.
    ///
    /// What is narrowed is a directory another user may *write*, which is the
    /// one that decides what a root daemon does. One others may only read is
    /// left alone: that is what `RuntimeDirectory=` in the unit produces -
    /// 0755, made by systemd, reset by it on every start - and a daemon that
    /// changed it back on every start would be a warning a day and an
    /// argument it cannot win. The notes themselves are 0600 either way, so
    /// there is nothing to read through it.
    pub(super) fn ensure_state_dir(&self) -> io::Result<()> {
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
            let set = self.read_owned(dev);
            if self.note_is_readable(dev) {
                self.remember(dev, &set);
            } else {
                // The read failed, and what `read_owned` returns then is an
                // empty set that means "could not tell", not "owns nothing".
                // Remembering it would be worse than the failure: the copy is
                // believed for as long as the file's identity, size and
                // timestamp do not change, and a file this could not read is
                // a file nothing changed - so one unreadable moment would be
                // taken as the answer for good, long after whatever caused it
                // had gone. Every entry the note names would stay in the card
                // with nothing on record saying it is ours, which is the
                // orphan the notes exist to prevent.
                //
                // Nothing on record instead, so the next look reads the file
                // again and the device comes back the moment it can be read.
                self.notes.borrow_mut().remove(dev);
            }
        }
        // The shared borrow of `notes` is held while `f` runs. Nothing `f`
        // does today reaches back into these notes - and nothing may: a
        // callback that calls load_owned, read_owned or remember here is an
        // immediate double-borrow panic, which the release profile turns
        // into an abort.
        match self.notes.borrow().get(dev) {
            Some(note) => f(&note.macs),
            // Nothing on record: no file, or one that could not be read.
            None => f(&crate::hash::set()),
        }
    }

    /// Note what was just read or written, together with what the file looks
    /// like now, so the next read can be a stat.
    pub(super) fn remember(&self, dev: &str, set: &Set<Mac>) {
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

    pub(super) fn read_owned(&self, dev: &str) -> Set<Mac> {
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
            Err(e) => {
                // Not the same as owning nothing, and the difference is
                // destructive: a pass would rename a fresh note over it, and
                // --flush and the orphan sweep would unlink it - in every
                // case abandoning entries that are still in the card with
                // nothing left to say they are ours.
                // Said when it starts, not on every attempt: the file is
                // read again on every look for as long as it cannot be read -
                // that is what stops one bad moment becoming permanent - and
                // a look happens per batch of learning.
                if self.unreadable.borrow_mut().insert(dev.to_string()) {
                    eprintln!(
                        "warning: cannot read {}: {e} - leaving that device alone \
                         until it can be read",
                        self.state_path(dev).display()
                    );
                }
                return set;
            }
        }
        if self.unreadable.borrow_mut().remove(dev) {
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
        !self.unreadable.borrow().contains(dev)
    }

    /// Hold the note against everybody else while it is rewritten.
    ///
    /// `--once` and `--flush` are run by hand while the daemon is running,
    /// and a pass takes long enough for that to happen inside one: a single
    /// filter write has been measured waiting seconds on rtnl. Whoever
    /// renamed last used to keep only its own lines, so an address one of
    /// them had registered ended up in the card owned by nobody - which is
    /// the orphan the notes exist to prevent, and which --flush cannot clean
    /// up because it iterates the notes.
    pub(super) fn locked<R>(&self, dev: &str, f: impl FnOnce() -> R) -> R {
        use std::os::fd::AsRawFd;
        // Every write to a note goes through here, so this is where the
        // directory holding them gets its one look per run. An error is not
        // reported here: whatever it was, the open below runs into it too and
        // says so with the name of the file somebody is waiting on.
        if !self.dir_checked.replace(true) {
            let _ = self.ensure_state_dir();
        }
        let path = self.state_dir.join(format!(".{dev}.owned.lock"));
        let open = || {
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
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
            // No lock to be had. Carrying on unlocked is what this did
            // before there was a lock at all; refusing to write would strand
            // whatever was just registered - so the note still gets written,
            // and this says what it was written without.
            //
            // Once per device: this sits on the path a burst of learning
            // takes, and a line per batch would bury the one that matters.
            // A permission or a read-only filesystem does not come and go.
            Err(e) => {
                if self.lock_warned.borrow_mut().insert(dev.to_string()) {
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
        // The taking of the lock can fail - EINTR, since nothing here sets
        // SA_RESTART, is the one that actually happens. Failing and running
        // anyway used to be silent, which is the exact hole the open-failure
        // warning above was written to close; now it is retried, and a
        // failure that is not an interruption gets the same warning.
        loop {
            if unsafe { libc::flock(fd, libc::LOCK_EX) } == 0 {
                break;
            }
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if self.lock_warned.borrow_mut().insert(dev.to_string()) {
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
    pub(super) fn save_owned_merged(&self, dev: &str, before: &Set<Mac>, after: &Set<Mac>) -> bool {
        if self.dry_run {
            return true;
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
            self.write_owned(dev, &merged)
        })
    }

    /// Seed a note with exactly this set. No production path writes a
    /// whole set any more - the pass and the reflection both write
    /// differences, so a parallel writer's lines survive - but the tests
    /// build their starting states this way.
    #[cfg(test)]
    pub(super) fn save_owned(&self, dev: &str, set: &Set<Mac>) {
        if self.dry_run {
            return;
        }
        self.locked(dev, || self.write_owned(dev, set));
    }

    /// The one atomic writer everything on-disk here goes through: a
    /// temporary file, then a rename onto `dest`.
    ///
    /// Through a temporary file because a file truncated by a crash
    /// mid-write would read as "we own nothing" (the note) or as no memory
    /// (the ports file). The temporary's name is the destination's with a
    /// hidden prefix and this process's id appended - a prefix, not a
    /// suffix, because "eth0.new" is a perfectly legal interface name
    /// whose own note would otherwise be this file; and the pid because
    /// the daemon is not the only writer - `--once` and `--flush` are run
    /// by hand while it is running, and two writers sharing one temporary
    /// file means one truncates what the other is writing and then renames
    /// it into place.
    ///
    /// 0600 rather than what `fs::write` asks for, which is 0666 with the
    /// process umask taken off it: the file the rename leaves behind keeps
    /// the mode of the temporary it came from, and state other users may
    /// write is state that decides what this daemon takes out of a card.
    /// The directory is 0700 as well; this is the second lock on the same
    /// door, for the case where the directory was made by something else.
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
                .open(tmp)?
                .write_all(text.as_bytes())
        };
        if let Err(e) = put(&tmp) {
            // The directory is created by the unit and survives a restart;
            // asking for it on every write was a syscall per write for a
            // thing that is already there.
            if e.kind() != io::ErrorKind::NotFound {
                return Err(e);
            }
            self.ensure_state_dir()?;
            put(&tmp)?;
        }
        fs::rename(&tmp, dest).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            e
        })
    }

    /// Take one address out of a note without touching the rest of it.
    ///
    /// The whole-set write sorts, and a `--check` that reordered a note it
    /// had no business changing is a trace where the point was to leave
    /// none. The lines that stay keep their bytes and their order; only the
    /// one line goes. Under the caller's lock.
    pub(super) fn drop_line_locked(&self, dev: &str, mac: &Mac) -> bool {
        let Ok(text) = fs::read_to_string(self.state_path(dev)) else {
            return false;
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
            return true;
        }
        let text = kept.join("\n") + "\n";
        // Either way the remembered copy is about a file that changed, or
        // that is no longer known to hold what it claims.
        self.notes.borrow_mut().remove(dev);
        match self.put_file(&self.state_path(dev), &text) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("warning: cannot write the ownership note for {dev}: {e}");
                false
            }
        }
    }

    /// The write itself. Every caller holds the lock. Whether the note now
    /// records the set - a caller that registered something on the strength
    /// of this write has to know, because an entry in the card that no note
    /// names would never be removed again.
    pub(super) fn write_owned(&self, dev: &str, set: &Set<Mac>) -> bool {
        if !self.note_is_readable(dev) {
            eprintln!(
                "warning: not writing the ownership note for {dev}: it could not \
                 be read, and replacing it would abandon whatever it names"
            );
            return false;
        }
        // Most passes change nothing, and rewriting the note every time would
        // be pointless work on a host that is simply idle. The remembered
        // copy answers this without reading the file - and when it cannot be
        // believed, load_owned reads it and the comparison is against what is
        // really there either way.
        if self.load_owned(dev) == *set {
            return true;
        }
        let mut lines: Vec<String> = set.iter().map(format_mac).collect();
        lines.sort();
        // An empty set is an empty file. `join + newline` wrote a lone
        // newline for it, and the next append then produced a note with a
        // phantom blank first line - harmless to the parser, but visible to
        // anything comparing note contents.
        let text = if lines.is_empty() {
            String::new()
        } else {
            lines.join("\n") + "\n"
        };
        // A note that cannot be written strands every entry it should have
        // named: the next pass reads nothing and counts them as foreign,
        // forever. That must not happen in silence. The how - temporary
        // file, hidden pid-carrying name, 0600 - lives on put_file.
        match self.put_file(&self.state_path(dev), &text) {
            Ok(()) => {
                self.remember(dev, set);
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
    pub(super) fn append_owned(&self, dev: &str, added: &[Mac]) -> bool {
        if self.dry_run || added.is_empty() {
            return true;
        }
        // Only what the note does not already name. A line that is already
        // there would never be taken out again: a full pass rewrites the file
        // only when the set of addresses changed, and a duplicate does not
        // change the set - so the file would grow by a line every time an
        // address was registered afresh, for ever. Read and write under one
        // lock, or two writers each decide "not there yet" and both add it.
        self.locked(dev, || self.append_owned_locked(dev, added).is_some())
    }

    /// The addresses that were actually appended - the register paths need
    /// them, because only a line this very call added may be taken back out
    /// when the card refuses the address as somebody else's. `None` when
    /// the note could not take the addresses, and the caller then must not
    /// write any of them into the card: the note comes first.
    pub(super) fn append_owned_locked(&self, dev: &str, added: &[Mac]) -> Option<Vec<Mac>> {
        use std::io::Write;
        let mut set = self.load_owned(dev);
        // A note that cannot be read cannot be added to either: what the
        // file holds is unknown, and read_owned has already said the device
        // is on hold until it can be read. Appending anyway would put lines
        // into a file this cannot check for duplicates - and, worse, let a
        // caller register on the strength of a note nobody can believe.
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
            .append(true)
            .open(&path)
            .or_else(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    self.ensure_state_dir()?;
                    fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .mode(0o600)
                        .open(&path)
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
                set.extend(fresh.iter().copied());
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
                Some(fresh)
            }
            Err(e) => {
                self.notes.borrow_mut().remove(dev);
                eprintln!("warning: cannot add to the ownership note for {dev}: {e}");
                None
            }
        }
    }

    /// Take addresses back out of the note, the lock already held. For the
    /// intent that turned out to be somebody else's entry: the card
    /// answered EEXIST, and a line left standing would have that entry
    /// deleted the day its address stops being wanted. Whether the note now
    /// agrees - a caller that cannot un-note has claimed a foreign entry
    /// and has to say so.
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

    /// Move a note - and its index record - to the name its interface now
    /// wears. Both locks are taken, in name order so that two processes
    /// migrating a swapped pair of names cannot deadlock; the append comes
    /// before the unlink, so a crash between the two leaves the addresses
    /// named twice - which the next sweep settles, the append deduplicates -
    /// rather than named nowhere.
    pub(super) fn migrate_note(&self, old: &str, new: &str, index: u32) -> bool {
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

    /// How many addresses this daemon currently has on record as its own,
    /// across every device it has a note for. Read from the notes rather than
    /// from memory, for the same reason everything else here is: a --flush
    /// from a second process is a thing that happens.
    pub fn registered(&self) -> usize {
        self.noted_devices_or_none()
            .iter()
            .map(|dev| self.with_owned(dev, |o| o.len()))
            .sum()
    }

    /// Every device with a note. "The directory is not there" means none -
    /// nothing was ever noted. Any other failure to list it means the
    /// answer is unknown, which is not the same thing, and the difference
    /// is what --flush's exit code stands on.
    pub(super) fn noted_devices(&self) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        match fs::read_dir(&self.state_dir) {
            Ok(rd) => {
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
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

    /// The same list for the callers that can only shrug at a failure - a
    /// scheduling heuristic and the orphan sweep. They act on "none" the
    /// harmless way (no sweep, no warning threshold), so an unlistable
    /// directory costs a warning, once, rather than an invented answer.
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
