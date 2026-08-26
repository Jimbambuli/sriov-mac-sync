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

/// The notes decide what this daemon takes back out of a card, and the
/// daemon is root. A note another user may write is a note another user
/// may use to have root remove entries - or, through a symlink in a
/// directory they may write, to have root write somewhere else entirely.
/// The mode is asked for rather than left to whatever umask the daemon
/// was started with.
#[test]
fn the_notes_are_out_of_other_users_reach() {
    let dir = scratch("modes");
    let mut set = crate::hash::set();
    set.insert(BEHIND_NIC);

    // The umask is the whole point: `create_dir_all` and `fs::write` ask
    // for 0777 and 0666 and let it take bits off, so on a host whose
    // daemon was started without one they got everything they asked for.
    // Nought here, so this test is about the code rather than about the
    // umask whoever runs it happens to have.
    let was = unsafe { libc::umask(0) };
    let s = Syncer::new(Vec::new(), dir.clone());
    s.save_owned("nic1", &set);
    let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700, "the directory is reachable by others");
    assert_eq!(
        mode(&dir.join("nic1.owned")),
        0o600,
        "the note is readable, or writable, by others"
    );

    // A directory left behind by an older run, or by a hand, is not one
    // we chose the mode of - so it is looked at rather than trusted.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
    let later = Syncer::new(Vec::new(), dir.clone());
    later.save_owned("nic2", &set);
    assert_eq!(
        mode(&dir),
        0o700,
        "a world-writable state directory was left as it was found"
    );

    // What `RuntimeDirectory=` in the unit makes, and remakes on every
    // start. Others may read it and the notes in it are 0600, so there is
    // nothing to take; changing it back every start would be a warning a
    // day and an argument with systemd that this cannot win.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    let later = Syncer::new(Vec::new(), dir.clone());
    later.save_owned("nic3", &set);
    assert_eq!(
        mode(&dir),
        0o755,
        "the mode systemd gives this directory was fought over"
    );
    unsafe { libc::umask(was) };
    let _ = fs::remove_dir_all(&dir);
}

/// A note that cannot be read means "could not tell", and the daemon
/// leaves that device alone until it can. What it must not do is decide
/// that once: the copy in memory is believed for as long as the file's
/// identity, size and timestamp do not change, and a file that could not
/// be read is a file nothing changed - so remembering the empty set that
/// a failed read returns would make one bad moment permanent, and every
/// entry the note names would stay in the card owned by nobody.
#[test]
fn a_note_that_could_not_be_read_is_not_remembered_as_an_empty_one() {
    let dir = scratch("unreadable");
    let mut set = crate::hash::set();
    set.insert(BEHIND_NIC);
    let s = Syncer::new(Vec::new(), dir.clone());
    s.save_owned("nic1", &set);
    assert_eq!(s.load_owned("nic1"), set);

    // A directory where the note should be: reading it fails, and not
    // with "it is not there" - which is the one failure that does mean
    // "owns nothing".
    let path = dir.join("nic1.owned");
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    let s = Syncer::new(Vec::new(), dir.clone());
    assert!(s.load_owned("nic1").is_empty());
    assert!(!s.note_is_readable("nic1"), "the failure went unnoticed");
    assert!(
        s.notes.borrow().get("nic1").is_none(),
        "an unreadable note was remembered as an empty one, which is the \
         answer this device would then have for good"
    );

    // And the moment it can be read, it is read.
    fs::remove_dir(&path).unwrap();
    fs::write(&path, format!("{}\n", format_mac(&BEHIND_NIC))).unwrap();
    assert_eq!(s.load_owned("nic1"), set);
    assert!(s.note_is_readable("nic1"));

    // The same file, unchanged, unreadable for a moment and readable
    // again - the case the remembered copy would otherwise answer for.
    // Only reachable as somebody who is not root.
    if unsafe { libc::geteuid() } != 0 {
        let s = Syncer::new(Vec::new(), dir.clone());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        assert!(s.load_owned("nic1").is_empty());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            s.load_owned("nic1"),
            set,
            "the note came back and this went on believing it was empty"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

/// A lock that cannot be taken is not a reason to drop what was just
/// registered on the floor - the note is still written. It is a reason to
/// say so: unlocked is how entries got lost to a `--flush` run by hand at
/// the wrong moment, and that is not something to find out about from the
/// symptom.
#[test]
fn a_lock_that_cannot_be_taken_is_said_once_and_the_note_still_written() {
    let dir = scratch("lockless");
    fs::create_dir_all(&dir).unwrap();
    // Something where the lock file goes, that opening cannot get past
    // and that is not "it is not there".
    fs::create_dir(dir.join(".nic1.owned.lock")).unwrap();

    let mut set = crate::hash::set();
    set.insert(BEHIND_NIC);
    let s = Syncer::new(Vec::new(), dir.clone());
    s.save_owned("nic1", &set);
    assert_eq!(
        s.load_owned("nic1"),
        set,
        "the note was not written, so what was registered has no owner"
    );
    assert!(
        s.lock_warned.borrow().contains("nic1"),
        "the note was written unlocked and nothing said so"
    );

    // Said once. This sits on the path a burst of learning takes, and the
    // reasons an open fails do not come and go.
    set.insert(BEHIND_GUEST);
    s.save_owned("nic1", &set);
    assert_eq!(s.lock_warned.borrow().len(), 1);
    assert_eq!(s.load_owned("nic1"), set);
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
        // The world answers the driver question the same way the carried
        // answer was primed: a batch that would register asks afresh, and a
        // fake that then reported nothing would talk the daemon out of the
        // very exclusions this test is about.
        let mut sock = FakeSock {
            vf: vf.clone(),
            ..Default::default()
        };
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

/// A batch that would grow the filter asks the driver afresh instead of
/// believing the carried answer - when a physical function is mute. A
/// virtual function's address can change without any link message when its
/// PF is administratively down (netdev_state_change() on a down device
/// announces nothing, seen on mlx4), so the carried answer may be the only
/// thing standing between a guest and its traffic being sent past it. The
/// fixture's PFs are down - the builder's default, and the careful side.
/// Shrinking batches keep the carried answer: they cost at most a filter
/// slot until the next pass.
#[test]
fn a_batch_that_would_register_asks_the_driver_afresh() {
    let dir = scratch("grow-refresh");
    let topo = host(mac(1));
    let mut s = ready_syncer(&dir);
    // The carried answer predates the address: as far as it knows, the
    // functions have no addresses at all.
    s.remember_vf(vec![2], Vec::new());
    // The world has moved on: VF_ADMIN now belongs to a virtual function.
    let mut sock = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };

    // The address turns up behind the bridge. The carried answer would let
    // it in; the fresh one keeps it out.
    s.fast_apply(
        &mut sock,
        &topo,
        &[(crate::netlink::RTM_NEWNEIGH, learned(3, 10, VF_ADMIN))],
    )
    .unwrap();
    assert_eq!(sock.vf_asked, 1, "an addition consults the driver");
    assert!(
        sock.added.is_empty(),
        "the fresh answer keeps the function's address out"
    );

    // An ordinary guest still registers - the refresh filters, it does not
    // block.
    s.fast_apply(
        &mut sock,
        &topo,
        &[(crate::netlink::RTM_NEWNEIGH, learned(3, 10, BEHIND_NIC))],
    )
    .unwrap();
    assert!(
        sock.added.iter().any(|(_, m)| *m == BEHIND_NIC),
        "an ordinary address still goes in"
    );

    // A shrinking batch does not pay the question.
    let asked = sock.vf_asked;
    s.fast_apply(
        &mut sock,
        &topo,
        &[(crate::netlink::RTM_DELNEIGH, learned(3, 10, BEHIND_NIC))],
    )
    .unwrap();
    assert_eq!(sock.vf_asked, asked, "a deletion-only batch stays cheap");
    let _ = fs::remove_dir_all(&dir);
}

/// The counterpart: an up physical function announces its VF-address
/// changes, every announcement marks the carried answer stale, and the
/// carried answer is then as good as a fresh one - so additions do not pay
/// the driver question. On the cards where that question is expensive
/// (mlx5 answers out of firmware, ~0.6 ms) the PFs are up, which is what
/// keeps the fast path fast there; the mute-PF case above is the mlx4
/// shape, where the question costs next to nothing.
#[test]
fn an_up_pf_lets_additions_trust_the_carried_answer() {
    let dir = scratch("grow-trust");
    let topo = Builder::new()
        .add("nic1", 2, Some(mac(1)))
        .master("vmbr1")
        .vfs(1)
        .up()
        .add("nic2", 3, Some(mac(2)))
        .master("vmbr1")
        .add("vmbr1", 10, Some(mac(1)))
        .bridge()
        .lower("nic1")
        .lower("nic2")
        .build();
    let mut s = ready_syncer(&dir);
    s.remember_vf(vec![2], Vec::new());
    // The fake world holds an address the carried answer does not - in the
    // real world an up PF would have announced it, the answer would be
    // stale, and this batch would ask. Here nothing announced, so the
    // trust shows plainly: no question, and the address goes in.
    let mut sock = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.fast_apply(
        &mut sock,
        &topo,
        &[(crate::netlink::RTM_NEWNEIGH, learned(3, 10, VF_ADMIN))],
    )
    .unwrap();
    assert_eq!(
        sock.vf_asked, 0,
        "an up PF announces, so additions keep the carried answer"
    );
    assert!(
        sock.added.iter().any(|(_, m)| *m == VF_ADMIN),
        "the carried answer is believed - that is the deal, and why the \
         announcement channel must exist"
    );
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
    // CRLF is trimmed, garbage is dropped, and uppercase IS an address -
    // parse_mac takes both cases, which matters for a note edited by
    // hand. (This comment used to claim the opposite, and the missing
    // length check below would have hidden either answer.)
    assert!(owned.contains(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]));
    assert!(owned.contains(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]));
    assert!(owned.contains(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03]));
    assert_eq!(owned.len(), 3, "the garbage line was counted as an address");
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

/// An orphan whose note cannot be read is not an orphan that owns
/// nothing - it is an orphan nobody can answer for. load_owned returns
/// the empty set for both, and the empty branch used to unlink the note
/// on that answer: one unreadable moment and the note was gone for good,
/// with every entry it named still in the card and nothing left to say
/// it was ours. The sibling branch fifteen lines down guards exactly
/// this with note_is_readable; the empty branch has to as well.
#[test]
fn an_orphan_with_an_unreadable_note_keeps_it() {
    let dir = scratch("orphan-unreadable");
    fs::create_dir_all(&dir).unwrap();
    // A note that cannot be read but could be unlinked: a symlink loop.
    // (Root reads through any permission bits, so chmod cannot stand in.)
    let path = dir.join("nic1.owned");
    std::os::unix::fs::symlink(&path, &path).unwrap();

    let mut s = Syncer::new(Vec::new(), dir.clone());
    s.authoritative = true;
    let topo = host(mac(1));
    let mut sock = FakeSock::default();
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();

    assert!(
        fs::symlink_metadata(&path).is_ok(),
        "an unreadable note was unlinked - its entries are now nobody's"
    );
    assert!(sock.removed.is_empty(), "nothing was known to remove");

    // The moment it can be read again, the sweep may finish its work.
    fs::remove_file(&path).unwrap();
    fs::write(&path, format!("{}\n", format_mac(&mac(0x91)))).unwrap();
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    assert_eq!(
        sock.removed,
        vec![(2, mac(0x91))],
        "a readable orphan note is swept as before"
    );
    assert!(!path.exists(), "the settled note lingers");
    let _ = fs::remove_dir_all(&dir);
}

/// --flush against a live topology: what the note names is taken back
/// out of the named device's filter, and the settled note is unlinked.
/// This path ran only against an empty topology in every earlier test -
/// the branch that does the actual unregistering was never exercised.
#[test]
fn a_flush_takes_back_what_the_notes_name_and_says_when_it_could_not() {
    let dir = scratch("flush-real");
    let mut s = Syncer::new(Vec::new(), dir.clone());
    let both: Set<Mac> = [mac(0x61), mac(0x62)].into_iter().collect();
    s.save_owned("nic1", &both);
    let mut sock = FakeSock {
        links: vec![crate::netlink::LinkInfo {
            index: 5,
            name: "nic1".into(),
            mac: Some(mac(1)),
            kind: Some("veth".into()),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(s.flush(&mut sock).unwrap(), "a clean flush says so");
    let mut removed = sock.removed.clone();
    removed.sort();
    assert_eq!(
        removed,
        vec![(5, mac(0x61)), (5, mac(0x62))],
        "the flush did not go through the device the note names"
    );
    assert!(!dir.join("nic1.owned").exists(), "the settled note lingers");

    // And when one refuses to go, it stays on record and the flush says
    // it was not clean - that exit code is the operator's only signal.
    s.save_owned("nic1", &both);
    let mut sock = FakeSock {
        links: vec![crate::netlink::LinkInfo {
            index: 5,
            name: "nic1".into(),
            mac: Some(mac(1)),
            kind: Some("veth".into()),
            ..Default::default()
        }],
        fail_del: [(mac(0x62), libc::EIO)].into_iter().collect(),
        ..Default::default()
    };
    assert!(!s.flush(&mut sock).unwrap(), "a dirty flush claimed clean");
    assert_eq!(
        s.load_owned("nic1"),
        [mac(0x62)].into_iter().collect::<Set<_>>(),
        "what could not be removed has to stay on record"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A bridge missing from one reading makes every wanted address vanish,
/// and a pass that believed it would remove everything - during exactly
/// the ifreload moment the daemon exists to survive. The pass must leave
/// that pair alone entirely.
#[test]
fn a_missing_bridge_fails_closed() {
    let dir = scratch("bridge-gone");
    let mut s = ready_syncer(&dir);
    s.save_owned("nic1", &[mac(0x71)].into_iter().collect::<Set<_>>());
    // A topology in which nic1 exists but vmbr1 does not.
    let topo = Builder::new().add("nic1", 2, Some(mac(1))).build();
    let mut sock = FakeSock::default();
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    assert!(
        sock.removed.is_empty(),
        "a missing bridge was taken for permission to remove"
    );
    assert_eq!(
        s.load_owned("nic1"),
        [mac(0x71)].into_iter().collect::<Set<_>>(),
        "the note has to survive the blink"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A line appended while --flush is inside its read-unregister-unlink
/// window must not be destroyed by the unlink. The window is real: a
/// removal waits on rtnl, and the daemon appends the moment it registers.
/// Losing the line leaves the freshly registered entry in the card with
/// no owner on record - the orphan everything here exists to prevent.
/// The writers hold the note's lock for exactly this reason, so the
/// flush has to hold it across its window too.
#[test]
fn a_flush_cannot_lose_a_line_appended_while_it_runs() {
    let dir = scratch("flush-interleave");
    let appended: Mac = mac(0x77);
    let mut s = Syncer::new(Vec::new(), dir.clone());
    s.save_owned(
        "nic1",
        &[mac(0x75), mac(0x76)].into_iter().collect::<Set<_>>(),
    );

    // A daemon in another process, registering an address and noting it
    // while the flush stands in its window.
    let other_dir = dir.clone();
    let daemon = std::thread::spawn(move || {
        std::thread::sleep(Dur::from_millis(80));
        let other = Syncer::new(Vec::new(), other_dir);
        other.append_owned("nic1", &[appended]);
    });

    let mut sock = FakeSock {
        links: vec![crate::netlink::LinkInfo {
            index: 5,
            name: "nic1".into(),
            mac: Some(mac(1)),
            kind: Some("veth".into()),
            ..Default::default()
        }],
        del_delay_ms: 150,
        ..Default::default()
    };
    s.flush(&mut sock).unwrap();
    daemon.join().unwrap();

    let note = fs::read_to_string(dir.join("nic1.owned")).unwrap_or_default();
    assert!(
        note.contains(&format_mac(&appended)),
        "the flush destroyed a line appended while it ran - that entry \
         is now in the card with no owner on record"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The lock is a lock: a second holder waits. Nothing anywhere proved
/// this before - every earlier test covered only the failure to open
/// the lock file.
#[test]
fn the_note_lock_actually_excludes_a_second_holder() {
    let dir = scratch("lock-excludes");
    fs::create_dir_all(&dir).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let b2 = barrier.clone();
    let d2 = dir.clone();
    let holder = std::thread::spawn(move || {
        let s = Syncer::new(Vec::new(), d2);
        s.locked("nic1", || {
            b2.wait(); // the other thread now heads for the lock
            std::thread::sleep(Dur::from_millis(200));
        });
    });
    let s = Syncer::new(Vec::new(), dir.clone());
    barrier.wait();
    let waited = Instant::now();
    s.locked("nic1", || {});
    assert!(
        waited.elapsed() >= Dur::from_millis(100),
        "the second holder got in while the first still held the lock"
    );
    holder.join().unwrap();
    let _ = fs::remove_dir_all(&dir);
}

/// The unknowable-VF warning is for when the situation arises - which is
/// not necessarily the first pass. A VF that is fully named today and
/// handed to a guest tomorrow (its admin address cleared) becomes
/// unknowable then; marking the uplink "warned" on a pass that had
/// nothing to warn about silences the warning for the life of the
/// process. And once the situation passes, it re-arms, the way the
/// pinned-address warning does.
#[test]
fn the_unknowable_vf_warning_fires_when_the_situation_arises() {
    let dir = scratch("unknowable-late");
    let topo = host(mac(1));
    let mut s = ready_syncer(&dir);

    // Pass one: the single VF has an address, nothing is unknowable.
    s.warn_about_unknowable_vfs(&topo, "nic1", &[(2, VF_ADMIN)]);
    assert!(
        !s.warned_unknown_vf.contains("nic1"),
        "a pass with nothing to warn about must not use up the warning"
    );

    // Pass two: the address is gone - a guest took the VF. Now it warns.
    s.warn_about_unknowable_vfs(&topo, "nic1", &[]);
    assert!(
        s.warned_unknown_vf.contains("nic1"),
        "the situation arose and the warning did not fire"
    );

    // While it persists: once was enough (the set held it).
    s.warn_about_unknowable_vfs(&topo, "nic1", &[]);
    assert!(s.warned_unknown_vf.contains("nic1"));

    // It clears, and a later return deserves a fresh warning.
    s.warn_about_unknowable_vfs(&topo, "nic1", &[(2, VF_ADMIN)]);
    assert!(
        !s.warned_unknown_vf.contains("nic1"),
        "a situation that ended has to re-arm its warning"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// --flush's one promise is "everything this daemon put in comes back
/// out". A state directory that cannot be listed used to read as "no
/// notes": flush printed nothing, removed nothing, and exited 0 - success
/// claimed for work it could not even enumerate. Being unable to tell
/// what exists is a failure, and the exit code has to say so.
#[test]
fn a_state_directory_that_cannot_be_listed_fails_a_flush_loudly() {
    let dir = scratch("flush-unlistable");
    // A regular file where the directory should be: read_dir fails with
    // ENOTDIR, for root too.
    fs::write(&dir, b"not a directory").unwrap();
    let mut s = Syncer::new(Vec::new(), dir.clone());
    let mut sock = FakeSock::default();
    let out = s.flush(&mut sock);
    assert!(
        out.is_err(),
        "an unlistable state directory was reported as a clean flush"
    );
    // The quiet callers stay quiet in their answers - a scheduling
    // heuristic and the orphan sweep must not invent devices - but they
    // must not panic either.
    assert_eq!(s.registered(), 0);
    s.authoritative = true;
    assert!(s.orphaned().is_empty());
    let _ = fs::remove_file(&dir);
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

/// `--once` beside a running daemon writes the same note. A pass takes
/// long enough for that to happen inside one - a single filter write has
/// waited seconds on rtnl - and whoever wrote last used to keep only its
/// own lines. The address the other one registered was then in the card
/// owned by nobody: the orphan the notes exist to prevent, and one
/// --flush cannot clean up, because it iterates the notes.
///
/// Verified by mutation: writing the pass's own picture instead of its
/// difference loses the other writer's address.
#[test]
fn a_pass_writes_its_difference_not_its_picture() {
    let dir = scratch("note-merge");
    let s = Syncer::new(Vec::new(), dir.clone());

    // What the pass read when it started.
    let before = [BEHIND_NIC].into_iter().collect::<Set<_>>();
    s.save_owned("nic1", &before);

    // While it worked, somebody's --once registered another address.
    let mut theirs = before.clone();
    theirs.insert(UPLINK_WARD);
    s.save_owned("nic1", &theirs);

    // The pass finishes: it claimed one address and released none.
    let mut after = before.clone();
    after.insert(BEHIND_GUEST);
    s.save_owned_merged("nic1", &before, &after);

    assert_eq!(
        s.load_owned("nic1"),
        [BEHIND_NIC, UPLINK_WARD, BEHIND_GUEST]
            .into_iter()
            .collect::<Set<_>>(),
        "both writers' addresses have to survive"
    );

    // And a release still releases.
    let mut fewer = s.load_owned("nic1");
    let start = fewer.clone();
    fewer.remove(&BEHIND_NIC);
    s.save_owned_merged("nic1", &start, &fewer);
    assert!(!s.load_owned("nic1").contains(&BEHIND_NIC));
    let _ = fs::remove_dir_all(&dir);
}

/// The same window as the unit test above, but through a whole pass: the
/// note is written to from outside while the pass is between reading it
/// and writing it back. What the other writer added has to survive.
///
/// Verified by mutation: with the pass writing its own picture instead of
/// its difference, the other address is gone.
#[test]
fn a_pass_does_not_overwrite_what_appeared_while_it_ran() {
    let dir = scratch("note-window");
    let topo = host(mac(1));
    let mut s = ready_syncer(&dir);
    s.save_owned("nic1", &crate::hash::set());
    let mut sock = FakeSock {
        fdb: fdb(),
        vf: vec![(2, VF_ADMIN)],
        // Somebody else's --once registers this the moment our pass
        // writes its first entry.
        meanwhile: Some((dir.join("nic1.owned"), OTHER_BRIDGE)),
        ..Default::default()
    };

    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();

    let note = s.load_owned("nic1");
    assert!(
        note.contains(&OTHER_BRIDGE),
        "the other writer's address was thrown away: {note:?}"
    );
    assert!(
        note.contains(&BEHIND_NIC),
        "and our own registrations are still on record"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A virtual function handed straight to a guest, with no address set
/// from the host and no interface here, is in no exclusion set: its
/// address is not knowable. Nothing can be done about that in code - so
/// it has to be said, once, with the two ways to close it.
///
/// Verified by mutation: with the count comparison inverted the quiet
/// case warns and this fails.
#[test]
fn an_unknowable_virtual_function_is_reported_once() {
    let dir = scratch("vf-unknown");
    // Two functions, one netdev here, no address set from the host.
    let topo = Builder::new()
        .add("pf0", 2, Some(mac(1)))
        .master("br0")
        .vfs(2)
        .add("pf0v0", 3, Some(mac(2)))
        .physfn("pf0")
        .add("br0", 10, Some(mac(1)))
        .bridge()
        .lower("pf0")
        .build();
    let mut s = Syncer::new(
        vec![Pair {
            dev: "pf0".into(),
            bridge: "br0".into(),
        }],
        dir.clone(),
    );

    assert!(
        !s.warned_unknown_vf.contains("pf0"),
        "nothing said before it is looked at"
    );
    s.warn_about_unknowable_vfs(&topo, "pf0", &[]);
    assert!(
        s.warned_unknown_vf.contains("pf0"),
        "and once looked at, not looked at again every pass for ever"
    );

    // With both addresses known there is nothing to report, and nothing
    // to silence either: the mark stays off, so the warning is armed for
    // the day a guest takes one of these and the situation actually
    // arises. It used to be set here - "asked and answered" - which
    // silenced the warning for the life of the process.
    let mut quiet = Syncer::new(s.pairs.clone(), dir.clone());
    quiet.warn_about_unknowable_vfs(
        &topo,
        "pf0",
        &[(2, [0x02, 0, 0, 0, 0, 9]), (2, [0x02, 0, 0, 0, 0, 10])],
    );
    assert!(!quiet.warned_unknown_vf.contains("pf0"));
    let _ = fs::remove_dir_all(&dir);
}
