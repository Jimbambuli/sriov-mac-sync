use super::tests::*;
use super::*;
use crate::netlink::{RTM_DELNEIGH, RTM_NEWNEIGH};

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

    let mut s = br0_syncer(&dir);
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
use crate::topology::fixture::{mac, Builder};

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
    let mut sock = kernel(fdb());
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
        s.fast_apply(&mut sock, &topo, &[(RTM_NEWNEIGH, entry.clone())])
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
/// believing the carried answer - always. A virtual function's address can
/// change without any link message: a down PF announces nothing, and even
/// an up one is silent when the guest changes it over the ixgbe/i40e
/// mailbox - so no event reliably marks the carried answer stale, and the
/// carried answer may be the only thing standing between a guest and its
/// traffic being sent past it. Shrinking batches keep the carried answer:
/// they cost at most a filter slot until the next pass.
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
        &[(RTM_NEWNEIGH, learned(3, 10, VF_ADMIN))],
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
        &[(RTM_NEWNEIGH, learned(3, 10, BEHIND_NIC))],
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
        &[(RTM_DELNEIGH, learned(3, 10, BEHIND_NIC))],
    )
    .unwrap();
    assert_eq!(sock.vf_asked, asked, "a deletion-only batch stays cheap");
    let _ = fs::remove_dir_all(&dir);
}

/// The refresh a growing batch pays must not fail open: when the driver
/// cannot be asked, the carried answer is marked stale, so the prompt full
/// pass that answers the error asks afresh instead of taking the very
/// answer the refresh distrusted - which would register the function's
/// address after all.
#[test]
fn a_failed_refresh_leaves_the_carried_answer_distrusted() {
    let dir = scratch("refresh-fail");
    let topo = host(mac(1));
    let mut s = ready_syncer(&dir);
    // Carried, and stale in truth: the world has an address it lacks.
    s.remember_vf(vec![2], Vec::new());
    let mut sock = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        fail_vf: Some(libc::ENOBUFS),
        ..Default::default()
    };
    let r = s.fast_apply(
        &mut sock,
        &topo,
        &[(RTM_NEWNEIGH, learned(3, 10, VF_ADMIN))],
    );
    assert!(r.is_err(), "the failed question reaches the caller");
    assert!(s.vf_stale, "and the carried answer is no longer believed");
    assert!(sock.added.is_empty(), "nothing went in on the failed batch");

    // Whoever comes next - main schedules a prompt pass - now asks afresh
    // and the address stays out.
    s.fast_apply(
        &mut sock,
        &topo,
        &[(RTM_NEWNEIGH, learned(3, 10, VF_ADMIN))],
    )
    .unwrap();
    assert!(
        sock.added.is_empty(),
        "asked afresh, the function's address stays out"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The reflection path stands in an rtnl window that can last seconds, and
/// its write-back is a difference, not the whole set: what a parallel
/// writer noted in that window survives. Written back whole, the parallel
/// entry vanished from the note while staying in the card - an orphan on
/// exactly the path the notes exist to prevent.
#[test]
fn reflection_keeps_what_a_parallel_writer_noted() {
    let dir = scratch("reflect-merge");
    let topo = host(mac(1));
    let mut s = ready_syncer(&dir);
    s.remember_vf(vec![2], Vec::new());
    // WIRE is ours, registered and noted; while the reflection removes it,
    // a parallel --once appends BEHIND_GUEST to the same note.
    s.append_owned("nic1", &[WIRE]);
    let mut sock = FakeSock {
        meanwhile_del: Some((dir.join("nic1.owned"), BEHIND_GUEST)),
        ..Default::default()
    };
    // WIRE turns up on the uplink port itself: the wire has the last word.
    s.fast_apply(&mut sock, &topo, &[(RTM_NEWNEIGH, learned(2, 10, WIRE))])
        .unwrap();
    assert!(
        sock.removed.iter().any(|(_, m)| *m == WIRE),
        "the reflected address came out of the filter"
    );
    let note = fs::read_to_string(dir.join("nic1.owned")).unwrap_or_default();
    assert!(!note.contains(&format_mac(&WIRE)), "and out of the note");
    assert!(
        note.contains(&format_mac(&BEHIND_GUEST)),
        "the parallel writer's entry survives the write-back"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// Re-learning an address we own AND the card still holds buys no driver
/// question: it was vetted by the fresh answer that let it in, and
/// re-registering is an EEXIST no-op. Without this, the tail of a burst
/// asked once per queued re-learn.
#[test]
fn relearning_a_registered_address_buys_no_question() {
    let dir = scratch("owned-relearn");
    let topo = host(mac(1));
    let (_, mut s, _) = registered(&dir);
    assert!(s.load_owned("nic1").contains(&BEHIND_NIC));
    s.remember_vf(vec![2], Vec::new());
    let mut sock = FakeSock::default();
    s.fast_apply(
        &mut sock,
        &topo,
        &[(RTM_NEWNEIGH, learned(3, 10, BEHIND_NIC))],
    )
    .unwrap();
    assert_eq!(sock.vf_asked, 0, "nothing grew, nothing was asked");
    let _ = fs::remove_dir_all(&dir);
}

/// Owned is not enough: an address on the note that the card no longer
/// holds - a driver that cleared its list on link-down - is a GROWTH when
/// it comes back, and a growth asks the driver afresh. Without the card
/// side of the test, a virtual function that claimed that address in the
/// meantime would have it registered past its guest until the next full
/// pass, up to a whole interval away.
#[test]
fn relearning_an_owned_but_absent_address_asks_the_driver() {
    let dir = scratch("owned-absent-relearn");
    let topo = host(mac(1));
    let mut s = ready_syncer(&dir);
    // On the note, never in this process's picture of the card.
    s.append_owned("nic1", &[BEHIND_NIC]);
    s.remember_vf(vec![2], Vec::new());
    let mut sock = FakeSock::default();
    s.fast_apply(
        &mut sock,
        &topo,
        &[(RTM_NEWNEIGH, learned(3, 10, BEHIND_NIC))],
    )
    .unwrap();
    assert!(
        sock.vf_asked >= 1,
        "putting an absent address back is a growth and has to ask"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The grow-refresh asks only the functions of the pairs that would grow;
/// the unasked functions keep their carried entries, merged back under the
/// full function list so the next pass still matches the carry.
#[test]
fn the_grow_refresh_asks_only_the_growing_pairs_functions() {
    const OTHER: Mac = [0x02, 0x11, 0x22, 0x33, 0x44, 9];
    let dir = scratch("grow-scope");
    let topo = host(mac(1));
    let mut s = Syncer::new(
        vec![
            pair(),
            Pair {
                dev: "nic0".into(),
                bridge: "vmbr0".into(),
            },
        ],
        dir.clone(),
    );
    s.authoritative = true;
    // Carried for both functions; the world also knows an address on nic1.
    s.remember_vf(vec![2, 21], vec![(21, OTHER)]);
    let mut sock = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    // Growth behind vmbr1 only.
    s.fast_apply(
        &mut sock,
        &topo,
        &[(RTM_NEWNEIGH, learned(3, 10, BEHIND_NIC))],
    )
    .unwrap();
    assert_eq!(
        sock.asked.last().unwrap(),
        &vec![2u32],
        "only the growing pair's function is asked"
    );
    let (for_pfs, kept) = s.carried_vf.clone().expect("an answer is carried");
    assert_eq!(
        for_pfs,
        vec![2, 21],
        "the carry still covers every function"
    );
    assert!(
        kept.contains(&(21, OTHER)),
        "the unasked function's carried entries survive the merge"
    );
    assert!(
        kept.contains(&(2, VF_ADMIN)),
        "the asked function's entries are the fresh ones"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The check probe is noted before it exists and forgotten after it is
/// gone, and the forgetting is a difference: a parallel writer's line in
/// the same window survives. This is what turns a killed --check from a
/// permanent foreign entry into one the next pass heals.
#[test]
fn a_check_probe_is_noted_first_and_forgotten_as_a_difference() {
    let dir = scratch("check-probe");
    let s = ready_syncer(&dir);
    const PROBE: Mac = [0x02, 0xe3, 0, 0, 0, 0x59];
    assert!(
        s.note_check_probe("nic1", 2, &PROBE),
        "a probe the note took has to say so"
    );
    let noted = fs::read_to_string(dir.join("nic1.owned")).unwrap();
    assert!(noted.contains(&format_mac(&PROBE)), "noted before written");
    // A parallel --once registers something while the probe is out.
    s.append_owned("nic1", &[BEHIND_GUEST]);
    s.forget_check_probe("nic1", &PROBE);
    let after = fs::read_to_string(dir.join("nic1.owned")).unwrap();
    assert!(!after.contains(&format_mac(&PROBE)), "forgotten");
    assert!(
        after.contains(&format_mac(&BEHIND_GUEST)),
        "the parallel writer's line survives the forgetting"
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

/// The note takes an address before the card does. Killed between the two,
/// the old order left an entry in the card that no note named - permanent,
/// counted as foreign, never touched again. The new order leaves a note
/// naming an entry that is not there, and the ordinary paths heal that:
/// the add is retried while the address is wanted, and the removal's
/// ENOENT settles the note once it is not. A failed add is the observable
/// half of that crash window - the intent has to be on file although the
/// card never took the address.
#[test]
fn an_addition_is_noted_before_the_card_is_written() {
    let dir = scratch("note-first");
    let topo = host(mac(1));
    let mut s = ready_syncer(&dir);
    let mut sock = FakeSock {
        fdb: vec![learned(3, 10, BEHIND_NIC)],
        vf: vec![(2, VF_ADMIN)],
        fail_add: [(BEHIND_NIC, libc::EIO)].into_iter().collect::<Map<_, _>>(),
        ..Default::default()
    };
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    assert!(
        s.load_owned("nic1").contains(&BEHIND_NIC),
        "the failed add lost its intent - a crash in that window is an orphan again"
    );
    assert!(
        s.timings.failures.iter().any(|f| f.contains("register")),
        "the failure went unrecorded: {:?}",
        s.timings.failures
    );

    // The address stops being wanted before the add ever succeeds: the
    // removal meets ENOENT and the intent settles to nothing.
    let mut sock = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        fail_del: [(BEHIND_NIC, libc::ENOENT)]
            .into_iter()
            .collect::<Map<_, _>>(),
        ..Default::default()
    };
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    assert!(
        !s.load_owned("nic1").contains(&BEHIND_NIC),
        "the intent outlived the address it was for"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The same order on the fast path: the batch's addresses are in the note
/// before any of them reaches the card, and a failed add keeps its intent
/// for the prompt pass to retry.
#[test]
fn the_fast_path_notes_before_it_writes() {
    let dir = scratch("fast-note-first");
    let topo = host(mac(1));
    let mut s = ready_syncer(&dir);
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let mut sock = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        fail_add: [(BEHIND_NIC, libc::EIO)].into_iter().collect::<Map<_, _>>(),
        ..Default::default()
    };
    let urgency = s
        .fast_apply(
            &mut sock,
            &topo,
            &[(RTM_NEWNEIGH, learned(3, 10, BEHIND_NIC))],
        )
        .unwrap();
    assert!(
        sock.added.is_empty(),
        "the card took what the driver refused"
    );
    assert!(
        s.load_owned("nic1").contains(&BEHIND_NIC),
        "the failed add lost its intent"
    );
    assert_eq!(
        urgency,
        Urgency::Now,
        "the failed add has to buy the pass that retries it"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// EEXIST on the fast path is somebody else's entry, exactly as in a full
/// pass - and with the note written first, the fresh intent has to come
/// back out, or their entry is deleted the day it stops being wanted.
#[test]
fn a_foreign_entry_met_by_the_fast_path_is_not_claimed() {
    let dir = scratch("fast-eexist");
    let topo = host(mac(1));
    let mut s = ready_syncer(&dir);
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let mut sock = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        fail_add: [(BEHIND_NIC, libc::EEXIST)]
            .into_iter()
            .collect::<Map<_, _>>(),
        ..Default::default()
    };
    s.fast_apply(
        &mut sock,
        &topo,
        &[(RTM_NEWNEIGH, learned(3, 10, BEHIND_NIC))],
    )
    .unwrap();
    assert!(
        !s.load_owned("nic1").contains(&BEHIND_NIC),
        "an entry somebody else created was claimed"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A note that cannot be taken keeps the card untouched: nothing may reach
/// the hardware that the note does not already name, or a crash right
/// after leaves the entry ownerless - the exact window the note-first
/// order exists to close. A directory where the note should be is
/// unreadable and unwritable alike, for root too.
#[test]
fn an_unusable_note_holds_the_card_back() {
    let dir = scratch("note-refused");
    fs::create_dir_all(&dir).unwrap();
    fs::create_dir(dir.join("nic1.owned")).unwrap();
    let topo = host(mac(1));
    let mut s = ready_syncer(&dir);
    let mut sock = FakeSock {
        fdb: vec![learned(3, 10, BEHIND_NIC)],
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    assert!(
        sock.added.is_empty(),
        "the card took an address the note could not: {:?}",
        sock.added
    );
    assert!(
        s.timings.failures.iter().any(|f| f.contains("held back")),
        "the held-back registrations left no failure: {:?}",
        s.timings.failures
    );

    // The fast path refuses the same way.
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    s.fast_apply(
        &mut sock,
        &topo,
        &[(RTM_NEWNEIGH, learned(3, 10, BEHIND_NIC))],
    )
    .unwrap();
    assert!(
        sock.added.is_empty(),
        "the fast path wrote past a note it could not take"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// --check's healing story stands on the probe being noted first, so a
/// probe that cannot be noted has to be refused out loud - the caller
/// then writes nothing.
#[test]
fn a_probe_that_cannot_be_noted_says_so() {
    let dir = scratch("probe-refused");
    fs::create_dir_all(&dir).unwrap();
    fs::create_dir(dir.join("nic1.owned")).unwrap();
    let s = ready_syncer(&dir);
    assert!(
        !s.note_check_probe("nic1", 2, &[0x02, 0xe3, 0, 0, 0, 0x59]),
        "a probe the note could not take was reported as noted"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// An interface rename keeps the index, the filter entries and the guests -
/// it takes only the name, and the note is found by name. The sweep used
/// to read that as the device being gone: note unlinked, "removed" logged,
/// and every entry it named still in the card under the new name, owned by
/// nobody. The index recorded beside the note is what tells a rename from
/// a disappearance, and the note follows the interface.
#[test]
fn a_renamed_uplink_keeps_its_note() {
    let dir = scratch("rename");
    let topo = host(mac(1));
    let mut s = ready_syncer(&dir);
    let mut sock = kernel(vec![learned(3, 10, BEHIND_NIC)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    assert!(s.load_owned("nic1").contains(&BEHIND_NIC));
    assert_eq!(
        s.noted_index("nic1"),
        Some(2),
        "the index went unrecorded - a rename could never be told apart"
    );

    // The same interface, same index, new name - and still the uplink, as
    // autodetection would rediscover it.
    let renamed = Builder::new()
        .add("nicX", 2, Some(mac(1)))
        .master("vmbr1")
        .vfs(1)
        .add("nic2", 3, Some(mac(2)))
        .master("vmbr1")
        .add("vmbr1", 10, Some(mac(1)))
        .bridge()
        .lower("nicX")
        .lower("nic2")
        .build();
    s.pairs = vec![Pair {
        dev: "nicX".into(),
        bridge: "vmbr1".into(),
    }];
    let mut sock = FakeSock {
        fdb: vec![
            learned(3, 10, BEHIND_NIC),
            // The registration itself, alive in the card under the new name.
            FdbEntry {
                ifindex: 2,
                master: None,
                mac: BEHIND_NIC,
                state: 0x80, // NUD_PERMANENT
                flags: 0x02, // NTF_SELF
            },
        ],
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.reconcile(&mut sock, true, &renamed, Dur::ZERO).unwrap();
    assert!(
        sock.removed.is_empty(),
        "a rename had something removed from a live filter: {:?}",
        sock.removed
    );
    assert!(
        !dir.join("nic1.owned").exists(),
        "the note stayed under the old name, where nothing can reach it"
    );
    assert_eq!(
        s.load_owned("nicX"),
        [BEHIND_NIC].into_iter().collect::<Set<_>>(),
        "the note did not follow the interface"
    );
    assert!(
        sock.added.is_empty(),
        "the migrated note was not believed and the entry re-registered: {:?}",
        sock.added
    );
    let _ = fs::remove_dir_all(&dir);
}

/// --flush finds notes by name but removes entries by index, and a rename
/// moves only the name: the recorded index has to reach the entries under
/// whatever the interface is called now.
#[test]
fn a_flush_reaches_entries_through_a_rename() {
    let dir = scratch("flush-rename");
    let mut s = Syncer::new(Vec::new(), dir.clone());
    s.save_owned("nic1", &[mac(0x61)].into_iter().collect::<Set<_>>());
    s.note_index("nic1", 5);
    let mut sock = FakeSock {
        links: vec![crate::netlink::LinkInfo {
            index: 5,
            name: "nicX".into(),
            mac: Some(mac(1)),
            kind: Some("veth".into()),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(s.flush(&mut sock).unwrap(), "a clean flush says so");
    assert_eq!(
        sock.removed,
        vec![(5, mac(0x61))],
        "the entries were not removed through the renamed interface"
    );
    assert!(
        !dir.join("nic1.owned").exists() && !dir.join(".nic1.owned.index").exists(),
        "the settled note or its index record lingers"
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

/// A device that is not under its bridge in this reading - a bond-member
/// flap, an `ifreload -a` rebuilding the enslavement - must not be taken
/// for the wire port. uplink_port used to fall back to the device itself
/// then, whereupon nothing in the forwarding table classified as wire and
/// the cable's own peers were registered into the filter: invariant 1,
/// violated in exactly the reload window the daemon reacts to fastest.
#[test]
fn a_detached_device_is_left_alone_rather_than_mistaken_for_the_port() {
    let dir = scratch("detached");
    // nic1 carries the VFs but is enslaved nowhere; the bridge lives on,
    // with the bond as its real port and the cable's peer learnt there.
    let topo = Builder::new()
        .add("nic1", 2, Some(mac(1)))
        .vfs(1)
        .add("bond0", 4, Some(mac(4)))
        .master("vmbr1")
        .add("vmbr1", 10, Some(mac(3)))
        .bridge()
        .lower("bond0")
        .build();
    let mut sock = kernel(vec![learned(4, 10, WIRE)]);
    let mut s = ready_syncer(&dir);
    let reports = s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    assert!(
        sock.added.is_empty(),
        "a cable-side peer was registered on a detached device"
    );
    assert!(sock.removed.is_empty(), "a detached pair removed something");
    assert!(reports.is_empty(), "a detached pair produced a report");

    // The fast path refuses the same pair the same way.
    let urgency = s
        .fast_apply(&mut sock, &topo, &[(RTM_NEWNEIGH, learned(4, 10, WIRE))])
        .unwrap();
    assert!(
        sock.added.is_empty(),
        "the fast path registered on a detached device"
    );
    assert_eq!(urgency, Urgency::Nothing);
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
    let mut sock = kernel(fdb());
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
    use crate::topology::fixture::Builder;
    use std::time::Instant;

    // An SDN-shaped host: uplink + second NIC under the bridge, VLAN
    // interfaces stacked on it, each carrying a vnet bridge with ports.
    fn build(vnets: u32) -> crate::topology::Topology {
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
        let mut sock = kernel(entries(n, 8));
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
        &[(RTM_NEWNEIGH, learned(2, 10, BEHIND_NIC))],
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
        &[(RTM_NEWNEIGH, learned(2, 10, BEHIND_NIC))],
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
            (RTM_NEWNEIGH, learned(3, 10, BEHIND_NIC)),
            // ... and on the uplink's own port in the same breath
            (RTM_NEWNEIGH, learned(2, 10, BEHIND_NIC)),
        ],
    )
    .unwrap();

    assert!(
        sock.added.is_empty(),
        "the wire side of the same batch says this address is out there: {:?}",
        sock.added
    );

    // The dangerous order: wire first, inner learn second - the kernel's
    // end state is "behind the bridge". The refusal must buy the pass that
    // registers it from the real dump; a batch that ends quiet here leaves
    // the guest deaf until the timer, while ARP for it still resolves.
    let mut sock = FakeSock::default();
    let urgency = s
        .fast_apply(
            &mut sock,
            &topo,
            &[
                (RTM_NEWNEIGH, learned(2, 10, BEHIND_GUEST)),
                (RTM_NEWNEIGH, learned(13, 12, BEHIND_GUEST)),
            ],
        )
        .unwrap();
    assert!(sock.added.is_empty(), "the wire still has the last word");
    assert_ne!(
        urgency,
        Urgency::Nothing,
        "a reflection refusal suppressed its own correction"
    );

    // And a batch that is wire and nothing else stays passless - the
    // refusal above must not have bought this one a pass too.
    let mut sock = FakeSock::default();
    let urgency = s
        .fast_apply(&mut sock, &topo, &[(RTM_NEWNEIGH, learned(2, 10, WIRE))])
        .unwrap();
    assert_eq!(
        urgency,
        Urgency::Nothing,
        "wire-only learning bought a pass; the wire-load optimisation is gone"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The full pass obeys the same rule as the fast path: a carried answer
/// decides nothing that grows a filter. A VF's address can change without
/// any link message - a down PF announces nothing, a guest-side change
/// runs over the ixgbe/i40e mailbox - and a pass registers in several real
/// flows the fast path never vetted. Growing on stale news sends a guest's
/// traffic past it until the timed refresh.
#[test]
fn a_pass_that_would_register_asks_the_driver_afresh() {
    let dir = scratch("pass-grow-refresh");
    let topo = host(mac(1));
    let mut s = ready_syncer(&dir);
    // The carried answer predates the change: BEHIND_NIC is, by the
    // driver's current truth, a virtual function's own address now.
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let mut sock = FakeSock {
        fdb: vec![learned(3, 10, BEHIND_NIC)],
        vf: vec![(2, VF_ADMIN), (2, BEHIND_NIC)],
        ..Default::default()
    };
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    assert_eq!(
        sock.vf_asked, 1,
        "a growing pass on a carried answer has to ask the driver first"
    );
    assert!(
        !sock.added.iter().any(|(_, m)| *m == BEHIND_NIC),
        "the pass registered a VF's own address on the strength of stale news"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The mirror image: an address the carried answer still calls a VF's own
/// may have been freed without any link message. With a carried answer
/// such a refusal goes through the decide phase, the fresh question
/// settles it, and the freed address is registered in the same batch
/// instead of waiting out the interval.
#[test]
fn a_stale_vf_exclusion_is_settled_by_the_fresh_question() {
    let dir = scratch("stale-vf-skip");
    let topo = host(mac(1));
    let mut s = ready_syncer(&dir);
    // Carried: BEHIND_NIC still counted as a VF's address. Truth: freed.
    s.remember_vf(vec![2], vec![(2, VF_ADMIN), (2, BEHIND_NIC)]);
    let mut sock = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    let urgency = s
        .fast_apply(
            &mut sock,
            &topo,
            &[(RTM_NEWNEIGH, learned(3, 10, BEHIND_NIC))],
        )
        .unwrap();
    assert_eq!(
        sock.vf_asked, 1,
        "the stale exclusion never asked the driver"
    );
    assert!(
        sock.added.iter().any(|(_, m)| *m == BEHIND_NIC),
        "the freed address stayed blocked by the carried answer"
    );
    assert_eq!(urgency, Urgency::Now);
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
        &[(RTM_DELNEIGH, learned(3, 10, BEHIND_NIC))],
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
        s.fast_apply(&mut sock, &topo, &[(RTM_NEWNEIGH, learned(2, 10, WIRE))])
            .unwrap()
            == Urgency::Nothing,
        "learning on the wire that was never ours leaves nothing to reconcile"
    );

    // An entry on a bridge that has nothing to do with this uplink.
    assert!(
        s.fast_apply(
            &mut sock,
            &topo,
            &[(RTM_NEWNEIGH, learned(22, 20, OTHER_BRIDGE))]
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
            &[(RTM_NEWNEIGH, learned(3, 10, BEHIND_NIC))]
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
            &[(RTM_DELNEIGH, learned(3, 10, BEHIND_NIC))]
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
            &[(RTM_NEWNEIGH, learned(2, 10, BEHIND_GUEST))]
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
    let gone = crate::topology::Topology::assemble(Vec::new(), crate::hash::map());
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
            &[(RTM_NEWNEIGH, learned(3, 10, BEHIND_NIC))],
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
    s.fast_apply(&mut sock, &topo, &[(RTM_NEWNEIGH, learned(3, 10, fresh))])
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
    s.drop_orphans(&mut sock, &topo, true, &mut Vec::new());
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
    s.drop_orphans(&mut sock, &topo, true, &mut Vec::new());
    assert!(sock.removed.is_empty(), "still nothing to remove");

    // A device that really is gone, with the grace period behind it.
    s.pairs.clear();
    s.orphan_grace = Dur::ZERO;
    s.drop_orphans(&mut sock, &topo, true, &mut Vec::new());
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

// ----------------------------------------------------------------- quiet keep

/// nic1 (one VF) and a veth guest port side by side in br0 - the small
/// stage most valve and clock tests play on. Indices: nic1=2, vetha=4,
/// br0=10.
fn small_host() -> crate::topology::Topology {
    Builder::new()
        .add("nic1", 2, Some(mac(1)))
        .master("br0")
        .vfs(1)
        .add("vetha", 4, Some(mac(4)))
        .master("br0")
        .add("br0", 10, Some(mac(3)))
        .bridge()
        .lower("nic1")
        .lower("vetha")
        .build()
}

/// An authoritative syncer over the nic1:br0 pair, state in `dir`.
fn br0_syncer(dir: &std::path::Path) -> Syncer {
    let mut s = Syncer::new(
        vec![Pair {
            dev: "nic1".into(),
            bridge: "br0".into(),
        }],
        dir.to_path_buf(),
    );
    s.authoritative = true;
    s
}

/// A socket answering with this forwarding table and one admin-set VF -
/// the shape 60-odd tests want and nothing else varies.
fn kernel(fdb: Vec<crate::netlink::FdbEntry>) -> FakeSock {
    FakeSock {
        fdb,
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    }
}

/// The ritual most quiet tests open with: the host fixture, a ready
/// syncer over `dir`, and a first pass that registered everything. The
/// returned sock holds what that pass added.
fn registered(dir: &std::path::Path) -> (crate::topology::Topology, Syncer, FakeSock) {
    let topo = host(mac(1));
    let mut s = ready_syncer(dir);
    let mut sock = kernel(fdb());
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    (topo, s, sock)
}

/// The forwarding table as the fixture knows it, minus one address - the
/// shape a dump takes after the bridge aged that address out.
fn fdb_without(mac: Mac) -> Vec<crate::netlink::FdbEntry> {
    fdb().into_iter().filter(|e| e.mac != mac).collect()
}

/// A `self` entry as the card would report it: the address is in the
/// uplink's own filter list.
fn card_holds(dev: u32, mac: Mac) -> crate::netlink::FdbEntry {
    crate::netlink::FdbEntry {
        ifindex: dev,
        master: None,
        mac,
        state: 0,
        flags: 0x02, // NTF_SELF
    }
}

/// A guest that goes quiet stays registered while its port lives. The
/// container behind the IOT vnet ages out of the bridge; its veth still
/// exists, so the address is neither removed nor re-added - it is simply
/// kept, and the report says so. This is also the stacked-vnet arm of the
/// reachability walk: veth0 hangs under IOT, which leads down to vmbr1.
#[test]
fn an_aged_guest_behind_a_living_port_stays_registered() {
    let dir = scratch("quiet-kept");
    let (topo, mut s, _) = registered(&dir);
    assert!(s.load_owned("nic1").contains(&BEHIND_GUEST));

    let mut aged = fdb_without(BEHIND_GUEST);
    aged.push(card_holds(2, BEHIND_GUEST));
    let mut sock2 = kernel(aged);
    let reports = s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    assert!(
        !sock2.removed.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "the quiet guest was unregistered although its port lives"
    );
    assert!(
        !sock2.added.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "the card already held it; re-adding is churn"
    );
    assert!(s.load_owned("nic1").contains(&BEHIND_GUEST));
    assert_eq!(reports[0].quiet, 1, "the report has to say what is held");
    let _ = fs::remove_dir_all(&dir);
}

/// A pass against the aged forwarding table, after the first pass of
/// `syncer` registered everything - the shape the quiet tests share.
fn age_out(s: &mut Syncer, topo: &crate::topology::Topology, m: Mac) -> Vec<Report> {
    let mut aged = fdb_without(m);
    aged.push(card_holds(2, m));
    let mut sock = kernel(aged);
    let reports = s.reconcile(&mut sock, true, topo, Dur::ZERO).unwrap();
    for (_, gone) in sock.removed {
        assert_ne!(gone, m, "removed although its port still lives");
    }
    reports
}

/// A device behind a physical NIC in the bridge is bitten by ageing exactly
/// like a guest - the frame must cross the bridge either way - so it is
/// kept the same way: while the port lives, without a clock. Time passing
/// changes nothing; only pressure, a move or the port going do.
#[test]
fn an_aged_address_on_a_physical_port_is_kept_while_the_port_lives() {
    let dir = scratch("quiet-lan-kept");
    let (topo, mut s, _) = registered(&dir);
    assert!(s.load_owned("nic1").contains(&BEHIND_NIC));

    let reports = age_out(&mut s, &topo, BEHIND_NIC);
    assert!(s.load_owned("nic1").contains(&BEHIND_NIC));
    assert_eq!(reports[0].quiet, 1, "the quiet device counts as held");

    // And again, later: there is no window to run out of.
    std::thread::sleep(Dur::from_millis(30));
    let reports = age_out(&mut s, &topo, BEHIND_NIC);
    assert!(s.load_owned("nic1").contains(&BEHIND_NIC));
    assert_eq!(reports[0].quiet, 1);
    let _ = fs::remove_dir_all(&dir);
}

/// The physical port disappearing takes its whole segment with it: the
/// kept address goes, exactly as a guest's does when its veth dies.
#[test]
fn a_kept_lan_address_leaves_when_its_nic_does() {
    let dir = scratch("quiet-lan-port-gone");
    let (topo, mut s, _) = registered(&dir);
    age_out(&mut s, &topo, BEHIND_NIC);

    // nic2 is unplugged from the picture entirely.
    let smaller = Builder::new()
        .add("nic1", 2, Some(mac(1)))
        .master("vmbr1")
        .vfs(1)
        .add("vmbr1", 10, Some(mac(1)))
        .bridge()
        .lower("nic1")
        .build();
    let mut sock2 = kernel(vec![card_holds(2, BEHIND_NIC)]);
    s.reconcile(&mut sock2, true, &smaller, Dur::ZERO).unwrap();
    assert!(
        sock2.removed.iter().any(|(_, m)| *m == BEHIND_NIC),
        "the NIC is gone; its addresses have to go with it"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The port going is the guest going: the keep ends with the veth.
#[test]
fn a_kept_address_leaves_when_its_port_does() {
    let dir = scratch("quiet-port-gone");
    let (_topo, mut s, _) = registered(&dir);

    // The container stopped: veth0 is gone from the picture.
    let vethless = Builder::new()
        .add("nic1", 2, Some(mac(1)))
        .master("vmbr1")
        .vfs(1)
        .add("nic2", 3, Some(mac(2)))
        .master("vmbr1")
        .add("vmbr1", 10, Some(mac(1)))
        .bridge()
        .lower("nic1")
        .lower("nic2")
        .add("vmbr1.44", 11, Some(mac(1)))
        .master("IOT")
        .lower("vmbr1")
        .add("IOT", 12, Some(mac(1)))
        .bridge()
        .lower("vmbr1.44")
        .build();
    let mut sock2 = kernel(fdb_without(BEHIND_GUEST));
    let reports = s.reconcile(&mut sock2, true, &vethless, Dur::ZERO).unwrap();
    assert!(
        sock2.removed.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "the port is gone, the keep has to end"
    );
    assert_eq!(reports[0].quiet, 0);
    let _ = fs::remove_dir_all(&dir);
}

/// The wire still has the last word: an address that reappears on the
/// uplink's own port is removed even while its old veth lives on.
#[test]
fn the_wire_wins_over_a_quiet_keep() {
    let dir = scratch("quiet-wire");
    let (topo, mut s, _) = registered(&dir);

    // The guest moved to another host: gone behind the bridge, learnt on
    // the uplink port instead.
    let mut moved = fdb_without(BEHIND_GUEST);
    moved.push(learned(2, 10, BEHIND_GUEST));
    let mut sock2 = kernel(moved);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    assert!(
        sock2.removed.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "an address out on the wire must not be kept alive"
    );
    assert!(!s.load_owned("nic1").contains(&BEHIND_GUEST));
    let _ = fs::remove_dir_all(&dir);
}

/// The reflection evicts the port memory along with the entry. Mandatory,
/// not tidiness: if its note write fails, the address stays on the note,
/// and a later pass whose dump no longer shows the wire entry would
/// otherwise keep alive the very address the reflection took out.
#[test]
fn a_reflection_evicts_the_port_memory() {
    let dir = scratch("quiet-reflection");
    let (topo, mut s, mut sock) = registered(&dir);

    // The batch that says the guest moved out onto the wire.
    s.fast_apply(
        &mut sock,
        &topo,
        &[(RTM_NEWNEIGH, learned(2, 10, BEHIND_GUEST))],
    )
    .unwrap();
    assert!(sock.removed.iter().any(|(_, m)| *m == BEHIND_GUEST));

    // A pass whose dump shows neither the wire entry nor the guest, with
    // the old veth still alive: nothing may come back.
    let mut sock2 = kernel(fdb_without(BEHIND_GUEST));
    let reports = s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    assert!(
        !sock2.added.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "the reflected address rose from the dead"
    );
    assert_eq!(reports[0].quiet, 0);
    let _ = fs::remove_dir_all(&dir);
}

/// A restart is mostly an update, and an update that forgot its keeps
/// would unregister every quiet guest on its first pass - the outage this
/// feature exists to prevent, caused by our own package. The memory is
/// written down beside the note and taken over by whoever runs next.
#[test]
fn a_restart_takes_over_the_quiet_memory() {
    let dir = scratch("quiet-restart");
    let (topo, mut s, _) = registered(&dir);
    // The guest goes quiet while the old process is still running, so the
    // clock is already ticking when it is written down.
    age_out(&mut s, &topo, BEHIND_GUEST);
    drop(s);

    let mut restarted = ready_syncer(&dir);
    let mut aged = fdb_without(BEHIND_GUEST);
    aged.push(card_holds(2, BEHIND_GUEST));
    let mut sock2 = kernel(aged);
    let reports = restarted
        .reconcile(&mut sock2, true, &topo, Dur::ZERO)
        .unwrap();
    assert!(
        !sock2.removed.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "the restart unregistered the quiet guest - the memory did not survive"
    );
    assert_eq!(reports[0].quiet, 1);
    assert!(restarted.load_owned("nic1").contains(&BEHIND_GUEST));
    let _ = fs::remove_dir_all(&dir);
}

/// A reboot is the one restart that legitimately forgets: /run is a tmpfs,
/// so the notes and the memory go together - and the card's filter went
/// with the power, so there is nothing left to keep.
#[test]
fn a_reboot_starts_from_nothing() {
    let dir = scratch("quiet-reboot");
    let (topo, mut s, _) = registered(&dir);
    age_out(&mut s, &topo, BEHIND_GUEST);
    assert!(
        dir.join(".nic1.owned.ports").exists(),
        "nothing was written down"
    );
    drop(s);

    // The tmpfs is empty again, but the note survived on paper - the state
    // this cannot distinguish from a hand-deleted memory, and it has to
    // behave like every build before it did.
    let _ = fs::remove_file(dir.join(".nic1.owned.ports"));
    let mut restarted = ready_syncer(&dir);
    let mut sock2 = kernel(fdb_without(BEHIND_GUEST));
    let reports = restarted
        .reconcile(&mut sock2, true, &topo, Dur::ZERO)
        .unwrap();
    assert!(
        sock2.removed.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "without a memory a restart has to fall back to the old behaviour"
    );
    assert_eq!(reports[0].quiet, 0);
    let _ = fs::remove_dir_all(&dir);
}

/// The written-down memory names a port both ways, and only a line whose
/// name still carries that very index counts. An interface replaced under
/// the same name does not hand its keeps to whatever took its place.
#[test]
fn a_replaced_port_does_not_inherit_the_memory() {
    let dir = scratch("quiet-replaced-port");
    let (topo, mut s, _) = registered(&dir);
    age_out(&mut s, &topo, BEHIND_GUEST);
    drop(s);

    // veth0 was deleted and recreated while nobody was running: same name,
    // new index - and index 13, which the memory names, now belongs to a
    // different interface that IS a live port of this bridge. Only the
    // name-and-index check can tell; an index alone still resolves, and
    // resolves to somebody else's port.
    let replaced = Builder::new()
        .add("nic1", 2, Some(mac(1)))
        .master("vmbr1")
        .vfs(1)
        .add("nic2", 3, Some(mac(2)))
        .master("vmbr1")
        .add("nic9", 13, Some(mac(9)))
        .master("vmbr1")
        .add("vmbr1", 10, Some(mac(1)))
        .bridge()
        .lower("nic1")
        .lower("nic2")
        .lower("nic9")
        .add("vmbr1.44", 11, Some(mac(1)))
        .lower("vmbr1")
        .add("IOT", 12, Some(mac(0x12)))
        .bridge()
        .lower("vmbr1.44")
        .lower("veth0")
        .add("veth0", 99, Some(mac(0x13)))
        .master("IOT")
        .build();
    let mut restarted = ready_syncer(&dir);
    let mut sock2 = kernel(vec![card_holds(2, BEHIND_GUEST)]);
    let reports = restarted
        .reconcile(&mut sock2, true, &replaced, Dur::ZERO)
        .unwrap();
    assert!(
        sock2.removed.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "the keep was inherited by an interface that only shares the name"
    );
    assert!(!restarted.load_owned("nic1").contains(&BEHIND_GUEST));
    // The address behind nic2 keeps its memory: that port is untouched,
    // and only the line about veth0 stopped describing this kernel.
    assert_eq!(reports[0].quiet, 1);
    let _ = fs::remove_dir_all(&dir);
}

/// The clock survives with the memory: an address that went quiet before a
/// restart keeps its age, so the valve still sheds the longest-missing
/// first rather than treating every survivor as newborn. Asserted through
/// the valve, because ordering evictions is the only thing the number is
/// for - reading it back out of the file would pass even if the loading
/// process had restamped it, because then it would write the same value
/// back.
#[test]
fn the_missing_clock_survives_a_restart() {
    let dir = scratch("quiet-clock-restart");
    // `old` sorts after `young`, so only a surviving clock can name it.
    let old: Mac = [0x02, 0xe6, 0, 0, 0, 2];
    let young: Mac = [0x02, 0xe6, 0, 0, 0, 1];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, old), learned(4, 10, young)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();

    // Both go quiet before the restart, thirty milliseconds apart: after
    // this the only thing that tells them apart is the gap between their
    // clocks, which is exactly what has to survive.
    let mut sock2 = kernel(vec![card_holds(2, old), learned(4, 10, young)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    std::thread::sleep(Dur::from_millis(30));
    let mut sock3 = kernel(vec![card_holds(2, old), card_holds(2, young)]);
    s.reconcile(&mut sock3, true, &topo, Dur::ZERO).unwrap();
    drop(s);

    // The update lands, and the filter is tight. The one shed has to be
    // `old`; a process that restamped both on the way in would see a tie
    // and fall back to the addresses themselves, which names `young`.
    let mut restarted = br0_syncer(&dir);
    restarted.max_macs = 6;
    let mut sock4 = kernel(vec![card_holds(2, old), card_holds(2, young)]);
    restarted
        .reconcile(&mut sock4, true, &topo, Dur::ZERO)
        .unwrap();
    assert!(
        sock4.removed.iter().any(|(_, m)| *m == old),
        "the restart lost the head start; the valve shed by address order"
    );
    assert!(
        !sock4.removed.iter().any(|(_, m)| *m == young),
        "the entry that only just went quiet was shed first"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A memory file full of nonsense is no memory: unreadable lines are
/// stepped over, and what is left still has to be true of this kernel.
#[test]
fn a_damaged_memory_file_is_stepped_over() {
    let dir = scratch("quiet-damaged");
    let (topo, mut s, _) = registered(&dir);
    // Both go quiet, so both are written down with a clock - one line to
    // damage, one to leave alone.
    let mut aged: Vec<crate::netlink::FdbEntry> = fdb()
        .into_iter()
        .filter(|e| e.mac != BEHIND_GUEST && e.mac != BEHIND_NIC)
        .collect();
    aged.push(card_holds(2, BEHIND_GUEST));
    aged.push(card_holds(2, BEHIND_NIC));
    let mut quiet = kernel(aged.clone());
    s.reconcile(&mut quiet, true, &topo, Dur::ZERO).unwrap();
    assert!(quiet.removed.is_empty(), "both should be kept, not removed");
    drop(s);

    let path = dir.join(".nic1.owned.ports");
    let good = fs::read_to_string(&path).unwrap();
    // Keep the guest's line intact and replace the other one with a line
    // whose clock cannot be read, then bury both in junk: no address, an
    // unparsable index, a truncated line, a blank one.
    let keep: Vec<&str> = good
        .lines()
        .filter(|l| l.starts_with(&format_mac(&BEHIND_GUEST)))
        .collect();
    assert_eq!(keep.len(), 1, "the fixture wrote something unexpected");
    let head = good.lines().next().unwrap().to_string();
    fs::write(
        &path,
        format!(
            "{head}\nnot-an-address veth0 13 0\n{}\n\n\
             02:00:00:00:00:99 veth0 notanumber 0\n\
             {} nic2 3 notaclock\n02:00:00:00:00:98\n",
            keep[0],
            format_mac(&BEHIND_NIC)
        ),
    )
    .unwrap();

    let mut restarted = ready_syncer(&dir);
    let mut sock2 = kernel(aged);
    let reports = restarted
        .reconcile(&mut sock2, true, &topo, Dur::ZERO)
        .unwrap();
    assert!(
        !sock2.removed.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "the one good line was thrown away with the damaged ones"
    );
    assert!(
        sock2.removed.iter().any(|(_, m)| *m == BEHIND_NIC),
        "a line whose clock cannot be read was believed anyway"
    );
    assert_eq!(reports[0].quiet, 1);
    let _ = fs::remove_dir_all(&dir);
}

/// A kept address missing from the filter is a growth, and a growth on a
/// carried VF answer is the bug class the grow-refresh exists for: the
/// fresh answer may call it a VF's own address, and then it must not come
/// back. The card holds everything else, so the kept address is the ONLY
/// thing that can trip the trigger - a pass that puts the survivors into
/// `want` after the trigger decided would sail past it and register on
/// the carried answer.
#[test]
fn a_kept_absent_address_triggers_the_grow_refresh() {
    let dir = scratch("quiet-grow");
    let (topo, mut s, sock) = registered(&dir);

    // Everything the first pass registered is in the card.
    let holds: Vec<crate::netlink::FdbEntry> =
        sock.added.iter().map(|&(_, m)| card_holds(2, m)).collect();

    // Pass 2: aged out of the bridge, the card still whole - entering the
    // kept state buys its own fresh question, and the answer is clean.
    let mut aged: Vec<crate::netlink::FdbEntry> = fdb_without(BEHIND_GUEST);
    aged.extend(holds.iter().cloned());
    let mut sock2 = kernel(aged);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    assert!(
        sock2.vf_asked >= 1,
        "entering the kept state has to buy a fresh driver question"
    );
    assert!(s.load_owned("nic1").contains(&BEHIND_GUEST));

    // Pass 3: long quiet now, and the card lost the entry (a driver that
    // cleared its list on link-down). Meanwhile a guest claimed the
    // address over the mailbox: the driver's current truth calls it a
    // VF's own. Healing it back in would be a growth - the carried answer
    // must not decide it.
    let mut lost: Vec<crate::netlink::FdbEntry> = fdb_without(BEHIND_GUEST);
    lost.extend(holds.iter().filter(|e| e.mac != BEHIND_GUEST).cloned());
    let mut sock3 = FakeSock {
        fdb: lost,
        vf: vec![(2, VF_ADMIN), (2, BEHIND_GUEST)],
        ..Default::default()
    };
    s.reconcile(&mut sock3, true, &topo, Dur::ZERO).unwrap();
    assert!(
        sock3.vf_asked >= 1,
        "a growing pass on a carried answer has to ask the driver"
    );
    assert!(
        !sock3.added.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "a VF's own address was kept alive past its guest"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The quiet state's entry ticket, on its own: a guest can claim an aged
/// address over the driver mailbox without any link message, so the pass
/// that begins keeping an address asks the driver afresh even when the
/// card already holds it and nothing else grows.
#[test]
fn entering_the_kept_state_buys_a_fresh_driver_question() {
    let dir = scratch("quiet-entry-ask");
    let (topo, mut s, sock) = registered(&dir);
    let holds: Vec<crate::netlink::FdbEntry> =
        sock.added.iter().map(|&(_, m)| card_holds(2, m)).collect();

    // Aged, card whole, and the fresh answer says: that is a VF's own
    // address now. The keep must yield to it on the spot.
    let mut aged: Vec<crate::netlink::FdbEntry> = fdb_without(BEHIND_GUEST);
    aged.extend(holds);
    let mut sock2 = FakeSock {
        fdb: aged,
        vf: vec![(2, VF_ADMIN), (2, BEHIND_GUEST)],
        ..Default::default()
    };
    let reports = s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    assert!(
        sock2.vf_asked >= 1,
        "the entry into quietness has to ask the driver"
    );
    assert!(
        sock2.removed.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "an address the fresh answer calls a VF's own has to leave the card"
    );
    assert_eq!(reports[0].quiet, 0);
    let _ = fs::remove_dir_all(&dir);
}

/// Crash healing: a kept address that is missing from the card is
/// re-registered - the keep holds the claim, the pass repairs the filter.
#[test]
fn a_kept_address_missing_from_the_card_is_reregistered() {
    let dir = scratch("quiet-heal");
    let (topo, mut s, _) = registered(&dir);

    // Aged AND absent from the card (no self entry in the dump).
    let mut sock2 = FakeSock {
        fdb: fdb_without(BEHIND_GUEST),
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    assert!(
        sock2.added.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "a kept address missing from the filter has to be healed back in"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// An operator's EXCLUDE outranks the keep, and a pinned EXTRA is wanted
/// outright - quiet counts neither.
#[test]
fn exclusions_and_extras_outrank_the_keep() {
    let dir = scratch("quiet-exclude");
    let (topo, mut s, _) = registered(&dir);

    // Excluded after the fact: the keep must not override the operator.
    s.exclude.insert(BEHIND_GUEST);
    let mut sock2 = kernel(fdb_without(BEHIND_GUEST));
    let reports = s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    assert!(sock2.removed.iter().any(|(_, m)| *m == BEHIND_GUEST));
    assert_eq!(reports[0].quiet, 0);

    // Pinned instead: wanted through EXTRA, not counted as quiet.
    s.exclude.remove(&BEHIND_GUEST);
    s.extra.insert(BEHIND_NIC);
    let mut sock3 = kernel(fdb_without(BEHIND_NIC));
    let reports = s.reconcile(&mut sock3, true, &topo, Dur::ZERO).unwrap();
    assert!(
        !sock3.removed.iter().any(|(_, m)| *m == BEHIND_NIC),
        "a pinned address fell out"
    );
    assert_eq!(reports[0].quiet, 0, "extra is want, not quiet");
    let _ = fs::remove_dir_all(&dir);
}

/// An unreadable note stalls the keep but must not erase its memory: when
/// the note heals, the quiet guest is still known.
#[test]
fn an_unreadable_note_does_not_erase_the_port_memory() {
    // Unreadability is only reachable as somebody who is not root.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let dir = scratch("quiet-unreadable");
    let (topo, mut s, _) = registered(&dir);

    let note = dir.join("nic1.owned");
    fs::set_permissions(&note, fs::Permissions::from_mode(0o000)).unwrap();
    let mut sock2 = kernel(fdb_without(BEHIND_GUEST));
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    assert!(
        sock2.removed.is_empty(),
        "an unreadable note must hold the card still"
    );

    fs::set_permissions(&note, fs::Permissions::from_mode(0o600)).unwrap();
    let mut aged = fdb_without(BEHIND_GUEST);
    aged.push(card_holds(2, BEHIND_GUEST));
    let mut sock3 = kernel(aged);
    let reports = s.reconcile(&mut sock3, true, &topo, Dur::ZERO).unwrap();
    assert!(
        !sock3.removed.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "the memory did not survive the unreadable window"
    );
    assert_eq!(reports[0].quiet, 1);
    let _ = fs::remove_dir_all(&dir);
}

/// Kept addresses cost filter slots and are the first surrendered as the
/// list nears its capacity - a surrendered keep is exactly the old
/// behaviour. The wanted core stays untouched.
#[test]
fn the_pressure_valve_sheds_keeps_first() {
    let dir = scratch("quiet-pressure");
    let m1: Mac = [0x02, 0xdd, 0, 0, 0, 1];
    let m2: Mac = [0x02, 0xdd, 0, 0, 0, 2];
    let m3: Mac = [0x02, 0xdd, 0, 0, 0, 3];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![
        learned(4, 10, m1),
        learned(4, 10, m2),
        learned(4, 10, m3),
    ]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();

    // All three age out; with the bridge's own address that is four
    // occupied slots against allowed = max - headroom = 3: one must yield.
    s.max_macs = 7;
    let mut sock2 = kernel(vec![
        card_holds(2, m1),
        card_holds(2, m2),
        card_holds(2, m3),
    ]);
    let reports = s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    assert_eq!(
        reports[0].quiet, 2,
        "the shed count is deterministic: one keep yields, two stand"
    );
    assert!(
        !sock2.removed.is_empty(),
        "a surrendered keep has to leave the card"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// Under pressure the longest-missing entry yields first, and a fresh
/// learn makes an entry young again: what goes is what has not been heard
/// from for the longest, not whoever happens to sort first.
#[test]
fn the_pressure_valve_sheds_the_longest_missing_first() {
    let dir = scratch("quiet-pressure-order");
    let old: Mac = [0x02, 0xde, 0, 0, 0, 2];
    let young: Mac = [0x02, 0xde, 0, 0, 0, 1];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, old), learned(4, 10, young)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();

    // `old` ages out first and its clock starts; `young` is still learnt.
    // `young` sorts before `old` by address, so a valve that ignored the
    // clock would shed `young` - only the clock names `old`.
    let mut sock2 = kernel(vec![card_holds(2, old), learned(4, 10, young)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    std::thread::sleep(Dur::from_millis(30));

    // Now both are quiet, and the limit leaves room for only some of the
    // list: the longest-missing - `old` - is the one surrendered.
    s.max_macs = 6;
    let mut sock3 = kernel(vec![card_holds(2, old), card_holds(2, young)]);
    s.reconcile(&mut sock3, true, &topo, Dur::ZERO).unwrap();
    assert!(
        sock3.removed.iter().any(|(_, m)| *m == old),
        "pressure has to cost the longest-missing entry"
    );
    assert!(
        !sock3.removed.iter().any(|(_, m)| *m == young),
        "the recently heard-from entry was shed although an older one stood"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A behind-the-bridge learn buys the pass that records the port - the
/// reason the fast path needs no recording of its own.
#[test]
fn a_learn_buys_the_pass_that_records() {
    let dir = scratch("quiet-learn-pass");
    let topo = host(mac(1));
    let mut s = ready_syncer(&dir);
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let mut sock = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    let urgency = s
        .fast_apply(
            &mut sock,
            &topo,
            &[(RTM_NEWNEIGH, learned(13, 12, BEHIND_GUEST))],
        )
        .unwrap();
    assert_eq!(
        urgency,
        Urgency::Now,
        "the learn did not buy the pass whose dump records the port"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The memory follows the latest learn: a guest that moved to another
/// veth is kept by the port it lives behind now, not the one it left.
#[test]
fn the_memory_follows_the_latest_learn() {
    let dir = scratch("quiet-moved-port");
    let m: Mac = [0x02, 0xee, 0, 0, 0, 1];
    let build = |with_a: bool| {
        let mut b = Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .master("br0")
            .vfs(1);
        if with_a {
            b = b.add("vetha", 4, Some(mac(4))).master("br0");
        }
        b = b.add("vethb", 5, Some(mac(5))).master("br0");
        let mut br = b.add("br0", 10, Some(mac(3))).bridge().lower("nic1");
        if with_a {
            br = br.lower("vetha");
        }
        br.lower("vethb").build()
    };
    let topo = build(true);
    let mut s = br0_syncer(&dir);

    // Learnt behind vetha first, then behind vethb.
    let mut sock = kernel(vec![learned(4, 10, m)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    let mut sock2 = kernel(vec![learned(5, 10, m)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();

    // vetha dies, the address ages - vethb is what keeps it.
    let gone_a = build(false);
    let mut sock3 = kernel(vec![card_holds(2, m)]);
    let reports = s.reconcile(&mut sock3, true, &gone_a, Dur::ZERO).unwrap();
    assert!(
        !sock3.removed.iter().any(|(_, mm)| *mm == m),
        "the memory clung to the port the guest left"
    );
    assert_eq!(reports[0].quiet, 1);
    let _ = fs::remove_dir_all(&dir);
}

/// The pass-start read is the one the memory prune must be judged by. A
/// note unreadable at the start but readable again mid-pass (a parallel
/// writer healed it while the grow-refresh ran) makes `note_is_readable`
/// true while `owned` still descends from the could-not-tell empty set -
/// pruning against that erased the very memory the gate protects.
struct FlipSock {
    inner: FakeSock,
    heal: Option<PathBuf>,
}
impl FdbWriter for FlipSock {
    fn dump_fdb(&mut self) -> io::Result<Vec<crate::netlink::FdbEntry>> {
        self.inner.dump_fdb()
    }
    fn dump_links(&mut self) -> io::Result<Vec<crate::netlink::LinkInfo>> {
        self.inner.dump_links()
    }
    fn vf_macs_of(&mut self, indices: &[u32]) -> io::Result<Vec<(u32, Mac)>> {
        if let Some(p) = self.heal.take() {
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        }
        self.inner.vf_macs_of(indices)
    }
    fn set_self_fdb(&mut self, ifindex: u32, mac: &Mac, add: bool) -> io::Result<()> {
        self.inner.set_self_fdb(ifindex, mac, add)
    }
}

#[test]
fn a_note_turning_readable_mid_pass_keeps_the_memory() {
    // Unreadability is only reachable as somebody who is not root.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let dir = scratch("quiet-flip");
    let (topo, mut s, _) = registered(&dir);
    assert!(s.load_owned("nic1").contains(&BEHIND_GUEST));

    // A parallel --once rewrote the note (same content, new inode), and
    // right after, the file is momentarily unreadable. The stat cache is
    // invalid, so the pass really reads - and fails.
    let note = dir.join("nic1.owned");
    let text = fs::read_to_string(&note).unwrap();
    let tmp = dir.join(".nic1.owned.flip.tmp");
    fs::write(&tmp, &text).unwrap();
    fs::rename(&tmp, &note).unwrap();
    fs::set_permissions(&note, fs::Permissions::from_mode(0o000)).unwrap();

    // BEHIND_GUEST has aged (still in the card), and a NEW address is
    // learnt - the growth that triggers the vf refresh, during which the
    // note becomes readable again; the append then re-reads it fine.
    let newmac: Mac = [0x02, 0x77, 0, 0, 0, 9];
    let mut aged = fdb_without(BEHIND_GUEST);
    aged.push(card_holds(2, BEHIND_GUEST));
    aged.push(learned(3, 10, newmac));
    let mut sock2 = FlipSock {
        inner: kernel(aged.clone()),
        heal: Some(note.clone()),
    };
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    assert!(
        sock2.inner.added.iter().any(|(_, m)| *m == newmac),
        "the new learn was registered (the flip really happened)"
    );

    // Everything readable again: the quiet guest's port still lives, so
    // the keep must hold - which it only can if the memory survived.
    let mut aged3 = fdb_without(BEHIND_GUEST);
    aged3.push(card_holds(2, BEHIND_GUEST));
    aged3.push(learned(3, 10, newmac));
    aged3.push(card_holds(2, newmac));
    let mut sock3 = kernel(aged3);
    let reports = s.reconcile(&mut sock3, true, &topo, Dur::ZERO).unwrap();
    assert!(
        !sock3.removed.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "the unreadable window erased the port memory"
    );
    assert_eq!(reports[0].quiet, 1);
    let _ = fs::remove_dir_all(&dir);
}

/// A failed unregister keeps the note for the retry - the memory it must
/// not keep: with the port memory alive, the quiet keep would re-adopt the
/// moved-out address as soon as its wire evidence fades (an ifreload
/// flushed the bridge's table), and a one-off EBUSY would harden into a
/// permanent keep the stale loop can never reach.
#[test]
fn a_failed_reflection_removal_does_not_become_a_keep() {
    let dir = scratch("quiet-reflect-err");
    let (topo, mut s, _) = registered(&dir);
    assert!(s.load_owned("nic1").contains(&BEHIND_GUEST));

    // The guest's address fails over to the wire; the reflection's removal
    // hits a transient error (rtnl contention during the very ifreload).
    let mut fail = crate::hash::map();
    fail.insert(BEHIND_GUEST, libc::EBUSY);
    let mut sock2 = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        fail_del: fail,
        ..Default::default()
    };
    s.fast_apply(
        &mut sock2,
        &topo,
        &[(RTM_NEWNEIGH, learned(2, 10, BEHIND_GUEST))],
    )
    .unwrap();
    assert!(sock2.removed.is_empty(), "the removal really failed");

    // The ifreload flushed the bridge's table: the next pass's dump shows
    // neither the wire entry nor the guest - only the card still holding
    // the address. The removal must now happen, not a keep.
    let mut flushed = fdb_without(BEHIND_GUEST);
    flushed.push(card_holds(2, BEHIND_GUEST));
    let mut sock3 = kernel(flushed);
    let reports = s.reconcile(&mut sock3, true, &topo, Dur::ZERO).unwrap();
    assert!(
        sock3.removed.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "the moved-out address was held as a quiet keep (quiet={})",
        reports[0].quiet
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A living port is not enough - it has to still lead to this bridge. A
/// veth re-enslaved to an unrelated bridge keeps existing, but its guest
/// is no longer behind the uplink, and holding its address would steer
/// that MAC into the wrong bridge for ever.
#[test]
fn a_port_moved_to_another_bridge_ends_the_keep() {
    let dir = scratch("quiet-moved-bridge");
    let m: Mac = [0x02, 0xdf, 0, 0, 0, 1];
    let before = Builder::new()
        .add("nic1", 2, Some(mac(1)))
        .master("br0")
        .vfs(1)
        .add("vetha", 4, Some(mac(4)))
        .master("br0")
        .add("br0", 10, Some(mac(3)))
        .bridge()
        .lower("nic1")
        .lower("vetha")
        .build();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, m)]);
    s.reconcile(&mut sock, true, &before, Dur::ZERO).unwrap();
    assert!(s.load_owned("nic1").contains(&m));

    // The veth lives on - under br9 now. The address has aged.
    let after = Builder::new()
        .add("nic1", 2, Some(mac(1)))
        .master("br0")
        .vfs(1)
        .add("vetha", 4, Some(mac(4)))
        .master("br9")
        .add("br0", 10, Some(mac(3)))
        .bridge()
        .lower("nic1")
        .add("br9", 11, Some(mac(9)))
        .bridge()
        .lower("vetha")
        .build();
    let mut sock2 = kernel(vec![card_holds(2, m)]);
    let reports = s.reconcile(&mut sock2, true, &after, Dur::ZERO).unwrap();
    assert!(
        sock2.removed.iter().any(|(_, r)| *r == m),
        "the port left this bridge; the keep has to end"
    );
    assert_eq!(reports[0].quiet, 0);
    let _ = fs::remove_dir_all(&dir);
}

/// A learn-port folded in under the uplink is the wire's side of the
/// fence now: two NICs joined into a bond uplink carry their old peers
/// out, not in, and keeping those addresses would steer wire traffic
/// into the bridge.
#[test]
fn a_port_folded_under_the_uplink_ends_the_keep() {
    let dir = scratch("quiet-bonded-away");
    let m: Mac = [0x02, 0xdf, 0, 0, 0, 2];
    let before = Builder::new()
        .add("nic1", 2, Some(mac(1)))
        .master("br0")
        .vfs(1)
        .add("nic2", 5, Some(mac(5)))
        .master("br0")
        .add("br0", 10, Some(mac(3)))
        .bridge()
        .lower("nic1")
        .lower("nic2")
        .build();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(5, 10, m)]);
    s.reconcile(&mut sock, true, &before, Dur::ZERO).unwrap();
    assert!(s.load_owned("nic1").contains(&m));

    // Re-plumbed: nic1 and nic2 are members of bond0, bond0 the sole
    // bridge port; the re-enslavement flushed the bridge's table.
    let after = Builder::new()
        .add("nic1", 2, Some(mac(1)))
        .master("bond0")
        .vfs(1)
        .add("nic2", 5, Some(mac(5)))
        .master("bond0")
        .add("bond0", 7, Some(mac(1)))
        .master("br0")
        .lower("nic1")
        .lower("nic2")
        .add("br0", 10, Some(mac(3)))
        .bridge()
        .lower("bond0")
        .build();
    let mut sock2 = kernel(vec![card_holds(2, m)]);
    let reports = s.reconcile(&mut sock2, true, &after, Dur::ZERO).unwrap();
    assert!(
        sock2.removed.iter().any(|(_, r)| *r == m),
        "the learn-port now lies under the uplink; its address is the wire's"
    );
    assert_eq!(reports[0].quiet, 0);
    let _ = fs::remove_dir_all(&dir);
}

/// The valve opens exactly when the measured occupancy no longer fits
/// above the headroom, and not one slot earlier: off by one in either
/// direction means a needless shed or a silent overflow on the next learn.
#[test]
fn the_pressure_valve_opens_exactly_at_its_margin() {
    let dir = scratch("quiet-pressure-edge");
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    // Eight learns plus the bridge's own address: want is exactly 9.
    let learns: Vec<Mac> = (1..=8u8).map(|i| [0x02, 0xe0, 0, 0, 0, i]).collect();
    let mut sock = kernel(learns.iter().map(|m| learned(4, 10, *m)).collect());
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();

    // All eight age: nine occupied slots. At max 13 they sit exactly on
    // the margin (9 + 4 == 13) and nothing may yield yet.
    s.max_macs = 13;
    let mut sock2 = kernel(learns.iter().map(|m| card_holds(2, *m)).collect());
    let reports = s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    assert!(
        sock2.removed.is_empty(),
        "exactly on the margin nothing yields (quiet={})",
        reports[0].quiet
    );
    assert_eq!(reports[0].quiet, 8);

    // One slot tighter, and exactly one keep has to go.
    s.max_macs = 12;
    let mut sock3 = kernel(learns.iter().map(|m| card_holds(2, *m)).collect());
    let reports = s.reconcile(&mut sock3, true, &topo, Dur::ZERO).unwrap();
    assert_eq!(
        sock3.removed.len(),
        1,
        "one past the margin exactly one keep yields (quiet={})",
        reports[0].quiet
    );
    assert_eq!(reports[0].quiet, 7);
    let _ = fs::remove_dir_all(&dir);
}

/// The missing-clock keeps its start across passes: re-stamped on every
/// quiet pass, all entries would look equally young and the valve would
/// degenerate to shedding by address order.
#[test]
fn the_missing_clock_is_not_wound_up_by_later_passes() {
    let dir = scratch("quiet-clock-start");
    // `old` sorts after `young` by address, so only a preserved clock can
    // name it as the one to shed.
    let old: Mac = [0x02, 0xe1, 0, 0, 0, 2];
    let young: Mac = [0x02, 0xe1, 0, 0, 0, 1];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, old), learned(4, 10, young)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();

    // Pass 2: `old` ages, `young` still speaks.
    let mut sock2 = kernel(vec![card_holds(2, old), learned(4, 10, young)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    std::thread::sleep(Dur::from_millis(20));

    // Pass 3: both quiet now - `old`'s clock must keep its earlier start.
    let both = vec![card_holds(2, old), card_holds(2, young)];
    let mut sock3 = kernel(both.clone());
    s.reconcile(&mut sock3, true, &topo, Dur::ZERO).unwrap();
    std::thread::sleep(Dur::from_millis(20));

    // Pass 4, under pressure: the one shed has to be `old`.
    s.max_macs = 6;
    let mut sock4 = kernel(both);
    s.reconcile(&mut sock4, true, &topo, Dur::ZERO).unwrap();
    assert!(
        sock4.removed.iter().any(|(_, m)| *m == old),
        "the longest-missing entry has to be the one shed"
    );
    assert!(
        !sock4.removed.iter().any(|(_, m)| *m == young),
        "a rewound clock shed by address order instead"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The port memory follows the note through a rename, or an ifupdown
/// moment that renames the uplink silently forgets exactly the quiet
/// guests it was carrying.
#[test]
fn a_rename_carries_the_quiet_memory_along() {
    let dir = scratch("quiet-rename");
    let (topo, mut s, _) = registered(&dir);

    // The guest goes quiet while still called nic1.
    age_out(&mut s, &topo, BEHIND_GUEST);
    assert!(s.load_owned("nic1").contains(&BEHIND_GUEST));

    // Same interface, same index, new name - and the guest still quiet.
    let renamed = Builder::new()
        .add("nicX", 2, Some(mac(1)))
        .master("vmbr1")
        .vfs(1)
        .add("nic2", 3, Some(mac(2)))
        .master("vmbr1")
        .add("vmbr1", 10, Some(mac(1)))
        .bridge()
        .lower("nicX")
        .lower("nic2")
        .add("vmbr1.44", 11, Some(mac(1)))
        .lower("vmbr1")
        .add("IOT", 12, Some(mac(0x12)))
        .bridge()
        .lower("vmbr1.44")
        .lower("veth0")
        .add("veth0", 13, Some(mac(0x13)))
        .master("IOT")
        .build();
    s.pairs = vec![Pair {
        dev: "nicX".into(),
        bridge: "vmbr1".into(),
    }];
    let mut aged = fdb_without(BEHIND_GUEST);
    aged.retain(|e| !e.is_self());
    aged.push(card_holds(2, BEHIND_GUEST));
    let mut sock2 = kernel(aged);
    let reports = s.reconcile(&mut sock2, true, &renamed, Dur::ZERO).unwrap();
    assert!(
        !sock2.removed.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "the rename lost the quiet guest's memory"
    );
    assert!(
        reports.iter().any(|r| r.dev == "nicX" && r.quiet >= 1),
        "the keep did not survive under the new name"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A dry-run daemon reports, it does not write - the fast path included.
/// The guard is the early return; without it a --dry-run daemon would put
/// real entries into a live filter the moment a guest speaks.
#[test]
fn dry_run_gates_the_fast_path() {
    let dir = scratch("dry-fast");
    let topo = host(mac(1));
    let mut s = ready_syncer(&dir);
    s.dry_run = true;
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let mut sock = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    let urgency = s
        .fast_apply(
            &mut sock,
            &topo,
            &[(RTM_NEWNEIGH, learned(13, 12, BEHIND_GUEST))],
        )
        .unwrap();
    assert!(sock.added.is_empty(), "a dry run wrote to the filter");
    assert_eq!(
        urgency,
        Urgency::Now,
        "the pass is where a dry run reports; the batch has to buy one"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A successful --check leaves nothing behind: when the probe was the
/// note's only line, note and index go with it - an empty leftover reads
/// as a managed device to --flush and to anyone listing the directory.
#[test]
fn a_clean_check_probe_leaves_no_note_behind() {
    let dir = scratch("check-traceless");
    let s = ready_syncer(&dir);
    const PROBE: Mac = [0x02, 0xe3, 0, 0, 0, 0x60];
    assert!(s.note_check_probe("nic9", 2, &PROBE));
    assert!(dir.join("nic9.owned").exists());
    s.forget_check_probe("nic9", &PROBE);
    assert!(
        !dir.join("nic9.owned").exists(),
        "the probe's note survived the check"
    );
    assert!(
        !dir.join(".nic9.owned.index").exists(),
        "the probe's index survived the check"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// An orphan sweep that cannot take an entry out has to say so in the
/// failures it hands the oneshot - a --once that exits 0 over entries it
/// left in the card is how orphans become permanent in silence.
#[test]
fn an_unremovable_orphan_fails_the_sweep_out_loud() {
    let dir = scratch("orphan-fail");
    let orphan: Mac = [0x02, 0xe4, 0, 0, 0, 1];
    // A note for an interface that still exists but stopped being an
    // uplink - its entries are still in a live card, so a failed removal
    // is an orphan left behind, not dust settled.
    let mut set = crate::hash::set();
    set.insert(orphan);
    let mut s = Syncer::new(Vec::new(), dir.clone());
    s.authoritative = true;
    s.save_owned("nic2", &set);

    let topo = host(mac(1));
    let mut fail = crate::hash::map();
    fail.insert(orphan, libc::EBUSY);
    let mut sock = FakeSock {
        fail_del: fail,
        ..Default::default()
    };
    let mut failures = Vec::new();
    s.drop_orphans(&mut sock, &topo, true, &mut failures);
    assert!(
        !failures.is_empty(),
        "the failed removal has to reach the oneshot's exit code"
    );
    assert!(
        dir.join("nic2.owned").exists(),
        "the note has to stay for the retry"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// Invariant 2's third leg: a virtual function still bound on the host -
/// no admin MAC set, so absent from the driver's answer - is recognised
/// by its netdev, and its address must never be registered past it.
#[test]
fn a_bound_sister_vf_is_excluded_by_its_netdev() {
    let dir = scratch("vf-netdev-excl");
    let vf_mac: Mac = [0x02, 0xe5, 0, 0, 0, 1];
    let topo = Builder::new()
        .add("nic1", 2, Some(mac(1)))
        .master("br0")
        .vfs(2)
        .vf_netdev("nic1v1")
        .add("nic1v1", 6, Some(vf_mac))
        .physfn("nic1")
        .add("vetha", 4, Some(mac(4)))
        .master("br0")
        .add("br0", 10, Some(mac(3)))
        .bridge()
        .lower("nic1")
        .lower("vetha")
        .build();
    let mut s = br0_syncer(&dir);
    // The bridge learns the VF's own address behind a guest port - the
    // reflection case the exclusion set exists to refuse. The driver's
    // answer does NOT name it: no admin MAC was ever set.
    let mut sock = kernel(vec![learned(4, 10, vf_mac)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    assert!(
        !sock.added.iter().any(|(_, m)| *m == vf_mac),
        "a bound VF's own address was registered past its function"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A `--check` leaves the note byte for byte as it found it. The probe is
/// added and taken away again, and everything else keeps its own bytes and
/// its own order - a whole-set write would sort the file, which is a trace
/// where the point is to leave none.
#[test]
fn a_check_probe_leaves_the_note_byte_identical() {
    let dir = scratch("check-bytes");
    let s = ready_syncer(&dir);
    const PROBE: Mac = [0x02, 0xe3, 0, 0, 0, 0x61];
    // Deliberately unsorted, the way an append leaves a note.
    let path = dir.join("nic1.owned");
    fs::create_dir_all(&dir).unwrap();
    let before = format!(
        "{}\n{}\n{}\n",
        format_mac(&BEHIND_GUEST),
        format_mac(&BEHIND_NIC),
        format_mac(&[0x02, 0x00, 0, 0, 0, 0x77])
    );
    fs::write(&path, &before).unwrap();

    assert!(s.note_check_probe("nic1", 2, &PROBE));
    s.forget_check_probe("nic1", &PROBE);
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        before,
        "the check rewrote the note it was only borrowing"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// An uplink with nothing to remember keeps no file around. The first
/// pass on a quiet host used to leave an empty one per uplink, for the
/// next process to read nothing out of.
#[test]
fn an_empty_memory_leaves_no_file() {
    let dir = scratch("quiet-empty-file");
    let (topo, mut s, _) = registered(&dir);
    let path = dir.join(".nic1.owned.ports");
    assert!(path.exists(), "the learnt addresses were not written down");

    // Everything moves out onto the wire: nothing is owned, nothing is
    // remembered, and the file goes with it.
    let wire: Vec<crate::netlink::FdbEntry> = fdb()
        .into_iter()
        .filter(|e| !e.is_self())
        .map(|e| learned(2, 10, e.mac))
        .collect();
    let mut sock2 = kernel(wire);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    assert!(
        s.load_owned("nic1").is_empty(),
        "the fixture did not end up owning nothing"
    );
    assert!(!path.exists(), "an empty memory left its file behind");
    let _ = fs::remove_dir_all(&dir);
}

/// A stamp from the future is brought back to now, not believed.
///
/// The clock counts from boot, so a memory file that outlives a reboot
/// carries stamps that are hours ahead of a freshly started machine's.
/// Believed, such a stamp says "spoke since the last pass" for the life of
/// the process - which is not a harmless "youngest": an address that is
/// never quiet is never a candidate the pressure valve can surrender, so
/// the slot is held until the guest itself leaves the bridge, which is
/// exactly the deadlock the valve exists to prevent.
#[test]
fn a_future_stamp_is_clamped_not_believed() {
    let dir = scratch("quiet-future-stamp");
    let a: Mac = [0x02, 0xe7, 0, 0, 0, 1];
    let b: Mac = [0x02, 0xe7, 0, 0, 0, 2];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, a), learned(4, 10, b)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    drop(s);

    // Both stamps are doctored to lie far ahead - the shape a memory file
    // that outlived a reboot has, since the clock counts from boot.
    let path = dir.join(".nic1.owned.ports");
    let doctored: String = fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|l| {
            let mut f: Vec<&str> = l.split(' ').collect();
            if f.len() == 4 {
                f[3] = "18446744073709551615";
            }
            format!("{}\n", f.join(" "))
        })
        .collect();
    fs::write(&path, doctored).unwrap();

    // Restart with room to spare: both are silent now, both are kept.
    let mut s = br0_syncer(&dir);
    let mut sock2 = kernel(vec![card_holds(2, a), card_holds(2, b)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    assert_eq!(s.carried["nic1"].quiet.len(), 2, "both should be kept");
    assert!(sock2.removed.is_empty(), "there was no pressure yet");
    // A clamped stamp reads as "spoke just now" for exactly one pass; the
    // second one leaves it behind, and from there it ages honestly. The
    // sleep is what makes that second pass's stamp certainly later: both
    // land in the same millisecond otherwise, and which of the two the
    // clock ticks between decides the outcome.
    std::thread::sleep(Dur::from_millis(5));
    let mut sock2b = kernel(vec![card_holds(2, a), card_holds(2, b)]);
    s.reconcile(&mut sock2b, true, &topo, Dur::ZERO).unwrap();

    // Now the room runs out and a newcomer arrives. One of the two silent
    // addresses has to pay for it.
    s.max_macs = 7;
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let newcomer: Mac = [0x02, 0xe7, 0, 0, 0, 9];
    let mut sock3 = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.fast_apply(
        &mut sock3,
        &topo,
        &[(RTM_NEWNEIGH, learned(4, 10, newcomer))],
    )
    .unwrap();
    assert_eq!(
        sock3.removed.len(),
        1,
        "a believed future stamp is never quiet, so the valve found nothing to surrender"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// An idle pass writes no memory file: the lines are compared against what
/// was last written, and a host where nothing changes must not rewrite a
/// file per pass - the notes hold themselves to the same rule.
#[test]
fn an_idle_pass_leaves_the_memory_file_untouched() {
    let dir = scratch("quiet-idle-file");
    let (topo, mut s, _) = registered(&dir);
    let path = dir.join(".nic1.owned.ports");
    // Backdate, then run an unchanged pass: an untouched file keeps the
    // old timestamp, a rewritten one comes back young.
    let old = filetime_backdate(&path);
    let mut sock2 = kernel(fdb());
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    let meta = fs::metadata(&path).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        (meta.mtime(), meta.mtime_nsec()),
        old,
        "an idle pass rewrote the memory file"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// Set a file's mtime into the past and return what it was set to.
fn filetime_backdate(path: &std::path::Path) -> (i64, i64) {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path).unwrap();
    let old = meta.mtime() - 3600;
    let times = [
        libc::timespec {
            tv_sec: old,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: old,
            tv_nsec: 0,
        },
    ];
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) };
    assert_eq!(rc, 0, "utimensat failed");
    (old, 0)
}

/// Foreign entries occupy real slots, and the valve counts them: the card
/// is read back anyway, so somebody's hand-added entries must press on
/// the keeps instead of eating an invisible margin.
#[test]
fn the_pressure_valve_counts_foreign_entries() {
    let dir = scratch("quiet-pressure-foreign");
    let m1: Mac = [0x02, 0xe8, 0, 0, 0, 1];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, m1)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();

    // m1 ages; two slots are wanted (bridge + keep). Alone that fits a
    // max of 6 - but four foreign entries sit in the card, and 2 + 4 + 4
    // headroom crosses 6: the keep has to yield to reality.
    s.max_macs = 6;
    let foreign: Vec<crate::netlink::FdbEntry> = (1..=4u8)
        .map(|i| card_holds(2, [0xaa, 0xee, 0, 0, 0, i]))
        .collect();
    let mut fdb2 = vec![card_holds(2, m1)];
    fdb2.extend(foreign.clone());
    let mut sock2 = kernel(fdb2);
    let reports = s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    assert!(
        sock2.removed.iter().any(|(_, m)| *m == m1),
        "foreign entries went uncounted; the keep stayed past the margin"
    );
    assert!(
        !sock2
            .removed
            .iter()
            .any(|(_, m)| m[0] == 0xaa && m[1] == 0xee),
        "foreign entries are pressed against, never touched"
    );
    assert_eq!(reports[0].quiet, 0);
    let _ = fs::remove_dir_all(&dir);
}

/// The fast path is capacity-aware: a learn that would not fit surrenders
/// the longest-missing keep synchronously - card, note and memory in one
/// breath - because 200 ms of overflow is 200 ms of the card dropping
/// arbitrarily, possibly the very guest that is speaking.
#[test]
fn a_burst_over_capacity_sheds_a_keep_on_the_fast_path() {
    let dir = scratch("quiet-fast-shed");
    let old: Mac = [0x02, 0xe9, 0, 0, 0, 1];
    let newcomer: Mac = [0x02, 0xe9, 0, 0, 0, 2];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, old)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();

    // `old` goes quiet; occupancy is 2 (bridge + keep) with max 6, i.e.
    // exactly at allowed = max - headroom.
    s.max_macs = 6;
    let mut sock2 = kernel(vec![card_holds(2, old)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    assert!(s.load_owned("nic1").contains(&old));

    // A new guest speaks. The batch would make three against allowed two:
    // the keep leaves in the same batch, the newcomer gets its slot.
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let mut sock3 = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.fast_apply(
        &mut sock3,
        &topo,
        &[(RTM_NEWNEIGH, learned(4, 10, newcomer))],
    )
    .unwrap();
    assert!(
        sock3.removed.iter().any(|(_, m)| *m == old),
        "the keep did not yield to the newcomer on the fast path"
    );
    assert!(
        sock3.added.iter().any(|(_, m)| *m == newcomer),
        "the newcomer was not registered"
    );
    assert!(
        !s.load_owned("nic1").contains(&old),
        "the shed keep stayed on the note - an orphan in the making"
    );
    assert!(s.load_owned("nic1").contains(&newcomer));
    let _ = fs::remove_dir_all(&dir);
}

/// The carried occupancy is CARRIED: several batches between two passes
/// each count against what the ones before them put in the card. Without
/// that, N single-address batches overflow the card by N-1 and nothing
/// notices until the next pass.
#[test]
fn successive_batches_count_against_each_other() {
    let dir = scratch("occupancy-carried");
    let quiet: Mac = [0x02, 0xea, 0, 0, 0, 1];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, quiet)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    // The guest goes quiet: two slots held (bridge + keep).
    let mut sock2 = kernel(vec![card_holds(2, quiet)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();

    // allowed = 8 - 4 = 4, occupancy 2. Two newcomers fit; the third must
    // buy its slot from the keep - which only happens if each batch counts
    // the ones before it.
    s.max_macs = 8;
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let newcomers: Vec<Mac> = (1..=3u8).map(|i| [0x02, 0xeb, 0, 0, 0, i]).collect();
    let mut last = FakeSock::default();
    for m in &newcomers {
        last = FakeSock {
            vf: vec![(2, VF_ADMIN)],
            ..Default::default()
        };
        s.fast_apply(&mut last, &topo, &[(RTM_NEWNEIGH, learned(4, 10, *m))])
            .unwrap();
    }
    assert!(
        last.removed.iter().any(|(_, m)| *m == quiet),
        "the third batch did not count the first two; the card overflows"
    );
    assert!(last.added.iter().any(|(_, m)| *m == newcomers[2]));
    let _ = fs::remove_dir_all(&dir);
}

/// A re-learn of an address the card already holds is not a new slot -
/// counting it would shed keeps to make room for something already in.
#[test]
fn a_relearn_buys_no_slot_and_sheds_nothing() {
    let dir = scratch("occupancy-relearn");
    let quiet: Mac = [0x02, 0xec, 0, 0, 0, 1];
    let live: Mac = [0x02, 0xec, 0, 0, 0, 2];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, quiet), learned(4, 10, live)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    // `quiet` ages; three slots held (bridge, keep, live).
    let mut sock2 = kernel(vec![card_holds(2, quiet), learned(4, 10, live)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();

    // Sitting exactly on the margin: allowed = 7 - 4 = 3, occupancy 3.
    // A re-learn of `live` must not be read as a fourth slot.
    s.max_macs = 7;
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let mut sock3 = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.fast_apply(&mut sock3, &topo, &[(RTM_NEWNEIGH, learned(4, 10, live))])
        .unwrap();
    assert!(
        sock3.removed.is_empty(),
        "a re-learn shed a keep for a slot it did not need: {:?}",
        sock3.removed
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The shedder never surrenders a guest that is speaking: only addresses
/// with a missing-stamp are candidates, the longest-missing goes first,
/// and an address the batch itself is registering is spared - deleting it
/// to add it back frees no slot at all.
#[test]
fn the_shedder_spares_the_live_and_the_incoming() {
    let dir = scratch("shed-selection");
    let old: Mac = [0x02, 0xed, 0, 0, 0, 3];
    let young: Mac = [0x02, 0xed, 0, 0, 0, 2];
    let live: Mac = [0x02, 0xed, 0, 0, 0, 1];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = FakeSock {
        fdb: vec![
            learned(4, 10, old),
            learned(4, 10, young),
            learned(4, 10, live),
        ],
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    // `old` goes quiet first, `young` a moment later; `live` keeps talking.
    let mut sock2 = FakeSock {
        fdb: vec![
            card_holds(2, old),
            learned(4, 10, young),
            learned(4, 10, live),
        ],
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    std::thread::sleep(Dur::from_millis(20));
    let mut sock3 = FakeSock {
        fdb: vec![
            card_holds(2, old),
            card_holds(2, young),
            learned(4, 10, live),
        ],
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.reconcile(&mut sock3, true, &topo, Dur::ZERO).unwrap();

    // Four slots held, allowed = 8 - 4 = 4: one newcomer needs one slot.
    s.max_macs = 8;
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let newcomer: Mac = [0x02, 0xed, 0, 0, 0, 9];
    let mut sock4 = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.fast_apply(
        &mut sock4,
        &topo,
        &[(RTM_NEWNEIGH, learned(4, 10, newcomer))],
    )
    .unwrap();
    assert!(
        sock4.removed.iter().any(|(_, m)| *m == old),
        "the longest-missing keep was not the one surrendered"
    );
    assert!(
        !sock4.removed.iter().any(|(_, m)| *m == young),
        "a younger keep was surrendered before an older one"
    );
    assert!(
        !sock4.removed.iter().any(|(_, m)| *m == live),
        "a guest that is still speaking was surrendered"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A guest that speaks again is young again on the FAST path too, not
/// only in a pass: otherwise the shedder names the guest that just spoke,
/// and the delete is undone by the add that follows it - zero slots freed.
#[test]
fn a_fast_path_learn_makes_an_entry_young_again() {
    let dir = scratch("shed-rejuvenate");
    let a: Mac = [0x02, 0xee, 0, 0, 0, 1];
    let b: Mac = [0x02, 0xee, 0, 0, 0, 2];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, a), learned(4, 10, b)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    // `a` goes quiet first, then `b`: a is the older keep.
    let mut sock2 = kernel(vec![card_holds(2, a), learned(4, 10, b)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    std::thread::sleep(Dur::from_millis(20));
    let mut sock3 = kernel(vec![card_holds(2, a), card_holds(2, b)]);
    s.reconcile(&mut sock3, true, &topo, Dur::ZERO).unwrap();

    // `a` speaks again - a re-learn, no new slot - and must now be the
    // YOUNGER of the two. The newcomer that follows then costs `b`.
    s.max_macs = 7;
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let mut sock4 = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.fast_apply(&mut sock4, &topo, &[(RTM_NEWNEIGH, learned(4, 10, a))])
        .unwrap();
    assert!(sock4.removed.is_empty(), "the re-learn should shed nothing");

    let newcomer: Mac = [0x02, 0xee, 0, 0, 0, 9];
    let mut sock5 = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.fast_apply(
        &mut sock5,
        &topo,
        &[(RTM_NEWNEIGH, learned(4, 10, newcomer))],
    )
    .unwrap();
    assert!(
        sock5.removed.iter().any(|(_, m)| *m == b),
        "the entry that spoke most recently was surrendered"
    );
    assert!(
        !sock5.removed.iter().any(|(_, m)| *m == a),
        "speaking again did not make the entry young"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A shed whose removal the card refuses keeps its line on the note: an
/// entry still in the filter that no note names is the orphan nothing
/// would ever take out. ENOENT is the other way round - it is already
/// gone, and the note goes with it.
#[test]
fn a_refused_shed_keeps_its_note_line() {
    let dir = scratch("shed-refused");
    let quiet: Mac = [0x02, 0xef, 0, 0, 0, 1];
    let topo = small_host();
    for (errno, still_noted) in [(libc::EBUSY, true), (libc::ENOENT, false)] {
        let dir = dir.join(format!("e{errno}"));
        let mut s = br0_syncer(&dir);
        let mut sock = kernel(vec![learned(4, 10, quiet)]);
        s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
        let mut sock2 = kernel(vec![card_holds(2, quiet)]);
        s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();

        s.max_macs = 6;
        s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
        let mut fail = crate::hash::map();
        fail.insert(quiet, errno);
        let mut sock3 = FakeSock {
            vf: vec![(2, VF_ADMIN)],
            fail_del: fail,
            ..Default::default()
        };
        let newcomer: Mac = [0x02, 0xef, 0, 0, 0, 9];
        s.fast_apply(
            &mut sock3,
            &topo,
            &[(RTM_NEWNEIGH, learned(4, 10, newcomer))],
        )
        .unwrap();
        assert_eq!(
            s.load_owned("nic1").contains(&quiet),
            still_noted,
            "errno {errno}: the note has to keep what is still in the card, \
             and let go of what is not"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

/// A note that cannot be read holds the card still - the shedder included.
/// It is the one removal path that could delete entries while the batch
/// that asked for the room is refused, which would be pure loss.
#[test]
fn an_unreadable_note_stops_the_shedder() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let dir = scratch("shed-unreadable");
    let quiet: Mac = [0x02, 0xf0, 0, 0, 0, 1];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, quiet)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    let mut sock2 = kernel(vec![card_holds(2, quiet)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();

    // Somebody replaced the note with one this daemon cannot read - a new
    // inode, so the remembered copy is not believed either, and the
    // process genuinely no longer knows what it owns.
    let note = dir.join("nic1.owned");
    let tmp = dir.join(".nic1.owned.swap");
    fs::write(&tmp, fs::read_to_string(&note).unwrap()).unwrap();
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o000)).unwrap();
    fs::rename(&tmp, &note).unwrap();
    assert!(
        s.load_owned("nic1").is_empty() && !s.note_is_readable("nic1"),
        "the fixture failed to make the note unreadable"
    );
    s.max_macs = 6;
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let newcomer: Mac = [0x02, 0xf0, 0, 0, 0, 9];
    let mut sock3 = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.fast_apply(
        &mut sock3,
        &topo,
        &[(RTM_NEWNEIGH, learned(4, 10, newcomer))],
    )
    .unwrap();
    assert!(
        sock3.removed.is_empty(),
        "the shedder emptied slots out of a note it could not read"
    );
    fs::set_permissions(&note, fs::Permissions::from_mode(0o600)).unwrap();
    let _ = fs::remove_dir_all(&dir);
}

/// A replaced note is read again even when it kept the old timestamp: the
/// identity check is what carries this, not the clock. Coarse-clock
/// filesystems hand a rename the mtime of what it replaced often enough
/// that a guard resting on time alone would answer from a stale copy -
/// and an address somebody appended would then count foreign for ever.
#[test]
fn a_replaced_note_is_read_again_even_at_the_same_mtime() {
    let dir = scratch("note-moved-under-read");
    let s = ready_syncer(&dir);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("nic1.owned");
    fs::write(&path, format!("{}\n", format_mac(&BEHIND_NIC))).unwrap();
    assert_eq!(s.load_owned("nic1").len(), 1);

    // Replaced through a rename, the way every writer here replaces it -
    // new inode, and on a coarse-clock filesystem quite possibly the same
    // mtime as the read that just happened.
    let tmp = dir.join(".nic1.owned.other");
    fs::write(
        &tmp,
        format!(
            "{}\n{}\n",
            format_mac(&BEHIND_NIC),
            format_mac(&BEHIND_GUEST)
        ),
    )
    .unwrap();
    let meta = fs::metadata(&path).unwrap();
    fs::rename(&tmp, &path).unwrap();
    // Make the new file look exactly as old as the one it replaced: this
    // is the state the coarse clock produces on its own.
    let times = [
        libc::timespec {
            tv_sec: meta.mtime(),
            tv_nsec: meta.mtime_nsec(),
        },
        libc::timespec {
            tv_sec: meta.mtime(),
            tv_nsec: meta.mtime_nsec(),
        },
    ];
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(
        unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) },
        0
    );
    assert_eq!(
        s.load_owned("nic1").len(),
        2,
        "the replaced note was answered from a stale remembered copy"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A device that stopped being an uplink loses its whole record - note,
/// index and quiet memory together. A memory file left behind is
/// invisible to every sweep (nothing globs it) and would be adopted by
/// the device's next life.
#[test]
fn the_orphan_sweep_takes_the_memory_file_with_the_note() {
    let dir = scratch("orphan-memory");
    let topo = host(mac(1));
    let (_, mut s, _) = registered(&dir);
    age_out(&mut s, &topo, BEHIND_GUEST);
    let ports = dir.join(".nic1.owned.ports");
    assert!(ports.exists(), "the fixture wrote no memory to sweep");

    // nic1 is no longer an uplink: no pairs at all, and the topology no
    // longer has it either, so the sweep removes rather than migrates.
    s.pairs = Vec::new();
    let mut sock = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    let mut failures = Vec::new();
    s.drop_orphans(&mut sock, &host(mac(1)), true, &mut failures);
    assert!(
        !dir.join("nic1.owned").exists(),
        "the note outlived the sweep"
    );
    assert!(!ports.exists(), "the quiet memory outlived its note");
    let _ = fs::remove_dir_all(&dir);
}

/// A renamed uplink keeps its capacity arithmetic: the pass that follows
/// the rename recomputes it, and the batches after that count against the
/// recomputed number rather than from zero. (The rename's own transfer of
/// the two maps is belt-and-braces for the pass that skips its pair; what
/// this pins is that the arithmetic is right under the new name at all.)
#[test]
fn the_capacity_arithmetic_survives_a_rename() {
    let dir = scratch("occupancy-rename");
    let quiet: Mac = [0x02, 0xf1, 0, 0, 0, 1];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, quiet)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    let mut sock2 = kernel(vec![card_holds(2, quiet)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();

    // Same interface, same index, new name.
    let renamed = Builder::new()
        .add("nicX", 2, Some(mac(1)))
        .master("br0")
        .vfs(1)
        .add("vetha", 4, Some(mac(4)))
        .master("br0")
        .add("br0", 10, Some(mac(3)))
        .bridge()
        .lower("nicX")
        .lower("vetha")
        .build();
    s.pairs = vec![Pair {
        dev: "nicX".into(),
        bridge: "br0".into(),
    }];
    let mut sock3 = kernel(vec![card_holds(2, quiet)]);
    s.reconcile(&mut sock3, true, &renamed, Dur::ZERO).unwrap();

    // Under the new name, one newcomer past the margin: the keep pays.
    // Counting from zero here would leave it standing and overfill.
    s.max_macs = 6;
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let newcomer: Mac = [0x02, 0xf1, 0, 0, 0, 9];
    let mut sock4 = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.fast_apply(
        &mut sock4,
        &renamed,
        &[(RTM_NEWNEIGH, learned(4, 10, newcomer))],
    )
    .unwrap();
    assert!(
        sock4.removed.iter().any(|(_, m)| *m == quiet),
        "the renamed uplink counted from zero and overfilled its card"
    );

    // And the list of WHICH addresses travelled too: re-learning the
    // newcomer costs no slot, so nothing more may be shed. Without the
    // carried list the re-learn reads as a fresh slot and takes a keep
    // with it - here there are none left, so it would warn instead.
    let mut sock5 = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.fast_apply(
        &mut sock5,
        &renamed,
        &[(RTM_NEWNEIGH, learned(4, 10, newcomer))],
    )
    .unwrap();
    assert!(
        sock5.removed.is_empty(),
        "a re-learn after the rename was counted as a new slot"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A stale removal the card refused evicts its port memory so it cannot
/// harden into a keep - and the pass's own memory merge must not put it
/// straight back. Otherwise the outcome depends on whether the card
/// errored, which is the opposite of what the failure arm intends.
#[test]
fn a_refused_stale_removal_does_not_return_through_the_merge() {
    let dir = scratch("stale-refused-merge");
    let topo = host(mac(1));
    let (_, mut s, _) = registered(&dir);
    assert!(s.load_owned("nic1").contains(&BEHIND_GUEST));

    // The guest's port goes: nothing vouches for the address any more, so
    // the pass wants it gone - and the card refuses to let go.
    let without_veth = Builder::new()
        .add("nic1", 2, Some(mac(1)))
        .master("vmbr1")
        .vfs(1)
        .add("nic2", 3, Some(mac(2)))
        .master("vmbr1")
        .add("vmbr1", 10, Some(mac(1)))
        .bridge()
        .lower("nic1")
        .lower("nic2")
        .build();
    let mut fail = crate::hash::map();
    fail.insert(BEHIND_GUEST, libc::EBUSY);
    let mut sock2 = FakeSock {
        fdb: vec![card_holds(2, BEHIND_GUEST)],
        vf: vec![(2, VF_ADMIN)],
        fail_del: fail,
        ..Default::default()
    };
    s.reconcile(&mut sock2, true, &without_veth, Dur::ZERO)
        .unwrap();
    assert!(
        s.load_owned("nic1").contains(&BEHIND_GUEST),
        "a refused removal keeps its note line for the retry"
    );

    // The port comes back - a container restarting under the same name.
    // With the memory evicted the address is still stale and the retry
    // removes it; with the memory put back by the merge it would be held
    // as a quiet keep instead, and the retry would never come.
    let mut sock3 = FakeSock {
        fdb: vec![card_holds(2, BEHIND_GUEST)],
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.reconcile(&mut sock3, true, &topo, Dur::ZERO).unwrap();
    assert!(
        sock3.removed.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "the refused removal came back as a keep instead of being retried"
    );
    assert!(
        !s.load_owned("nic1").contains(&BEHIND_GUEST),
        "and the note lets go once the card did"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// When the room needed is more than the quiet can give, the shedder
/// stops rather than reaching into the living: a guest the bridge still
/// knows is one somebody is talking to right now, and taking its entry
/// out to make room for another is the outage this daemon exists to
/// prevent. The ordering alone would not stop it - it would simply carry
/// on into the next-oldest, which is a speaking guest.
#[test]
fn the_shedder_stops_rather_than_take_a_living_guest() {
    let dir = scratch("shed-stops");
    let quiet: Mac = [0x02, 0xf2, 0, 0, 0, 1];
    let live: Mac = [0x02, 0xf2, 0, 0, 0, 2];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, quiet), learned(4, 10, live)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    // `quiet` falls silent; `live` keeps talking. Three slots held.
    let mut sock2 = kernel(vec![card_holds(2, quiet), learned(4, 10, live)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();

    // Three slots held, allowed = 7 - 4 = 3, two newcomers: two slots are
    // needed and only one quiet entry can pay. The shedder must stop
    // there rather than carry on into `live`, which the ordering alone
    // would happily do.
    s.max_macs = 7;
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let a: Mac = [0x02, 0xf2, 0, 0, 0, 8];
    let b: Mac = [0x02, 0xf2, 0, 0, 0, 9];
    let mut sock3 = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.fast_apply(
        &mut sock3,
        &topo,
        &[
            (RTM_NEWNEIGH, learned(4, 10, a)),
            (RTM_NEWNEIGH, learned(4, 10, b)),
        ],
    )
    .unwrap();
    assert!(
        sock3.removed.iter().any(|(_, m)| *m == quiet),
        "the one quiet entry should have been surrendered"
    );
    assert!(
        !sock3.removed.iter().any(|(_, m)| *m == live),
        "a guest the bridge still knows was surrendered for room"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The over-capacity warning is said once per stay above the limit and
/// re-armed when it clears - and it counts what the CARD holds, foreign
/// entries included, not merely what the daemon wants. Every part of that
/// could be deleted without a test noticing.
#[test]
fn the_over_capacity_warning_counts_the_card_and_says_it_once() {
    let dir = scratch("over-capacity-warning");
    let mine: Mac = [0x02, 0xf3, 0, 0, 0, 1];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    // Four foreign entries in the card plus our two: six against a limit
    // of five. Wanting two alone would stay under it.
    s.max_macs = 5;
    let foreign: Vec<crate::netlink::FdbEntry> = (1..=4u8)
        .map(|i| card_holds(2, [0xaa, 0xf3, 0, 0, 0, i]))
        .collect();
    let mut fdb1 = vec![learned(4, 10, mine)];
    fdb1.extend(foreign.clone());
    let mut sock = kernel(fdb1);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    assert!(
        s.warned_over.contains("nic1"),
        "the card is over its limit and nothing said so"
    );

    // Said once: a second identical pass must not re-arm it.
    let mut fdb2 = vec![learned(4, 10, mine)];
    fdb2.extend(foreign);
    let mut sock2 = kernel(fdb2);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    assert!(s.warned_over.contains("nic1"), "the mark must stand");

    // The foreign entries go: back under the limit, and the warning is
    // armed again for the next time.
    let mut sock3 = kernel(vec![learned(4, 10, mine)]);
    s.reconcile(&mut sock3, true, &topo, Dur::ZERO).unwrap();
    assert!(
        !s.warned_over.contains("nic1"),
        "back under the limit has to re-arm the warning"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A memory file from a build whose numbers meant something else is no
/// memory at all. Without the format line this silently read the old
/// missing-since milliseconds as last-seen nanoseconds, and every
/// carried-over entry looked silent since boot.
#[test]
fn a_memory_file_from_another_format_is_ignored() {
    let dir = scratch("ports-format");
    let topo = host(mac(1));
    let (_, mut s, _) = registered(&dir);
    age_out(&mut s, &topo, BEHIND_GUEST);
    let path = dir.join(".nic1.owned.ports");
    let good = fs::read_to_string(&path).unwrap();
    drop(s);

    // The same lines under a header this build does not know.
    let body: Vec<&str> = good.lines().skip(1).collect();
    fs::write(
        &path,
        format!("sriov-mac-sync ports 1\n{}\n", body.join("\n")),
    )
    .unwrap();

    let mut restarted = ready_syncer(&dir);
    let mut aged = fdb_without(BEHIND_GUEST);
    aged.push(card_holds(2, BEHIND_GUEST));
    let mut sock = kernel(aged);
    let reports = restarted
        .reconcile(&mut sock, true, &topo, Dur::ZERO)
        .unwrap();
    assert!(
        sock.removed.iter().any(|(_, m)| *m == BEHIND_GUEST),
        "a file in an unknown format was believed anyway"
    );
    assert_eq!(reports[0].quiet, 0);
    // And the next write leaves it in the format this build does read.
    assert_eq!(
        fs::read_to_string(&path).unwrap().lines().next(),
        good.lines().next(),
        "the file was not rewritten in this build's own format"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A bridge forgets an address exactly its ageing time after the last
/// frame from it, so the deletion it announces dates that frame: the
/// guest spoke one ageing time ago. Where the pass had only "it was
/// still there when I looked", the deletion can say "and it went on
/// speaking after that" - never the reverse, which is what the
/// only-if-later guard is for. The valve evicts by this number, so an
/// address the bridge vouches for outlives one it says nothing about.
#[test]
fn a_deletion_says_how_long_after_the_pass_the_guest_spoke() {
    let dir = scratch("delneigh-dates");
    // `spoke_later` sorts FIRST, so the address tie-break alone would
    // name it: only a real date can spare it.
    let spoke_later: Mac = [0x02, 0xf4, 0, 0, 0, 1];
    let just_quiet: Mac = [0x02, 0xf4, 0, 0, 0, 2];
    // A bridge that forgets in 10 ms, so "one ageing time ago" lands
    // inside a test's lifetime rather than five minutes outside it.
    let topo = Builder::new()
        .add("nic1", 2, Some(mac(1)))
        .master("br0")
        .vfs(1)
        .add("vetha", 4, Some(mac(4)))
        .master("br0")
        .add("br0", 10, Some(mac(3)))
        .bridge()
        .ageing(Some(10))
        .lower("nic1")
        .lower("vetha")
        .build();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![
        learned(4, 10, spoke_later),
        learned(4, 10, just_quiet),
    ]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();

    // Time passes with no pass in it - the window the daemon is blind in.
    std::thread::sleep(Dur::from_millis(40));

    // The bridge forgets one of them and says so. Its ageing time places
    // that guest's last frame 10 ms ago, well after the pass above.
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let mut ev = FakeSock::default();
    s.fast_apply(
        &mut ev,
        &topo,
        &[(RTM_DELNEIGH, learned(4, 10, spoke_later))],
    )
    .unwrap();

    // Both are keeps now, and there is room for one.
    let mut sock2 = kernel(vec![card_holds(2, spoke_later), card_holds(2, just_quiet)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    s.max_macs = 7;
    let newcomer: Mac = [0x02, 0xf4, 0, 0, 0, 9];
    let mut sock3 = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.fast_apply(
        &mut sock3,
        &topo,
        &[(RTM_NEWNEIGH, learned(4, 10, newcomer))],
    )
    .unwrap();
    assert!(
        sock3.removed.iter().any(|(_, m)| *m == just_quiet),
        "the address nothing vouched for should have paid"
    );
    assert!(
        !sock3.removed.iter().any(|(_, m)| *m == spoke_later),
        "the address the bridge dated as speaking after the pass was evicted"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The dating never runs backwards. A vlan-aware bridge holds one entry
/// per VLAN and ages them apart, so a deletion can arrive for an address
/// that spoke in another VLAN moments ago - and the later word is the
/// true one. Without the guard the deletion would date it a whole ageing
/// time into the past and the valve would evict the address that is in
/// fact the most recently heard of the two.
#[test]
fn a_deletion_never_makes_an_address_older_than_it_is() {
    let dir = scratch("delneigh-no-regress");
    let a: Mac = [0x02, 0xf5, 0, 0, 0, 1];
    let b: Mac = [0x02, 0xf5, 0, 0, 0, 2];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, a), learned(4, 10, b)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();

    // `b` falls silent; `a` keeps speaking, so the next pass moves only
    // `a`'s stamp forward. `a` is now the more recently heard of the two.
    let mut sock2 = kernel(vec![learned(4, 10, a), card_holds(2, b)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();

    // One of `a`'s VLAN entries ages out and says so. Dating it back a
    // whole ageing time would put it behind `b`, which is the opposite of
    // what the bridge just told us about `a`.
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let mut ev = FakeSock::default();
    s.fast_apply(&mut ev, &topo, &[(RTM_DELNEIGH, learned(4, 10, a))])
        .unwrap();
    // Now `a` really does fall silent too, so both are keeps.
    let mut sock3 = kernel(vec![card_holds(2, a), card_holds(2, b)]);
    s.reconcile(&mut sock3, true, &topo, Dur::ZERO).unwrap();

    // Three slots held, allowed = 3, one newcomer: exactly one keep pays,
    // and it has to be `b`.
    s.max_macs = 7;
    let newcomer: Mac = [0x02, 0xf5, 0, 0, 0, 9];
    let mut sock4 = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.fast_apply(
        &mut sock4,
        &topo,
        &[(RTM_NEWNEIGH, learned(4, 10, newcomer))],
    )
    .unwrap();
    assert!(
        sock4.removed.iter().any(|(_, m)| *m == b),
        "the address silent since the earlier pass should have paid"
    );
    assert!(
        !sock4.removed.iter().any(|(_, m)| *m == a),
        "a deletion dated an address older than the bridge had just shown it"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The date is the deletion's moment minus the bridge's ageing time, not
/// the deletion's moment: the bridge gave up now, so the guest spoke one
/// ageing time ago. Taking the moment itself would credit every aged-out
/// address with having just spoken - and the valve would then protect the
/// addresses that have been silent longest.
#[test]
fn the_date_is_one_ageing_time_before_the_deletion() {
    let dir = scratch("delneigh-arithmetic");
    let m: Mac = [0x02, 0xf6, 0, 0, 0, 1];
    // A bridge that forgets after 200 ms, so a test can outlive it.
    let topo = Builder::new()
        .add("nic1", 2, Some(mac(1)))
        .master("br0")
        .vfs(1)
        .add("vetha", 4, Some(mac(4)))
        .master("br0")
        .add("br0", 10, Some(mac(3)))
        .bridge()
        .ageing(Some(200))
        .lower("nic1")
        .lower("vetha")
        .build();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, m)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();

    // Long enough that the deletion's date lands after the pass, so the
    // only-if-later guard lets it through and the number is really this
    // code's arithmetic rather than the pass's stamp.
    // Twice the ageing time, so that the two answers are far apart: dated,
    // the silence comes out at one ageing time; undated, it is the whole
    // wait. A window that admits both is a window that pins nothing.
    std::thread::sleep(Dur::from_millis(400));
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let mut ev = FakeSock::default();
    s.fast_apply(&mut ev, &topo, &[(RTM_DELNEIGH, learned(4, 10, m))])
        .unwrap();

    let mut sock2 = kernel(vec![card_holds(2, m)]);
    let reports = s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    let (_, silent) = reports[0]
        .quiet_ages
        .iter()
        .find(|(a, _)| *a == m)
        .expect("the address should be held quiet");
    assert!(
        (190..=310).contains(silent),
        "the silence should be the bridge's 200 ms ageing time, not the 400 ms \
         since the pass - was {silent} ms"
    );
}

/// Stamps only ever move forward, whoever writes them. The sources do
/// not share a clock reading: a pass stamp is nudged past its
/// predecessor and can sit a millisecond ahead of the clock a learn
/// moments later reads, and a deletion's date is deliberately older than
/// now. Written without that rule, a learn - the very evidence that a
/// guest is alive - could set its stamp back and make it the pressure
/// valve's first victim.
#[test]
fn a_stamp_never_moves_backwards_whoever_writes_it() {
    let dir = scratch("stamp-monotone");
    let m: Mac = [0x02, 0xf7, 0, 0, 0, 1];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, m)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();

    // A pass stamp is `max(clock, previous + 1)`, so a run of passes
    // inside one millisecond walks ahead of the clock. Two passes back to
    // back usually do that by themselves - usually is not a premise, and
    // for two years of this test's life it silently did not hold - so the
    // predecessor is set a minute ahead and the nudge is certain.
    s.last_pass_at = Syncer::boot_millis() + 60_000;
    let mut sock2 = kernel(vec![learned(4, 10, m)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    let after_pass = s.carried_ports["nic1"][&m].1;
    assert!(
        after_pass > Syncer::boot_millis(),
        "the premise: the pass stamp has to be ahead of the clock a learn reads"
    );

    // A learn now: evidence the guest is alive, and it must not read as
    // older than what the pass already recorded.
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let mut ev = FakeSock::default();
    s.fast_apply(&mut ev, &topo, &[(RTM_NEWNEIGH, learned(4, 10, m))])
        .unwrap();
    assert!(
        s.carried_ports["nic1"][&m].1 >= after_pass,
        "a learn set the stamp back: {} then {}",
        after_pass,
        s.carried_ports["nic1"][&m].1
    );

    // And a deletion, which dates deliberately into the past, cannot
    // either.
    let before_del = s.carried_ports["nic1"][&m].1;
    let mut ev2 = FakeSock::default();
    s.fast_apply(&mut ev2, &topo, &[(RTM_DELNEIGH, learned(4, 10, m))])
        .unwrap();
    assert!(
        s.carried_ports["nic1"][&m].1 >= before_del,
        "a deletion set the stamp back"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A registration the card refused with a hard error is NOT in the card,
/// and must not be recorded as if it were. The grow-gate reads
/// owned-and-present as "re-learning this grows nothing" and skips the
/// fresh driver question - so a wrongly-present address lets the next
/// re-learn write a virtual function's own address into the filter.
#[test]
fn a_refused_registration_is_not_recorded_as_present() {
    let dir = scratch("present-honest");
    let m: Mac = [0x02, 0xf8, 0, 0, 0, 1];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);

    // The card refuses the add outright. The note keeps the line for the
    // retry - that is the crash posture and deliberate.
    let mut fail = crate::hash::map();
    fail.insert(m, libc::EBUSY);
    let mut sock = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        fail_add: fail,
        ..Default::default()
    };
    s.fast_apply(&mut sock, &topo, &[(RTM_NEWNEIGH, learned(4, 10, m))])
        .unwrap();
    assert!(
        s.load_owned("nic1").contains(&m),
        "a refused add keeps its note line for the retry"
    );
    assert!(
        !s.carried["nic1"].present.contains(&m),
        "an address the card refused was recorded as present"
    );

    // The re-learn is therefore a growth, and a growth asks the driver.
    let mut sock2 = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.fast_apply(&mut sock2, &topo, &[(RTM_NEWNEIGH, learned(4, 10, m))])
        .unwrap();
    assert!(
        sock2.vf_asked >= 1,
        "putting an address the card never took back in is a growth and has to ask"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The event path's valve surrenders from the same pool the pass's does -
/// the pass's keeps - so it can never reach an address the pass would
/// refuse to shed. A pinned EXTRA that has aged out of the bridge is
/// exactly such an address: `quiet_survivors` skips everything still
/// wanted, so the pass would never surrender it, and neither may a burst.
#[test]
fn the_fast_valve_never_sheds_a_pinned_address() {
    let dir = scratch("shed-spares-pinned");
    let pinned: Mac = [0x02, 0xf9, 0, 0, 0, 1];
    let ordinary: Mac = [0x02, 0xf9, 0, 0, 0, 2];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    s.extra.insert(pinned);
    let mut sock = kernel(vec![learned(4, 10, pinned), learned(4, 10, ordinary)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();

    // Both fall silent. `pinned` stays wanted because EXTRA pins it, so
    // it is not a keep; `ordinary` is.
    let mut sock2 = kernel(vec![card_holds(2, pinned), card_holds(2, ordinary)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();

    // Room for one: `ordinary` has to pay, whatever the addresses sort
    // like - `pinned` sorts first and would go if the pool were the whole
    // port memory.
    s.max_macs = 7;
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let newcomer: Mac = [0x02, 0xf9, 0, 0, 0, 9];
    let mut sock3 = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.fast_apply(
        &mut sock3,
        &topo,
        &[(RTM_NEWNEIGH, learned(4, 10, newcomer))],
    )
    .unwrap();
    assert!(
        !sock3.removed.iter().any(|(_, m)| *m == pinned),
        "the burst surrendered a pinned address the pass would have kept"
    );
    assert!(
        sock3.removed.iter().any(|(_, m)| *m == ordinary),
        "the ordinary keep should have paid instead"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A pass that could not read its note refreshes no stamp, so it must not
/// advance the ground stamps are judged against either - every live guest
/// would read as quiet afterwards and the event path would delete a
/// speaking guest's entry to make room.
#[test]
fn a_blind_pass_does_not_move_the_ground() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let dir = scratch("blind-pass-ground");
    let m: Mac = [0x02, 0xfa, 0, 0, 0, 1];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, m)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    let ground = s.carried["nic1"].passed_at;

    // The note is replaced by one this daemon cannot read.
    let note = dir.join("nic1.owned");
    let tmp = dir.join(".nic1.owned.swap");
    fs::write(&tmp, fs::read_to_string(&note).unwrap()).unwrap();
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o000)).unwrap();
    fs::rename(&tmp, &note).unwrap();

    let mut sock2 = kernel(vec![learned(4, 10, m)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    assert_eq!(
        s.carried["nic1"].passed_at, ground,
        "a pass that saw nothing moved the ground its stamps are judged against"
    );
    assert!(
        s.carried["nic1"].quiet.is_empty(),
        "a pass that could not read its note keeps nothing"
    );
    fs::set_permissions(&note, fs::Permissions::from_mode(0o600)).unwrap();
    let _ = fs::remove_dir_all(&dir);
}

/// The memory only ever learns about addresses this daemon registered.
///
/// A deletion arrives for every address the bridge forgets, ours or not,
/// and `date_the_silence` dates them all - but an address with no entry
/// yet gets one only when a port comes with it, and a deletion carries
/// none. Without that, the neighbour's printer would sit in the memory,
/// and the pressure valve draws its victims from there: it would send a
/// `bridge fdb del` for an entry this daemon never put in the card, which
/// is the one thing the removal path may never do.
#[test]
fn a_deletion_alone_never_puts_an_address_into_the_memory() {
    let dir = scratch("memory-owned-only");
    let ours: Mac = [0x02, 0xfb, 0, 0, 0, 1];
    let stranger: Mac = [0x02, 0xfb, 0, 0, 0, 2];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, ours)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);

    // The bridge forgets both: one of ours, and one that was never ours
    // to begin with.
    let mut ev = FakeSock::default();
    s.fast_apply(
        &mut ev,
        &topo,
        &[
            (RTM_DELNEIGH, learned(4, 10, ours)),
            (RTM_DELNEIGH, learned(4, 10, stranger)),
        ],
    )
    .unwrap();
    assert!(
        s.carried_ports["nic1"].contains_key(&ours),
        "our own address should still be remembered"
    );
    assert!(
        !s.carried_ports["nic1"].contains_key(&stranger),
        "a deletion put a foreign address into the memory the valve deletes from"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// What the valve surrenders, it also stops counting.
///
/// The occupancy is what the next burst measures its room against, and
/// `present` is what tells the decide phase an address is already in the
/// card. A shed entry that stays in either makes the valve believe it
/// freed nothing - so it sheds again, and again, one guest per burst,
/// while the card never gets any emptier.
#[test]
fn a_shed_entry_stops_being_counted() {
    let dir = scratch("shed-bookkeeping");
    let old: Mac = [0x02, 0xfc, 0, 0, 0, 1];
    let topo = small_host();
    let mut s = br0_syncer(&dir);
    let mut sock = kernel(vec![learned(4, 10, old)]);
    s.reconcile(&mut sock, true, &topo, Dur::ZERO).unwrap();
    std::thread::sleep(Dur::from_millis(5));
    let mut sock2 = kernel(vec![card_holds(2, old)]);
    s.reconcile(&mut sock2, true, &topo, Dur::ZERO).unwrap();
    let before = s.carried["nic1"].occupancy;
    assert!(s.carried["nic1"].present.contains(&old));

    s.max_macs = 5;
    s.remember_vf(vec![2], vec![(2, VF_ADMIN)]);
    let newcomer: Mac = [0x02, 0xfc, 0, 0, 0, 9];
    let mut ev = FakeSock {
        vf: vec![(2, VF_ADMIN)],
        ..Default::default()
    };
    s.fast_apply(&mut ev, &topo, &[(RTM_NEWNEIGH, learned(4, 10, newcomer))])
        .unwrap();
    assert!(
        ev.removed.iter().any(|(_, m)| *m == old),
        "the silent entry should have been surrendered"
    );
    assert!(
        !s.carried["nic1"].present.contains(&old),
        "a surrendered address is still counted as being in the card"
    );
    assert!(
        !s.carried["nic1"].quiet.contains(&old),
        "a surrendered address is still offered to the next burst"
    );
    // One out, one in: the count says exactly that.
    assert_eq!(
        s.carried["nic1"].occupancy, before,
        "the occupancy did not follow what the valve did"
    );
    let _ = fs::remove_dir_all(&dir);
}
