//! sriov-mac-sync - make hosts behind a Linux bridge reachable from an SR-IOV
//! virtual function.
//!
//! A NIC with SR-IOV switches internally. Its forwarding table holds the
//! addresses of its own vports and nothing else, so a frame from a VF to any
//! other destination misses and is pushed out on the wire. That is right until
//! the uplink is a bridge port and the bridge carries local guests or a second
//! NIC: those peers sit behind the uplink, and frames for them leave the host
//! and are lost. Broadcast still floods, so address resolution succeeds and
//! the unicast that follows disappears.
//!
//! An address can be put into the uplink's own unicast filter list, which the
//! driver mirrors into the NIC's vport context; the internal switch then has a
//! hit and delivers to the uplink, where the bridge takes over. This daemon
//! keeps that list in step with what the bridges learn.

mod daemon;
mod devlink;
mod hash;
mod netlink;
mod sync;
mod topology;

use crate::daemon::{
    adopt_reported_capacity, capacities_via_devlink, daemon_loop, read_topology, Live,
};
use crate::hash::Set;
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use netlink::{format_mac, parse_mac, Socket};
use sync::{Pair, Syncer};
use topology::Topology;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const CONF: &str = "/etc/sriov-mac-sync.conf";
const STATE_DIR: &str = "/run/sriov-mac-sync";
/// The same directory where the system keeps its runtime state elsewhere.
const STATE_DIR_FALLBACK: &str = "/var/run/sriov-mac-sync";

/// Where the notes live on THIS system.
///
/// `/run` is the tmpfs on every systemd platform. OpenWrt up to 23.05 has
/// no `/run` at all, and creating it there puts the state on the overlay:
/// persistent flash, worn by every note write, and a "reboot starts from
/// nothing" story that quietly stops being true. `/var/run` is OpenWrt's
/// spelling of the same tmpfs (a symlink into /tmp); 24.10 symlinks `/run`
/// to it as well, where this simply takes the first spelling. Decided by
/// what the system provides, not by a build flag, so one binary is right
/// on all of them.
fn state_dir() -> PathBuf {
    if std::path::Path::new("/run").is_dir() {
        PathBuf::from(STATE_DIR)
    } else {
        PathBuf::from(STATE_DIR_FALLBACK)
    }
}

/// Ordinary progress, on stdout.
///
/// Everything this daemon says used to go to stderr, which systemd timestamps
/// exactly like stdout and nobody ever noticed. procd on OpenWrt does notice:
/// it files stderr under the error level, so a service whose whole normal life
/// (started, registered, reconciled) arrives as `daemon.err` teaches the
/// operator that its log is noise. Trouble still goes to stderr, which is what
/// makes the distinction worth anything.
///
/// Flushed on every line: stdout is block-buffered when it is a pipe, which is
/// exactly what an init system hands a daemon, and a log that appears in
/// four-kilobyte lumps hours later is not a log.
#[macro_export]
macro_rules! note {
    ($($arg:tt)*) => {{
        use std::io::Write;
        let out = std::io::stdout();
        let mut out = out.lock();
        let _ = writeln!(out, $($arg)*);
        let _ = out.flush();
    }};
}

#[derive(PartialEq)]
enum Mode {
    Daemon,
    Once,
    Status,
    Check,
    Flush,
}

struct Options {
    mode: Mode,
    pairs: Vec<String>,
    interval: u64,
    max_macs: usize,
    /// Whether the threshold above came from the operator. If it did, nothing
    /// may quietly move it - not even a card that reports its own capacity.
    max_macs_set: bool,
    exclude: Vec<String>,
    extra: Vec<String>,
    dry_run: bool,
    verbose: bool,
    timings: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            mode: Mode::Daemon,
            pairs: Vec::new(),
            interval: 300,
            max_macs: sync::DEFAULT_MAX_MACS,
            max_macs_set: false,
            exclude: Vec::new(),
            extra: Vec::new(),
            dry_run: false,
            verbose: false,
            timings: false,
        }
    }
}

/// Set by the signal handler, read by the daemon loop.
static STOPPING: AtomicBool = AtomicBool::new(false);

/// The write end of the stop pipe, or -1 before `catch_signals` made one.
/// The flag alone leaves a race: a signal that lands between the loop's
/// `stopping()` check and its poll has already been consumed, and the poll
/// then sleeps toward the full interval - systemd's stop timeout turns
/// that into a SIGKILL. The byte in the pipe is what wakes the poll.
static STOP_PIPE_W: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

extern "C" fn note_signal(_sig: libc::c_int) {
    // A store and a write(2) - the whole async-signal-safe vocabulary
    // this handler needs.
    STOPPING.store(true, Ordering::Relaxed);
    let fd = STOP_PIPE_W.load(Ordering::Relaxed);
    if fd >= 0 {
        unsafe { libc::write(fd, [1u8].as_ptr().cast(), 1) };
    }
}

fn stopping() -> bool {
    STOPPING.load(Ordering::Relaxed)
}

/// Ask for SIGTERM and SIGINT rather than being killed by them.
///
/// Nothing is undone on the way out: the registrations stay in the card and
/// the notes stay in /run, which is what makes restarting the daemon - for an
/// update, say - invisible to every guest behind the bridge. Taking them out
/// would put a gap there on every restart, and `--flush` is the way to say
/// that is what you want.
///
/// What this buys is smaller and worth having anyway: the loop finishes what
/// it is doing, says how it ended and how much is deliberately left behind,
/// and systemd sees a service that stopped rather than one that was killed.
/// `sigaction` without SA_RESTART, so the poll the daemon spends its life in
/// returns instead of being restarted under us - with SA_RESTART a stop would
/// wait out the full reconciliation interval.
fn catch_signals() -> Option<std::os::fd::OwnedFd> {
    // The pipe before the handlers, so no caught signal can find fd -1.
    let stop_rx = unsafe {
        let mut fds = [0i32; 2];
        if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) == 0 {
            STOP_PIPE_W.store(fds[1], Ordering::Relaxed);
            Some(std::os::fd::OwnedFd::from_raw_fd(fds[0]))
        } else {
            // The flag still works; only the mid-pass wake-up is lost.
            None
        }
    };
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    // `sa_sigaction` is the only name libc has for this field on any Linux
    // target - the C struct puts the one-argument handler and the
    // three-argument one in a union, and the flags say which of them the
    // kernel is looking at. No SA_SIGINFO below, so it is the one-argument
    // one, which is what `note_signal` is. Setting SA_SIGINFO to match the
    // field's name is what would be wrong: the kernel would then call a
    // three-argument handler that is not there.
    action.sa_sigaction = note_signal as *const () as libc::sighandler_t;
    action.sa_flags = 0;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
        for sig in [libc::SIGTERM, libc::SIGINT] {
            if libc::sigaction(sig, &action, std::ptr::null_mut()) != 0 {
                eprintln!(
                    "warning: cannot catch signal {sig}: {} - a stop will be abrupt",
                    std::io::Error::last_os_error()
                );
            }
        }
    }
    stop_rx
}

fn usage() {
    print!("{}", usage_text());
}

/// The help text, separate from printing it so a test can read it: the
/// defaults are written out here by hand and drifted from the code once
/// already.
fn usage_text() -> String {
    format!(
        "\
sriov-mac-sync {VERSION} - keep an SR-IOV uplink's unicast filter in step with
the bridge behind it

usage: sriov-mac-sync [options]

  (no option)     run as a daemon
  --once          reconcile once and exit
  --status        show what is detected, wanted and registered
  --check         test whether the uplink accepts unicast filter entries
  --flush         remove every address this daemon registered
  --dry-run       report changes without applying them
  --timings       after every pass, say what each phase cost and what it
                  found, and name anything that failed along the way
  --pair DEV:BR   uplink/bridge pair to manage (repeatable, skips autodetect)
  --interval SEC  full reconciliation interval (default 300)
  --max NUM       the filter capacity to respect: warn above it, and shed
                  quiet keeps as the list nears it (default 128)
  --exclude MACS  addresses never to register, comma or space separated
  --extra MACS    addresses to register unconditionally, likewise separated
  -v, --verbose   explain what is skipped and why; with --status or --once,
                  list every wanted address, longest silence last
  -h, --help      this text
      --version   print the version

Pairs are found automatically: every interface with virtual functions - or
itself a virtual function - that ends up in a bridge, following bonds.
{CONF} may set PAIRS, RESYNC, MAX_MACS, EXCLUDE and EXTRA.
See sriov-mac-sync(8) for the whole of it.
"
    )
}

/// The addresses in one `EXTRA`, `EXCLUDE`, `--extra` or `--exclude` value.
///
/// Commas or whitespace, in any mixture: somebody who writes
/// `EXCLUDE=aa:...:ff, 02:...:01` means two addresses, and so does somebody
/// whose editor put a tab between them. Splitting on the comma and the space
/// alone made the tab part of the address, and then the whole thing was "not
/// an address, ignored" - the address they meant never excluded, over a
/// character they cannot see. `PAIRS` has always taken any whitespace; these
/// now do too.
fn addresses(value: &str) -> impl Iterator<Item = String> + '_ {
    value
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Addresses from the command line or the configuration file. A typo here
/// used to vanish without a word - and an address that was meant to be pinned
/// and silently was not is exactly the kind of thing somebody spends an
/// evening looking for in the wrong place.
fn macs(what: &str, given: &[String]) -> Set<[u8; 6]> {
    let mut out = crate::hash::set();
    for s in given {
        match parse_mac(s) {
            Some(m) => {
                out.insert(m);
            }
            None => eprintln!("warning: {what}: not an address, ignored: {s}"),
        }
    }
    out
}

/// Everything up to a `#` that is not inside quotes.
fn strip_comment(value: &str) -> &str {
    let mut quote: Option<char> = None;
    for (i, c) in value.char_indices() {
        match (quote, c) {
            (None, '"') | (None, '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '#') => return &value[..i],
            _ => {}
        }
    }
    value
}

fn load_conf(opts: &mut Options) {
    let text = match std::fs::read_to_string(CONF) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        // A file that exists but cannot be read is not the same as no file:
        // the settings somebody wrote down are not taking effect, and only
        // this line will ever say so.
        Err(e) => {
            eprintln!("warning: cannot read {CONF}: {e} - continuing without it");
            return;
        }
    };
    read_conf(opts, &text);
}

/// The file's contents, apart from finding them. Every way a line can be
/// malformed ends in a warning and the next line; a configuration file is not
/// a thing to die on, and this runs before the daemon has done anything.
/// Separate from `load_conf` so a test can hand it the awkward lines rather
/// than needing a file at a fixed path in /etc.
fn read_conf(opts: &mut Options, text: &str) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // A line that is not a setting is somebody trying to write one.
        // Dropping it in silence contradicts the whole point of the warnings
        // below - the setting they wrote down never takes effect and nothing
        // says so.
        //
        // The split is the test. Asking `contains` first and then unwrapping
        // the same split was two answers to one question, and the second one
        // was a panic if they ever stopped agreeing - a daemon that dies on a
        // line of configuration rather than warning about it.
        let Some((key, value)) = line.split_once('=') else {
            eprintln!("warning: {CONF}: not a setting, ignored: {line}");
            continue;
        };
        // "RESYNC=300  # seconds" means 300, not a parse warning - but a hash
        // inside quotes is part of the value, not the start of a comment.
        // Nothing this file takes can legitimately contain one today; the
        // rule is here so that the day something can, the parser does not
        // quietly eat half of it.
        let value = strip_comment(value);
        let value = value.trim().trim_matches('"').trim_matches('\'');
        match key.trim() {
            "PAIRS" => opts
                .pairs
                .extend(value.split_whitespace().map(|s| s.to_string())),
            "RESYNC" => match value
                .parse()
                .map_err(|_| ())
                .and_then(|v| clamp_interval(v).map_err(|_| ()))
            {
                Ok(v) => opts.interval = v,
                Err(_) => eprintln!(
                    "warning: {CONF}: RESYNC is not a usable number of seconds, ignored: {value}"
                ),
            },
            "MAX_MACS" => match value
                .parse()
                .map_err(|_| ())
                .and_then(|v| clamp_max_macs(v).map_err(|_| ()))
            {
                Ok(v) => {
                    opts.max_macs = v;
                    opts.max_macs_set = true;
                }
                Err(()) => {
                    eprintln!("warning: {CONF}: MAX_MACS is not a usable count, ignored: {value}")
                }
            },
            "EXTRA" => opts.extra.extend(addresses(value)),
            "EXCLUDE" => opts.exclude.extend(addresses(value)),
            other => eprintln!("warning: {CONF}: unknown setting, ignored: {other}"),
        }
    }
}

/// Two modes on one command line are a contradiction, and the last one
/// winning in silence means somebody ran --flush thinking they ran --status.
/// Zero would busy-loop - the deadline is always due, poll never sleeps -
/// and u64::MAX overflows the Instant it is added to, which aborts. Both are
/// answers to a typo, and neither is a sane one.
fn clamp_interval(v: u64) -> Result<u64, String> {
    const MAX: u64 = 30 * 24 * 3600;
    if v == 0 || v > MAX {
        return Err(format!(
            "the interval has to be between 1 and {MAX} seconds"
        ));
    }
    Ok(v)
}

/// A capacity of zero says the filter is always full,
/// which schedules the fast pass rate for ever - a typo that turns a quiet
/// host into a busy one. And a threshold near usize::MAX overflows the
/// arithmetic that asks "are we at nine tenths of it" - an abort in a debug
/// build, a wrong answer in release. No hardware justifies either end.
fn clamp_max_macs(v: usize) -> Result<usize, String> {
    const MAX: usize = 1 << 20;
    if v == 0 || v > MAX {
        return Err(format!("--max has to be between 1 and {MAX}"));
    }
    Ok(v)
}

fn set_mode(opts: &mut Options, mode: Mode, arg: &str) -> Result<(), String> {
    if !matches!(opts.mode, Mode::Daemon) {
        return Err(format!("{arg}: another mode is already given (pick one)"));
    }
    opts.mode = mode;
    Ok(())
}

fn parse_args(opts: &mut Options) -> Result<(), String> {
    parse_args_from(opts, std::env::args().skip(1))
}

fn parse_args_from<I: Iterator<Item = String>>(opts: &mut Options, args: I) -> Result<(), String> {
    let mut args = args;
    // Whether a --pair has been seen on this command line. The first one
    // replaces whatever PAIRS= in the configuration put here - a command
    // line names the whole pair list or none of it, else the harmless
    // `--pair nic1:vmbr1` on a host whose conf says the same is refused
    // as a duplicate and a differing bridge cannot win at all.
    let mut pairs_from_cli = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--once" => set_mode(opts, Mode::Once, &arg)?,
            "--status" => set_mode(opts, Mode::Status, &arg)?,
            "--check" => set_mode(opts, Mode::Check, &arg)?,
            "--flush" => set_mode(opts, Mode::Flush, &arg)?,
            "--dry-run" => opts.dry_run = true,
            "--timings" => opts.timings = true,
            "-v" | "--verbose" => opts.verbose = true,
            "--pair" => {
                if !pairs_from_cli {
                    opts.pairs.clear();
                    pairs_from_cli = true;
                }
                opts.pairs
                    .push(args.next().ok_or("--pair needs DEV:BRIDGE")?);
            }
            "--interval" => {
                opts.interval = clamp_interval(
                    args.next()
                        .ok_or("--interval needs seconds")?
                        .parse()
                        .map_err(|_| "--interval needs a number")?,
                )?
            }
            "--max" => {
                opts.max_macs_set = true;
                opts.max_macs = clamp_max_macs(
                    args.next()
                        .ok_or("--max needs a number")?
                        .parse()
                        .map_err(|_| "--max needs a number")?,
                )?
            }
            "--extra" => {
                let value = args.next().ok_or("--extra needs addresses")?;
                opts.extra.extend(addresses(&value));
            }
            "--exclude" => {
                let value = args.next().ok_or("--exclude needs addresses")?;
                opts.exclude.extend(addresses(&value));
            }
            "-h" | "--help" => {
                usage();
                std::process::exit(0);
            }
            "--version" => {
                note!("sriov-mac-sync {VERSION}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown option: {other} (try --help)")),
        }
    }
    Ok(())
}

fn resolve_pairs(topo: &Topology, opts: &Options) -> Result<Vec<Pair>, String> {
    // Flush and status must not require a pair to exist: the state they
    // inspect - notes and filter entries - outlives the pair on purpose,
    // and "the bridge is gone" is exactly when --flush is reached for. The
    // daemon may start before its interfaces exist and waits for them.
    let allow_empty = matches!(opts.mode, Mode::Daemon | Mode::Flush | Mode::Status);
    // Strict only where a person is at the keyboard to fix the typo.
    let strict = matches!(opts.mode, Mode::Once | Mode::Check);
    let mut pairs = Vec::new();
    if opts.pairs.is_empty() {
        let (found, skipped) = topo.autodetect();
        if opts.verbose {
            for s in skipped {
                note!("{s}");
            }
        }
        if found.is_empty() && !allow_empty {
            return Err("no SR-IOV interface found that ends up in a bridge \
                 (use --pair; -v explains what was skipped)"
                .into());
        }
        pairs.extend(found.into_iter().map(|(dev, bridge)| Pair { dev, bridge }));
    } else {
        for spec in &opts.pairs {
            let (dev, bridge) = spec
                .split_once(':')
                .ok_or_else(|| format!("malformed pair: {spec} (expected DEV:BRIDGE)"))?;
            // Nonsense stays nonsense in every mode.
            if dev == bridge {
                return Err(format!("{spec}: a bridge cannot be its own uplink"));
            }
            // A pair whose device does not actually sit under that bridge
            // disables the one protection that matters: nothing the bridge
            // learnt counts as wire-side any more, so everything it learnt -
            // the peers out on the cable included - would be written into
            // the device's filter. A typo must fail here, not there - but
            // only where a person is watching. --flush works from the notes
            // and never reads a pair; --status reports whatever is there;
            // and a daemon whose named interface is not up yet at boot must
            // wait for it, not crash-loop until it appears. Those warn and
            // keep the pair; the reconciler skips missing devices anyway.
            let topology_says = (|| -> Result<(), String> {
                let Some(dev_index) = topo.index_of(dev) else {
                    return Err(format!("no such interface: {dev}"));
                };
                let Some(bridge_index) = topo.index_of(bridge) else {
                    // Its own answer: "not a bridge" about an interface
                    // that does not exist sends the operator checking
                    // bridge flags instead of spelling.
                    return Err(format!("no such interface: {bridge}"));
                };
                if !topo.is_bridge(bridge_index) {
                    return Err(format!("not a bridge: {bridge}"));
                }
                if topo.bridge_above(dev_index).map(|(b, _)| b) != Some(bridge_index) {
                    return Err(format!(
                        "{spec}: {dev} is not enslaved to {bridge}, directly or through a bond"
                    ));
                }
                Ok(())
            })();
            if let Err(msg) = topology_says {
                if strict {
                    return Err(msg);
                }
                eprintln!("warning: {msg} - kept, in case it appears");
            }
            // Two pairs on one device would share one ownership note and
            // spend every pass undoing each other's work.
            if pairs.iter().any(|p: &Pair| p.dev == dev) {
                return Err(format!("{spec}: {dev} is already named by another pair"));
            }
            pairs.push(Pair {
                dev: dev.to_string(),
                bridge: bridge.to_string(),
            });
        }
    }
    Ok(pairs)
}

fn pair_names(pairs: &[Pair]) -> Vec<String> {
    let mut v: Vec<String> = pairs
        .iter()
        .map(|p| format!("{}:{}", p.dev, p.bridge))
        .collect();
    v.sort();
    v
}

/// Can this driver take entries at all? Only half an answer: it proves the
/// kernel accepted the address, not that the hardware acts on it.
fn check(sock: &mut Socket, topo: &Topology, pairs: &[Pair], syncer: &Syncer) -> bool {
    let mut ok = true;
    for pair in pairs {
        let Some(link) = topo.get(&pair.dev) else {
            note!("{}: skipped - the interface is gone", pair.dev);
            continue;
        };
        let Some(mut probe) = link.mac else {
            note!(
                "{}: skipped - it has no address to derive a probe from",
                pair.dev
            );
            continue;
        };
        probe[0] = 0x02;
        probe[5] ^= 0x5a;
        let driver = link.driver.clone().unwrap_or_default();

        // Noted before it is written: a check killed between the write and
        // the take-back then leaves an OWNED entry, which the daemon's next
        // pass removes and heals - unnoted it was foreign, and foreign
        // entries are deliberately never touched. Which is why a probe the
        // note could not take is not written at all: the healing story
        // held only when this call happened to succeed, and nothing said so.
        if !syncer.note_check_probe(&pair.dev, link.index, &probe) {
            note!(
                "{} ({driver}): cannot check - the probe could not be noted in \
                 {STATE_DIR} first, and an unnoted probe would outlive a killed \
                 check as a foreign entry",
                pair.dev
            );
            ok = false;
            continue;
        }
        match sock.set_self_fdb(link.index, &probe, true) {
            Ok(()) => {}
            // Left over from an earlier check that could not clean up. The
            // driver plainly accepts entries - that is the question here.
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
            Err(e) => {
                syncer.forget_check_probe(&pair.dev, &probe);
                note!(
                    "{} ({driver}): FAILED - the driver refuses unicast filter entries: {e}",
                    pair.dev
                );
                ok = false;
                continue;
            }
        }
        // A dump that failed is not an absent entry. Folding the two
        // together blamed the driver for the kernel's refusal to answer.
        let listed = match sock.dump_fdb() {
            Ok(fdb) => fdb
                .iter()
                .any(|e| e.is_self() && e.ifindex == link.index && e.mac == probe),
            Err(e) => {
                note!(
                    "{} ({driver}): inconclusive - the entry was accepted, but the \
                     forwarding table could not be read back: {e}",
                    pair.dev
                );
                ok = false;
                if sock.set_self_fdb(link.index, &probe, false).is_ok() {
                    syncer.forget_check_probe(&pair.dev, &probe);
                }
                continue;
            }
        };
        if listed {
            note!(
                "{} ({driver}): ok - accepts unicast filter entries \
                 (kernel side only; confirm with traffic)",
                pair.dev
            );
        } else {
            note!(
                "{} ({driver}): FAILED - entry accepted but not listed",
                pair.dev
            );
            ok = false;
        }
        match sock.set_self_fdb(link.index, &probe, false) {
            Ok(()) => syncer.forget_check_probe(&pair.dev, &probe),
            Err(e) => eprintln!(
                "warning: {}: the probe entry {} could not be taken back out: {e} - \
                 it stays noted, and the daemon's next pass takes it back",
                pair.dev,
                format_mac(&probe)
            ),
        }
    }
    ok
}

/// A millisecond count the way an operator reads one: seconds under two
/// minutes, minutes under two hours, hours beyond.
/// A silence, in days, hours, minutes and seconds.
///
/// Every unit from the largest non-zero one down to seconds, and no
/// rounding: the form before this said "2h" for anything between two hours
/// and three, so two entries fifty minutes apart printed the same thing and
/// there was no way to tell which of them the pressure valve would take
/// first. Below a minute it is seconds alone.
///
/// No weeks and no months. Days already carry that, and a unit whose length
/// is a matter of opinion is a unit an operator has to convert back.
fn human_duration(ms: u64) -> String {
    let s = ms / 1000;
    let (d, h, m, sec) = (s / 86_400, (s / 3600) % 24, (s / 60) % 60, s % 60);
    if d > 0 {
        format!("{d}d {h}h {m}m {sec}s")
    } else if h > 0 {
        format!("{h}h {m}m {sec}s")
    } else if m > 0 {
        format!("{m}m {sec}s")
    } else {
        format!("{sec}s")
    }
}

/// The addresses an uplink wants, one per line, marking the ones held
/// through a silence with how long each has been silent.
///
/// Returned rather than printed, because the two callers emit it in
/// different places - under `--status`'s uplink block, and under the report
/// lines of a `--once` - and the wording must not drift between them. Both
/// go to stdout: this is normal operation, and `note!` says why.
fn address_lines(detail: &sync::Detail) -> Vec<String> {
    let ages: std::collections::BTreeMap<_, _> = detail.quiet_ages.iter().copied().collect();
    let mut wanted = detail.wanted.clone();
    // By age, longest silence LAST: the list ends where the pressure valve
    // begins, so the bottom of it is what the filter gives up first - and
    // on a terminal that is the part still on screen. An address the bridge
    // still holds has no silence at all and comes first; the address itself
    // is the tiebreak, so the list does not shuffle between two runs that
    // saw the same thing.
    wanted.sort_by(|a, b| {
        let (sa, sb) = (
            ages.get(a).copied().unwrap_or(0),
            ages.get(b).copied().unwrap_or(0),
        );
        sa.cmp(&sb).then(a.cmp(b))
    });
    wanted
        .iter()
        .map(|mac| match ages.get(mac) {
            // The question the 502 hunt actually asked: which of these is
            // a keep, and for how long has nobody heard from it.
            Some(ms) => format!(
                "    {} (quiet, silent {})",
                format_mac(mac),
                human_duration(*ms)
            ),
            None => format!("    {}", format_mac(mac)),
        })
        .collect()
}

fn report_changes(reports: &[sync::Report], dry_run: bool, verbose: bool, trigger: &str) {
    for r in reports {
        if verbose && r.foreign > 0 {
            note!(
                "{}: {} address(es) already present, left alone",
                r.dev,
                r.foreign
            );
        }
        if r.added > 0 || r.removed > 0 {
            // Composed, not branched four ways: the words stay byte for
            // byte what the journal greps in bench/ expect.
            let quiet = if r.quiet > 0 {
                format!(", {} held quiet", r.quiet)
            } else {
                String::new()
            };
            if dry_run {
                note!(
                    "{}: would be +{} -{}, {} address(es) in total{quiet} [{trigger}]",
                    r.dev,
                    r.added,
                    r.removed,
                    r.wanted
                );
            } else {
                note!(
                    "{}: +{} -{}, {} address(es) registered{quiet} [{trigger}]",
                    r.dev,
                    r.added,
                    r.removed,
                    r.wanted
                );
            }
        }
    }
}

fn run() -> Result<bool, String> {
    let mut opts = Options::default();
    load_conf(&mut opts);
    parse_args(&mut opts)?;

    let mut sock = Socket::new().map_err(|e| format!("cannot open netlink socket: {e}"))?;

    // Subscribed BEFORE the interfaces are read, so that nothing can slip
    // through between the reading and the listening: every change after
    // this point is announced, and the reading below is therefore a
    // picture the daemon may keep. It used to be opened afterwards, which
    // is why the loop read the interfaces a second time for itself.
    let mon = if opts.mode == Mode::Daemon {
        Some(
            Socket::subscribed()
                .map_err(|e| format!("cannot subscribe to neighbour events: {e}"))?,
        )
    } else {
        None
    };

    let topo_started = Instant::now();
    let topo = read_topology(&mut sock)?;
    let topo_load = topo_started.elapsed();
    let pairs = resolve_pairs(&topo, &opts)?;

    // What the cards say their filters hold. Only when the operator has not
    // said: a number from the hardware is better than this program's constant,
    // and worse than an instruction.
    if !opts.max_macs_set && matches!(opts.mode, Mode::Daemon | Mode::Once | Mode::Status) {
        let devs: Vec<String> = pairs.iter().map(|p| p.dev.clone()).collect();
        // Nothing to ask about is the ordinary state of a host whose
        // uplink is not in a bridge yet, and a devlink dump for an empty
        // list is a syscall round trip for a guaranteed empty answer.
        if !devs.is_empty() {
            if let Some(v) =
                adopt_reported_capacity(capacities_via_devlink(&devs), opts.verbose, opts.max_macs)
            {
                opts.max_macs = v;
            }
        }
    }

    let mut syncer = Syncer::new(pairs.clone(), state_dir());
    syncer.dry_run = opts.dry_run;
    // Only the modes that print the per-address half of a report pay for
    // building one. Both are a single pass run by hand; the daemon, which
    // would build it once a pass for ever, is not among them.
    syncer.detail = matches!(opts.mode, Mode::Status | Mode::Once);
    // Only autodetection sees every uplink, so only autodetection may conclude
    // that a leftover note belongs to none of them.
    syncer.authoritative = opts.pairs.is_empty();
    syncer.max_macs = opts.max_macs;
    // The lists merge CLI values and conf-file values, so the label names
    // both homes - a tab-mangled EXCLUDE= line must not send its operator
    // grepping unit files for an --exclude nobody ever passed.
    syncer.exclude = macs("--exclude/EXCLUDE", &opts.exclude);
    syncer.extra = macs("--extra/EXTRA", &opts.extra);

    match opts.mode {
        Mode::Flush => syncer.flush(&mut sock).map_err(|e| e.to_string()),
        Mode::Status => {
            let reports = syncer
                .reconcile(&mut sock, false, &topo, topo_load)
                .map_err(|e| e.to_string())?;
            for r in &reports {
                note!("{} on {} ({})", r.dev, r.bridge, r.driver);
                if r.port != r.dev {
                    note!("  enslaved through  : {}", r.port);
                }
                // "wanted", not "behind the bridge": EXTRA-pinned
                // addresses are in this number precisely because they are
                // NOT in the bridge's table, and the count must not
                // disagree with `bridge fdb show` over them.
                note!("  wanted in filter  : {}", r.wanted);
                note!("  registered by us  : {}", r.owned);
                // Worth a line only when there are any: the memory this
                // reads is the running daemon's, taken from the file it
                // writes, so a fresh --status can now answer for it.
                if r.quiet > 0 {
                    note!("  held quiet        : {}", r.quiet);
                }
                note!("  unicast list      : {}", r.present);
                note!(
                    "  stacked bridges   : {}",
                    if r.stacked.is_empty() {
                        "none".to_string()
                    } else {
                        r.stacked.join(" ")
                    }
                );
                // The per-address half is built only for the two modes
                // that print it, so the daemon does not copy the whole
                // desired set and walk every silence once a pass for
                // numbers nothing prints.
                if let (true, Some(detail)) = (opts.verbose, r.detail.as_ref()) {
                    for line in address_lines(detail) {
                        note!("{line}");
                    }
                }
            }
            Ok(true)
        }
        Mode::Once => {
            let reports = syncer
                .reconcile(&mut sock, true, &topo, topo_load)
                .map_err(|e| e.to_string())?;
            report_changes(&reports, opts.dry_run, opts.verbose, "once");
            // On the same stream as the report lines: a single pass by
            // hand is exactly when somebody wants to see WHICH addresses,
            // and it is the one mode where the list cannot scroll a
            // journal away. Each list gets its own heading rather than
            // sitting under the report line above it - that line appears
            // only when something changed, so on a quiet host two uplinks'
            // lists would have run into each other unlabelled.
            if opts.verbose {
                for r in &reports {
                    let Some(detail) = r.detail.as_ref() else {
                        continue;
                    };
                    if detail.wanted.is_empty() {
                        continue;
                    }
                    note!("{}: {} address(es) wanted", r.dev, r.wanted);
                    for line in address_lines(detail) {
                        note!("{line}");
                    }
                }
            }
            if opts.timings {
                note!("{}", syncer.timings.report().trim_end());
            }
            // A oneshot that could not do what it was asked has to say so in
            // its exit code - the warnings above scroll away, the code stays.
            Ok(syncer.timings.failures.is_empty())
        }
        Mode::Daemon => {
            let listed = pair_names(&pairs);
            note!(
                "sriov-mac-sync {VERSION}: watching {}, full reconciliation every {}s",
                if listed.is_empty() {
                    "nothing yet".to_string()
                } else {
                    listed.join(" ")
                },
                opts.interval
            );
            let stop_rx = catch_signals();
            // Opened before the reading above; `mon` is Some in this mode
            // by construction.
            let mon = mon.expect("the daemon subscribes before it reads");
            // A device that drops out of one reading is not gone: an
            // interface reload takes a bridge away for a moment, and taking
            // its guests' addresses out of a live filter over that is the
            // outage this daemon exists to prevent. Long enough to outlive
            // `ifreload -a`, short enough that a bridge genuinely taken apart
            // is tidied up within the interval.
            syncer.orphan_grace = Duration::from_secs(60);
            let mut world = Live { sock, mon, stop_rx };
            // The reading this process already did, handed over rather
            // than paid for twice. It was taken after the subscription was
            // opened, so anything that changed since is on its way as an
            // event.
            daemon_loop(&mut world, &mut syncer, &opts, Some(topo));

            // Deliberately without a flush - catch_signals says why. Say how
            // much is left behind, so nobody has to wonder.
            let held: usize = syncer.registered();
            note!(
                "sriov-mac-sync: stopping; {held} address(es) left registered on purpose \
                 (--flush removes them)"
            );
            Ok(true)
        }
        Mode::Check => {
            if opts.dry_run {
                return Err("--check works by writing a probe entry, which --dry-run \
                            rules out - run it without --dry-run"
                    .into());
            }
            // The probe bookkeeping wants the same notes the daemon keeps -
            // that is what makes a killed check healable at all. That the
            // syncer above also carries exclude/extra is irrelevant to the
            // note helpers check() uses.
            Ok(check(&mut sock, &topo, &pairs, &syncer))
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            // The dying reason is trouble, and trouble goes to stderr - the
            // one place `--once >/dev/null` and procd's error level both
            // still show it.
            eprintln!("sriov-mac-sync: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// The help text names the defaults in prose. It said 60 while the code
    /// said 300, and nothing noticed until somebody read both.
    #[test]
    fn help_states_the_defaults_the_code_actually_uses() {
        let d = Options::default();
        let text = usage_text();
        assert!(
            text.contains(&format!("(default {})", d.interval)),
            "help does not name the real interval default of {}:\n{text}",
            d.interval
        );
        assert!(
            text.contains(&format!("(default {})", d.max_macs)),
            "help does not name the real max default of {}:\n{text}",
            d.max_macs
        );
    }

    /// The assumed capacity is written out in five places, and four of
    /// them cannot be interpolated - a manual page, a README, an example
    /// configuration and the trial harness's own preflight, which measures
    /// its margin against it. Changing the constant used to leave all four
    /// quietly lying.
    #[test]
    fn every_document_names_the_capacity_the_code_assumes() {
        // Anchored, not a bare substring. `128` occurs in prose, in a
        // year, in a byte count; the needle has to be the sentence that
        // states the default, or the test passes against every document
        // for a DEFAULT_MAX_MACS of 8 - which it did.
        let n = sync::DEFAULT_MAX_MACS.to_string();
        for (what, text, needle) in [
            (
                "the manual page",
                include_str!("../dist/sriov-mac-sync.8"),
                format!("default {n}"),
            ),
            (
                "the README",
                include_str!("../README.md"),
                format!("default {n}"),
            ),
            (
                "the example configuration",
                include_str!("../dist/sriov-mac-sync.conf.example"),
                format!("MAX_MACS={n}"),
            ),
            (
                "the trial harness",
                include_str!("../bench/trial.py"),
                format!("FILTER_CAPACITY = {n}"),
            ),
            (
                "the help text",
                usage_text().as_str(),
                format!("default {n}"),
            ),
        ] {
            assert!(
                text.contains(&needle),
                "{what} never says \"{needle}\", the capacity the code assumes"
            );
        }
    }

    /// Every option a help line offers. "-v, --verbose" is two spellings
    /// of one option; taking only a line's first token let the long form
    /// escape every doc check - and the README really had forgotten it.
    fn help_options(text: &str) -> Vec<String> {
        text.lines()
            .flat_map(|l| {
                l.split_whitespace()
                    .take_while(|w| w.starts_with('-'))
                    .map(|w| w.trim_end_matches(',').to_string())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    #[test]
    fn every_documented_option_is_accepted() {
        let text = usage_text();
        // The long options the help offers, minus the two that exit the process.
        for opt in help_options(&text)
            .iter()
            .filter(|w| !matches!(w.as_str(), "-h" | "--help" | "--version"))
        {
            let mut o = Options::default();
            let with_value = match opt.as_str() {
                "--pair" => Some("nic0:vmbr0"),
                "--interval" => Some("42"),
                "--max" => Some("7"),
                "--exclude" | "--extra" => Some("02:00:00:00:00:01"),
                _ => None,
            };
            let argv = match with_value {
                Some(v) => args(&[opt, v]),
                None => args(&[opt]),
            };
            assert!(
                parse_args_from(&mut o, argv.into_iter()).is_ok(),
                "help offers {opt}, but parsing it fails"
            );
        }
    }

    #[test]
    fn values_reach_the_options() {
        let mut o = Options::default();
        parse_args_from(
            &mut o,
            args(&["--interval", "42", "--max", "7"]).into_iter(),
        )
        .unwrap();
        assert_eq!(o.interval, 42);
        assert_eq!(o.max_macs, 7);
    }

    #[test]
    fn a_pair_is_kept_verbatim_and_repeatable() {
        let mut o = Options::default();
        parse_args_from(
            &mut o,
            args(&["--pair", "nic0:vmbr0", "--pair", "nic1:vmbr1"]).into_iter(),
        )
        .unwrap();
        assert_eq!(o.pairs, vec!["nic0:vmbr0", "nic1:vmbr1"]);
    }

    /// The separator between two addresses is a comma or whitespace of any
    /// kind. A tab used to end up inside the address, which then parsed as
    /// nothing and was dropped with a warning about a character nobody can
    /// see - and the address somebody wrote down was never excluded.
    #[test]
    fn addresses_are_separated_by_commas_or_any_whitespace() {
        let one = "02:00:00:00:00:01";
        let two = "02:00:00:00:00:02";
        for value in [
            format!("{one},{two}"),
            format!("{one}, {two}"),
            format!("{one}\t{two}"),
            format!("{one} ,\t {two}"),
            format!("  {one}   {two}  "),
        ] {
            let mut o = Options::default();
            parse_args_from(&mut o, args(&["--exclude", &value]).into_iter()).unwrap();
            assert_eq!(o.exclude, vec![one, two], "{value:?} did not split");
            assert_eq!(
                macs("--exclude", &o.exclude).len(),
                2,
                "{value:?} split but did not parse"
            );
        }
    }

    /// The bare flags really land in their fields - a swapped assignment
    /// here would pass every parse-ok test.
    #[test]
    fn the_bare_flags_reach_their_options() {
        let mut o = Options::default();
        parse_args_from(&mut o, args(&["--timings", "--dry-run", "-v"]).into_iter()).unwrap();
        assert!(o.timings);
        assert!(o.dry_run);
        assert!(o.verbose);
    }

    /// The clamps accept their own boundaries and refuse one past them.
    #[test]
    fn the_clamps_hold_exactly_at_their_edges() {
        const MONTH: u64 = 30 * 24 * 3600;
        assert_eq!(clamp_interval(MONTH).ok(), Some(MONTH));
        assert!(clamp_interval(MONTH + 1).is_err());
        assert_eq!(clamp_max_macs(1 << 20).ok(), Some(1 << 20));
        assert!(clamp_max_macs((1 << 20) + 1).is_err());
    }

    /// Every way a line of the configuration file can be malformed, in one
    /// place. None of them may be a panic: this runs before the daemon has
    /// done anything, and a daemon that dies on a stray line of /etc leaves a
    /// host with no filter maintenance at all - over a line it could have
    /// warned about and stepped over.
    #[test]
    fn a_malformed_configuration_line_is_stepped_over() {
        let mut o = Options::default();
        read_conf(
            &mut o,
            "\n\
             # a comment\n\
             this line has no equals sign at all\n\
             =\n\
             =a value with no key\n\
             NONSENSE=whatever\n\
             RESYNC=\n\
             RESYNC=not a number\n\
             MAX_MACS=\n\
             EXCLUDE=\n\
             \t  RESYNC = 600  # with a comment and spaces round the key\n\
             EXCLUDE=02:00:00:00:00:01\n",
        );
        assert_eq!(o.interval, 600, "the one good setting did not take effect");
        assert_eq!(o.exclude, vec!["02:00:00:00:00:01"]);
        assert_eq!(o.max_macs, Options::default().max_macs);
    }

    /// The value keeps its own equals signs. Splitting on the last one, or
    /// refusing the line, would both be wrong - and the key is what decides
    /// what the value means.
    #[test]
    fn only_the_first_equals_sign_separates_a_setting_from_its_value() {
        let mut o = Options::default();
        read_conf(&mut o, "PAIRS=nic0:vmbr0 odd=name\n");
        assert_eq!(
            o.pairs,
            vec!["nic0:vmbr0", "odd=name"],
            "the value lost an equals sign of its own"
        );
    }

    #[test]
    fn an_unknown_option_is_refused_rather_than_ignored() {
        let mut o = Options::default();
        let e = parse_args_from(&mut o, args(&["--nonsense"]).into_iter()).unwrap_err();
        assert!(
            e.contains("--nonsense"),
            "the message hides the option: {e}"
        );
    }

    #[test]
    fn an_option_missing_its_value_is_refused() {
        for opt in ["--pair", "--interval", "--max", "--exclude", "--extra"] {
            let mut o = Options::default();
            assert!(
                parse_args_from(&mut o, args(&[opt]).into_iter()).is_err(),
                "{opt} without a value was accepted"
            );
        }
    }

    #[test]
    fn an_unreadable_number_is_refused_rather_than_silently_default() {
        let mut o = Options::default();
        assert!(parse_args_from(&mut o, args(&["--interval", "soon"]).into_iter()).is_err());
        let mut o = Options::default();
        assert!(parse_args_from(&mut o, args(&["--max", "lots"]).into_iter()).is_err());
    }

    #[test]
    fn addresses_are_parsed_and_typos_dropped_not_guessed() {
        let good = macs("extra", &args(&["02:00:00:00:00:01", "aa:bb:cc:dd:ee:ff"]));
        assert_eq!(good.len(), 2);
        assert!(good.contains(&[0x02, 0, 0, 0, 0, 0x01]));

        // A typo must not turn into some other address.
        let bad = macs("extra", &args(&["02:00:00:00:00:0", "not-an-address", ""]));
        assert!(bad.is_empty(), "a malformed address was accepted: {bad:?}");
    }

    /// The README, the unit file and the example configuration all restate
    /// facts the code owns. Each has drifted at least once - the help text
    /// claimed a default the code had left behind - and this is the same
    /// cure applied to the other three documents.
    #[test]
    fn the_man_page_names_every_option_the_help_offers() {
        // A manual page is the one piece of documentation that is read offline,
        // months later, by somebody who cannot check whether it still matches
        // the program. It matches, or this fails.
        let page = include_str!("../dist/sriov-mac-sync.8");
        for opt in help_options(&usage_text())
            .into_iter()
            .filter(|w| w.starts_with("--"))
        {
            // roff wants its hyphens escaped, so that is how they appear there.
            let escaped = opt.replace('-', "\\-");
            assert!(
                page.contains(&escaped),
                "the manual page never mentions {opt}, which the help offers"
            );
        }
    }

    #[test]
    fn the_man_page_carries_the_files_it_claims() {
        let page = include_str!("../dist/sriov-mac-sync.8");
        for path in [CONF, STATE_DIR, STATE_DIR_FALLBACK] {
            let escaped = path.replace('-', "\\-");
            assert!(
                page.contains(&escaped),
                "the manual page never mentions {path}"
            );
        }
    }

    #[test]
    fn the_readme_names_every_option_the_help_offers() {
        let readme = include_str!("../README.md");
        // --help explains itself; a README that documented it would be
        // padding. Everything else the help offers has to be findable.
        for opt in help_options(&usage_text())
            .into_iter()
            .filter(|w| w.starts_with("--") && w != "--help")
        {
            assert!(
                readme.contains(&opt),
                "the README never mentions {opt}, which the help offers"
            );
        }
    }

    /// A silence is read off, not decoded.
    ///
    /// The form this replaced named one unit and truncated, so "2h" meant
    /// anything from two hours to three - and the whole point of the number
    /// is to say which of two keeps the valve will take first.
    #[test]
    fn a_silence_is_spelled_out_to_the_second() {
        for (ms, want) in [
            (0u64, "0s"),
            (999, "0s"),
            (1_000, "1s"),
            (59_000, "59s"),
            (60_000, "1m 0s"),
            (90_500, "1m 30s"),
            // The example from the day this changed: 112 minutes.
            (6_720_000, "1h 52m 0s"),
            (7_200_000, "2h 0m 0s"),
            // Just under three hours - the old form called this "2h" too.
            (10_740_000, "2h 59m 0s"),
            (86_400_000, "1d 0h 0m 0s"),
            (183_845_000, "2d 3h 4m 5s"),
        ] {
            assert_eq!(human_duration(ms), want, "{ms} ms");
        }
    }

    /// The two modes that print addresses say the same thing about them.
    ///
    /// `--status` writes to stdout and `--once` to stderr, so they cannot
    /// share a print; they share the rendering instead, and this is what
    /// keeps a second spelling from growing beside the first.
    #[test]
    fn the_address_lines_name_the_quiet_ones() {
        let detail = sync::Detail {
            wanted: vec![
                [2, 0, 0, 0, 0, 1],
                [2, 0, 0, 0, 0, 2],
                [2, 0, 0, 0, 0, 3],
                [2, 0, 0, 0, 0, 4],
            ],
            quiet_ages: vec![
                // The younger keep sorts FIRST by address and by age; the
                // older one sorts first by neither. An ordering that went
                // by address alone would put them the other way round.
                ([2, 0, 0, 0, 0, 4], 60_000),
                ([2, 0, 0, 0, 0, 1], 720_000),
            ],
        };
        let lines = address_lines(&detail);
        assert_eq!(
            lines,
            vec![
                "    02:00:00:00:00:02".to_string(),
                "    02:00:00:00:00:03".to_string(),
                "    02:00:00:00:00:04 (quiet, silent 1m 0s)".to_string(),
                "    02:00:00:00:00:01 (quiet, silent 12m 0s)".to_string(),
            ],
            "the live ones first by address, then rising silence, \
             and only the kept ones marked"
        );
    }

    /// And both are offered by the help text, or an operator has no way to
    /// know the list exists.
    #[test]
    fn the_help_says_which_modes_list_addresses() {
        let help = usage_text();
        let line = help
            .lines()
            .skip_while(|l| !l.contains("--verbose"))
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            line.contains("--status") && line.contains("--once"),
            "the help does not say which modes list addresses: {line}"
        );
    }

    #[test]
    fn the_unit_file_matches_the_paths_the_code_uses() {
        let unit = include_str!("../dist/sriov-mac-sync.service");
        let dir = STATE_DIR.strip_prefix("/run/").unwrap();
        assert!(
            unit.contains(&format!("RuntimeDirectory={dir}")),
            "the unit's RuntimeDirectory does not produce {STATE_DIR}"
        );
        assert!(
            unit.contains("RuntimeDirectoryPreserve=yes"),
            "without RuntimeDirectoryPreserve the ownership notes die on every stop"
        );
        // 0700, because `ensure_state_dir` narrows a directory it finds
        // group- or world-writable and says so - and 0755 & 0o022 is zero,
        // so it would find nothing to say. Dropping this line from the unit
        // is therefore silent, which is the reason to assert it here.
        assert!(
            unit.contains("RuntimeDirectoryMode=0700"),
            "the state directory has to be created 0700; nothing complains if it is not"
        );
    }

    #[test]
    fn the_example_config_offers_only_keys_the_code_reads() {
        let example = include_str!("../dist/sriov-mac-sync.conf.example");
        for key in example
            .lines()
            .filter_map(|l| l.strip_prefix('#'))
            .filter_map(|l| l.split_once('=').map(|(k, _)| k.trim().to_string()))
            .filter(|k| !k.is_empty() && k.chars().all(|c| c.is_ascii_uppercase() || c == '_'))
        {
            assert!(
                ["PAIRS", "RESYNC", "MAX_MACS", "EXCLUDE", "EXTRA"].contains(&key.as_str()),
                "the example offers {key}, which load_conf never reads"
            );
        }
    }

    #[test]
    fn an_interval_that_would_spin_or_abort_is_refused() {
        // Zero busy-loops; u64::MAX overflows the Instant it is added to.
        assert!(clamp_interval(0).is_err());
        assert!(clamp_interval(u64::MAX).is_err());
        assert_eq!(clamp_interval(300), Ok(300));
        let mut o = Options::default();
        assert!(parse_args_from(&mut o, args(&["--interval", "0"]).into_iter()).is_err());
    }

    /// Every way a --pair can be wrong, refused with a message that names
    /// the mistake. Each of these typos would otherwise disable the wire
    /// rule - the one protection that matters - and none of this was tested.
    #[test]
    fn a_pair_that_lies_about_the_topology_is_refused() {
        use crate::topology::fixture::{mac, Builder};
        let topo = Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .master("br0")
            .add("br0", 10, Some(mac(1)))
            .bridge()
            .lower("nic1")
            .add("nic2", 3, Some(mac(2)))
            .build();
        let with = |pairs: &[&str]| {
            let mut o = Options {
                pairs: pairs.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            };
            o.mode = Mode::Once; // strict: a person is at the keyboard
            resolve_pairs(&topo, &o)
        };
        // A named pair whose interface is missing refuses where a person
        // is watching, and is kept with a warning where availability wins:
        // the daemon at boot, and flush/status, which do not read it.
        {
            let mut o = Options {
                pairs: vec!["ghost:br0".into()],
                ..Default::default()
            };
            o.mode = Mode::Once;
            assert!(resolve_pairs(&topo, &o).is_err());
            o.mode = Mode::Daemon;
            let kept = resolve_pairs(&topo, &o).expect("lenient keeps it");
            assert_eq!(kept.len(), 1, "the pair waits for its interface");
        }
        for (spec, names) in [
            ("nic1", "malformed"),
            ("ghost:br0", "no such interface"),
            ("nic1:ghost", "no such interface"),
            ("nic1:nic2", "not a bridge"),
            ("br0:br0", "its own uplink"),
            ("nic2:br0", "not enslaved"),
        ] {
            let e = with(&[spec]).expect_err(spec);
            assert!(e.contains(names), "{spec}: {e}");
        }
        let e = with(&["nic1:br0", "nic1:br0"]).expect_err("duplicate dev");
        assert!(e.contains("already named"), "{e}");
        let ok = with(&["nic1:br0"]).unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].dev, "nic1");
    }

    /// --max 0 used to make "the filter is nine tenths full" permanently
    /// true, which schedules the fast pass rate for ever; a huge value
    /// overflowed the same arithmetic. Both are typos, and both now get an
    /// answer instead of a behaviour.
    #[test]
    fn a_threshold_that_would_spin_or_overflow_is_refused() {
        assert!(clamp_max_macs(0).is_err());
        assert!(clamp_max_macs(usize::MAX / 2).is_err());
        assert_eq!(clamp_max_macs(128), Ok(128));
        let mut o = Options::default();
        assert!(parse_args_from(&mut o, args(&["--max", "0"]).into_iter()).is_err());
        let mut o = Options::default();
        read_conf(&mut o, "MAX_MACS=0\n");
        assert_eq!(
            o.max_macs,
            Options::default().max_macs,
            "a refused threshold must not replace the default"
        );
    }

    #[test]
    fn a_second_mode_is_refused_rather_than_quietly_winning() {
        let mut o = Options::default();
        let e = parse_args_from(&mut o, args(&["--status", "--flush"]).into_iter()).unwrap_err();
        assert!(e.contains("--flush"), "the message hides the option: {e}");
        assert!(
            matches!(o.mode, Mode::Status),
            "the first mode did not stand"
        );
    }

    #[test]
    fn the_daemon_is_the_mode_without_arguments() {
        let mut o = Options::default();
        parse_args_from(&mut o, args(&[]).into_iter()).unwrap();
        assert!(matches!(o.mode, Mode::Daemon));
        assert!(!o.dry_run && !o.verbose);
    }

    /// The daemon asks for SIGTERM instead of being killed by it. If the
    /// handler were not installed - or installed wrongly - this test would
    /// not fail, it would take the whole test process down with it, which is
    /// as clear a signal as a failure.
    #[test]
    fn a_termination_signal_is_caught_and_only_noted() {
        catch_signals();
        assert!(!stopping(), "nothing has asked us to stop yet");
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        assert!(stopping(), "the handler has to record the request");
        // Other tests share this process.
        STOPPING.store(false, Ordering::Relaxed);
    }

    /// A hash starts a comment - unless it is inside quotes, where it is part
    /// of what somebody wrote down.
    #[test]
    fn a_comment_ends_a_value_but_quotes_protect_a_hash() {
        assert_eq!(strip_comment("300  # seconds"), "300  ");
        assert_eq!(strip_comment("300"), "300");
        assert_eq!(strip_comment("\"a#b\" # trailing"), "\"a#b\" ");
        assert_eq!(strip_comment("'a#b'"), "'a#b'");
        assert_eq!(strip_comment("#all of it"), "");
        // An unbalanced quote swallows the rest rather than guessing where
        // the value was meant to stop.
        assert_eq!(strip_comment("\"unclosed # here"), "\"unclosed # here");
    }
}

#[cfg(test)]
mod pair_override_tests {
    use super::*;

    /// The command line names the whole pair list or none of it: the first
    /// --pair replaces what PAIRS= put there, so repeating the conf's pair
    /// is not a duplicate and a differing bridge wins.
    #[test]
    fn a_cli_pair_replaces_the_configurations() {
        let mut opts = Options {
            pairs: vec!["nic1:vmbr1".into()],
            ..Default::default()
        };
        parse_args_from(
            &mut opts,
            ["--pair".to_string(), "nic1:vmbr1".to_string()].into_iter(),
        )
        .expect("the conf's own pair on the command line is not a duplicate");
        assert_eq!(opts.pairs, vec!["nic1:vmbr1".to_string()]);

        let mut opts = Options {
            pairs: vec!["nic1:vmbr1".into()],
            ..Default::default()
        };
        parse_args_from(
            &mut opts,
            ["--pair".to_string(), "nic1:vmbr9".to_string()].into_iter(),
        )
        .unwrap();
        assert_eq!(
            opts.pairs,
            vec!["nic1:vmbr9".to_string()],
            "a differing command line wins over the configuration"
        );
    }
}
