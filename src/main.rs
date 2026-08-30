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

mod devlink;
mod hash;
mod netlink;
mod sync;
mod sysfs;

use crate::hash::Set;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use netlink::{format_mac, parse_mac, Socket};
use sync::{Pair, Syncer};
use sysfs::Topology;

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
/// How long to wait before trying again when the kernel would not describe the
/// interfaces. Short, because until it answers the daemon is not doing its job
/// at all; not zero, because a kernel that just refused will refuse again.
const RETRY_AFTER: Duration = Duration::from_secs(5);
/// How long a batch that only reported deletions may hold the pass off. Long
/// enough that a table ageing out is answered once rather than fifty times,
/// short enough that a filter slot is not held by a guest that left.
const AGEING_SETTLE: Duration = Duration::from_secs(5);

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
    use sync::DEFAULT_MAX_MACS;
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
                  quiet keeps as the list nears it (default {DEFAULT_MAX_MACS})
  --exclude MACS  addresses never to register, comma or space separated
  --extra MACS    addresses to register unconditionally, likewise separated
  -v, --verbose   explain what is skipped and why
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
                println!("sriov-mac-sync {VERSION}");
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
            println!("{}: skipped - the interface is gone", pair.dev);
            continue;
        };
        let Some(mut probe) = link.mac else {
            println!(
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
            println!(
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
                println!(
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
                println!(
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
            println!(
                "{} ({driver}): ok - accepts unicast filter entries \
                 (kernel side only; confirm with traffic)",
                pair.dev
            );
        } else {
            println!(
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
fn human_duration(ms: u64) -> String {
    let s = ms / 1000;
    if s < 120 {
        format!("{s}s")
    } else if s < 7200 {
        format!("{}m", s / 60)
    } else {
        format!("{}h", s / 3600)
    }
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
                    r.wanted.len()
                );
            } else {
                note!(
                    "{}: +{} -{}, {} address(es) registered{quiet} [{trigger}]",
                    r.dev,
                    r.added,
                    r.removed,
                    r.wanted.len()
                );
            }
        }
    }
}

/// The interface picture, from the kernel in one dump.
fn read_topology(sock: &mut Socket) -> Result<Topology, String> {
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
trait World: sync::FdbWriter {
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
struct Live {
    sock: Socket,
    mon: Socket,
    /// The stop pipe's read end; a byte here is a signal that landed
    /// outside the poll and must still cut the wait short.
    stop_rx: Option<std::os::fd::OwnedFd>,
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
struct Schedule {
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
struct Picture {
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
fn distrust_carried(picture: &mut Picture, syncer: &mut Syncer) {
    picture.invalidate();
    syncer.vf_stale = true;
}

/// The daemon: answer batches through the fast path, keep the pass rate
/// bounded, and never trust a picture longer than the interval. Everything
/// here is a decision about time or about what the world said, which is why
/// the world arrives as a parameter - the tests hand in a scripted one and
/// this function cannot tell.
fn daemon_loop<W: World>(world: &mut W, syncer: &mut Syncer, opts: &Options) {
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
enum Pass {
    Done,
    Refused,
}

/// One full pass: read the picture if it can no longer be believed, work out
/// which pairs there are, and reconcile every one of them against the kernel.
/// The daemon loop's accumulated say-once and adoption state, threaded
/// through the passes as one thing because it lives exactly as long as the
/// loop does.
struct LoopState {
    said_empty: bool,
    /// Whether a configured pair's card still owes its capacity answer.
    capacity_pending: bool,
}

fn run_pass<W: World>(
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
fn handle_batch<W: World>(
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
fn capacities_via_devlink(devs: &[String]) -> Vec<(String, CapacityAnswer)> {
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
fn adopt_reported_capacity(
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

fn run() -> Result<bool, String> {
    let mut opts = Options::default();
    load_conf(&mut opts);
    parse_args(&mut opts)?;

    let mut sock = Socket::new().map_err(|e| format!("cannot open netlink socket: {e}"))?;

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
                println!("{} on {} ({})", r.dev, r.bridge, r.driver);
                if r.port != r.dev {
                    println!("  enslaved through  : {}", r.port);
                }
                // "wanted", not "behind the bridge": EXTRA-pinned
                // addresses are in this number precisely because they are
                // NOT in the bridge's table, and the count must not
                // disagree with `bridge fdb show` over them.
                println!("  wanted in filter  : {}", r.wanted.len());
                println!("  registered by us  : {}", r.owned);
                // Worth a line only when there are any: the memory this
                // reads is the running daemon's, taken from the file it
                // writes, so a fresh --status can now answer for it.
                if r.quiet > 0 {
                    println!("  held quiet        : {}", r.quiet);
                }
                println!("  unicast list      : {}", r.present);
                println!(
                    "  stacked bridges   : {}",
                    if r.stacked.is_empty() {
                        "none".to_string()
                    } else {
                        r.stacked.join(" ")
                    }
                );
                if opts.verbose {
                    let ages: std::collections::BTreeMap<_, _> =
                        r.quiet_ages.iter().copied().collect();
                    let mut wanted = r.wanted.clone();
                    wanted.sort();
                    for mac in &wanted {
                        match ages.get(mac) {
                            // The question the 502 hunt actually asked:
                            // which of these is a keep, and for how long
                            // has nobody heard from it.
                            Some(ms) => println!(
                                "    {} (quiet, missing {})",
                                format_mac(mac),
                                human_duration(*ms)
                            ),
                            None => println!("    {}", format_mac(mac)),
                        }
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
            let mon = Socket::subscribed()
                .map_err(|e| format!("cannot subscribe to neighbour events: {e}"))?;
            // A device that drops out of one reading is not gone: an
            // interface reload takes a bridge away for a moment, and taking
            // its guests' addresses out of a live filter over that is the
            // outage this daemon exists to prevent. Long enough to outlive
            // `ifreload -a`, short enough that a bridge genuinely taken apart
            // is tidied up within the interval.
            syncer.orphan_grace = Duration::from_secs(60);
            let mut world = Live { sock, mon, stop_rx };
            daemon_loop(&mut world, &mut syncer, &opts);

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
        use crate::sysfs::fixture::mac;
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
                    Ok(crate::sysfs::fixture::Builder::new()
                        .add("nic1", 2, Some(mac(1)))
                        .vfs(1)
                        .build())
                } else {
                    Ok(host(mac(1)))
                }
            }
        }

        fn scratch(name: &str) -> std::path::PathBuf {
            let d = std::env::temp_dir()
                .join(format!("sriov-mac-sync-loop-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            d
        }

        /// nic1:vmbr1 named on the command line, so the loop does not
        /// autodetect and the pair set stays put.
        fn setup(name: &str, interval: u64) -> (Syncer, Options) {
            let mut opts = Options {
                interval,
                pairs: vec!["nic1:vmbr1".into()],
                ..Default::default()
            };
            opts.mode = Mode::Daemon;
            let syncer = Syncer::new(
                vec![Pair {
                    dev: "nic1".into(),
                    bridge: "vmbr1".into(),
                }],
                scratch(name),
            );
            (syncer, opts)
        }

        fn secs(d: Duration) -> u64 {
            d.as_secs()
        }

        /// The timed pass runs at the interval, exactly, for as long as
        /// nothing happens - the heartbeat everything else is measured
        /// against, and until now the one thing no test could see.
        #[test]
        fn a_quiet_host_gets_its_pass_once_per_interval() {
            let (mut syncer, opts) = setup("cadence", 10);
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
            let mut syncer = Syncer::new(Vec::new(), scratch("hotplug"));
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
            let (mut syncer, opts) = setup("refresh-distrust", 10);
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
            let (mut syncer, opts) = setup("wait-fails", 8);
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
            let mut syncer = Syncer::new(Vec::new(), scratch("hotplug-capacity"));
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
            let mut syncer = Syncer::new(Vec::new(), scratch("hotplug-capacity-set"));
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
            let (mut syncer, opts) = setup("learn", 300);
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
            let (mut syncer, opts) = setup("ageing", 300);
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
            let (mut syncer, opts) = setup("foreign", 300);
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
            let (mut syncer, opts) = setup("lost", 300);
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
            let (mut syncer, opts) = setup("refused", 300);
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
            let (mut syncer, opts) = setup("links", 300);
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
            let (mut syncer, opts) = setup("conf-capacity", 300);
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
            let (mut syncer, opts) = setup("filling", 300);
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
            let (mut syncer, opts) = setup("stop", 300);
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
        use crate::sysfs::fixture::{mac, Builder};
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
