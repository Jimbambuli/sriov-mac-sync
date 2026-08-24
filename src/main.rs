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

mod netlink;
mod sync;
mod sysfs;

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use netlink::{format_mac, parse_mac, Socket};
use sync::{Pair, Syncer};
use sysfs::Topology;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const CONF: &str = "/etc/sriov-mac-sync.conf";
const STATE_DIR: &str = "/run/sriov-mac-sync";

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
            max_macs: 128,
            exclude: Vec::new(),
            extra: Vec::new(),
            dry_run: false,
            verbose: false,
            timings: false,
        }
    }
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
  --max NUM       warn above this many addresses per uplink (default 128)
  --exclude MACS  comma separated addresses never to register
  --extra MACS    comma separated addresses to register unconditionally
  -v, --verbose   explain what is skipped and why
  -h, --help      this text
      --version   print the version

Pairs are found automatically: every interface with virtual functions - or
itself a virtual function - that ends up in a bridge, following bonds. {CONF} may set PAIRS, RESYNC,
MAX_MACS, EXCLUDE and EXTRA.
"
    )
}

/// Addresses from the command line or the configuration file. A typo here
/// used to vanish without a word - and an address that was meant to be pinned
/// and silently was not is exactly the kind of thing somebody spends an
/// evening looking for in the wrong place.
fn macs(what: &str, given: &[String]) -> HashSet<[u8; 6]> {
    let mut out = HashSet::new();
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
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let (key, value) = line.split_once('=').unwrap();
        // "RESYNC=300  # seconds" means 300, not a parse warning. No value
        // this file takes can legitimately contain a hash.
        let value = value.split('#').next().unwrap_or("");
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
            "MAX_MACS" => match value.parse() {
                Ok(v) => opts.max_macs = v,
                Err(_) => eprintln!("warning: {CONF}: MAX_MACS is not a number, ignored: {value}"),
            },
            "EXTRA" => opts.extra.extend(
                value
                    .split([',', ' '])
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string()),
            ),
            "EXCLUDE" => opts.exclude.extend(
                value
                    .split([',', ' '])
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string()),
            ),
            // Silently ignoring a misspelt key means the setting somebody
            // wrote down never takes effect and nothing ever says so.
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
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--once" => set_mode(opts, Mode::Once, &arg)?,
            "--status" => set_mode(opts, Mode::Status, &arg)?,
            "--check" => set_mode(opts, Mode::Check, &arg)?,
            "--flush" => set_mode(opts, Mode::Flush, &arg)?,
            "--dry-run" => opts.dry_run = true,
            "--timings" => opts.timings = true,
            "-v" | "--verbose" => opts.verbose = true,
            "--pair" => opts
                .pairs
                .push(args.next().ok_or("--pair needs DEV:BRIDGE")?),
            "--interval" => {
                opts.interval = clamp_interval(
                    args.next()
                        .ok_or("--interval needs seconds")?
                        .parse()
                        .map_err(|_| "--interval needs a number")?,
                )?
            }
            "--max" => {
                opts.max_macs = args
                    .next()
                    .ok_or("--max needs a number")?
                    .parse()
                    .map_err(|_| "--max needs a number")?
            }
            "--extra" => opts.extra.extend(
                args.next()
                    .ok_or("--extra needs addresses")?
                    .split([',', ' '])
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string()),
            ),
            "--exclude" => opts.exclude.extend(
                args.next()
                    .ok_or("--exclude needs addresses")?
                    .split([',', ' '])
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string()),
            ),
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

fn resolve_pairs(topo: &Topology, opts: &Options, allow_empty: bool) -> Result<Vec<Pair>, String> {
    let mut pairs = Vec::new();
    if opts.pairs.is_empty() {
        let (found, skipped) = topo.autodetect();
        if opts.verbose {
            for s in skipped {
                eprintln!("{s}");
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
            if topo.get(dev).is_none() {
                return Err(format!("no such interface: {dev}"));
            }
            if !topo.is_bridge(bridge) {
                return Err(format!("not a bridge: {bridge}"));
            }
            // A pair whose device does not actually sit under that bridge
            // disables the one protection that matters: nothing the bridge
            // learnt counts as wire-side any more, so everything it learnt -
            // the peers out on the cable included - would be written into
            // the device's filter. A typo must fail here, not there.
            if dev == bridge {
                return Err(format!("{spec}: a bridge cannot be its own uplink"));
            }
            if topo.bridge_above(dev).map(|(b, _)| b).as_deref() != Some(bridge) {
                return Err(format!(
                    "{spec}: {dev} is not enslaved to {bridge}, directly or through a bond"
                ));
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
fn check(sock: &mut Socket, topo: &Topology, pairs: &[Pair], dry_run: bool) -> bool {
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

        // The check *is* a write: it proves the driver accepts an entry by
        // giving it one and taking it back. A dry run has nothing to probe
        // with, and pretending otherwise would print an answer it never had.
        if dry_run {
            println!(
                "{} ({driver}): skipped - the check works by writing a probe entry, \
                 which --dry-run rules out",
                pair.dev
            );
            continue;
        }

        match sock.set_self_fdb(link.index, &probe, true) {
            Ok(()) => {}
            // Left over from an earlier check that could not clean up. The
            // driver plainly accepts entries - that is the question here.
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
            Err(e) => {
                println!(
                    "{} ({driver}): FAILED - the driver refuses unicast filter entries: {e}",
                    pair.dev
                );
                ok = false;
                continue;
            }
        }
        let listed = sock
            .dump_fdb()
            .map(|fdb| {
                fdb.iter()
                    .any(|e| e.is_self() && e.ifindex == link.index && e.mac == probe)
            })
            .unwrap_or(false);
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
        if let Err(e) = sock.set_self_fdb(link.index, &probe, false) {
            eprintln!(
                "warning: {}: the probe entry {} could not be taken back out: {e}",
                pair.dev,
                format_mac(&probe)
            );
        }
    }
    ok
}

fn report_changes(
    reports: &[sync::Report],
    dry_run: bool,
    max_macs: usize,
    verbose: bool,
    trigger: &str,
) {
    for r in reports {
        if r.wanted.len() > max_macs {
            eprintln!(
                "warning: {}: {} addresses behind {}, above the {} the vport list \
                 is assumed to hold - some will be dropped silently",
                r.dev,
                r.wanted.len(),
                r.bridge,
                max_macs
            );
        }
        if verbose && r.foreign > 0 {
            eprintln!(
                "{}: {} address(es) already present, left alone",
                r.dev, r.foreign
            );
        }
        if r.added > 0 || r.removed > 0 {
            if dry_run {
                eprintln!(
                    "{}: would be +{} -{}, {} address(es) in total [{trigger}]",
                    r.dev,
                    r.added,
                    r.removed,
                    r.wanted.len()
                );
            } else {
                eprintln!(
                    "{}: +{} -{}, {} address(es) registered [{trigger}]",
                    r.dev,
                    r.added,
                    r.removed,
                    r.wanted.len()
                );
            }
        }
    }
}

fn run() -> Result<bool, String> {
    let mut opts = Options::default();
    load_conf(&mut opts);
    parse_args(&mut opts)?;

    let topo_started = Instant::now();
    let topo = Topology::load().map_err(|e| format!("cannot read /sys/class/net: {e}"))?;
    let topo_load = topo_started.elapsed();
    // Flush and status must not require a pair to exist: the state they
    // inspect - notes and filter entries - outlives the pair on purpose, and
    // "the bridge is gone" is exactly when --flush is reached for.
    let pairs = resolve_pairs(
        &topo,
        &opts,
        matches!(opts.mode, Mode::Daemon | Mode::Flush | Mode::Status),
    )?;

    let mut sock = Socket::new().map_err(|e| format!("cannot open netlink socket: {e}"))?;

    if opts.mode == Mode::Check {
        return Ok(check(&mut sock, &topo, &pairs, opts.dry_run));
    }

    let mut syncer = Syncer::new(pairs.clone(), PathBuf::from(STATE_DIR));
    syncer.dry_run = opts.dry_run;
    // Only autodetection sees every uplink, so only autodetection may conclude
    // that a leftover note belongs to none of them.
    syncer.authoritative = opts.pairs.is_empty();
    syncer.exclude = macs("--exclude", &opts.exclude);
    syncer.extra = macs("--extra", &opts.extra);

    match opts.mode {
        Mode::Flush => syncer.flush(&mut sock).map_err(|e| e.to_string()),
        Mode::Status => {
            let reports = syncer
                .reconcile(&mut sock, false, &topo, topo_load, true)
                .map_err(|e| e.to_string())?;
            for r in &reports {
                println!("{} on {} ({})", r.dev, r.bridge, r.driver);
                if r.port != r.dev {
                    println!("  enslaved through  : {}", r.port);
                }
                println!("  behind the bridge : {}", r.wanted.len());
                println!("  registered by us  : {}", r.owned);
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
                    let mut wanted = r.wanted.clone();
                    wanted.sort();
                    for mac in &wanted {
                        println!("    {}", format_mac(mac));
                    }
                }
            }
            Ok(true)
        }
        Mode::Once => {
            let reports = syncer
                .reconcile(&mut sock, true, &topo, topo_load, true)
                .map_err(|e| e.to_string())?;
            report_changes(&reports, opts.dry_run, opts.max_macs, opts.verbose, "once");
            if opts.timings {
                eprint!("{}", syncer.timings.report());
            }
            // A oneshot that could not do what it was asked has to say so in
            // its exit code - the warnings above scroll away, the code stays.
            Ok(syncer.timings.failures.is_empty())
        }
        Mode::Daemon => {
            let auto = opts.pairs.is_empty();
            let listed = pair_names(&pairs);
            eprintln!(
                "sriov-mac-sync {VERSION}: watching {}, full reconciliation every {}s",
                if listed.is_empty() {
                    "nothing yet".to_string()
                } else {
                    listed.join(" ")
                },
                opts.interval
            );
            let mon = Socket::subscribed()
                .map_err(|e| format!("cannot subscribe to neighbour events: {e}"))?;
            let mut said_empty = false;
            let interval = Duration::from_secs(opts.interval);
            // A deadline, not a sleep. Wake-ups that turn out to be none of our
            // business must not push the full pass further away.
            let mut next_full = Instant::now();
            // Which of the three reasons for a pass actually produced work is
            // the only way to tell whether the timed one earns its keep.
            let mut trigger = "start";
            // The topology carried over from the last pass, and whether it can
            // still be believed. A forwarding entry appearing or going says
            // nothing about which interfaces exist or what they are enslaved
            // to, so a pass woken by one works from the picture it already
            // has. Anything that touches interfaces marks it stale, as does
            // losing notifications and the timed pass, whose whole purpose is
            // to find what the events missed.
            let mut held: Option<Topology> = None;
            let mut stale = true;

            loop {
                if Instant::now() >= next_full {
                    // The timed pass exists to catch what the events missed,
                    // an interface change whose notification never arrived
                    // included. It reads afresh - and the flag is set here,
                    // where the reason for this pass is known, not after one
                    // where it only says what the next would be called.
                    if trigger == "timed" {
                        stale = true;
                    }
                    // Autodetection is redone every pass. A NIC that gets its
                    // VFs later, or a bridge built after boot, must not need a
                    // restart to be noticed - and starting before the network
                    // is up must not turn into a crash loop.
                    // One reading of /sys serves both the autodetection and
                    // the pass. They ask about the same moment, and reading it
                    // twice was work nobody asked for.
                    let mut topo_load = Duration::ZERO;
                    let reloaded = stale || held.is_none();
                    if reloaded {
                        let load_started = Instant::now();
                        match Topology::load() {
                            Ok(t) => {
                                topo_load = load_started.elapsed();
                                held = Some(t);
                                stale = false;
                            }
                            Err(e) => {
                                eprintln!("warning: cannot read /sys/class/net: {e}");
                                held = None;
                            }
                        }
                    }
                    let loaded = held.as_ref().map(|t| (t, topo_load));
                    if let (true, Some((topo, _))) = (auto, loaded) {
                        let found: Vec<Pair> = topo
                            .autodetect()
                            .0
                            .into_iter()
                            .map(|(dev, bridge)| Pair { dev, bridge })
                            .collect();
                        if pair_names(&found) != pair_names(&syncer.pairs) {
                            if !found.is_empty() {
                                eprintln!("now watching {}", pair_names(&found).join(" "));
                                said_empty = false;
                            }
                            syncer.pairs = found;
                        }
                    }

                    if syncer.pairs.is_empty() && !said_empty {
                        eprintln!("waiting for an SR-IOV interface to appear in a bridge");
                        said_empty = true;
                    }
                    {
                        let Some((topo, topo_load)) = loaded else {
                            next_full = Instant::now() + interval;
                            trigger = "timed";
                            continue;
                        };
                        match syncer.reconcile(&mut sock, true, topo, topo_load, reloaded) {
                            Ok(reports) => {
                                report_changes(
                                    &reports,
                                    opts.dry_run,
                                    opts.max_macs,
                                    opts.verbose,
                                    trigger,
                                );
                                if opts.timings {
                                    eprint!("pass [{trigger}]\n{}", syncer.timings.report());
                                }
                            }
                            // One failed pass is no reason to give up: the next
                            // is seconds away and starts from the kernel's
                            // state again.
                            Err(e) => eprintln!("warning: reconciliation failed: {e}"),
                        }
                    }
                    next_full = Instant::now() + interval;
                    trigger = "timed";
                }

                let due = next_full.saturating_duration_since(Instant::now());
                let woken = match mon.wait(due.as_millis().min(i32::MAX as u128) as i32) {
                    Ok(w) => w,
                    Err(e) => {
                        eprintln!("warning: waiting for events failed: {e}");
                        next_full = Instant::now();
                        stale = true;
                        trigger = "recovery";
                        continue;
                    }
                };
                if !woken {
                    continue; // the deadline came round; the pass happens above
                }

                let events = match mon.recv_events() {
                    Ok(events) => events,
                    // ENOBUFS means the kernel dropped notifications because we
                    // could not keep up. Losing them is survivable - a full pass
                    // reads the real state - but exiting over it would not be.
                    Err(e) => {
                        eprintln!("warning: lost neighbour notifications: {e}");
                        next_full = Instant::now();
                        // What was in the messages that never arrived is not
                        // knowable, so nothing carried over may be believed.
                        stale = true;
                        trigger = "lost events";
                        continue;
                    }
                };
                if events.fdb.is_empty() && !events.links_changed {
                    continue; // something else's neighbour, not a bridge's
                }
                // Not the trigger name: a batch carrying both kinds is
                // reported as a forwarding change, and would otherwise keep a
                // topology that the link messages in the same batch just
                // invalidated.
                if events.links_changed {
                    stale = true;
                }
                trigger = if events.fdb.is_empty() {
                    "interface change"
                } else {
                    "forwarding change"
                };

                // Register what just appeared before anything else, so the
                // first reply to it is not sent into the void.
                //
                // The pass that follows a few milliseconds later works from
                // the same picture, so read it here if it is wanted and let
                // that one have it too. Reading it twice for one event was
                // the whole of what this used to cost.
                if stale || held.is_none() {
                    match Topology::load() {
                        Ok(t) => {
                            held = Some(t);
                            stale = false;
                        }
                        Err(e) => eprintln!("warning: cannot read /sys/class/net: {e}"),
                    }
                }
                if let Some(topo) = held.as_ref() {
                    let arrived: Vec<_> = events
                        .fdb
                        .into_iter()
                        .filter(|(kind, _)| *kind == netlink::RTM_NEWNEIGH)
                        .map(|(_, entry)| entry)
                        .collect();
                    let _ = syncer.fast_add_all(&mut sock, topo, &arrived);
                }

                // Let a burst settle, then make the full pass due at once.
                // Bounded, because on a host whose neighbour table never goes
                // quiet for 200 ms this would wait for a lull that never comes
                // and the pass would never happen at all.
                let settle_until = Instant::now() + Duration::from_secs(2);
                while Instant::now() < settle_until && mon.wait(200).unwrap_or(false) {
                    // The batches read here are not acted on - the full pass
                    // that follows covers their forwarding entries - but an
                    // interface message among them still means the carried
                    // picture is no longer true. Before this was looked at,
                    // a container starting mid-burst had its veth ignored
                    // until the next timed pass.
                    match mon.recv_events() {
                        Ok(ev) if ev.links_changed => stale = true,
                        Ok(_) => {}
                        Err(_) => stale = true,
                    }
                }
                next_full = Instant::now();
            }
        }
        Mode::Check => unreachable!(),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
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

    #[test]
    fn every_documented_option_is_accepted() {
        let text = usage_text();
        // The long options the help offers, minus the two that exit the process.
        for opt in text
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .filter(|w| w.starts_with("--"))
            .filter(|w| !matches!(*w, "--help" | "--version"))
        {
            let mut o = Options::default();
            let with_value = match opt {
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
    fn the_readme_names_every_option_the_help_offers() {
        let readme = include_str!("../README.md");
        for opt in usage_text()
            .lines()
            .filter_map(|l| l.split_whitespace().next().map(|w| w.to_string()))
            .filter(|w| w.starts_with("--"))
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
    fn the_daemon_is_the_mode_without_arguments() {
        let mut o = Options::default();
        parse_args_from(&mut o, args(&[]).into_iter()).unwrap();
        assert!(matches!(o.mode, Mode::Daemon));
        assert!(!o.dry_run && !o.verbose);
    }
}
