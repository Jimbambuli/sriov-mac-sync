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
    dry_run: bool,
    verbose: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            mode: Mode::Daemon,
            pairs: Vec::new(),
            interval: 30,
            max_macs: 128,
            exclude: Vec::new(),
            dry_run: false,
            verbose: false,
        }
    }
}

fn usage() {
    print!(
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
  --pair DEV:BR   uplink/bridge pair to manage (repeatable, skips autodetect)
  --interval SEC  full reconciliation interval (default 30)
  --max NUM       warn above this many addresses per uplink (default 128)
  --exclude MACS  comma separated addresses never to register
  -v, --verbose   explain what is skipped and why
  -h, --help      this text
      --version   print the version

Pairs are found automatically: every interface with virtual functions that ends
up in a bridge, following bonds. {CONF} may set PAIRS, RESYNC,
MAX_MACS and EXCLUDE.
"
    );
}

fn load_conf(opts: &mut Options) {
    let Ok(text) = std::fs::read_to_string(CONF) else {
        return;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let (key, value) = line.split_once('=').unwrap();
        let value = value.trim().trim_matches('"').trim_matches('\'');
        match key.trim() {
            "PAIRS" => opts
                .pairs
                .extend(value.split_whitespace().map(|s| s.to_string())),
            "RESYNC" => {
                if let Ok(v) = value.parse() {
                    opts.interval = v;
                }
            }
            "MAX_MACS" => {
                if let Ok(v) = value.parse() {
                    opts.max_macs = v;
                }
            }
            "EXCLUDE" => opts.exclude.extend(
                value
                    .split(|c| c == ',' || c == ' ')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string()),
            ),
            _ => {}
        }
    }
}

fn parse_args(opts: &mut Options) -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--once" => opts.mode = Mode::Once,
            "--status" => opts.mode = Mode::Status,
            "--check" => opts.mode = Mode::Check,
            "--flush" => opts.mode = Mode::Flush,
            "--dry-run" => opts.dry_run = true,
            "-v" | "--verbose" => opts.verbose = true,
            "--pair" => opts
                .pairs
                .push(args.next().ok_or("--pair needs DEV:BRIDGE")?),
            "--interval" => {
                opts.interval = args
                    .next()
                    .ok_or("--interval needs seconds")?
                    .parse()
                    .map_err(|_| "--interval needs a number")?
            }
            "--max" => {
                opts.max_macs = args
                    .next()
                    .ok_or("--max needs a number")?
                    .parse()
                    .map_err(|_| "--max needs a number")?
            }
            "--exclude" => opts.exclude.extend(
                args.next()
                    .ok_or("--exclude needs addresses")?
                    .split(|c| c == ',' || c == ' ')
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

fn resolve_pairs(topo: &Topology, opts: &Options) -> Result<Vec<Pair>, String> {
    let mut pairs = Vec::new();
    if opts.pairs.is_empty() {
        let (found, skipped) = topo.autodetect();
        if opts.verbose {
            for s in skipped {
                eprintln!("{s}");
            }
        }
        if found.is_empty() {
            return Err(
                "no SR-IOV interface found that ends up in a bridge \
                 (use --pair; -v explains what was skipped)"
                    .into(),
            );
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
            pairs.push(Pair {
                dev: dev.to_string(),
                bridge: bridge.to_string(),
            });
        }
    }
    Ok(pairs)
}

/// Can this driver take entries at all? Only half an answer: it proves the
/// kernel accepted the address, not that the hardware acts on it.
fn check(sock: &mut Socket, topo: &Topology, pairs: &[Pair]) -> bool {
    let mut ok = true;
    for pair in pairs {
        let Some(link) = topo.get(&pair.dev) else {
            continue;
        };
        let Some(mut probe) = link.mac else { continue };
        probe[0] = 0x02;
        probe[5] ^= 0x5a;
        let driver = link.driver.clone().unwrap_or_default();

        if let Err(e) = sock.set_self_fdb(link.index, &probe, true) {
            println!(
                "{} ({driver}): FAILED - the driver refuses unicast filter entries: {e}",
                pair.dev
            );
            ok = false;
            continue;
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
        let _ = sock.set_self_fdb(link.index, &probe, false);
    }
    ok
}

fn report_changes(reports: &[sync::Report], dry_run: bool, max_macs: usize, verbose: bool) {
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
                    "{}: would be +{} -{}, {} address(es) in total",
                    r.dev,
                    r.added,
                    r.removed,
                    r.wanted.len()
                );
            } else {
                eprintln!(
                    "{}: +{} -{}, {} address(es) registered",
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

    let topo = Topology::load().map_err(|e| format!("cannot read /sys/class/net: {e}"))?;
    let pairs = resolve_pairs(&topo, &opts)?;

    let mut sock = Socket::new().map_err(|e| format!("cannot open netlink socket: {e}"))?;

    if opts.mode == Mode::Check {
        return Ok(check(&mut sock, &topo, &pairs));
    }

    let mut syncer = Syncer::new(pairs.clone(), PathBuf::from(STATE_DIR));
    syncer.max_macs = opts.max_macs;
    syncer.dry_run = opts.dry_run;
    syncer.exclude = opts
        .exclude
        .iter()
        .filter_map(|s| parse_mac(s))
        .collect::<HashSet<_>>();

    match opts.mode {
        Mode::Flush => {
            syncer.flush(&mut sock).map_err(|e| e.to_string())?;
            Ok(true)
        }
        Mode::Status => {
            let reports = syncer
                .reconcile(&mut sock, false)
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
                    for mac in &r.wanted {
                        println!("    {}", format_mac(mac));
                    }
                }
            }
            Ok(true)
        }
        Mode::Once => {
            let reports = syncer
                .reconcile(&mut sock, true)
                .map_err(|e| e.to_string())?;
            report_changes(&reports, opts.dry_run, opts.max_macs, opts.verbose);
            Ok(true)
        }
        Mode::Daemon => {
            let names: Vec<String> = pairs
                .iter()
                .map(|p| format!("{}:{}", p.dev, p.bridge))
                .collect();
            eprintln!(
                "sriov-mac-sync {VERSION}: watching {}, full reconciliation every {}s",
                names.join(" "),
                opts.interval
            );
            let mon = Socket::subscribed()
                .map_err(|e| format!("cannot subscribe to neighbour events: {e}"))?;
            let reports = syncer
                .reconcile(&mut sock, true)
                .map_err(|e| e.to_string())?;
            report_changes(&reports, opts.dry_run, opts.max_macs, opts.verbose);

            loop {
                let woken = mon
                    .wait((opts.interval * 1000) as i32)
                    .map_err(|e| e.to_string())?;
                if woken {
                    // Register what just appeared before doing anything else,
                    // so the first reply to it is not lost.
                    let topo = Topology::load().map_err(|e| e.to_string())?;
                    for (kind, entry) in mon.recv_events().map_err(|e| e.to_string())? {
                        if kind == netlink::RTM_NEWNEIGH {
                            let _ = syncer.fast_add(&mut sock, &topo, &entry);
                        }
                    }
                    // Let a burst settle before the full pass.
                    while mon.wait(200).map_err(|e| e.to_string())? {
                        let _ = mon.recv_events();
                    }
                }
                let reports = syncer
                    .reconcile(&mut sock, true)
                    .map_err(|e| e.to_string())?;
                report_changes(&reports, opts.dry_run, opts.max_macs, opts.verbose);
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
