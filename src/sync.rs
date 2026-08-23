//! Deciding which addresses belong in an uplink's unicast filter, and putting
//! them there.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::PathBuf;

use crate::netlink::{format_mac, FdbEntry, Socket};
use crate::sysfs::Topology;

pub type Mac = [u8; 6];

#[derive(Debug, Clone)]
pub struct Pair {
    pub dev: String,
    pub bridge: String,
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

pub struct Syncer {
    pub pairs: Vec<Pair>,
    pub max_macs: usize,
    pub exclude: HashSet<Mac>,
    pub dry_run: bool,
    pub state_dir: PathBuf,
    owned: HashMap<String, HashSet<Mac>>,
}

impl Syncer {
    pub fn new(pairs: Vec<Pair>, state_dir: PathBuf) -> Self {
        Syncer {
            pairs,
            max_macs: 128,
            exclude: HashSet::new(),
            dry_run: false,
            state_dir,
            owned: HashMap::new(),
        }
    }

    fn state_path(&self, dev: &str) -> PathBuf {
        self.state_dir.join(format!("{dev}.owned"))
    }

    /// What this daemon put there itself. Kept on disk so a restart does not
    /// have to choose between forgetting its entries and claiming everybody
    /// else's.
    fn load_owned(&mut self, dev: &str) -> HashSet<Mac> {
        if let Some(set) = self.owned.get(dev) {
            return set.clone();
        }
        let mut set = HashSet::new();
        if let Ok(text) = fs::read_to_string(self.state_path(dev)) {
            for line in text.lines() {
                if let Some(mac) = crate::netlink::parse_mac(line.trim()) {
                    set.insert(mac);
                }
            }
        }
        self.owned.insert(dev.to_string(), set.clone());
        set
    }

    fn save_owned(&mut self, dev: &str, set: &HashSet<Mac>) {
        self.owned.insert(dev.to_string(), set.clone());
        if self.dry_run {
            return;
        }
        let _ = fs::create_dir_all(&self.state_dir);
        let mut lines: Vec<String> = set.iter().map(format_mac).collect();
        lines.sort();
        let _ = fs::write(self.state_path(dev), lines.join("\n") + "\n");
    }

    /// The addresses that belong in `pair`'s filter list, and the ones that
    /// must stay out of it.
    fn desired(
        &self,
        topo: &Topology,
        pair: &Pair,
        port: &str,
        fdb: &[FdbEntry],
        vf_macs: &[(u32, Mac)],
    ) -> (HashSet<Mac>, Vec<String>) {
        let Some(bridge_link) = topo.get(&pair.bridge) else {
            return (HashSet::new(), Vec::new());
        };
        let port_index = topo.get(port).map(|l| l.index).unwrap_or(0);

        // Bridges stacked on the uplink bridge. Their tables hold the guests
        // whose addresses the lower bridge never learns: that traffic enters it
        // from the bridge's own local port, and a bridge does not learn from
        // itself.
        let mut relevant: HashMap<u32, String> = HashMap::new();
        for b in topo.bridges() {
            if b.name == pair.bridge {
                continue;
            }
            let ports: Vec<&String> = topo
                .links
                .values()
                .filter(|l| l.master.as_deref() == Some(b.name.as_str()))
                .map(|l| &l.name)
                .collect();
            if ports.iter().any(|p| topo.leads_to(p, &pair.bridge)) {
                relevant.insert(b.index, b.name.clone());
            }
        }

        let mut wire: HashSet<Mac> = HashSet::new();
        let mut want: HashSet<Mac> = HashSet::new();

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
            } else if relevant.contains_key(&master) {
                let toward_uplink = topo
                    .name_of(e.ifindex)
                    .map(|n| topo.leads_to(n, &pair.bridge))
                    .unwrap_or(false);
                if !toward_uplink {
                    want.insert(e.mac);
                }
            }
        }

        // The host's own addresses on this bridge. Usually the uplink's own,
        // in which case they drop out again below - but not on a host where
        // the bridge carries a different address, and there the host would
        // otherwise be unreachable from the VF.
        if let Some(mac) = bridge_link.mac {
            want.insert(mac);
        }
        for link in topo.links.values() {
            if link.name != pair.bridge && topo.leads_to(&link.name, &pair.bridge) {
                if let Some(mac) = link.mac {
                    want.insert(mac);
                }
            }
        }

        // Everything the host owns on this side of the uplink.
        let mut skip: HashSet<Mac> = wire;
        skip.extend(self.exclude.iter().copied());
        skip.extend(topo.subtree_macs(port));
        if let Some(l) = topo.get(&pair.dev) {
            if let Some(mac) = l.mac {
                skip.insert(mac);
            }
        }
        let pf = topo
            .get(&pair.dev)
            .and_then(|l| l.physfn.clone())
            .unwrap_or_else(|| pair.dev.clone());
        if let Some(pf_link) = topo.get(&pf) {
            if let Some(mac) = pf_link.mac {
                skip.insert(mac);
            }
            for (ifindex, mac) in vf_macs {
                if *ifindex == pf_link.index {
                    skip.insert(*mac);
                }
            }
            for vf in &pf_link.vf_netdevs {
                if let Some(l) = topo.get(vf) {
                    if let Some(mac) = l.mac {
                        skip.insert(mac);
                    }
                }
            }
        }

        want.retain(|m| !skip.contains(m) && m[0] & 1 == 0);
        let mut stacked: Vec<String> = relevant.into_values().collect();
        stacked.sort();
        (want, stacked)
    }

    pub fn reconcile(&mut self, sock: &mut Socket, apply: bool) -> io::Result<Vec<Report>> {
        let topo = Topology::load()?;
        let fdb = sock.dump_fdb()?;
        let vf_macs = sock.dump_vf_macs().unwrap_or_default();
        let mut reports = Vec::new();

        for pair in self.pairs.clone() {
            let Some(dev_link) = topo.get(&pair.dev) else {
                continue;
            };
            let dev_index = dev_link.index;
            let driver = dev_link.driver.clone().unwrap_or_default();
            let port = topo.uplink_port(&pair.dev, &pair.bridge);
            let (want, stacked) = self.desired(&topo, &pair, &port, &fdb, &vf_macs);

            let present: HashSet<Mac> = fdb
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
                        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                            owned.insert(*mac);
                        }
                        Err(e) => {
                            eprintln!(
                                "warning: {}: cannot register {}: {e}",
                                pair.dev,
                                format_mac(mac)
                            );
                            added -= 1;
                        }
                    }
                }
            }

            let stale: Vec<Mac> = owned.iter().filter(|m| !want.contains(*m)).copied().collect();
            for mac in stale {
                removed += 1;
                if apply && !self.dry_run {
                    let _ = sock.set_self_fdb(dev_index, &mac, false);
                    owned.remove(&mac);
                }
            }

            if apply {
                self.save_owned(&pair.dev, &owned);
            }

            let mut wanted: Vec<Mac> = want.into_iter().collect();
            wanted.sort();
            reports.push(Report {
                dev: pair.dev.clone(),
                bridge: pair.bridge.clone(),
                port,
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
        Ok(reports)
    }

    /// Register one address straight away, without waiting for the next full
    /// pass. A device that has only just appeared would otherwise miss the
    /// first reply sent to it.
    pub fn fast_add(
        &mut self,
        sock: &mut Socket,
        topo: &Topology,
        entry: &FdbEntry,
    ) -> io::Result<()> {
        if !entry.is_learned() || !entry.is_unicast() {
            return Ok(());
        }
        let Some(master) = entry.master else {
            return Ok(());
        };
        let Some(port_name) = topo.name_of(entry.ifindex).map(|s| s.to_string()) else {
            return Ok(());
        };
        for pair in self.pairs.clone() {
            let Some(bridge_link) = topo.get(&pair.bridge) else {
                continue;
            };
            let port = topo.uplink_port(&pair.dev, &pair.bridge);
            if port_name == port {
                continue; // on the wire
            }
            if master != bridge_link.index {
                // only bridges stacked on the uplink bridge are of interest
                let Some(master_name) = topo.name_of(master) else {
                    continue;
                };
                let ports: Vec<&String> = topo
                    .links
                    .values()
                    .filter(|l| l.master.as_deref() == Some(master_name))
                    .map(|l| &l.name)
                    .collect();
                if !ports.iter().any(|p| topo.leads_to(p, &pair.bridge)) {
                    continue;
                }
            }
            if topo.leads_to(&port_name, &pair.bridge) {
                continue;
            }
            let Some(dev_link) = topo.get(&pair.dev) else {
                continue;
            };
            if self.dry_run {
                continue;
            }
            match sock.set_self_fdb(dev_link.index, &entry.mac, true) {
                Ok(()) | Err(_) => {
                    let mut owned = self.load_owned(&pair.dev);
                    owned.insert(entry.mac);
                    self.save_owned(&pair.dev, &owned);
                }
            }
        }
        Ok(())
    }

    pub fn flush(&mut self, sock: &mut Socket) -> io::Result<()> {
        let topo = Topology::load()?;
        for pair in self.pairs.clone() {
            let owned = self.load_owned(&pair.dev);
            let n = owned.len();
            if let Some(link) = topo.get(&pair.dev) {
                for mac in &owned {
                    let _ = sock.set_self_fdb(link.index, mac, false);
                }
            }
            self.save_owned(&pair.dev, &HashSet::new());
            println!("{}: removed {} address(es)", pair.dev, n);
        }
        Ok(())
    }
}
