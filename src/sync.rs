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
    /// addresses to register whether or not a bridge has learnt them
    pub extra: HashSet<Mac>,
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
            extra: HashSet::new(),
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

        // Addresses pinned by configuration are registered even when nothing
        // has been heard from them yet - for a device that never speaks first,
        // or to close the gap before a guest's first frame.
        want.extend(self.extra.iter().copied());

        want.retain(|m| !skip.contains(m) && m[0] & 1 == 0);

        for m in &self.extra {
            if !want.contains(m) {
                eprintln!(
                    "warning: {}: pinned address {} not registered - it is the host's own, \
                     or the bridge has it out on the wire",
                    pair.dev,
                    format_mac(m)
                );
            }
        }
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
                        // The dump a moment ago said it was absent, so it
                        // appeared in between - ours in all but timing.
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

            let stale: Vec<Mac> = owned
                .iter()
                .filter(|m| !want.contains(*m))
                .copied()
                .collect();
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
                Ok(()) => {
                    let mut owned = self.load_owned(&pair.dev);
                    owned.insert(entry.mac);
                    self.save_owned(&pair.dev, &owned);
                }
                // Already there, and unlike in a full pass nothing checked
                // beforehand whether it was ours. Claiming it now could mean
                // deleting somebody else's entry later, so leave the note be;
                // the next full pass classifies it properly.
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
                Err(e) => eprintln!(
                    "warning: {}: cannot register {}: {e}",
                    pair.dev,
                    format_mac(&entry.mac)
                ),
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::netlink::FdbEntry;
    use crate::sysfs::fixture::{mac, Builder};

    pub(crate) const WIRE: Mac = [0xaa, 0, 0, 0, 0, 1]; // a peer out on the switch
    pub(crate) const BEHIND_NIC: Mac = [0xaa, 0, 0, 0, 0, 2]; // on the bridge's other NIC
    pub(crate) const BEHIND_GUEST: Mac = [0xaa, 0, 0, 0, 0, 3]; // a container, seen by a vnet
    pub(crate) const UPLINK_WARD: Mac = [0xaa, 0, 0, 0, 0, 4]; // seen by a vnet on its way down
    pub(crate) const OTHER_BRIDGE: Mac = [0xaa, 0, 0, 0, 0, 5]; // nothing to do with this uplink
    pub(crate) const VF_ADMIN: Mac = [0x02, 0x11, 0x22, 0x33, 0x44, 1];
    pub(crate) const MCAST: Mac = [0x01, 0x00, 0x5e, 0, 0, 1];

    /// A learnt entry: not permanent, not `self`, so the bridge picked it up
    /// from traffic.
    pub(crate) fn learned(ifindex: u32, master: u32, mac: Mac) -> FdbEntry {
        FdbEntry {
            ifindex,
            master: Some(master),
            mac,
            state: 0x02, // NUD_REACHABLE
            flags: 0,
        }
    }

    /// nic1 and nic2 in vmbr1, a vnet bridge IOT stacked on vmbr1.44 with a
    /// container on it, and an unrelated vmbr0 carrying a VM tap.
    pub(crate) fn host(bridge_mac: [u8; 6]) -> crate::sysfs::Topology {
        Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .master("vmbr1")
            .vfs(1)
            .add("nic2", 3, Some(mac(2)))
            .master("vmbr1")
            .add("vmbr1", 10, Some(bridge_mac))
            .bridge()
            .lower("nic1")
            .lower("nic2")
            .add("vmbr1.44", 11, Some(bridge_mac))
            .master("IOT")
            .lower("vmbr1")
            .add("IOT", 12, Some(bridge_mac))
            .bridge()
            .lower("vmbr1.44")
            .lower("veth0")
            .add("veth0", 13, Some(mac(0x13)))
            .master("IOT")
            .add("vmbr0", 20, Some(mac(0xaa)))
            .bridge()
            .lower("nic0")
            .lower("tap0")
            .add("nic0", 21, Some(mac(0xaa)))
            .master("vmbr0")
            .vfs(1)
            .add("tap0", 22, Some(mac(0xa0)))
            .master("vmbr0")
            .build()
    }

    pub(crate) fn fdb() -> Vec<FdbEntry> {
        vec![
            learned(2, 10, WIRE),          // on the uplink itself
            learned(3, 10, BEHIND_NIC),    // on the bridge's other NIC
            learned(13, 12, BEHIND_GUEST), // on the vnet's container port
            learned(11, 12, UPLINK_WARD),  // on the vnet's way back to vmbr1
            learned(22, 20, OTHER_BRIDGE), // on an unrelated bridge
            learned(3, 10, MCAST),         // multicast is not a destination to register
            learned(3, 10, VF_ADMIN),      // our own VF, seen from the other side
            FdbEntry {
                ifindex: 3,
                master: Some(10),
                mac: mac(2),
                state: 0x80, // NUD_PERMANENT - the port's own address
                flags: 0,
            },
        ]
    }

    pub(crate) fn syncer() -> Syncer {
        Syncer::new(Vec::new(), PathBuf::from("/nonexistent"))
    }

    pub(crate) fn pair() -> Pair {
        Pair {
            dev: "nic1".into(),
            bridge: "vmbr1".into(),
        }
    }

    #[test]
    fn registers_what_is_behind_the_bridge_and_nothing_else() {
        let topo = host(mac(1));
        let (want, stacked) = syncer().desired(&topo, &pair(), "nic1", &fdb(), &[(2, VF_ADMIN)]);

        assert!(want.contains(&BEHIND_NIC), "the bridge's other NIC");
        assert!(
            want.contains(&BEHIND_GUEST),
            "a container behind a stacked vnet"
        );

        assert!(!want.contains(&WIRE), "peers on the wire must stay out");
        assert!(
            !want.contains(&UPLINK_WARD),
            "entries pointing back at the uplink"
        );
        assert!(
            !want.contains(&OTHER_BRIDGE),
            "a bridge that is not stacked on this one is none of our business"
        );
        assert!(!want.contains(&MCAST), "multicast");
        assert!(!want.contains(&VF_ADMIN), "our own VF");
        assert!(
            !want.contains(&mac(2)),
            "a port's own address is not learnt"
        );
        assert!(!want.contains(&mac(1)), "the uplink's own address");

        assert_eq!(stacked, vec!["IOT".to_string()]);
    }

    /// The host's own address on the bridge is normally the uplink's, and then
    /// the internal switch knows it anyway. When it differs it has to be
    /// registered, or the VF cannot reach the host at all. Checked on a plain
    /// bridge with nothing stacked on it, so only the bridge's own address can
    /// account for the result.
    #[test]
    fn a_bridge_with_its_own_address_gets_registered() {
        let plain = |bridge_mac: [u8; 6]| {
            Builder::new()
                .add("nic1", 2, Some(mac(1)))
                .master("br0")
                .vfs(1)
                .add("nic2", 3, Some(mac(2)))
                .master("br0")
                .add("br0", 10, Some(bridge_mac))
                .bridge()
                .lower("nic1")
                .lower("nic2")
                .build()
        };
        let p = Pair {
            dev: "nic1".into(),
            bridge: "br0".into(),
        };

        let odd = mac(0x99);
        let (want, stacked) = syncer().desired(&plain(odd), &p, "nic1", &[], &[]);
        assert!(
            want.contains(&odd),
            "a bridge address that is not the uplink's must be registered"
        );
        assert!(stacked.is_empty(), "nothing is stacked on this one");

        let (want, _) = syncer().desired(&plain(mac(1)), &p, "nic1", &[], &[]);
        assert!(
            !want.contains(&mac(1)),
            "when it is the uplink's address there is nothing to do"
        );
    }

    /// The same for interfaces stacked on the bridge - a VLAN interface the
    /// host routes from is reachable only through the bridge.
    #[test]
    fn stacked_interfaces_of_the_host_get_registered_too() {
        let vlan_mac = mac(0x77);
        let topo = Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .master("br0")
            .vfs(1)
            .add("br0", 10, Some(mac(1)))
            .bridge()
            .lower("nic1")
            .add("br0.44", 11, Some(vlan_mac))
            .lower("br0")
            .build();
        let p = Pair {
            dev: "nic1".into(),
            bridge: "br0".into(),
        };
        let (want, _) = syncer().desired(&topo, &p, "nic1", &[], &[]);
        assert!(want.contains(&vlan_mac));
    }

    #[test]
    fn excluded_addresses_stay_out() {
        let topo = host(mac(1));
        let mut s = syncer();
        s.exclude.insert(BEHIND_GUEST);
        let (want, _) = s.desired(&topo, &pair(), "nic1", &fdb(), &[]);
        assert!(!want.contains(&BEHIND_GUEST));
        assert!(want.contains(&BEHIND_NIC));
    }

    /// With a bond in between, the wire side is the whole bond: entries learnt
    /// on it belong out there, and every member's address is the host's own.
    #[test]
    fn a_bond_counts_as_the_wire_side_in_full() {
        let topo = Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .master("bond0")
            .vfs(1)
            .add("nic1b", 3, Some(mac(2)))
            .master("bond0")
            .add("bond0", 4, Some(mac(1)))
            .master("br0")
            .lower("nic1")
            .lower("nic1b")
            .add("br0", 10, Some(mac(1)))
            .bridge()
            .lower("bond0")
            .lower("tap0")
            .add("tap0", 5, Some(mac(5)))
            .master("br0")
            .build();
        let entries = vec![
            learned(4, 10, WIRE),       // arrived over the bond
            learned(5, 10, BEHIND_NIC), // a local guest
            learned(5, 10, mac(2)),     // a bond member's address, oddly placed
        ];
        let p = Pair {
            dev: "nic1".into(),
            bridge: "br0".into(),
        };
        let (want, _) = syncer().desired(&topo, &p, "bond0", &entries, &[]);
        assert!(want.contains(&BEHIND_NIC));
        assert!(
            !want.contains(&WIRE),
            "learnt on the bond, so it is on the wire"
        );
        assert!(
            !want.contains(&mac(2)),
            "a bond member's address is the host's own"
        );
    }
}

#[cfg(test)]
mod extra_tests {
    use super::tests::*;
    use super::*;
    use crate::sysfs::fixture::mac;

    #[test]
    fn pinned_addresses_are_registered_without_being_learnt() {
        let unheard: Mac = [0xaa, 0, 0, 0, 0, 0x42];
        let topo = host(mac(1));
        let mut s = syncer();
        s.extra.insert(unheard);
        let (want, _) = s.desired(&topo, &pair(), "nic1", &fdb(), &[]);
        assert!(
            want.contains(&unheard),
            "nothing has ever been heard from it"
        );
    }

    /// Pinning must not become a way to break the wire.
    #[test]
    fn pinning_cannot_override_the_wire_side() {
        let topo = host(mac(1));
        let mut s = syncer();
        s.extra.insert(WIRE);
        s.extra.insert(mac(1));
        let (want, _) = s.desired(&topo, &pair(), "nic1", &fdb(), &[]);
        assert!(!want.contains(&WIRE), "it lives out on the wire");
        assert!(!want.contains(&mac(1)), "it is the uplink's own address");
    }
}
