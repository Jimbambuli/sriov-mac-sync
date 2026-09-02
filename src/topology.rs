//! The interface topology: which interface leads where.
//!
//! Built from one rtnetlink link dump plus a few `/sys` reads for what the
//! dump deliberately leaves out. The `/sys`-only reader further down is
//! test scaffolding - an independent second opinion the suite holds this
//! against - not the production path, which is why the file is named for
//! what it produces rather than where it once read it.
//!
//! Everything here is about answering two structural questions without ever
//! looking at an interface's name: which way is the wire, and which way is the
//! rest of the host. Naming conventions differ between distributions and
//! guessing from them is how a tool like this breaks on somebody else's
//! machine.

use crate::hash::{Map, Set};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(test)]
use crate::netlink::parse_mac;

const NET: &str = "/sys/class/net";

/// Interfaces that carry a `lower_<parent>` link in sysfs because they are
/// stacked on that parent. A veth also reports a peer over netlink, and a
/// tunnel reports its underlay - neither is stacking, and treating them as
/// such would send the uplink search off in the wrong direction.
const STACKED_ON_PARENT: &[&str] = &[
    "vlan", "macvlan", "macvtap", "ipvlan", "ipvtap", "macsec", "vxlan",
];

/// One interface, with its relations held as interface indices rather than
/// names. The kernel identifies interfaces by index in every message the
/// daemon reads, the walks below follow these relations constantly, and a
/// name is a heap allocation that has to be hashed character by character
/// every time it is looked up. The name is kept for one purpose: saying
/// which interface is meant in a message a person will read.
#[derive(Debug, Clone, Default)]
pub struct Link {
    pub name: String,
    pub index: u32,
    pub mac: Option<[u8; 6]>,
    /// what this interface is enslaved to - a bridge, a bond, a team
    pub master: Option<u32>,
    /// what is enslaved to, or stacked under, this interface
    pub lowers: Vec<u32>,
    /// The interface whose unicast filter this one really writes into: a
    /// VLAN interface has none of its own, the kernel hands a `self` entry
    /// down to its parent. Only VLAN, measured; a VXLAN is a tunnel and its
    /// guests never appear on the underlay, and for macvlan and the rest it
    /// is unknown - naming the wrong carrier is worse than naming none.
    pub filter_below: Option<u32>,
    pub is_bridge: bool,
    /// How long this bridge takes to forget a silent address, in
    /// milliseconds - and so how long ago an address it has just aged out
    /// last spoke. Only bridges have one; from the same dump everything
    /// else here comes from.
    pub ageing_ms: Option<u64>,
    pub numvfs: u32,
    pub driver: Option<String>,
    /// the PF, when this interface is a virtual function. On a card where one
    /// PCI function backs several ports, `physfn/net` lists a netdev per port
    /// and this is the lowest-numbered of them - readdir order is not
    /// promised, and this is a key elsewhere; `pf_netdevs` holds them all.
    pub physfn: Option<u32>,
    /// every PF netdev of this virtual function's PCI function - more than one
    /// when a multiport card shares a single function across its ports, where
    /// each port's netdev reports only its own port's VF addresses. The
    /// exclusion set must take them all in, or a sibling VF on the other port
    /// goes unexcluded and its address is registered past the guest holding it.
    pub pf_netdevs: Vec<u32>,
    /// netdevs of this interface's VFs, as far as they are bound on the host
    pub vf_netdevs: Vec<u32>,
    /// what has this interface as a lower - the inverse of `lowers`, worked
    /// out once when the topology is built. Without it, "which interfaces sit
    /// on top of this bridge" is answered by asking every interface on the
    /// host whether it leads to the bridge, which walks the same edges once
    /// per interface instead of once.
    pub uppers: Vec<u32>,
    /// what is enslaved to this interface - the inverse of `master`
    pub slaves: Vec<u32>,
}

/// See `Topology::anatomy`.
#[derive(Debug, Clone, PartialEq)]
pub struct Anatomy {
    pub dev: u32,
    pub bridge: u32,
    pub port: u32,
    pub card: u32,
    pub functions: Vec<u32>,
}

#[derive(Debug, Default)]
pub struct Topology {
    pub links: Map<u32, Link>,
    by_name: Map<String, u32>,
    /// The bridges in name order, worked out once when the topology is
    /// built: `bridges()` is asked once per pair per pass, and collecting
    /// and sorting the same answer that often bought nothing.
    bridge_order: Vec<u32>,
}

/// What an interface's relations look like in /sys before they are resolved:
/// names, which is all that is there until every interface has been seen.
#[cfg(test)]
#[derive(Default)]
struct Names {
    master: Option<String>,
    lowers: Vec<String>,
    pf_netdevs: Vec<String>,
    vf_netdevs: Vec<String>,
}

fn read_trim(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn link_target_name(path: impl AsRef<Path>) -> Option<String> {
    fs::read_link(path)
        .ok()
        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
}

impl Topology {
    /// The same picture, walked out of `/sys/class/net`.
    ///
    /// Not used in anger any more - `from_links` reads the kernel directly,
    /// which on a host with hundreds of interfaces is the difference between
    /// 11.5 ms and one request. It is kept because it is an independent
    /// second opinion, and a test holds the two to each other on whatever
    /// host it runs on: two ways of describing the same thing drift apart
    /// silently otherwise.
    #[cfg(test)]
    pub fn load() -> std::io::Result<Self> {
        // Relations come out of /sys as names - a symlink's target, a
        // lower_* entry - and are turned into indices once every interface
        // has been seen. Anything naming an interface that is not there any
        // more is dropped: it went while this was being read, and the next
        // reading is the one that will have it right.
        let mut named: Vec<(Link, Names)> = Vec::new();
        for entry in fs::read_dir(NET)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let base = entry.path();

            let index = match read_trim(base.join("ifindex")).and_then(|s| s.parse().ok()) {
                Some(i) => i,
                None => continue,
            };
            // Whether there is a PCI device behind this interface decides four
            // of the reads below. Veth, VLAN and bridge interfaces have none -
            // on a host carrying containers they are the large majority - and
            // asking each of them for a driver, a VF count, a physical function
            // and a VF list is four failed lookups apiece. One look answers all
            // four.
            let dev = base.join("device");
            let has_dev = dev.is_dir();

            let mut names = Names {
                master: link_target_name(base.join("master")),
                ..Default::default()
            };
            let link = Link {
                name: name.clone(),
                index,
                mac: read_trim(base.join("address"))
                    .as_deref()
                    .and_then(parse_mac),
                is_bridge: base.join("bridge").is_dir(),
                driver: if has_dev {
                    link_target_name(dev.join("driver"))
                } else {
                    None
                },
                numvfs: if has_dev {
                    read_trim(dev.join("sriov_numvfs"))
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0)
                } else {
                    0
                },
                ..Default::default()
            };

            if let Ok(rd) = fs::read_dir(&base) {
                for e in rd.flatten() {
                    // A Cow: nothing is allocated for the ~40 entries that do
                    // not start with lower_, which is nearly all of them.
                    let f = e.file_name();
                    let f = f.to_string_lossy();
                    if let Some(rest) = f.strip_prefix("lower_") {
                        names.lowers.push(rest.to_string());
                    }
                }
            }

            // A virtual function points back at its physical function; take the
            // PF's netdev name, not the PCI address.
            if has_dev {
                // read_dir on a missing directory fails by itself; asking
                // twice was one syscall per interface for nothing.
                if let Ok(rd) = fs::read_dir(dev.join("physfn/net")) {
                    for e in rd.flatten() {
                        names
                            .pf_netdevs
                            .push(e.file_name().to_string_lossy().into_owned());
                    }
                }
            }

            // A PCI device directory holds fifty-odd entries; walking it on
            // an interface that has no virtual functions finds nothing, fifty
            // times, on every reading.
            if link.numvfs > 0 {
                if let Ok(rd) = fs::read_dir(&dev) {
                    for e in rd.flatten() {
                        let f = e.file_name();
                        if !f.to_string_lossy().starts_with("virtfn") {
                            continue;
                        }
                        if let Ok(nets) = fs::read_dir(e.path().join("net")) {
                            for n in nets.flatten() {
                                names
                                    .vf_netdevs
                                    .push(n.file_name().to_string_lossy().into_owned());
                            }
                        }
                    }
                }
            }

            named.push((link, names));
        }

        let by_name: Map<String, u32> = named
            .iter()
            .map(|(l, _)| (l.name.clone(), l.index))
            .collect();
        let mut links: Vec<Link> = Vec::with_capacity(named.len());
        for (mut link, names) in named {
            let idx = |n: &String| by_name.get(n).copied();
            link.master = names.master.as_ref().and_then(idx);
            link.lowers = names.lowers.iter().filter_map(idx).collect();
            link.pf_netdevs = names.pf_netdevs.iter().filter_map(idx).collect();
            link.pf_netdevs.sort_unstable();
            link.physfn = link.pf_netdevs.first().copied();
            link.vf_netdevs = names.vf_netdevs.iter().filter_map(idx).collect();
            links.push(link);
        }
        // The name index is already built; handing it over rather than
        // building a second one is the difference between one pass over the
        // names and two.
        Ok(Topology::assemble(links, by_name))
    }

    /// The same picture, from one netlink dump instead of a walk over
    /// `/sys/class/net`.
    ///
    /// The walk is six or more file operations per interface, and on a host
    /// with hundreds of them that is the whole cost of having a topology at
    /// all - measured at 11.5 ms of a 11.7 ms load for 406 interfaces. The
    /// dump is one request. What it does not carry is the SR-IOV relations:
    /// the physical function behind a VF, and the netdevs of a PF's VFs.
    /// Those come from /sys, for the interfaces that have a bus device behind
    /// them and no others - two or three on a normal host.
    pub fn from_links(links: Vec<crate::netlink::LinkInfo>) -> Self {
        // Whether the kernel names bus devices for us at all. It has done
        // since 5.13; where it does not, the presence of the directory has to
        // be asked for one interface at a time.
        let names_parents = links.iter().any(|l| l.parent_dev.is_some());

        // ... but only where an interface could have one. The kernel gives a
        // kind to interfaces it creates itself - bridge, vlan, veth, bond,
        // tun - and a driver bound to a bus device does not. So an interface
        // with a kind has no device directory to find, and asking is one
        // statx that always fails. On a host full of containers that is
        // nearly every interface: 409 of them here, 3.2 ms of a 23 ms pass.
        // The dump cannot say which interfaces have virtual functions - that
        // count is only sent when the request asks for the functions
        // themselves, which is the expensive thing this avoids - so the kind
        // is the whole of the test. An interface handing out virtual
        // functions is a driver bound to a bus device and has no kind.
        let could_have_device = |l: &crate::netlink::LinkInfo| l.kind.is_none();

        let mut by_name: Map<String, u32> =
            Map::with_capacity_and_hasher(links.len(), Default::default());
        for l in &links {
            by_name.insert(l.name.clone(), l.index);
        }
        let mut out: Vec<Link> = Vec::with_capacity(links.len());
        for l in links {
            let probed = if names_parents {
                l.parent_dev.is_some()
            } else {
                could_have_device(&l) && Path::new(NET).join(&l.name).join("device").is_dir()
            };
            // Built only for interfaces with a device behind them: on the
            // 406-interface measuring host this was ~400 allocations per
            // reading spent on veths that never touch it, and the reading
            // sits on the batch path. The empty PathBuf does not allocate.
            let base = if probed {
                Path::new(NET).join(&l.name)
            } else {
                PathBuf::new()
            };
            // The dump and the reads below are two moments, and a rename in
            // between - udev renames NICs at boot, which is when this daemon
            // starts - makes <name> another interface's directory. Its VF
            // count, driver and functions would then become THIS uplink's
            // exclusions, which is the wrong set in the dangerous direction.
            // One file says whether the directory still answers for this
            // interface; on any disagreement the device-backed extras are
            // skipped for this pass, and the next pass reads afresh.
            let has_device = probed
                && read_trim(base.join("ifindex")).and_then(|s| s.parse::<u32>().ok())
                    == Some(l.index);

            // sysfs carries a lower_<name> link for what an interface is
            // built on. Two relations produce those: a port's master, seen
            // from the master's side, and the parent a stacked interface sits
            // on. A veth's peer and a tunnel's underlay are neither, which is
            // why the kind has to be consulted before believing IFLA_LINK.
            let lowers = match (l.kind.as_deref(), l.link) {
                (Some(k), Some(parent)) if STACKED_ON_PARENT.contains(&k) => vec![parent],
                _ => Vec::new(),
            };

            let filter_below = match (l.kind.as_deref(), l.link) {
                (Some("vlan"), Some(parent)) => Some(parent),
                _ => None,
            };
            let mut link = Link {
                name: l.name,
                index: l.index,
                mac: l.mac,
                master: l.master,
                lowers,
                filter_below,
                is_bridge: l.kind.as_deref() == Some("bridge"),
                // clock_t is USER_HZ hundredths of a second on every
                // architecture this runs on: 30000 is the default 300 s.
                ageing_ms: l.ageing.map(|c| c as u64 * 10),
                // Not from the dump. IFLA_NUM_VF is only sent when the
                // request carries RTEXT_FILTER_VF, which this one does not -
                // that flag makes every driver with virtual functions answer
                // out of its firmware, and avoiding it is why the dump is
                // cheap. Reading one file for the interfaces that have a
                // device behind them costs nothing by comparison, and the
                // count is load-bearing: the autodetection looks for
                // interfaces that hand out virtual functions, and the
                // exclusions need the netdevs of those functions.
                numvfs: if has_device {
                    read_trim(base.join("device/sriov_numvfs"))
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0)
                } else {
                    0
                },
                driver: if has_device {
                    link_target_name(base.join("device/driver"))
                } else {
                    None
                },
                ..Default::default()
            };

            if has_device {
                if let Ok(rd) = fs::read_dir(base.join("device/physfn/net")) {
                    for e in rd.flatten() {
                        if let Some(i) = e.file_name().to_str().and_then(|n| by_name.get(n)) {
                            link.pf_netdevs.push(*i);
                        }
                    }
                    link.pf_netdevs.sort_unstable();
                    link.physfn = link.pf_netdevs.first().copied();
                }
                if link.numvfs > 0 {
                    if let Ok(rd) = fs::read_dir(base.join("device")) {
                        for e in rd.flatten() {
                            if !e.file_name().to_string_lossy().starts_with("virtfn") {
                                continue;
                            }
                            if let Ok(nets) = fs::read_dir(e.path().join("net")) {
                                for n in nets.flatten() {
                                    if let Some(i) =
                                        n.file_name().to_str().and_then(|n| by_name.get(n))
                                    {
                                        link.vf_netdevs.push(*i);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            out.push(link);
        }
        // A master relation is a lower relation seen from the other side, and
        // assemble() derives the inverse edges anyway - but `lowers` has to
        // hold both kinds, because that is what sysfs puts there and what
        // every walk in here expects.
        let mut ports: Vec<(u32, u32)> = Vec::new();
        for l in &out {
            if let Some(m) = l.master {
                ports.push((m, l.index));
            }
        }
        let mut at: Map<u32, usize> = Map::with_capacity_and_hasher(out.len(), Default::default());
        for (i, l) in out.iter().enumerate() {
            at.insert(l.index, i);
        }
        for (master, port) in ports {
            if let Some(i) = at.get(&master) {
                out[*i].lowers.push(port);
            }
        }
        Self::assemble(out, by_name)
    }

    /// Build a topology from links whose relations are already indices, and
    /// work out the inverse relations. Both the reading of /sys and the test
    /// fixtures come through here, so neither can end up with a view of the
    /// host the other does not have.
    pub(crate) fn assemble(links: Vec<Link>, by_name: Map<String, u32>) -> Self {
        // Collected while the links are still a list: reading them out of the
        // map afterwards is a second walk over every one of them, and on a
        // host with hundreds of interfaces that showed up in the measurement.
        let mut edges: Vec<(u32, u32, bool)> = Vec::with_capacity(links.len() * 2);
        for l in &links {
            for low in &l.lowers {
                edges.push((*low, l.index, true));
            }
            if let Some(m) = l.master {
                edges.push((m, l.index, false));
            }
        }
        let mut map: Map<u32, Link> =
            Map::with_capacity_and_hasher(links.len(), Default::default());
        for l in links {
            map.insert(l.index, l);
        }
        for (of, other, is_upper) in edges {
            if let Some(l) = map.get_mut(&of) {
                if is_upper {
                    l.uppers.push(other);
                } else {
                    l.slaves.push(other);
                }
            }
        }
        let mut bridge_order: Vec<(String, u32)> = map
            .values()
            .filter(|l| l.is_bridge)
            .map(|l| (l.name.clone(), l.index))
            .collect();
        bridge_order.sort();
        Topology {
            links: map,
            by_name,
            bridge_order: bridge_order.into_iter().map(|(_, i)| i).collect(),
        }
    }

    /// One flood over one kind of edge, roots included - the shape both
    /// directions share.
    fn flood(&self, roots: &[u32], next: impl Fn(&Link) -> &[u32]) -> Set<u32> {
        let mut seen: Set<u32> = crate::hash::set();
        let mut stack: Vec<u32> = roots.to_vec();
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur) {
                continue;
            }
            let Some(link) = self.at(cur) else { continue };
            stack.extend(next(link).iter().copied());
        }
        seen
    }

    /// Everything stacked on top of `root`, `root` itself included: VLAN
    /// interfaces over a bridge, bridges over those, and so on. One walk up
    /// the inverse of the `lowers` edges.
    pub fn stacked_above(&self, root: u32) -> Set<u32> {
        self.flood(&[root], |l| &l.uppers)
    }

    /// By name. For the few places that start from one - a --pair, a bridge
    /// out of the configuration file, a report to a person.
    pub fn get(&self, name: &str) -> Option<&Link> {
        self.by_name.get(name).and_then(|i| self.links.get(i))
    }

    /// By index, which is how everything the kernel says identifies an
    /// interface, and how every walk in here travels.
    pub fn at(&self, index: u32) -> Option<&Link> {
        self.links.get(&index)
    }

    pub fn index_of(&self, name: &str) -> Option<u32> {
        self.by_name.get(name).copied()
    }

    pub fn name_of(&self, index: u32) -> Option<&str> {
        self.links.get(&index).map(|l| l.name.as_str())
    }

    pub fn is_bridge(&self, index: u32) -> bool {
        self.at(index).map(|l| l.is_bridge).unwrap_or(false)
    }

    pub fn bridges(&self) -> Vec<&Link> {
        self.bridge_order
            .iter()
            .filter_map(|i| self.links.get(i))
            .collect()
    }

    /// Does `dev` sit on top of `target`, directly or through any number of
    /// layers? True for a VLAN interface over a bridge, for a bridge built on
    /// such a VLAN interface, and so on.
    pub fn leads_to(&self, dev: u32, target: u32) -> bool {
        if dev == target {
            return true;
        }
        let mut seen: Set<u32> = crate::hash::set();
        let mut stack: Vec<u32> = vec![dev];
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur) {
                continue;
            }
            let Some(link) = self.at(cur) else { continue };
            for low in &link.lowers {
                if *low == target {
                    return true;
                }
                stack.push(*low);
            }
        }
        false
    }

    /// Everything at or below `roots`, the walk `leads_to` does turned the
    /// other way up. One walk down from the bridge answers for every
    /// interface at once, where asking each interface whether it leads to the
    /// bridge walks the same edges once per interface.
    pub fn subtree_of(&self, roots: &[u32]) -> Set<u32> {
        self.flood(roots, |l| &l.lowers)
    }

    /// The interface whose unicast filter an uplink really writes into -
    /// down the VLAN stack to the first interface that holds one.
    pub fn filter_carrier(&self, dev: u32) -> u32 {
        let mut seen = crate::hash::set();
        let mut cur = dev;
        while seen.insert(cur) {
            match self.at(cur).and_then(|l| l.filter_below) {
                Some(parent) => cur = parent,
                None => break,
            }
        }
        cur
    }

    /// The physical functions behind an interface - the PFs whose VF
    /// addresses must never be registered through it (invariant 2).
    /// A VF names its function's netdevs; a PF is its own; a bond has none
    /// itself but every member's, because the kernel spreads its entries
    /// over all of them. Empty means: no card behind this at all.
    pub fn physical_functions(&self, dev: u32) -> Vec<u32> {
        let mut out: Vec<u32> = Vec::new();
        let mut seen = crate::hash::set();
        let mut stack = vec![dev];
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur) {
                continue;
            }
            let Some(l) = self.at(cur) else { continue };
            if !l.pf_netdevs.is_empty() {
                out.extend(l.pf_netdevs.iter().copied());
            } else if l.numvfs > 0 {
                out.push(cur);
            } else {
                stack.extend(l.slaves.iter().copied());
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// What a pair is made of. One answer to the four questions every
    /// invariant used to ask separately, computed once per pass:
    /// `port` is where the wire comes in (invariant 1), `functions` are
    /// the cards whose VF addresses stay out (invariant 2), `card` holds
    /// the filter the capacity is measured on.
    pub fn anatomy(&self, dev: u32, bridge: u32) -> Option<Anatomy> {
        let port = self.uplink_port(dev, bridge)?;
        let card = self.filter_carrier(dev);
        Some(Anatomy {
            dev,
            bridge,
            port,
            card,
            functions: self.physical_functions(card),
        })
    }

    /// Follow the master chain upwards - through bonds, teams, whatever -
    /// until a bridge is reached. Returns the bridge and the interface that is
    /// actually enslaved to it, which is what the bridge's tables refer to.
    pub fn bridge_above(&self, dev: u32) -> Option<(u32, u32)> {
        // A seen-set, like every other walk here: a hop budget also stops a
        // cycle, but it silently gives up on a legitimate stack that is
        // merely deep.
        let mut seen = crate::hash::set();
        let mut cur = dev;
        loop {
            if !seen.insert(cur) {
                return None; // a masters-cycle; nothing above is a bridge
            }
            let master = self.at(cur)?.master?;
            if self.is_bridge(master) {
                return Some((master, cur));
            }
            cur = master;
        }
    }

    /// The interface of `bridge` under which `dev` sits; `dev` itself when it
    /// is enslaved directly. `None` when the master chain does not reach that
    /// bridge at all. It used to fall back to `dev` in that case, and the
    /// fallback was a hole in invariant 1: a pass working with a detached
    /// device as the port classifies nothing as wire - `e.ifindex == port`
    /// never matches - and registers the cable's own peers into the filter.
    /// A bond-member flap or an `ifreload -a` opens exactly that window.
    pub fn uplink_port(&self, dev: u32, bridge: u32) -> Option<u32> {
        match self.bridge_above(dev) {
            Some((br, port)) if br == bridge => Some(port),
            _ => None,
        }
    }

    /// Every address at or below `dev`. For a bond port that is the bond's own
    /// address plus every member's - all of them face the wire.
    pub fn subtree_macs(&self, dev: u32) -> Vec<[u8; 6]> {
        self.subtree_of(&[dev])
            .iter()
            .filter_map(|i| self.at(*i).and_then(|l| l.mac))
            .collect()
    }

    /// Whether an interface can be an uplink at all: a card of its own, or a
    /// VLAN interface with a card somewhere below. A bond is neither - its
    /// members are the candidates, the bond is only their port - and so
    /// nothing else stacked or enslaved is.
    fn could_be_uplink(&self, link: &Link) -> bool {
        if link.numvfs > 0 || !link.pf_netdevs.is_empty() {
            return true;
        }
        link.filter_below.is_some()
            && !self
                .physical_functions(self.filter_carrier(link.index))
                .is_empty()
    }

    /// The pairs this host wants: every interface that could be an uplink
    /// and ends up in a bridge, one pair per (functions, bridge). Two vports
    /// of one eSwitch must not both claim a bridge's addresses - a VF and its
    /// PF, or two sister VFs - and which of them is the port is arbitrary,
    /// so the first in name order wins and the rest are reported.
    pub fn autodetect(&self) -> (Vec<(String, String)>, Vec<String>) {
        let mut pairs: Vec<(String, String)> = Vec::new();
        let mut taken: Vec<(Vec<u32>, u32, String)> = Vec::new(); // functions, bridge, by
        let mut skipped = Vec::new();
        let mut sorted: Vec<&Link> = self.links.values().collect();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        for link in sorted {
            if !self.could_be_uplink(link) {
                continue;
            }
            let Some((br, port)) = self.bridge_above(link.index) else {
                if link.numvfs > 0 {
                    skipped.push(format!(
                        "skip {}: {} VF(s) but does not end up in a bridge",
                        link.name, link.numvfs
                    ));
                }
                continue;
            };
            let Some(anat) = self.anatomy(link.index, br) else {
                continue;
            };
            let br_name = self.name_of(br).unwrap_or_default().to_string();
            // A PF that itself carries this bridge, on any of its ports: the
            // bridge's addresses already have a vport, and a VF taking it
            // too would claim them twice on one eSwitch.
            if let Some(pf) = anat
                .functions
                .iter()
                .find(|&&pf| pf != link.index && self.bridge_above(pf).map(|(b, _)| b) == Some(br))
            {
                skipped.push(format!(
                    "skip {}: {} already carries {br_name}",
                    link.name,
                    self.name_of(*pf).unwrap_or_default()
                ));
                continue;
            }
            if let Some((_, _, by)) = taken
                .iter()
                .find(|(f, b, _)| *b == br && f.iter().any(|x| anat.functions.contains(x)))
            {
                skipped.push(format!(
                    "skip {}: {by} of the same function already carries {br_name} - two \
                     vports of one eSwitch cannot both claim the same addresses",
                    link.name
                ));
                continue;
            }
            if port != link.index {
                skipped.push(format!(
                    "{} reaches {br_name} through {}",
                    link.name,
                    self.name_of(port).unwrap_or_default()
                ));
            }
            taken.push((anat.functions.clone(), br, link.name.clone()));
            pairs.push((link.name.clone(), br_name));
        }
        (pairs, skipped)
    }
}

/// Building topologies by hand, so the logic above can be tested without a
/// machine that happens to have the right hardware in it.
#[cfg(test)]
pub(crate) mod fixture {
    use super::{Link, Topology};
    use crate::hash::Map;

    pub fn mac(last: u8) -> [u8; 6] {
        [0x00, 0x11, 0x22, 0x33, 0x44, last]
    }

    /// Builds a topology the way `load()` does: names while it is being
    /// described, indices once it is built. A fixture that resolved its own
    /// relations would be a second implementation of the thing under test.
    pub struct Builder {
        links: Vec<Link>,
        names: Vec<Names>,
    }

    #[derive(Default)]
    struct Names {
        master: Option<String>,
        lowers: Vec<String>,
        physfn: Option<String>,
        pf_netdevs: Vec<String>,
        vf_netdevs: Vec<String>,
        filter_below: Option<String>,
    }

    impl Builder {
        pub fn new() -> Self {
            Builder {
                links: Vec::new(),
                names: Vec::new(),
            }
        }

        pub fn add(mut self, name: &str, index: u32, mac: Option<[u8; 6]>) -> Self {
            self.links.push(Link {
                name: name.to_string(),
                index,
                mac,
                ..Default::default()
            });
            self.names.push(Names::default());
            self
        }

        fn last(&mut self) -> &mut Link {
            self.links.last_mut().expect("add a link first")
        }

        fn last_names(&mut self) -> &mut Names {
            self.names.last_mut().expect("add a link first")
        }

        pub fn bridge(mut self) -> Self {
            self.last().is_bridge = true;
            // The kernel default, five minutes, unless a test says else -
            // a bridge without one is a bridge whose kernel did not say,
            // which is a different state and has its own setter.
            self.last().ageing_ms = Some(300_000);
            self
        }

        /// How long this bridge takes to forget, in milliseconds. `None`
        /// is the kernel that did not say.
        pub fn ageing(mut self, ms: Option<u64>) -> Self {
            self.last().ageing_ms = ms;
            self
        }

        pub fn master(mut self, m: &str) -> Self {
            self.last_names().master = Some(m.to_string());
            self
        }

        pub fn lower(mut self, l: &str) -> Self {
            self.last_names().lowers.push(l.to_string());
            self
        }

        /// A VLAN interface on `parent`: stacked, and writing into the
        /// filter below - unlike a tunnel, whose guests never reach it.
        pub fn vlan_on(mut self, parent: &str) -> Self {
            self.last_names().lowers.push(parent.to_string());
            self.last_names().filter_below = Some(parent.to_string());
            self
        }

        pub fn vfs(mut self, n: u32) -> Self {
            self.last().numvfs = n;
            self
        }

        pub fn physfn(mut self, pf: &str) -> Self {
            self.last_names().physfn = Some(pf.to_string());
            self
        }

        /// Every PF netdev of a virtual function's PCI function, for the
        /// multiport-shared-function case where `physfn/net` lists more than
        /// one. Resolved the way production does: sorted by index, with
        /// `physfn` the lowest - build() takes care of both.
        pub fn pf_netdevs(mut self, pfs: &[&str]) -> Self {
            self.last_names().pf_netdevs = pfs.iter().map(|p| p.to_string()).collect();
            self
        }

        /// A virtual function's netdev still bound on the host, hanging
        /// off this PF - the `virtfn*/net` reading.
        pub fn vf_netdev(mut self, vf: &str) -> Self {
            self.last_names().vf_netdevs.push(vf.to_string());
            self
        }

        pub fn build(self) -> Topology {
            let by_name: Map<String, u32> = self
                .links
                .iter()
                .map(|l| (l.name.clone(), l.index))
                .collect();
            let idx = |n: &String| by_name.get(n).copied();
            let links: Vec<Link> = self
                .links
                .into_iter()
                .zip(self.names)
                .map(|(mut l, n)| {
                    l.master = n.master.as_ref().and_then(idx);
                    l.lowers = n.lowers.iter().filter_map(idx).collect();
                    l.filter_below = n.filter_below.as_ref().and_then(idx);
                    // A VF described with only `physfn` has that one PF as its
                    // whole function; the multiport case names them explicitly.
                    let pf_names = if n.pf_netdevs.is_empty() {
                        n.physfn.iter().cloned().collect()
                    } else {
                        n.pf_netdevs.clone()
                    };
                    l.pf_netdevs = pf_names.iter().filter_map(idx).collect();
                    // The same resolution production applies: sorted, and
                    // physfn names the lowest-numbered netdev of the
                    // function - a fixture state production cannot produce
                    // is a state not worth testing against.
                    l.pf_netdevs.sort_unstable();
                    if let Some(&first) = l.pf_netdevs.first() {
                        l.physfn = Some(first);
                    }
                    l.vf_netdevs = n.vf_netdevs.iter().filter_map(idx).collect();
                    l
                })
                .collect();
            Topology::assemble(links, by_name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{mac, Builder};
    use crate::note;

    use super::Topology;

    /// The topology answers in indices, because that is what the kernel
    /// talks in. These tests are about interfaces, so they say names and let
    /// these helpers do the looking up.
    fn leads(t: &Topology, dev: &str, target: &str) -> bool {
        let (Some(d), Some(g)) = (t.index_of(dev), t.index_of(target)) else {
            return false;
        };
        t.leads_to(d, g)
    }

    fn above(t: &Topology, dev: &str) -> Option<(String, String)> {
        let (br, port) = t.bridge_above(t.index_of(dev)?)?;
        Some((t.name_of(br)?.to_string(), t.name_of(port)?.to_string()))
    }

    fn port_of(t: &Topology, dev: &str, bridge: &str) -> Option<String> {
        let d = t.index_of(dev).expect("no such device");
        let b = t.index_of(bridge).unwrap_or(0);
        t.uplink_port(d, b)
            .and_then(|p| t.name_of(p))
            .map(str::to_string)
    }

    fn below(t: &Topology, dev: &str) -> Vec<[u8; 6]> {
        t.subtree_macs(t.index_of(dev).expect("no such device"))
    }

    /// A bridge with two NICs, a VLAN interface on top of it and a second
    /// bridge on top of that - the shape a Proxmox SDN host has.
    fn stacked() -> super::Topology {
        Builder::new()
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
            .lower("veth0")
            .add("veth0", 13, Some(mac(0x13)))
            .master("IOT")
            .build()
    }

    #[test]
    fn leads_to_follows_stacking_upwards() {
        let t = stacked();
        assert!(
            leads(&t, "vmbr1.44", "vmbr1"),
            "a VLAN interface on the bridge"
        );
        assert!(leads(&t, "IOT", "vmbr1"), "a bridge on that VLAN interface");
        assert!(leads(&t, "vmbr1", "vmbr1"), "itself");
        assert!(!leads(&t, "nic2", "vmbr1"), "a port is below, not above");
        assert!(!leads(&t, "veth0", "vmbr1"), "a guest port is below too");
    }

    #[test]
    fn a_port_enslaved_directly_is_its_own_uplink() {
        let t = stacked();
        assert_eq!(above(&t, "nic1"), Some(("vmbr1".into(), "nic1".into())));
        assert_eq!(port_of(&t, "nic1", "vmbr1").as_deref(), Some("nic1"));
    }

    #[test]
    fn a_bond_is_followed_to_the_bridge_above_it() {
        let t = Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .master("bond0")
            .vfs(2)
            .add("nic1b", 3, Some(mac(2)))
            .master("bond0")
            .add("bond0", 4, Some(mac(1)))
            .master("br0")
            .lower("nic1")
            .lower("nic1b")
            .add("br0", 10, Some(mac(1)))
            .bridge()
            .lower("bond0")
            .build();
        assert_eq!(above(&t, "nic1"), Some(("br0".into(), "bond0".into())));
        assert_eq!(
            port_of(&t, "nic1", "br0").as_deref(),
            Some("bond0"),
            "the bond is the port"
        );

        // every member faces the wire, so every member's address is the host's
        let mut macs = below(&t, "bond0");
        macs.sort();
        assert_eq!(macs, vec![mac(1), mac(1), mac(2)]);
    }

    #[test]
    fn uplink_port_refuses_a_bridge_the_device_is_not_under() {
        let t = stacked();
        // It used to answer `dev` here, and a pass took that for the wire
        // port - whereupon nothing was wire and the cable's peers were
        // registered. The honest answer is that there is no port.
        assert_eq!(port_of(&t, "nic1", "IOT"), None);
    }

    #[test]
    fn autodetect_wants_vfs_and_a_bridge() {
        let t = Builder::new()
            .add("withvfs", 2, Some(mac(1)))
            .master("br0")
            .vfs(1)
            .add("novfs", 3, Some(mac(2)))
            .master("br0")
            .add("loose", 4, Some(mac(3)))
            .vfs(4)
            .add("br0", 10, Some(mac(1)))
            .bridge()
            .lower("withvfs")
            .lower("novfs")
            .build();
        let (pairs, skipped) = t.autodetect();
        assert_eq!(pairs, vec![("withvfs".to_string(), "br0".to_string())]);
        assert!(
            skipped.iter().any(|s| s.contains("loose")),
            "a NIC with VFs but no bridge is reported, not silently dropped"
        );
    }

    #[test]
    fn autodetect_takes_a_vf_that_carries_the_bridge() {
        let t = Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .vfs(2)
            .add("nic1v0", 3, Some(mac(2)))
            .physfn("nic1")
            .add("nic1v1", 4, Some(mac(3)))
            .physfn("nic1")
            .master("br0")
            .add("br0", 10, Some(mac(3)))
            .bridge()
            .lower("nic1v1")
            .build();
        let (pairs, skipped) = t.autodetect();
        assert_eq!(pairs, vec![("nic1v1".to_string(), "br0".to_string())]);
        assert!(
            !skipped.iter().any(|s| s.contains("nic1v0")),
            "a VF sitting idle belongs to a guest and is not a finding"
        );
        assert!(
            skipped.iter().any(|s| s.contains("skip nic1:")),
            "the PF itself has VFs and no bridge, which is worth saying"
        );
    }

    #[test]
    fn autodetect_leaves_a_vf_alone_when_its_pf_holds_the_bridge() {
        let t = Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .vfs(2)
            .master("br0")
            .add("nic1v0", 3, Some(mac(2)))
            .physfn("nic1")
            .master("br0")
            .add("br0", 10, Some(mac(1)))
            .bridge()
            .lower("nic1")
            .lower("nic1v0")
            .build();
        let (pairs, skipped) = t.autodetect();
        assert_eq!(pairs, vec![("nic1".to_string(), "br0".to_string())]);
        assert!(
            skipped
                .iter()
                .any(|s| s.contains("nic1v0") && s.contains("already carries")),
            "two vports must not claim the same addresses"
        );
    }

    /// The same rule on a card whose four ports share one PCI function, where
    /// `physfn` names an arbitrary one of them. The port holding the bridge
    /// is deliberately the last, so a check that asks only the first is
    /// answered "no conflict" and takes the VF - the failure this guards.
    #[test]
    fn autodetect_asks_every_port_of_a_shared_function() {
        let t = Builder::new()
            .add("pf0", 2, Some(mac(1)))
            .vfs(4)
            .add("pf1", 3, Some(mac(2)))
            .vfs(4)
            .add("pf2", 4, Some(mac(3)))
            .vfs(4)
            .add("pf3", 5, Some(mac(4)))
            .vfs(4)
            .master("br0")
            .add("pf3v0", 6, Some(mac(5)))
            .pf_netdevs(&["pf0", "pf1", "pf2", "pf3"])
            .master("br0")
            .add("br0", 10, Some(mac(4)))
            .bridge()
            .lower("pf3")
            .lower("pf3v0")
            .build();
        let (pairs, skipped) = t.autodetect();
        assert_eq!(
            pairs,
            vec![("pf3".to_string(), "br0".to_string())],
            "the physical function keeps the bridge"
        );
        assert!(
            skipped
                .iter()
                .any(|s| s.contains("pf3v0") && s.contains("already carries")),
            "the VF must be declined: a netdev of its own function - the \
             fourth, not the first - already carries that bridge"
        );
    }

    /// Which interface really holds a filter. A VLAN interface has none of
    /// its own - the kernel keeps its entries on the interface below - while
    /// a bond has one per member and carries its own. Both relations arrive
    /// as `lowers`, so telling them apart is the whole point.
    #[test]
    fn a_vlan_shares_the_filter_below_it_but_a_bond_does_not() {
        let t = Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .vfs(1)
            .add("nic1.100", 20, Some(mac(1)))
            .master("br100")
            .vlan_on("nic1")
            .add("nic1.200", 21, Some(mac(1)))
            .master("br200")
            .vlan_on("nic1")
            .add("br100", 30, Some(mac(1)))
            .bridge()
            .lower("nic1.100")
            .add("br200", 31, Some(mac(1)))
            .bridge()
            .lower("nic1.200")
            .add("nic2", 3, Some(mac(2)))
            .master("bond0")
            .add("bond0", 4, Some(mac(2)))
            .lower("nic2")
            .build();
        let idx = |n: &str| t.index_of(n).unwrap();
        assert_eq!(
            t.filter_carrier(idx("nic1.100")),
            idx("nic1"),
            "a VLAN interface writes into the filter of the interface below"
        );
        assert_eq!(
            t.filter_carrier(idx("nic1.200")),
            idx("nic1"),
            "both VLANs of one function share one filter"
        );
        assert_eq!(
            t.filter_carrier(idx("nic1")),
            idx("nic1"),
            "an unstacked interface carries its own"
        );
        assert_eq!(
            t.filter_carrier(idx("bond0")),
            idx("bond0"),
            "a bond is not stacked on its member: each member has a filter, \
             and the kernel spreads the entries over them"
        );
    }

    /// A virtual function that reaches its bridge through a VLAN interface.
    /// The VLAN interface is what sits in the bridge, so that is the uplink;
    /// without this the host has to be configured by hand and loses the
    /// orphan sweep with it.
    #[test]
    fn autodetect_finds_an_uplink_that_hangs_in_through_a_vlan() {
        let t = Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .vfs(2)
            .add("nic1.100", 20, Some(mac(1)))
            .master("br100")
            .vlan_on("nic1")
            .add("nic1.200", 21, Some(mac(1)))
            .master("br200")
            .vlan_on("nic1")
            .add("br100", 30, Some(mac(1)))
            .bridge()
            .lower("nic1.100")
            .add("br200", 31, Some(mac(1)))
            .bridge()
            .lower("nic1.200")
            .build();
        let (pairs, _) = t.autodetect();
        assert_eq!(
            pairs,
            vec![
                ("nic1.100".to_string(), "br100".to_string()),
                ("nic1.200".to_string(), "br200".to_string())
            ],
            "both VLAN interfaces are uplinks in their own right"
        );
    }

    /// 1a: a tunnel stacked on a VF is not a VLAN. Its guests never reach
    /// the underlay, so it neither shares the VF's filter nor is an uplink.
    #[test]
    fn a_tunnel_over_a_vf_is_neither_carrier_nor_uplink() {
        let t = Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .vfs(1)
            .vf_netdev("nic1v0")
            .add("nic1v0", 3, Some(mac(3)))
            .physfn("nic1")
            .pf_netdevs(&["nic1"])
            .add("vx0", 20, Some(mac(20)))
            .master("br0")
            .lower("nic1v0")
            .add("br0", 30, Some(mac(30)))
            .bridge()
            .lower("vx0")
            .build();
        let idx = |n: &str| t.index_of(n).unwrap();
        assert_eq!(
            t.filter_carrier(idx("vx0")),
            idx("vx0"),
            "a tunnel holds no filter below"
        );
        let (pairs, _) = t.autodetect();
        assert!(pairs.is_empty(), "a tunnel is no uplink, got {pairs:?}");
    }

    /// 1b: the sister rule judges by the card, not by the interface in the
    /// bridge. A VLAN of a VF must decline a bridge its PF already carries -
    /// asked of the VLAN interface, whose netdev list is empty, the rule
    /// let it through.
    #[test]
    fn a_vlan_uplink_declines_a_bridge_its_pf_carries() {
        // The PF sorts AFTER the VLAN interface on purpose: the "already
        // taken" rule must not be what catches this, only the PF rule can.
        let t = Builder::new()
            .add("pf9", 2, Some(mac(1)))
            .master("br0")
            .vfs(1)
            .vf_netdev("pf9v0")
            .add("pf9v0", 3, Some(mac(3)))
            .physfn("pf9")
            .pf_netdevs(&["pf9"])
            .add("pf9v0.7", 20, Some(mac(3)))
            .master("br0")
            .vlan_on("pf9v0")
            .add("br0", 30, Some(mac(30)))
            .bridge()
            .lower("pf9")
            .lower("pf9v0.7")
            .build();
        let (pairs, skipped) = t.autodetect();
        assert_eq!(pairs, vec![("pf9".to_string(), "br0".to_string())]);
        assert!(
            skipped
                .iter()
                .any(|s| s.starts_with("skip pf9v0.7: pf9 already carries")),
            "{skipped:?}"
        );
    }

    /// 1c: a bond has no card of its own but every member's. Named as an
    /// uplink by hand, its exclusion set has to reach the sister VFs of
    /// each member's function - the worst failure direction this program
    /// has ran through the bond, which answered with an empty list.
    #[test]
    fn a_bond_answers_with_its_members_functions() {
        let t = Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .vfs(2)
            .vf_netdev("nic1v0")
            .add("nic2", 4, Some(mac(2)))
            .vfs(2)
            .vf_netdev("nic2v0")
            .add("nic1v0", 3, Some(mac(3)))
            .master("bond0")
            .physfn("nic1")
            .pf_netdevs(&["nic1"])
            .add("nic2v0", 5, Some(mac(5)))
            .master("bond0")
            .physfn("nic2")
            .pf_netdevs(&["nic2"])
            .add("bond0", 10, Some(mac(3)))
            .master("br0")
            .lower("nic1v0")
            .lower("nic2v0")
            .add("br0", 30, Some(mac(30)))
            .bridge()
            .lower("bond0")
            .build();
        let idx = |n: &str| t.index_of(n).unwrap();
        assert_eq!(
            t.physical_functions(idx("bond0")),
            vec![idx("nic1"), idx("nic2")]
        );
        let anat = t.anatomy(idx("bond0"), idx("br0")).unwrap();
        assert_eq!(anat.functions, vec![idx("nic1"), idx("nic2")]);
        assert_eq!(anat.port, idx("bond0"));
    }

    /// 1d: a VLAN on a bond of VFs. The bond is nobody's card, but there are
    /// cards below it, and the VLAN interface is what sits in the bridge.
    #[test]
    fn autodetect_finds_a_vlan_on_a_bond_of_vfs() {
        let t = Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .vfs(2)
            .vf_netdev("nic1v0")
            .add("nic2", 4, Some(mac(2)))
            .vfs(2)
            .vf_netdev("nic2v0")
            .add("nic1v0", 3, Some(mac(3)))
            .master("bond0")
            .physfn("nic1")
            .pf_netdevs(&["nic1"])
            .add("nic2v0", 5, Some(mac(5)))
            .master("bond0")
            .physfn("nic2")
            .pf_netdevs(&["nic2"])
            .add("bond0", 10, Some(mac(3)))
            .lower("nic1v0")
            .lower("nic2v0")
            .add("bond0.100", 11, Some(mac(3)))
            .master("br100")
            .vlan_on("bond0")
            .add("br100", 30, Some(mac(30)))
            .bridge()
            .lower("bond0.100")
            .build();
        let (pairs, _) = t.autodetect();
        assert_eq!(pairs, vec![("bond0.100".to_string(), "br100".to_string())]);
        let idx = |n: &str| t.index_of(n).unwrap();
        let anat = t.anatomy(idx("bond0.100"), idx("br100")).unwrap();
        assert_eq!(
            anat.card,
            idx("bond0"),
            "the filter is the bond's, spread over its members"
        );
        assert_eq!(anat.functions, vec![idx("nic1"), idx("nic2")]);
    }

    /// 1e: a bond straight in the bridge is still carried by its member
    /// VFs, one pair each - the bond itself must not become a third
    /// candidate that outranks them by name.
    #[test]
    fn a_bond_in_a_bridge_is_carried_by_its_members_not_itself() {
        let t = Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .vfs(2)
            .vf_netdev("nic1v0")
            .add("nic2", 4, Some(mac(2)))
            .vfs(2)
            .vf_netdev("nic2v0")
            .add("nic1v0", 3, Some(mac(3)))
            .master("bond0")
            .physfn("nic1")
            .pf_netdevs(&["nic1"])
            .add("nic2v0", 5, Some(mac(5)))
            .master("bond0")
            .physfn("nic2")
            .pf_netdevs(&["nic2"])
            .add("bond0", 10, Some(mac(3)))
            .master("br0")
            .lower("nic1v0")
            .lower("nic2v0")
            .add("br0", 30, Some(mac(30)))
            .bridge()
            .lower("bond0")
            .build();
        let (pairs, _) = t.autodetect();
        assert_eq!(
            pairs,
            vec![
                ("nic1v0".to_string(), "br0".to_string()),
                ("nic2v0".to_string(), "br0".to_string())
            ]
        );
    }

    #[test]
    fn autodetect_reports_the_bond_it_went_through() {
        let t = Builder::new()
            .add("nic1", 2, Some(mac(1)))
            .master("bond0")
            .vfs(1)
            .add("bond0", 4, Some(mac(1)))
            .master("br0")
            .lower("nic1")
            .add("br0", 10, Some(mac(1)))
            .bridge()
            .lower("bond0")
            .build();
        let (pairs, notes) = t.autodetect();
        assert_eq!(pairs, vec![("nic1".to_string(), "br0".to_string())]);
        assert!(notes.iter().any(|s| s.contains("bond0")));
    }

    #[test]
    fn stacking_cycles_do_not_hang() {
        let t = Builder::new()
            .add("a", 1, None)
            .lower("b")
            .add("b", 2, None)
            .lower("a")
            .build();
        assert!(!leads(&t, "a", "zz"));
        assert_eq!(below(&t, "a").len(), 0);
    }

    /// The netlink reading and the sysfs walk have to agree about this host,
    /// whatever host that is. They are two descriptions of one thing, and the
    /// one that is not used every day is the one that would drift.
    ///
    /// The two readings are separate moments, so a host that changes between
    /// them disagrees with itself: this caught `enp7s0` joining a bridge
    /// mid-test, reported it as a defect, and passed on the next run. A
    /// disagreement therefore has to survive being looked at again - a real
    /// difference in how the two are built survives any number of readings,
    /// a host in motion does not.
    ///
    /// Skipped where a netlink socket cannot be opened at all - some build
    /// containers - because there is then nothing to compare against.
    /// The kernel counts the ageing time in clock_t - hundredths of a
    /// second - and everything above works in milliseconds. The factor is
    /// the whole of the conversion, and getting it wrong by ten dates every
    /// deletion thirty seconds or fifty minutes into the past instead of
    /// five minutes. Both harnesses build their bridges at the default,
    /// where the dating provably cannot move a stamp, so nothing else here
    /// would notice.
    /// Of the stacked kinds only a VLAN writes into the filter below it -
    /// a tunnel's guests never reach the underlay. Decided where the kind
    /// is still known: on the way in.
    #[test]
    fn only_a_vlan_shares_the_filter_below_it() {
        let link = |index, name: &str, kind: &str| crate::netlink::LinkInfo {
            index,
            name: name.into(),
            mac: None,
            master: None,
            link: Some(2),
            kind: Some(kind.into()),
            parent_dev: None,
            ageing: None,
        };
        let topo = Topology::from_links(vec![
            crate::netlink::LinkInfo {
                index: 2,
                name: "nic1".into(),
                mac: None,
                master: None,
                link: None,
                kind: None,
                parent_dev: None,
                ageing: None,
            },
            link(20, "nic1.100", "vlan"),
            link(21, "vx0", "vxlan"),
            link(22, "mv0", "macvlan"),
        ]);
        assert_eq!(
            topo.at(20).unwrap().filter_below,
            Some(2),
            "a VLAN shares the filter"
        );
        assert_eq!(topo.at(21).unwrap().filter_below, None, "a tunnel does not");
        assert_eq!(
            topo.at(22).unwrap().filter_below,
            None,
            "macvlan is unmeasured, so no"
        );
        assert_eq!(topo.filter_carrier(20), 2);
        assert_eq!(topo.filter_carrier(21), 21);
    }

    #[test]
    fn the_ageing_time_arrives_in_milliseconds() {
        let topo = Topology::from_links(vec![crate::netlink::LinkInfo {
            index: 10,
            name: "vmbr1".into(),
            mac: None,
            master: None,
            link: None,
            kind: Some("bridge".into()),
            parent_dev: None,
            ageing: Some(30_000),
        }]);
        assert_eq!(
            topo.at(10).and_then(|l| l.ageing_ms),
            Some(300_000),
            "30000 clock_t is five minutes, the kernel's default"
        );
        let none = Topology::from_links(vec![crate::netlink::LinkInfo {
            index: 10,
            name: "vmbr1".into(),
            mac: None,
            master: None,
            link: None,
            kind: Some("bridge".into()),
            parent_dev: None,
            ageing: None,
        }]);
        assert_eq!(none.at(10).and_then(|l| l.ageing_ms), None);
    }

    #[test]
    fn the_kernel_and_the_filesystem_describe_the_same_host() {
        let mut sock = match crate::netlink::Socket::new() {
            Ok(s) => s,
            Err(e) => {
                note!("skipped: no netlink socket here ({e})");
                return;
            }
        };
        let mut differences = Vec::new();
        for attempt in 0..3 {
            differences = match compare_readings(&mut sock) {
                Some(d) => d,
                None => {
                    note!("skipped: the kernel would not list interfaces");
                    return;
                }
            };
            if differences.is_empty() {
                return;
            }
            note!(
                "attempt {}: {} difference(s), reading again in case the host moved",
                attempt + 1,
                differences.len()
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        panic!(
            "the two readings disagree about {} interface(s) on this host, \
             three readings running:\n{}",
            differences.len(),
            differences.join("\n")
        );
    }

    /// One comparison of the two readings; `None` when the kernel would not
    /// answer at all.
    fn compare_readings(sock: &mut crate::netlink::Socket) -> Option<Vec<String>> {
        let links = sock.dump_links().ok()?;
        let from_kernel = super::Topology::from_links(links.clone());
        let from_sysfs = super::Topology::load().expect("/sys/class/net is readable");

        let mut differences = Vec::new();
        for (index, a) in &from_kernel.links {
            // Only what both readings saw: an interface that appeared or went
            // between them is a race, not a disagreement.
            let Some(b) = from_sysfs.links.get(index) else {
                continue;
            };
            let mut al = a.lowers.clone();
            let mut bl = b.lowers.clone();
            al.sort();
            bl.sort();
            let mut av = a.vf_netdevs.clone();
            let mut bv = b.vf_netdevs.clone();
            av.sort();
            bv.sort();
            let ap = a.pf_netdevs.clone();
            let bp = b.pf_netdevs.clone();
            for (what, x, y) in [
                ("name", a.name.clone(), b.name.clone()),
                ("mac", format!("{:?}", a.mac), format!("{:?}", b.mac)),
                (
                    "master",
                    format!("{:?}", a.master),
                    format!("{:?}", b.master),
                ),
                ("lowers", format!("{al:?}"), format!("{bl:?}")),
                (
                    "is_bridge",
                    a.is_bridge.to_string(),
                    b.is_bridge.to_string(),
                ),
                ("numvfs", a.numvfs.to_string(), b.numvfs.to_string()),
                (
                    "driver",
                    format!("{:?}", a.driver),
                    format!("{:?}", b.driver),
                ),
                (
                    "physfn",
                    format!("{:?}", a.physfn),
                    format!("{:?}", b.physfn),
                ),
                ("vf_netdevs", format!("{av:?}"), format!("{bv:?}")),
                ("pf_netdevs", format!("{ap:?}"), format!("{bp:?}")),
            ] {
                if x != y {
                    differences.push(format!("{}: {what}: kernel {x}, sysfs {y}", a.name));
                }
            }
        }
        Some(differences)
    }
}
