//! The interface topology, read out of `/sys/class/net`.
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
    pub is_bridge: bool,
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

            let mut link = Link {
                name: l.name,
                index: l.index,
                mac: l.mac,
                master: l.master,
                lowers,
                is_bridge: l.kind.as_deref() == Some("bridge"),
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

    /// Everything stacked on top of `root`, `root` itself included: VLAN
    /// interfaces over a bridge, bridges over those, and so on. One walk up
    /// the inverse of the `lowers` edges.
    pub fn stacked_above(&self, root: u32) -> Set<u32> {
        let mut seen: Set<u32> = crate::hash::set();
        let mut stack: Vec<u32> = vec![root];
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur) {
                continue;
            }
            let Some(link) = self.at(cur) else { continue };
            stack.extend(link.uppers.iter().copied());
        }
        seen
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
        let mut seen: Set<u32> = crate::hash::set();
        let mut stack: Vec<u32> = roots.to_vec();
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur) {
                continue;
            }
            let Some(link) = self.at(cur) else { continue };
            stack.extend(link.lowers.iter().copied());
        }
        seen
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

    /// Interfaces that carry a bridge over an eSwitch: a NIC with virtual
    /// functions, or a virtual function itself where one stands in for the
    /// physical port. Both have to end up in a bridge, possibly through a
    /// bond - without one there is nothing behind them to be missed.
    pub fn autodetect(&self) -> (Vec<(String, String)>, Vec<String>) {
        let mut pairs: Vec<(String, String)> = Vec::new();
        let mut taken_for: Vec<(u32, u32, String)> = Vec::new(); // pf, bridge, uplink name
        let mut skipped = Vec::new();
        // In name order, so a host with several candidates always chooses the
        // same one rather than whichever the hash table offers first.
        let mut sorted: Vec<&Link> = self.links.values().collect();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        for link in sorted {
            let name = &link.name;
            let has_vfs = link.numvfs > 0;
            if !has_vfs && link.physfn.is_none() {
                continue;
            }
            match self.bridge_above(link.index) {
                Some((br, port)) => {
                    let br_name = self.name_of(br).unwrap_or_default().to_string();
                    // A VF cannot stand in for a port its own PF already
                    // holds: both would claim the same addresses, on two
                    // vports of one eSwitch. The same goes for a sister VF
                    // that was taken for this bridge a moment ago - the rule
                    // is about the eSwitch, not about who is a PF.
                    if let Some(pf) = link.physfn {
                        let pf_name = self.name_of(pf).unwrap_or_default();
                        // Every netdev of this function, not just the first:
                        // a card whose ports share one PCI function shows one
                        // netdev per port, and which of them `physfn` names is
                        // arbitrary. Asking only that one answers about the
                        // right port by luck - one time in two on a dual-port
                        // card, one in four on a quad - and the rest of the
                        // time a VF is taken for a bridge its own port already
                        // holds, which is what this rule exists to prevent.
                        // A sister port carrying the bridge is a different
                        // eSwitch and no conflict in theory; declining there
                        // too costs an autodetection that `--pair` can still
                        // make, and is the answer that cannot be wrong.
                        if let Some(holder) = link
                            .pf_netdevs
                            .iter()
                            .copied()
                            .find(|&p| self.bridge_above(p).map(|(b, _)| b) == Some(br))
                        {
                            let holder_name = self.name_of(holder).unwrap_or_default();
                            skipped.push(format!(
                                "skip {name}: {holder_name} already carries {br_name}"
                            ));
                            continue;
                        }
                        if let Some((_, _, taken)) =
                            taken_for.iter().find(|(p, b, _)| *p == pf && *b == br)
                        {
                            // Into `skipped` like every other declined
                            // candidate: autodetection runs on every pass,
                            // and a direct eprintln here was the same line
                            // thousands of times a day.
                            skipped.push(format!(
                                "skip {name}: {taken} of the same {pf_name} already \
                                 carries {br_name} - two vports of one eSwitch cannot \
                                 both claim the same addresses"
                            ));
                            continue;
                        }
                        taken_for.push((pf, br, name.clone()));
                    }
                    if port != link.index {
                        let port_name = self.name_of(port).unwrap_or_default();
                        skipped.push(format!("{name} reaches {br_name} through {port_name}"));
                    }
                    pairs.push((name.clone(), br_name));
                }
                // A VF outside a bridge is the ordinary case - it belongs to
                // a guest. Only a NIC handing out VFs is worth remarking on.
                None => {
                    if has_vfs {
                        skipped.push(format!(
                            "skip {name}: {} VF(s) but does not end up in a bridge",
                            link.numvfs
                        ));
                    }
                }
            }
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
