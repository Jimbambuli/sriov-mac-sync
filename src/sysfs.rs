//! The interface topology, read out of `/sys/class/net`.
//!
//! Everything here is about answering two structural questions without ever
//! looking at an interface's name: which way is the wire, and which way is the
//! rest of the host. Naming conventions differ between distributions and
//! guessing from them is how a tool like this breaks on somebody else's
//! machine.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::netlink::parse_mac;

const NET: &str = "/sys/class/net";

#[derive(Debug, Clone, Default)]
pub struct Link {
    pub name: String,
    pub index: u32,
    pub mac: Option<[u8; 6]>,
    /// what this interface is enslaved to - a bridge, a bond, a team
    pub master: Option<String>,
    /// what is enslaved to, or stacked under, this interface
    pub lowers: Vec<String>,
    pub is_bridge: bool,
    pub numvfs: u32,
    pub driver: Option<String>,
    /// the PF, when this interface is a virtual function
    pub physfn: Option<String>,
    /// netdevs of this interface's VFs, as far as they are bound on the host
    pub vf_netdevs: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Topology {
    pub links: HashMap<String, Link>,
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
    pub fn load() -> std::io::Result<Self> {
        let mut links = HashMap::new();
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

            let mut link = Link {
                name: name.clone(),
                index,
                mac: read_trim(base.join("address"))
                    .as_deref()
                    .and_then(parse_mac),
                master: link_target_name(base.join("master")),
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
                    let f = e.file_name().to_string_lossy().into_owned();
                    if let Some(rest) = f.strip_prefix("lower_") {
                        link.lowers.push(rest.to_string());
                    }
                }
            }

            // A virtual function points back at its physical function; take the
            // PF's netdev name, not the PCI address.
            if has_dev {
                let physfn_net = dev.join("physfn/net");
                if physfn_net.is_dir() {
                    if let Ok(rd) = fs::read_dir(&physfn_net) {
                        if let Some(e) = rd.flatten().next() {
                            link.physfn = Some(e.file_name().to_string_lossy().into_owned());
                        }
                    }
                }
            }

            if let Ok(rd) = fs::read_dir(&dev) {
                for e in rd.flatten() {
                    let f = e.file_name().to_string_lossy().into_owned();
                    if !f.starts_with("virtfn") {
                        continue;
                    }
                    if let Ok(nets) = fs::read_dir(e.path().join("net")) {
                        for n in nets.flatten() {
                            link.vf_netdevs
                                .push(n.file_name().to_string_lossy().into_owned());
                        }
                    }
                }
            }

            links.insert(name, link);
        }
        Ok(Topology { links })
    }

    pub fn get(&self, name: &str) -> Option<&Link> {
        self.links.get(name)
    }

    pub fn name_of(&self, index: u32) -> Option<&str> {
        self.links
            .values()
            .find(|l| l.index == index)
            .map(|l| l.name.as_str())
    }

    pub fn is_bridge(&self, name: &str) -> bool {
        self.get(name).map(|l| l.is_bridge).unwrap_or(false)
    }

    pub fn bridges(&self) -> Vec<&Link> {
        let mut v: Vec<&Link> = self.links.values().filter(|l| l.is_bridge).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Does `dev` sit on top of `target`, directly or through any number of
    /// layers? True for a VLAN interface over a bridge, for a bridge built on
    /// such a VLAN interface, and so on.
    pub fn leads_to(&self, dev: &str, target: &str) -> bool {
        if dev == target {
            return true;
        }
        let mut seen = HashSet::new();
        let mut stack = vec![dev.to_string()];
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur.clone()) {
                continue;
            }
            let Some(link) = self.get(&cur) else { continue };
            for low in &link.lowers {
                if low == target {
                    return true;
                }
                stack.push(low.clone());
            }
        }
        false
    }

    /// Follow the master chain upwards - through bonds, teams, whatever -
    /// until a bridge is reached. Returns the bridge and the interface that is
    /// actually enslaved to it, which is what the bridge's tables refer to.
    pub fn bridge_above(&self, dev: &str) -> Option<(String, String)> {
        let mut cur = dev.to_string();
        let mut hops = 0;
        while hops < 16 {
            hops += 1;
            let master = self.get(&cur)?.master.clone()?;
            if self.is_bridge(&master) {
                return Some((master, cur));
            }
            cur = master;
        }
        None
    }

    /// The interface of `bridge` under which `dev` sits; `dev` itself when it
    /// is enslaved directly.
    pub fn uplink_port(&self, dev: &str, bridge: &str) -> String {
        match self.bridge_above(dev) {
            Some((br, port)) if br == bridge => port,
            _ => dev.to_string(),
        }
    }

    /// Every address at or below `dev`. For a bond port that is the bond's own
    /// address plus every member's - all of them face the wire.
    pub fn subtree_macs(&self, dev: &str) -> Vec<[u8; 6]> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut stack = vec![dev.to_string()];
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur.clone()) {
                continue;
            }
            let Some(link) = self.get(&cur) else { continue };
            if let Some(mac) = link.mac {
                out.push(mac);
            }
            for low in &link.lowers {
                stack.push(low.clone());
            }
        }
        out
    }

    /// Interfaces that carry a bridge over an eSwitch: a NIC with virtual
    /// functions, or a virtual function itself where one stands in for the
    /// physical port. Both have to end up in a bridge, possibly through a
    /// bond - without one there is nothing behind them to be missed.
    pub fn autodetect(&self) -> (Vec<(String, String)>, Vec<String>) {
        let mut pairs = Vec::new();
        let mut skipped = Vec::new();
        let mut names: Vec<&String> = self.links.keys().collect();
        names.sort();
        for name in names {
            let link = &self.links[name];
            let has_vfs = link.numvfs > 0;
            if !has_vfs && link.physfn.is_none() {
                continue;
            }
            match self.bridge_above(name) {
                Some((br, port)) => {
                    // A VF cannot stand in for a port its own PF already
                    // holds: both would claim the same addresses, on two
                    // vports of one eSwitch.
                    if let Some(pf) = &link.physfn {
                        if self.bridge_above(pf).map(|(b, _)| b).as_deref() == Some(&br) {
                            skipped.push(format!("skip {name}: {pf} already carries {br}"));
                            continue;
                        }
                    }
                    if &port != name {
                        skipped.push(format!("{name} reaches {br} through {port}"));
                    }
                    pairs.push((name.clone(), br));
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
    use std::collections::HashMap;

    pub fn mac(last: u8) -> [u8; 6] {
        [0x00, 0x11, 0x22, 0x33, 0x44, last]
    }

    pub struct Builder {
        links: Vec<Link>,
    }

    impl Builder {
        pub fn new() -> Self {
            Builder { links: Vec::new() }
        }

        pub fn add(mut self, name: &str, index: u32, mac: Option<[u8; 6]>) -> Self {
            self.links.push(Link {
                name: name.to_string(),
                index,
                mac,
                ..Default::default()
            });
            self
        }

        fn last(&mut self) -> &mut Link {
            self.links.last_mut().expect("add a link first")
        }

        pub fn bridge(mut self) -> Self {
            self.last().is_bridge = true;
            self
        }

        pub fn master(mut self, m: &str) -> Self {
            self.last().master = Some(m.to_string());
            self
        }

        pub fn lower(mut self, l: &str) -> Self {
            self.last().lowers.push(l.to_string());
            self
        }

        pub fn vfs(mut self, n: u32) -> Self {
            self.last().numvfs = n;
            self
        }

        pub fn physfn(mut self, pf: &str) -> Self {
            self.last().physfn = Some(pf.to_string());
            self
        }

        pub fn build(self) -> Topology {
            let mut links = HashMap::new();
            for l in self.links {
                links.insert(l.name.clone(), l);
            }
            Topology { links }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{mac, Builder};

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
            t.leads_to("vmbr1.44", "vmbr1"),
            "a VLAN interface on the bridge"
        );
        assert!(
            t.leads_to("IOT", "vmbr1"),
            "a bridge on that VLAN interface"
        );
        assert!(t.leads_to("vmbr1", "vmbr1"), "itself");
        assert!(!t.leads_to("nic2", "vmbr1"), "a port is below, not above");
        assert!(!t.leads_to("veth0", "vmbr1"), "a guest port is below too");
    }

    #[test]
    fn a_port_enslaved_directly_is_its_own_uplink() {
        let t = stacked();
        assert_eq!(
            t.bridge_above("nic1"),
            Some(("vmbr1".into(), "nic1".into()))
        );
        assert_eq!(t.uplink_port("nic1", "vmbr1"), "nic1");
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
        assert_eq!(t.bridge_above("nic1"), Some(("br0".into(), "bond0".into())));
        assert_eq!(
            t.uplink_port("nic1", "br0"),
            "bond0",
            "the bond is the port"
        );

        // every member faces the wire, so every member's address is the host's
        let mut macs = t.subtree_macs("bond0");
        macs.sort();
        assert_eq!(macs, vec![mac(1), mac(1), mac(2)]);
    }

    #[test]
    fn uplink_port_falls_back_when_the_bridge_does_not_match() {
        let t = stacked();
        assert_eq!(t.uplink_port("nic1", "IOT"), "nic1");
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

    /// The kernel reports a VLAN's parent, a VXLAN's underlay and a veth's
    /// *peer* through the same-looking attributes. Only the first two are
    /// stacking; treating a peer as one would send the uplink search sideways.
    #[test]
    fn netlink_tells_parents_from_peers() {
        use crate::netlink::LinkInfo;
        let l = |index, name: &str, kind: Option<&str>, link, master| LinkInfo {
            index,
            name: name.to_string(),
            kind: kind.map(|k| k.to_string()),
            link,
            master,
            ..Default::default()
        };
        let t = super::Topology::from_netlink(&[
            l(1, "br0", Some("bridge"), None, None),
            l(2, "eth0", None, None, Some(1)),
            l(3, "br0.42", Some("vlan"), Some(1), None),
            l(4, "veth-a", Some("veth"), Some(5), Some(1)),
            l(5, "veth-b", Some("veth"), Some(4), None),
            l(6, "vx0", Some("vxlan"), Some(1), None),
        ]);
        assert_eq!(t.get("br0").unwrap().lowers, vec!["eth0", "veth-a"]);
        assert_eq!(
            t.get("br0.42").unwrap().lowers,
            vec!["br0"],
            "a VLAN parent"
        );
        assert_eq!(
            t.get("vx0").unwrap().lowers,
            vec!["br0"],
            "a VXLAN underlay"
        );
        assert!(
            t.get("veth-a").unwrap().lowers.is_empty(),
            "a veth peer is not something the interface is built on"
        );
        assert!(t.get("br0").unwrap().is_bridge);
        assert!(t.leads_to("br0.42", "br0"));
        assert!(
            !t.leads_to("veth-b", "br0"),
            "the peer must not lead anywhere"
        );
    }

    #[test]
    fn stacking_cycles_do_not_hang() {
        let t = Builder::new()
            .add("a", 1, None)
            .lower("b")
            .add("b", 2, None)
            .lower("a")
            .build();
        assert!(!t.leads_to("a", "zz"));
        assert_eq!(t.subtree_macs("a").len(), 0);
    }
}

/// Interfaces that carry a `lower_<parent>` link in sysfs because they are
/// stacked on that parent. A veth also reports a peer over netlink, and a tunnel
/// reports its underlay - neither is stacking, and treating them as such would
/// send the uplink search off in the wrong direction.
const STACKED_ON_PARENT: &[&str] = &["vlan", "macvlan", "macvtap", "ipvlan", "vxlan"];

impl Topology {
    /// The same picture, built from one netlink dump instead of a walk over
    /// `/sys/class/net`. Only the SR-IOV relationships still come from sysfs -
    /// the kernel does not describe them over netlink - and those are read only
    /// for interfaces that actually have a device behind them.
    pub fn from_netlink(links: &[crate::netlink::LinkInfo]) -> Self {
        use std::collections::HashMap as Map;
        let name_of: Map<u32, &str> = links.iter().map(|l| (l.index, l.name.as_str())).collect();

        let mut ports: Map<u32, Vec<String>> = Map::new();
        for l in links {
            if let Some(m) = l.master {
                ports.entry(m).or_default().push(l.name.clone());
            }
        }

        let mut out = HashMap::new();
        for l in links {
            let base = Path::new(NET).join(&l.name);
            let has_device = base.join("device").exists();

            let mut lowers = ports.remove(&l.index).unwrap_or_default();
            if STACKED_ON_PARENT.contains(&l.kind.as_deref().unwrap_or("")) {
                if let Some(parent) = l.link.and_then(|i| name_of.get(&i)) {
                    lowers.push((*parent).to_string());
                }
            }
            lowers.sort();

            let mut link = Link {
                name: l.name.clone(),
                index: l.index,
                mac: l.mac,
                master: l
                    .master
                    .and_then(|i| name_of.get(&i))
                    .map(|s| s.to_string()),
                lowers,
                is_bridge: l.kind.as_deref() == Some("bridge"),
                numvfs: l.vf_macs.len() as u32,
                driver: if has_device {
                    link_target_name(base.join("device/driver"))
                } else {
                    None
                },
                ..Default::default()
            };

            if has_device {
                let physfn_net = base.join("device/physfn/net");
                if let Ok(rd) = fs::read_dir(&physfn_net) {
                    if let Some(e) = rd.flatten().next() {
                        link.physfn = Some(e.file_name().to_string_lossy().into_owned());
                    }
                }
                if link.numvfs > 0 {
                    if let Ok(rd) = fs::read_dir(base.join("device")) {
                        for e in rd.flatten() {
                            if !e.file_name().to_string_lossy().starts_with("virtfn") {
                                continue;
                            }
                            if let Ok(nets) = fs::read_dir(e.path().join("net")) {
                                for n in nets.flatten() {
                                    link.vf_netdevs
                                        .push(n.file_name().to_string_lossy().into_owned());
                                }
                            }
                        }
                    }
                }
            }
            out.insert(l.name.clone(), link);
        }
        Topology { links: out }
    }

    /// Field-by-field differences against another picture of the same host.
    /// Used to prove the netlink path agrees with the sysfs one before anything
    /// depends on it.
    pub fn differences(&self, other: &Topology) -> Vec<String> {
        let mut d = Vec::new();
        let mut names: Vec<&String> = self.links.keys().chain(other.links.keys()).collect();
        names.sort();
        names.dedup();
        for n in names {
            match (self.links.get(n), other.links.get(n)) {
                (Some(a), Some(b)) => {
                    let mut al = a.lowers.clone();
                    let mut bl = b.lowers.clone();
                    al.sort();
                    bl.sort();
                    let mut av = a.vf_netdevs.clone();
                    let mut bv = b.vf_netdevs.clone();
                    av.sort();
                    bv.sort();
                    for (field, x, y) in [
                        ("index", a.index.to_string(), b.index.to_string()),
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
                    ] {
                        if x != y {
                            d.push(format!("{n}.{field}: sysfs {x} vs netlink {y}"));
                        }
                    }
                }
                (Some(_), None) => d.push(format!("{n}: only in sysfs")),
                (None, Some(_)) => d.push(format!("{n}: only in netlink")),
                (None, None) => {}
            }
        }
        d
    }
}
