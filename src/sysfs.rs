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
            let mut link = Link {
                name: name.clone(),
                index,
                mac: read_trim(base.join("address")).as_deref().and_then(parse_mac),
                master: link_target_name(base.join("master")),
                is_bridge: base.join("bridge").is_dir(),
                driver: link_target_name(base.join("device/driver")),
                numvfs: read_trim(base.join("device/sriov_numvfs"))
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
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
            let physfn_net = base.join("device/physfn/net");
            if physfn_net.is_dir() {
                if let Ok(rd) = fs::read_dir(&physfn_net) {
                    if let Some(e) = rd.flatten().next() {
                        link.physfn = Some(e.file_name().to_string_lossy().into_owned());
                    }
                }
            }

            if let Ok(rd) = fs::read_dir(base.join("device")) {
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

    /// Interfaces with virtual functions that end up in a bridge, possibly
    /// through a bond. Without a bridge there is nothing behind them that
    /// their VFs could be missing.
    pub fn autodetect(&self) -> (Vec<(String, String)>, Vec<String>) {
        let mut pairs = Vec::new();
        let mut skipped = Vec::new();
        let mut names: Vec<&String> = self.links.keys().collect();
        names.sort();
        for name in names {
            let link = &self.links[name];
            if link.numvfs == 0 {
                continue;
            }
            match self.bridge_above(name) {
                Some((br, port)) => {
                    if &port != name {
                        skipped.push(format!("{name} reaches {br} through {port}"));
                    }
                    pairs.push((name.clone(), br));
                }
                None => skipped.push(format!(
                    "skip {name}: {} VF(s) but does not end up in a bridge",
                    link.numvfs
                )),
            }
        }
        (pairs, skipped)
    }
}
