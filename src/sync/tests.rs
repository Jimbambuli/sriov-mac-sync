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

/// The kernel, as far as the bookkeeping is concerned: answers with what
/// a test injected and records what would have been written. Shared with
/// main's daemon-loop tests, which is why it lives in this module.
#[derive(Default)]
pub(crate) struct FakeSock {
    pub(crate) fdb: Vec<FdbEntry>,
    pub(crate) vf: Vec<(u32, Mac)>,
    pub(crate) added: Vec<(u32, Mac)>,
    pub(crate) removed: Vec<(u32, Mac)>,
    /// raw OS error to answer an add of this address with
    pub(crate) fail_add: Map<Mac, i32>,
    /// raw OS error to answer a removal of this address with
    pub(crate) fail_del: Map<Mac, i32>,
    /// A second process, writing the same note while the pass is inside
    /// it: on the first successful add, this address is appended to the
    /// note at this path. That is the window the merge exists for, and
    /// there is no other way to be inside it from a test.
    pub(crate) meanwhile: Option<(PathBuf, Mac)>,
    /// What dump_links answers. Only --flush reads the topology through
    /// the socket; an empty answer means every noted device looks gone,
    /// which is one case of many - so a test can now say otherwise.
    pub(crate) links: Vec<crate::netlink::LinkInfo>,
    /// Milliseconds each removal takes. A flush with entries to remove
    /// then stands in its read-unregister-unlink window long enough for
    /// another thread to try the things the lock exists to serialise.
    pub(crate) del_delay_ms: u64,
    /// How often the driver was asked for the functions' addresses -
    /// the most expensive question a pass asks, and exactly the one the
    /// vf_stale machinery exists to avoid asking twice.
    pub(crate) vf_asked: usize,
    /// raw OS error the next vf_macs_of answers with, taken once - the
    /// transient failure the refresh path has to stay distrustful through.
    pub(crate) fail_vf: Option<i32>,
    /// Which indices each vf_macs_of call named - the grow-refresh must
    /// ask only the growing pairs' functions.
    pub(crate) asked: Vec<Vec<u32>>,
    /// Like `meanwhile`, but firing on the first successful removal: the
    /// reflection path stands in an rtnl window too, and a parallel writer
    /// in that window is what its merged write-back exists for.
    pub(crate) meanwhile_del: Option<(PathBuf, Mac)>,
}

impl FdbWriter for FakeSock {
    fn dump_fdb(&mut self) -> io::Result<Vec<FdbEntry>> {
        Ok(self.fdb.clone())
    }
    fn dump_links(&mut self) -> io::Result<Vec<crate::netlink::LinkInfo>> {
        Ok(self.links.clone())
    }
    fn vf_macs_of(&mut self, indices: &[u32]) -> io::Result<Vec<(u32, Mac)>> {
        self.vf_asked += 1;
        self.asked.push(indices.to_vec());
        if let Some(code) = self.fail_vf.take() {
            return Err(io::Error::from_raw_os_error(code));
        }
        // Like the kernel: an interface answers only when it was asked.
        Ok(self
            .vf
            .iter()
            .filter(|(pf, _)| indices.contains(pf))
            .cloned()
            .collect())
    }
    fn set_self_fdb(&mut self, ifindex: u32, mac: &Mac, add: bool) -> io::Result<()> {
        let table = if add { &self.fail_add } else { &self.fail_del };
        if let Some(code) = table.get(mac) {
            return Err(io::Error::from_raw_os_error(*code));
        }
        if add {
            if let Some((path, other)) = self.meanwhile.take() {
                let mut text = fs::read_to_string(&path).unwrap_or_default();
                text.push_str(&format_mac(&other));
                text.push('\n');
                fs::write(&path, text).unwrap();
            }
            self.added.push((ifindex, *mac));
        } else {
            if self.del_delay_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(self.del_delay_ms));
            }
            if let Some((path, other)) = self.meanwhile_del.take() {
                let mut text = fs::read_to_string(&path).unwrap_or_default();
                text.push_str(&format_mac(&other));
                text.push('\n');
                fs::write(&path, text).unwrap();
            }
            self.removed.push((ifindex, *mac));
        }
        Ok(())
    }
}

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

/// `desired` as the tests think about it: by name. The production callers
/// hold indices already, having just looked the pair up.
pub(crate) fn desired_named(
    s: &Syncer,
    topo: &crate::sysfs::Topology,
    pair: &Pair,
    port: &str,
    fdb: &[FdbEntry],
    vf_macs: &[(u32, Mac)],
) -> (Set<Mac>, Vec<String>, Set<Mac>) {
    let dev = topo
        .index_of(&pair.dev)
        .expect("fixture has no such device");
    let bridge = topo.index_of(&pair.bridge).unwrap_or(0);
    let port = topo
        .index_of(port)
        .unwrap_or_else(|| panic!("fixture: no interface named {port}"));
    let (want, stacked, wire, _) = s.desired(topo, bridge, dev, port, fdb, vf_macs);
    (want, stacked, wire)
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
    let (want, stacked, _) =
        desired_named(&syncer(), &topo, &pair(), "nic1", &fdb(), &[(2, VF_ADMIN)]);

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
    let (want, stacked, _) = desired_named(&syncer(), &plain(odd), &p, "nic1", &[], &[]);
    assert!(
        want.contains(&odd),
        "a bridge address that is not the uplink's must be registered"
    );
    assert!(stacked.is_empty(), "nothing is stacked on this one");

    let (want, _, _) = desired_named(&syncer(), &plain(mac(1)), &p, "nic1", &[], &[]);
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
    let (want, _, _) = desired_named(&syncer(), &topo, &p, "nic1", &[], &[]);
    assert!(want.contains(&vlan_mac));
}

#[test]
fn excluded_addresses_stay_out() {
    let topo = host(mac(1));
    let mut s = syncer();
    s.exclude.insert(BEHIND_GUEST);
    let (want, _, _) = desired_named(&s, &topo, &pair(), "nic1", &fdb(), &[]);
    assert!(!want.contains(&BEHIND_GUEST));
    assert!(want.contains(&BEHIND_NIC));
}

/// A dual-port card that shares one PCI function across its ports shows a PF
/// netdev per port, and each reports only its own port's VF addresses. A VF
/// handed to a guest can sit on the other port than the uplink, so its admin
/// address arrives keyed to the other port's PF. It must still be excluded:
/// resolving the uplink to a single PF once left it out, and the daemon then
/// registered the guest's own address and sent its traffic past it. Observed
/// on an mlx4 ConnectX-3 as trial scenario S6.
#[test]
fn a_sibling_vf_on_the_shared_functions_other_port_is_excluded() {
    // pf0 and pf1 are two netdevs of one function; the uplink VF sits on pf0's
    // port and names both as its function. The guest VF's address is reported
    // under pf1 - the port a single-PF resolution of the uplink would miss.
    const SIBLING: Mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x99];
    let topo = Builder::new()
        .add("pf0", 100, Some(mac(0x50)))
        .vfs(2)
        .add("pf1", 101, Some(mac(0x51)))
        .vfs(2)
        .add("pf0v0", 110, Some(mac(0x60)))
        .master("br0")
        .pf_netdevs(&["pf0", "pf1"])
        .add("br0", 120, Some(mac(0xaa)))
        .bridge()
        .lower("pf0v0")
        .lower("tap0")
        .add("tap0", 121, Some(mac(0xa0)))
        .master("br0")
        .build();
    let p = Pair {
        dev: "pf0v0".into(),
        bridge: "br0".into(),
    };
    // Both addresses are learnt behind the bridge on the tap, not on the
    // uplink's own wire side: one is the misplaced guest VF, one a real guest.
    let entries = vec![learned(121, 120, SIBLING), learned(121, 120, BEHIND_GUEST)];
    let (want, _, _) = desired_named(
        &syncer(),
        &topo,
        &p,
        "pf0v0",
        &entries,
        &[(101, SIBLING)], // keyed to pf1, the uplink's other-port PF
    );
    assert!(
        !want.contains(&SIBLING),
        "a sibling VF on the shared function's other port must be excluded"
    );
    assert!(
        want.contains(&BEHIND_GUEST),
        "a genuine local guest is still registered"
    );
}

/// Two ports was the example, not the rule: the same shared function may
/// carry four. The sibling's address is reported under the LAST port here,
/// so anything that asks fewer than all of them lets it through.
#[test]
fn a_sibling_vf_is_excluded_across_all_four_ports_of_a_function() {
    const SIBLING: Mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x77];
    let topo = Builder::new()
        .add("pf0", 100, Some(mac(0x50)))
        .vfs(4)
        .add("pf1", 101, Some(mac(0x51)))
        .vfs(4)
        .add("pf2", 102, Some(mac(0x52)))
        .vfs(4)
        .add("pf3", 103, Some(mac(0x53)))
        .vfs(4)
        .add("pf0v0", 110, Some(mac(0x60)))
        .master("br0")
        .pf_netdevs(&["pf0", "pf1", "pf2", "pf3"])
        .add("br0", 120, Some(mac(0xaa)))
        .bridge()
        .lower("pf0v0")
        .lower("tap0")
        .add("tap0", 121, Some(mac(0xa0)))
        .master("br0")
        .build();
    let p = Pair {
        dev: "pf0v0".into(),
        bridge: "br0".into(),
    };
    let entries = vec![learned(121, 120, SIBLING), learned(121, 120, BEHIND_GUEST)];
    let (want, _, _) = desired_named(
        &syncer(),
        &topo,
        &p,
        "pf0v0",
        &entries,
        &[(103, SIBLING)], // keyed to pf3, the fourth port
    );
    assert!(
        !want.contains(&SIBLING),
        "a sibling on the fourth port of the function must be excluded too"
    );
    assert!(want.contains(&BEHIND_GUEST));
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
    let (want, _, _) = desired_named(&syncer(), &topo, &p, "bond0", &entries, &[]);
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

/// A PF whose numvfs went from 0 to N inside one batch is invisible to the
/// old picture; the old answer must not win over the new one, or the very
/// first VF address set right after enabling SR-IOV slips past the
/// exclusions until the timed refresh.
#[test]
fn a_pf_that_just_grew_vfs_counts_as_vf_relevant() {
    let before = Builder::new().add("nic1", 2, Some(mac(1))).build();
    let after = Builder::new().add("nic1", 2, Some(mac(1))).vfs(4).build();
    assert!(vf_may_have_changed(Some(&before), Some(&after), &[2]));
    // And the reverse: gone from the new picture, known to the old.
    assert!(vf_may_have_changed(Some(&after), Some(&before), &[2]));
    // Neither picture knows the interface: caution.
    assert!(vf_may_have_changed(Some(&before), Some(&before), &[99]));
    // Both know it, neither sees virtual functions: no reason to ask.
    assert!(!vf_may_have_changed(Some(&before), Some(&before), &[2]));
}
