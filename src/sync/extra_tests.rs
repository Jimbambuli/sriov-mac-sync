use super::tests::*;
use super::*;
use crate::sysfs::fixture::mac;

#[test]
fn pinned_addresses_are_registered_without_being_learnt() {
    let unheard: Mac = [0xaa, 0, 0, 0, 0, 0x42];
    let topo = host(mac(1));
    let mut s = syncer();
    s.extra.insert(unheard);
    let (want, _, _) = desired_named(&s, &topo, &pair(), "nic1", &fdb(), &[]);
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
    let (want, _, _) = desired_named(&s, &topo, &pair(), "nic1", &fdb(), &[]);
    assert!(!want.contains(&WIRE), "it lives out on the wire");
    assert!(!want.contains(&mac(1)), "it is the uplink's own address");
}
