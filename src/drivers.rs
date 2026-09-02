//! What the kernel's drivers do with an interface's unicast list, read from
//! the driver sources (Linux 7.3-rc2, read 2.9.2026; docs/driver-limits.md
//! has the evidence per row).
//!
//! `bridge fdb add <mac> dev X self` puts an address into the kernel's list
//! for X. The kernel accepts any number; what the card then holds is the
//! driver's business, and the list read back from the kernel cannot tell.
//! This table is the one source, beside the operator's --max.

/// What happens to addresses past the number the card holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Past {
    /// dropped, silently or with a kernel log line - the failure this daemon
    /// exists to keep operators from
    Drops,
    /// the interface goes unicast-promiscuous: traffic still flows, the
    /// filter is moot
    Promisc,
    /// a hash filter takes over: accepted, imperfectly
    Hashes,
    /// the driver never programs the list on this role at all - every entry
    /// this daemon adds is a no-op there
    Ignored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Filter {
    /// entries the card holds for one interface, as the driver counts them,
    /// where the source names a number; `None` where firmware decides
    pub holds: Option<usize>,
    pub past: Past,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Any,
    Pf,
    Vf,
}

use Past::*;
use Role::*;

/// Driver name as `/sys/class/net/X/device/driver` spells it. Numbers are
/// the conservative end where a table is shared or model-dependent.
const TABLE: &[(&str, Role, Option<usize>, Past)] = &[
    // Intel
    ("igb", Pf, Some(16), Promisc), // RAR table, 16 on the smallest models
    ("igbvf", Vf, Some(3), Drops),  // IGBVF_MAX_MAC_FILTERS, silent past it
    ("ixgbe", Pf, Some(128), Promisc), // 128 RARs shared with the VFs
    ("ixgbevf", Vf, Some(96), Drops), // pool of 112 - num_vfs for all VFs
    ("i40e", Pf, None, Promisc),    // firmware table
    ("iavf", Vf, Some(12), Drops),  // 18 filters incl. own, bcast, mcast (untrusted)
    ("ice", Pf, None, Drops),       // the "forcing promisc" log line does not
    ("idpf", Any, None, Drops),
    ("fm10k", Pf, None, Drops),
    ("fm10k", Vf, None, Ignored), // MAC-locked by the PF
    // Mellanox
    ("mlx5_core", Any, Some(128), Drops), // 1 << log_max_current_uc_list, 128 on every ConnectX seen
    ("mlx4_core", Any, Some(128), Promisc), // one MAC table per port, PF and VFs
    // Broadcom
    ("bnxt_en", Pf, Some(4), Promisc), // BNXT_MAX_UC_ADDRS
    ("bnxt_en", Vf, Some(4), Drops),   // promisc vetoed for an untrusted VF
    ("bnx2x", Pf, None, Promisc),      // CAM credit pool
    ("bnx2x", Vf, None, Ignored),
    // QLogic
    ("qede", Pf, None, Promisc),
    ("qede", Vf, None, Ignored), // one MAC per VF; promisc only when trusted
    ("qlcnic", Pf, None, Promisc),
    ("qlcnic", Vf, Some(2), Drops),
    // Chelsio
    ("cxgb4", Any, None, Hashes),
    ("cxgb4vf", Any, None, Hashes),
    // Emulex
    ("be2net", Pf, Some(30), Promisc), // BE_UC_PMAC_COUNT
    ("be2net", Vf, Some(2), Drops),
    // Solarflare
    ("sfc", Pf, Some(32), Promisc), // EFX_EF10_FILTER_DEV_UC_MAX
    ("sfc", Vf, Some(32), Drops),
    ("sfc_ef100", Any, None, Promisc), // promiscuous from the first entry
    ("sfc_siena", Any, None, Promisc),
    // Netronome
    ("nfp", Any, None, Promisc), // promiscuous from the first entry
    // Marvell / Cavium
    ("rvu_nicpf", Pf, Some(4), Promisc), // devlink unicast_filter_count
    ("rvu_nicvf", Vf, None, Ignored),    // untrusted VF
    ("octeon_ep", Any, None, Ignored),
    ("octeon_ep_vf", Any, None, Ignored),
    ("LiquidIO", Pf, None, Promisc),
    ("LiquidIO_VF", Vf, Some(32), Drops),
    ("nicvf", Any, None, Promisc), // ThunderX: promiscuous for the whole LMAC
    // HiSilicon / Huawei
    ("hns3", Pf, None, Promisc),
    ("hns3", Vf, None, Drops), // untrusted VF
    ("hinic", Pf, None, Promisc),
    ("hinic", Vf, None, Drops),
    ("hinic3", Any, None, Promisc),
    // Cloud and others
    ("ena", Any, None, Ignored),
    ("alibaba_eea", Any, None, Ignored),
    ("ionic", Any, None, Promisc), // max_ucast_filters, shared with multicast
    ("enic", Any, Some(32), Promisc),
    ("fsl_enetc", Pf, None, Hashes),
    ("fsl_enetc_vf", Vf, None, Ignored),
    ("funeth", Any, None, Ignored),
    ("mana", Any, None, Ignored),
    ("ngbe", Pf, Some(32), Promisc), // RARs shared with the VFs
    ("txgbe", Pf, Some(128), Promisc),
    ("ngbevf", Vf, None, Ignored), // list reaches the PF only at open
    ("txgbevf", Vf, None, Ignored),
];

/// What the driver named in sysfs does with the list of an interface that is
/// (`vf`) or is not a virtual function. `None` for a driver this table does
/// not know.
pub fn filter_of(driver: &str, vf: bool) -> Option<Filter> {
    TABLE
        .iter()
        .find(|(name, role, _, _)| {
            *name == driver && matches!((role, vf), (Any, _) | (Pf, false) | (Vf, true))
        })
        .map(|(_, _, holds, past)| Filter {
            holds: *holds,
            past: *past,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_role_tells_a_pf_from_a_vf_of_the_same_driver() {
        assert_eq!(filter_of("bnxt_en", false).unwrap().past, Promisc);
        assert_eq!(filter_of("bnxt_en", true).unwrap().past, Drops);
        assert_eq!(filter_of("mlx5_core", true), filter_of("mlx5_core", false));
        assert!(filter_of("virtio_net", false).is_none());
        assert_eq!(
            filter_of("ixgbevf", false),
            None,
            "a VF driver has no PF role"
        );
    }

    /// One row per (driver, role), every number usable as a limit, and the
    /// roles a driver can serve are spelled once: a PF/VF pair or Any, never
    /// both.
    #[test]
    fn the_table_is_well_formed() {
        for (i, (name, role, holds, past)) in TABLE.iter().enumerate() {
            if let Some(n) = holds {
                assert!(*n >= 1 && *n <= 1 << 20, "{name}: {n}");
                assert_ne!(*past, Ignored, "{name}: ignored lists hold nothing");
            }
            for (other, orole, _, _) in &TABLE[i + 1..] {
                if other == name {
                    assert_ne!(role, orole, "{name}: two rows for one role");
                    assert!(
                        *role != Any && *orole != Any,
                        "{name}: Any beside a role-specific row"
                    );
                }
            }
        }
    }
}
