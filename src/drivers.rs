//! What the kernel's drivers do with an interface's unicast list, read from
//! the driver sources (Linux 7.3-rc2, read 2.9.2026; docs/driver-limits.md
//! has the evidence per row).
//!
//! `bridge fdb add <mac> dev X self` puts an address into the kernel's list
//! for X. The kernel accepts any number; what the card then holds is the
//! driver's business, and the list read back from the kernel cannot tell.
//! This table is the one source, beside the operator's --max.
//!
//! For a virtual function the PF has a say: several drivers hold a
//! different number, or go promiscuous rather than drop, once the PF trusts
//! the function (`ip link set PF vf N trust on`), and some refuse every
//! address on a function whose address the PF set without trusting it. The
//! daemon reads trust off the PF's VF list (IFLA_VF_TRUST) for the drivers
//! where it matters, judges an unknown trust as none, and says what a
//! PF-set address would mean - that one it cannot read.

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
    /// the interface has no unicast filter at all: the kernel makes it
    /// promiscuous at the first entry - traffic flows, every entry is moot
    PromiscFromFirst,
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
    /// a virtual function the PF does not trust - or whose trust is
    /// unknown, which is read the same way
    Vf,
    /// a virtual function with `ip link set PF vf N trust on`, where the
    /// driver then does something else; only beside a `Vf` row
    TrustedVf,
}

/// VF drivers whose PF refuses every address beyond the one it set, for a
/// function it does not trust: a VF with an administratively set address
/// and trust off has no unicast list at all, whatever the row says. Whether
/// the PF set the address cannot be read - IFLA_VF_MAC shows the function's
/// own address the same way - so this only shapes the message.
const LOCKED_UNTRUSTED: &[&str] = &["igbvf", "ixgbevf", "iavf", "bnxt_en", "hinic"];

use Past::*;
use Role::*;

/// Driver name as `/sys/class/net/X/device/driver` spells it. The number
/// is the list size as the driver counts it, the interface's own address
/// included where the driver includes it - the headroom pays for that. Where
/// a table is shared or model-dependent it is the conservative end that a
/// common host reaches (ixgbevf: the pool of 112 minus 16 VFs; iavf: 18
/// filters less its own address, broadcast and a few multicast groups).
const TABLE: &[(&str, Role, Option<usize>, Past)] = &[
    // Intel
    ("igb", Pf, Some(16), Promisc), // RAR table, 16 on the smallest models
    ("igbvf", Vf, Some(3), Drops),  // IGBVF_MAX_MAC_FILTERS, silent past it
    ("ixgbe", Pf, Some(128), Promisc), // 128 RARs shared with the VFs
    ("ixgbevf", Vf, Some(96), Drops), // pool of 112 - num_vfs for all VFs
    ("i40e", Pf, None, Promisc),    // firmware table
    ("iavf", Vf, Some(12), Drops),  // 18 filters incl. own, bcast, mcast (untrusted)
    ("iavf", TrustedVf, None, Drops), // (3072/ports - 18*vfs)/vfs + 18 on i40e; firmware on ice
    ("ice", Pf, None, Drops),       // the "forcing promisc" log line does not
    ("idpf", Any, None, Drops),
    ("fm10k", Pf, None, Drops),
    ("fm10k", Vf, None, Ignored), // MAC-locked by the PF
    // Mellanox
    ("mlx5_core", Any, Some(128), Drops), // 1 << log_max_current_uc_list, 128 on every ConnectX seen
    ("mlx4_core", Any, Some(128), Promisc), // one MAC table per port, PF and VFs
    // Broadcom
    ("bnxt_en", Pf, Some(4), Promisc),        // BNXT_MAX_UC_ADDRS
    ("bnxt_en", Vf, Some(4), Drops),          // promisc vetoed for an untrusted VF
    ("bnxt_en", TrustedVf, Some(4), Promisc), // the veto lifted
    ("bnx2x", Pf, None, Promisc),             // CAM credit pool
    ("bnx2x", Vf, None, Ignored),
    // QLogic
    ("qede", Pf, None, Promisc),
    ("qede", Vf, None, Ignored), // one MAC per VF; promisc only when trusted
    ("qede", TrustedVf, None, PromiscFromFirst), // any second address makes the vport promiscuous
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
    ("sfc_ef100", Any, None, PromiscFromFirst),
    ("sfc_siena", Any, None, PromiscFromFirst),
    // Netronome
    ("nfp", Any, None, PromiscFromFirst),
    // Marvell / Cavium
    ("rvu_nicpf", Pf, Some(4), Promisc), // devlink unicast_filter_count
    ("rvu_nicvf", Vf, None, Ignored),    // untrusted VF
    ("rvu_nicvf", TrustedVf, None, PromiscFromFirst), // on silicon with nix_rx_multicast
    ("octeon_ep", Any, None, Ignored),
    ("octeon_ep_vf", Any, None, Ignored),
    ("LiquidIO", Pf, None, PromiscFromFirst),
    ("LiquidIO_VF", Vf, Some(32), Drops),
    ("nicvf", Any, None, PromiscFromFirst), // ThunderX: the whole LMAC, every VF on it
    // HiSilicon / Huawei
    ("hns3", Pf, None, Promisc),
    ("hns3", Vf, None, Drops),          // untrusted VF
    ("hns3", TrustedVf, None, Promisc), // the PF's promisc fallback, for a trusted VF
    ("hinic", Pf, None, PromiscFromFirst),
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
/// (`vf`) or is not a virtual function, and for a VF whether the PF trusts
/// it - unknown trust reads as no trust, the conservative row. `None` for a
/// driver this table does not know.
pub fn filter_of(driver: &str, vf: bool, trusted: bool) -> Option<Filter> {
    let row = |wanted: Role| {
        TABLE
            .iter()
            .find(|(name, role, _, _)| *name == driver && (*role == Any || *role == wanted))
    };
    let found = match (vf, trusted) {
        (false, _) => row(Pf),
        (true, false) => row(Vf),
        (true, true) => row(TrustedVf).or_else(|| row(Vf)),
    };
    found.map(|(_, _, holds, past)| Filter {
        holds: *holds,
        past: *past,
    })
}

/// Whether the PF's view of a VF - trust, and the address it set - changes
/// what this driver does. Only such cards pay the question.
pub fn trust_matters(driver: &str) -> bool {
    locks_untrusted(driver)
        || TABLE
            .iter()
            .any(|(n, r, _, _)| *n == driver && *r == TrustedVf)
}

/// Whether this VF driver's PF refuses every further address on a function
/// whose address it set without trusting it.
pub fn locks_untrusted(driver: &str) -> bool {
    LOCKED_UNTRUSTED.contains(&driver)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_role_tells_a_pf_from_a_vf_of_the_same_driver() {
        assert_eq!(filter_of("bnxt_en", false, false).unwrap().past, Promisc);
        assert_eq!(filter_of("bnxt_en", true, false).unwrap().past, Drops);
        assert_eq!(
            filter_of("bnxt_en", true, true).unwrap().past,
            Promisc,
            "trust lifts the promisc veto"
        );
        assert_eq!(
            filter_of("mlx5_core", true, false),
            filter_of("mlx5_core", false, false)
        );
        assert_eq!(
            filter_of("ixgbevf", true, true),
            filter_of("ixgbevf", true, false),
            "a driver without a trusted row answers with its VF row"
        );
        assert!(filter_of("virtio_net", false, false).is_none());
        assert_eq!(
            filter_of("ixgbevf", false, false),
            None,
            "a VF driver has no PF role"
        );
        assert!(trust_matters("ixgbevf") && trust_matters("qede") && !trust_matters("mlx5_core"));
        assert!(locks_untrusted("iavf") && !locks_untrusted("mlx4_core"));
    }

    /// One row per (driver, role), every number usable as a limit, and the
    /// roles a driver can serve are spelled once: a PF/VF pair or Any, never
    /// both.
    #[test]
    fn the_table_is_well_formed() {
        for (i, (name, role, holds, past)) in TABLE.iter().enumerate() {
            if let Some(n) = holds {
                assert!(*n >= 1 && *n <= 1 << 20, "{name}: {n}");
                assert!(
                    !matches!(past, Ignored | PromiscFromFirst),
                    "{name}: a list nobody programs, or that is moot, holds no number"
                );
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
            if *role == TrustedVf {
                assert!(
                    TABLE.iter().any(|(n, r, _, _)| n == name && *r == Vf),
                    "{name}: a trusted row refines a VF row that is not there"
                );
            }
        }
        for name in LOCKED_UNTRUSTED {
            assert!(
                TABLE.iter().any(|(n, r, _, _)| n == name && *r == Vf),
                "{name}: locked, but no VF row"
            );
        }
    }
}
