# What the kernel's drivers do with a unicast list

Evidence for the table in `src/drivers.rs`: what each SR-IOV-capable driver
in the Linux tree does when `bridge fdb add <mac> dev X self` puts an address
into the kernel's list for X. Read from the mainline sources (7.3-rc2,
commit 89a3129, 2 September 2026) by five independent reviews of the driver
code; file and function names are given per row so a claim can be checked
against a newer tree. The kernel path is the same everywhere:
`ndo_dflt_fdb_add` -> `dev_uc_add` -> the driver's `ndo_set_rx_mode`. The
kernel accepts any number of entries, and the list read back from it says
nothing about what the card holds - which is why this daemon cannot find the
limit by reading back, and needs this table.

Two facts drive many rows. A netdev without `IFF_UNICAST_FLT` is switched to
promiscuous mode by the kernel itself as soon as its list is non-empty, before
the driver sees anything. And `__hw_addr_sync_dev` stops at the first address
a driver refuses; every driver here ignores that return value.

A third decides the VF rows: what the PF thinks of the function. `ip link set
PF vf N trust on` lifts bnxt's promisc veto, turns qede's and rvu's dropped
promisc request into a working one, opens hns3's promisc fallback and the
i40e/ice formula for iavf; and on the Intel VF drivers, bnxt and hinic a PF
that set the function's address without trusting it refuses every other
address outright. The daemon reads trust and the PF-set address off the PF's
VF list (`IFLA_VF_TRUST`, `IFLA_VF_MAC`) for exactly these drivers - the table
in `src/drivers.rs` carries a `TrustedVf` row where the answer changes, and a
list of the drivers that lock - and treats unknown trust as none.


---

## Intel drivers: unicast filter capacity per netdev and overflow behaviour

Scope: `bridge fdb add <mac> dev <netdev> self permanent` -> `ndo_dflt_fdb_add` -> `dev_uc_add` -> driver `ndo_set_rx_mode`.
Kernel source read: `drivers/net/ethernet/intel/*` (mainline sparse checkout, 2026-09-02).
No Intel driver registers `DEVLINK_PARAM_GENERIC_ID_MAX_MACS` (grep over the whole intel/ tree: zero hits).
i40e registers the *different* generic param `max_mac_per_vf` (i40e_devlink.c: `DEVLINK_PARAM_GENERIC(MAX_MAC_PER_VF, ...)`).

| driver | role | capacity (unicast entries for this netdev) | overflow behaviour | devlink max_macs | evidence (file:function) |
|---|---|---|---|---|---|
| igb | PF | `hw->mac.rar_entry_count - vfs_allocated_count` RAR slots (16 on 82575, 24 on 82576/82580, 32 on I350/I354; I210/I211 fall into the default branch = 16), minus 1 default entry, minus any slots consumed by VF MAC filters. | `igb_add_mac_filter_flags` returns -ENOSPC -> `igb_uc_sync` fails -> `__dev_uc_sync` returns error -> `igb_set_rx_mode` sets `E1000_RCTL_UPE` + `VMOLR_ROPE`: **unicast promiscuous, no log**. Remaining addresses stay unsynced and are retried on every set_rx_mode. | no | igb/igb_main.c: `igb_set_rx_mode`, `igb_uc_sync`, `igb_add_mac_filter_flags`, `igb_available_rars`; igb/e1000_82575.c: `igb_get_invariants_82575` (rar_entry_count) |
| igbvf | VF | Driver-side hard cap **3** (`IGBVF_MAX_MAC_FILTERS`) extra unicast addresses beyond the VF's own MAC. PF side: a pool shared by *all* VFs of `rar_entry_count - (1 + IGB_PF_MAC_FILTERS_RESERVED(3) + num_vfs)` (I350 with 2 VFs: 26 slots for all VFs together). Denied entirely when the PF set the VF MAC (`ip link set vf N mac`) and VF is not trusted. | `netdev_uc_count > 3`: `igbvf_set_uni` prints `pr_err("Too many unicast filters - No Space")`, returns -ENOSPC, and **does not touch the mailbox at all** (previous filters stay, new list not programmed); return value is ignored by `igbvf_set_rx_mode`. Within 3: each address is sent via `E1000_VF_SET_MAC_ADDR|E1000_VF_MAC_FILTER_ADD`; PF NACK (`-ENOSPC`, `dev_warn "VF %d has requested MAC filter but there is no space for it"` / `"...administratively denied"`) is **ignored by the VF** -> silent drop, no promisc. | no | igbvf/netdev.c: `igbvf_set_uni`, `igbvf_set_rx_mode`; igbvf/vf.c: `e1000_set_uc_addr_vf`; igbvf/igbvf.h: `IGBVF_MAX_MAC_FILTERS`; igb/igb_main.c: `igb_set_vf_mac_filter`, `igb_set_vf_mac_addr`, VF-pool alloc in `igb_enable_sriov` (line ~3792) |
| ixgbe | PF | Free entries in the single RAR table `hw->mac.num_rar_entries` (**128** on 82599/X540/X550/E610, **16** on 82598), shared with: 1 default PF MAC, one MAC per VF, all VF macvlans. No PF-side reservation is enforced (`IXGBE_MAX_PF_MACVLANS`=15 only shrinks the VF pool). | `ixgbe_add_mac_filter` returns -ENOMEM when no free RAR -> `ixgbe_uc_sync` fails -> `ixgbe_set_rx_mode` sets `FCTRL_UPE` + `VMOLR_ROPE`: **unicast promiscuous, no log**. | no | ixgbe/ixgbe_main.c: `ixgbe_set_rx_mode`, `ixgbe_uc_sync`, `ixgbe_add_mac_filter`; num_rar_entries in ixgbe_82598.c/82599.c/x540.c/x550.c(`ixgbe_reset_hw_X550em` sets 128)/e610.c |
| ixgbevf | VF | No VF-side cap. PF pool shared by *all* VFs: `num_rar_entries - (IXGBE_MAX_PF_MACVLANS(15) + 1 + num_vfs)` (128-port parts: 112 - num_vfs, e.g. 110 with 2 VFs), further limited by whatever the PF's own uc list already consumed. Denied entirely (index>0) when PF set the VF MAC and VF not trusted. | VF sends `IXGBE_VF_SET_MACVLAN` per address (index 1 clears and restarts the VF's whole list each time). PF: `ixgbe_set_vf_macvlan` -> -ENOSPC -> `e_warn "VF %d has requested a MACVLAN filter but there is no space for it"` (or `"...administratively denied"`) and NACK. VF: `ixgbevf_set_uc_addr_vf` maps NACK to -ENOMEM but **`ixgbevf_write_uc_addr_list` discards the return value** -> silent drop, no promisc. | no | ixgbevf/ixgbevf_main.c: `ixgbevf_set_rx_mode`, `ixgbevf_write_uc_addr_list`; ixgbevf/vf.c: `ixgbevf_set_uc_addr_vf`; ixgbe/ixgbe_sriov.c: `ixgbe_alloc_vf_macvlans`, `ixgbe_set_vf_macvlan`, `ixgbe_set_vf_macvlan_msg` |
| i40e | PF | Firmware-owned MAC/VLAN filter table; no per-VSI constant in the driver. Device-wide budget `I40E_MAX_MACVLAN_PER_HW` = 3072 (only used for the trusted-VF formula). Address list is sent in AQ chunks (`i40e_aq_add_macvlan_v2`). | AQ rejects (fcnt != num_add) on the MAIN VSI -> `dev_warn "Error %s adding RX filters on %s, promiscuous mode forced on"`, sets `__I40E_VSI_OVERFLOW_PROMISC` -> `i40e_set_promiscuous(pf, true)` = **unicast promisc via `i40e_aq_set_vsi_unicast_promiscuous`**; leaves overflow only after active filters drop below 3/4 of the count at entry (`promisc_threshold`, log "filter logjam cleared"). | no (registers generic `max_mac_per_vf` instead) | i40e/i40e_main.c: `i40e_set_rx_mode`, `i40e_addr_sync`, `i40e_sync_vsi_filters`, `i40e_aqc_add_filters`, `i40e_set_promiscuous`; i40e/i40e_devlink.c: `i40e_dl_params` |
| iavf on i40e PF | VF | Enforced by the PF per VF, counting **all** VSI filters (own MAC, broadcast, multicast, unicast): untrusted `I40E_VC_MAX_MAC_ADDR_PER_VF` = **18** (16+1+1); trusted `(3072/num_ports - num_vfs*18)/num_vfs + 18`; both overridden by devlink `max_mac_per_vf` if > 0. Unicast additions are refused outright if PF set the VF MAC and VF untrusted. | `i40e_check_vf_permission` rejects the **whole virtchnl batch** with -EPERM and `dev_err "Cannot add more MAC addresses, VF is not trusted, ..."` / `"...trusted VF reached its maximum allowed limit (%d)"`. iavf: `dev_err "Failed to add MAC filter, error %s"` and `iavf_mac_add_reject` deletes **every filter still marked is_new_mac** (including ones that would have fit); the stack still sees them as synced -> not retried; **no promisc**. On a trusted VF that passes the count check but hits HW ENOSPC, PF logs "Error ... adding RX filters on %s, please set promiscuous on manually" and does not enable promisc for a VF VSI. | no | i40e/i40e_virtchnl_pf.c: `i40e_check_vf_permission`, `i40e_vc_add_mac_addr_msg`, macros at line ~2865; iavf/iavf_main.c: `iavf_set_rx_mode` (ndo_set_rx_mode_async, `__hw_addr_sync_dev`), `iavf_addr_sync`, `iavf_add_filter`; iavf/iavf_virtchnl.c: `iavf_add_ether_addrs`, `iavf_mac_add_reject`, `iavf_virtchnl_completion` (case VIRTCHNL_OP_ADD_ETH_ADDR) |
| ice | PF | Firmware switch rules; no constant in the driver (unknown (not found)). | `ice_fltr_add_mac_list` fails -> `netdev_err "Failed to add MAC filters"`; if AQ status is ENOSPC and `ICE_FLTR_OVERFLOW_PROMISC` not yet set: one-time `netdev_warn "Reached MAC filter limit, forcing promisc mode on VSI %d"`. **However** the following block only enables the default-VSI rule when `current_netdev_flags & IFF_PROMISC` is already set, and `ICE_FLTR_OVERFLOW_PROMISC` is never read anywhere else -> in practice **no promisc, silent drop after the first warning**. Addresses are already marked synced by `__dev_uc_sync` (callback `ice_add_mac_to_sync_list` returns 0) -> not retried. | no | ice/ice_main.c: `ice_set_rx_mode`, `ice_add_mac_to_sync_list`, `ice_vsi_sync_fltr` (lines ~330-470); ice/ice.h: `ICE_FLTR_OVERFLOW_PROMISC` |
| iavf on ice PF | VF | Untrusted: `vf->num_mac + batch > ICE_MAX_MACADDR_PER_VF` (**18**, counts unicast+multicast added by the VF, excludes its own dev_lan_addr) -> refused. Trusted: no driver limit, only firmware. Unicast refused when PF set the VF MAC and VF untrusted (`ice_can_vf_change_mac`). | Untrusted over 18: whole batch rejected `VIRTCHNL_STATUS_ERR_PARAM`, `dev_err "Can't add more MAC addresses, because VF-%d is not trusted, ..."`. Firmware ENOSPC on any element: `dev_err "Failed to add MAC %pM for VF %d, error %d"`, loop aborts with `VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR` (earlier elements of the batch stay programmed). iavf side identical to the i40e row: `iavf_mac_add_reject` drops all new filters, no promisc. | no | ice/virt/virtchnl.c: `ice_vc_handle_mac_addr_msg`, `ice_vc_add_mac_addr`, `ice_vc_can_add_mac`; ice/virt/virtchnl.h: `ICE_MAX_MACADDR_PER_VF` |
| idpf | PF and VF (same driver) | Control-plane/firmware owned; no constant in the driver (unknown (not found)). Sync only happens if `VIRTCHNL2_CAP_MACFILTER` is negotiated. Sent in messages of `IDPF_NUM_FILTERS_PER_MSG` = 20. | `idpf_add_mac_filter` queues the address and sends `VIRTCHNL2_OP_ADD_MAC_ADDR` asynchronously; the callback always returns 0 to `__dev_uc_sync`. On CP error `idpf_mac_filter_async_handler` removes the rejected addresses from the driver list and logs `dev_err_ratelimited "Received error %d on sending MAC filter request"`. **No promisc, no retry** (stack believes synced). | no | idpf/idpf_lib.c: `idpf_set_rx_mode`, `idpf_addr_sync`, `idpf_add_mac_filter`, `__idpf_add_mac_filter`; idpf/idpf_virtchnl.c: `idpf_add_del_mac_filters`, `idpf_mac_filter_async_handler` |
| fm10k | PF | Forwarded per (MAC, VLAN) to the external switch manager (`FM10K_PF_MSG_ID_UPDATE_MAC_FWD_RULE`); capacity lives in the switch manager, not the driver (unknown (not found)). One request per configured VLAN per address. | `fm10k_uc_sync` only queues (`fm10k_queue_mac_request`, fails only on -ENOMEM); `fm10k_macvlan_task` calls `update_uc_addr` and **discards its return value**; `fm10k_set_rx_mode` ignores `__dev_uc_sync`'s result. Any switch-manager rejection is invisible: **silent, no promisc, no log**. | no | fm10k/fm10k_netdev.c: `fm10k_set_rx_mode`, `__fm10k_uc_sync`, `fm10k_queue_mac_request`; fm10k/fm10k_pci.c: `fm10k_macvlan_task`; fm10k/fm10k_pf.c: `fm10k_update_uc_addr_pf`, `fm10k_update_xc_addr_pf` |
| fm10k | VF | Effectively **1 (its own MAC)** whenever the PF assigned a MAC: `fm10k_update_uc_addr_vf` returns `FM10K_ERR_PARAM` for any address != `hw->mac.perm_addr`, and the PF handler independently refuses any MAC != `vf_info->mac`. Only when perm_addr is zero/invalid are requests forwarded to the switch manager (capacity then unknown). | Error returned from `update_uc_addr` inside `fm10k_macvlan_task` is discarded -> **silent drop, no log, no promisc**. PF side returns `FM10K_ERR_PARAM` (mailbox error, no dmesg). | no | fm10k/fm10k_vf.c: `fm10k_update_uc_addr_vf`; fm10k/fm10k_iov.c: PF MAC/VLAN message handler around lines 55-140 ("block attempts to set MAC for a locked device"); fm10k/fm10k_pci.c: `fm10k_macvlan_task` |

## Notes and formulas

**Common kernel behaviour** (`net/core/dev_addr_lists.c: __hw_addr_sync_dev`): the first failing `sync()` callback aborts the walk and returns its error; addresses after it stay unsynced and are retried on the next `set_rx_mode`. Only igb and ixgbe PF drivers use that return value (to turn on unicast promisc). i40e, iavf, ice, idpf, fm10k callbacks return 0 (or only -ENOMEM), so the stack never learns about a rejected address.

**igb PF**: usable = `rar_entry_count - vfs_allocated_count - 1(default) - slots taken by VF filters`. The last `vfs_allocated_count` RAR slots are the VF primary MACs. With SR-IOV the VF filter pool `rar_entry_count - (1 + 3 + num_vfs)` is carved from the *same* table, first come first served between PF uc list and VF requests. I350 with 2 VFs: at most 29 PF unicast entries beyond the default, but every VF filter added later reduces that.

**igbvf**: two limits stack: VF-side 3 (`IGBVF_MAX_MAC_FILTERS`) and the shared PF pool. Exceeding 3 leaves the hardware list *unchanged* (early return before `E1000_VF_MAC_FILTER_CLR`), so a fourth fdb entry blocks all updates until the list shrinks again. Untrusted VF with PF-assigned MAC: zero extra filters.

**ixgbe PF / ixgbevf**: single 128-entry RAR table (82599, X540, X550, E610). Budget: 1 default + `num_vfs` VF MACs + PF uc list + VF macvlans. VF pool = `128 - (15 + 1 + num_vfs)` shared by all VFs; the 15 is a reservation used only for sizing that pool, the PF itself is not capped. `ixgbevf` resends its complete list on every change (index 1 = "clear then start new list"), so a full RAR table manifests as the PF logging the same "no space" warning per change and the VF silently missing the tail of its list.

**i40e / iavf**: untrusted VF budget 18 counts *every* filter on the VF VSI (primary MAC, broadcast, IPv6 multicast such as 33:33:00:00:00:01 and solicited-node addresses, LLDP multicast). For a bridge uplink VF with several IPv6 multicast groups the free unicast headroom is therefore well under 16. Trusted formula with `num_ports` PF ports on the device and `num_vfs` VFs: `(3072/num_ports - num_vfs*18)/num_vfs + 18`. `devlink dev param set ... name max_mac_per_vf value N cmode runtime` (i40e only, SR-IOV must be disabled to change it) becomes a strict cap for both trusted and untrusted VFs. Rejection is all-or-nothing per virtchnl batch, and iavf then purges all pending new addresses.

**ice / iavf**: untrusted cap 18 (`ICE_MAX_MACADDR_PER_VF`) counts unicast+multicast the VF added (not its primary MAC). Trusted VFs are limited only by firmware switch-rule space; on ENOSPC the batch is aborted mid-way. ice PF netdev: the "forcing promisc mode" warning is misleading; the code path does not actually enable unicast promiscuous on the PF unless the netdev is already IFF_PROMISC.

**idpf**: no per-vport cap visible in the driver; the control plane decides. Failures only show as rate-limited dev_err lines and the address vanishes from the driver list while remaining in `dev->uc`.

**fm10k**: VFs are MAC-locked by default (PF assigns `perm_addr`), so a VF cannot carry additional unicast addresses at all; a bridge behind an fm10k VF must rely on the PF's uc list or promiscuous mode.

---

## Unicast-filter capacity per driver (mlx5, mlx4, bnxt, bnx2x)

Source: mainline sparse checkout under the kernel tree (drivers/net/ethernet, net/core). All
paths below are relative to drivers/net/ethernet/ unless noted.

Common core path (net/core): `bridge fdb add … self permanent` -> `rtnetlink.c:ndo_dflt_fdb_add` ->
`dev_addr_lists.c:dev_uc_add_excl` -> `__dev_set_rx_mode`. This tree has the new
`ndo_set_rx_mode_async(dev, uc_snapshot, mc_snapshot)` (mlx5, bnxt): it runs from a workqueue,
and a non-zero return triggers `netif_rx_mode_schedule_retry` (dmesg: "rx_mode install failed,
retrying with backoff", after 4 tries "rx_mode retry limit reached, giving up"). Legacy
`ndo_set_rx_mode` (mlx4, bnx2x) returns void; errors are only visible in the driver's own log.
`__hw_addr_sync_dev` is not used by any of the four drivers. Without `IFF_UNICAST_FLT` the core
itself forces promiscuous mode as soon as dev->uc is non-empty (`netif_uc_promisc_update`).

| driver | role | capacity | overflow behaviour | devlink max_macs | evidence (file:function) |
|---|---|---|---|---|---|
| mlx5 (mlx5e) | PF | `1 << log_max_current_uc_list` (HCA cap of this function; CX-4 reports 128) incl. dev_addr; the per-address L2 flow rules (table size 32770) are not the binding limit | Log-and-truncate: `fs_warn` "mdev UC list size (%d) > (%d) max vport list size, some addresses will be dropped"; own dev_addr is pushed first, the rest in hash order (last byte of MAC), so which addresses survive is arbitrary. No promisc fallback. RX flow rules for ALL addresses still exist in the NIC L2 table, so on a PF whose vport is the uplink the extra MACs still work locally; truncation matters only for what the vport context advertises upward. | yes, `DEVLINK_PARAM_GENERIC(MAX_MACS)` driverinit, only if `log_max_current_uc_list_wr_supported`; value = `1 << log_max_current_uc_list`, written back into `cmd_hca_cap` at init. Equal to the enforced uc limit. | mlx5/core/en_fs.c:mlx5e_vport_context_update_addr_list, mlx5e_fill_addr_array; vport.c:mlx5_modify_nic_vport_mac_list (-ENOSPC guard); devlink.c:mlx5_devlink_max_uc_list_params_register; main.c:handle_hca_cap (log_max_current_uc_list) |
| mlx5 (mlx5e) | VF | same formula using the VF's OWN HCA cap (`log_max_current_uc_list` of the VF function). PF side (legacy eswitch): reads the VF's list with the VF's cap as bound (`mlx5_vport_max_mac_list_size` queries other-function caps) and installs one legacy-FDB rule per MAC; FDB table sized by firmware (`ft_attr.max_fte = MLX5_FS_MAX_POOL_SIZE`, effective `log_max_ft_size`), no per-VF quota, no trust check for the list. | VF driver: same log-and-truncate as PF. PF side: a failed FDB rule logs `esw_warn` "FDB: Failed to add flow rule: dmac_v(%pM) … -> vport(%d), err(%pe)" and the MAC is silently unreachable. VF promisc is dropped unless `ip link set … vf N trust on` (`esw_update_vport_rx_mode`). MPFS L2 table (`log_max_l2_table`) is only populated in switchdev mode (`mlx5_mpfs_enable` called from eswitch_offloads.c), not in legacy. | not registered on a VF unless the VF cap says writable (same check); the VF's own `log_max_current_uc_list` is what counts | en_fs.c as above; eswitch.c:esw_update_vport_addr_list, esw_apply_vport_addr_list, esw_add_uc_addr, __esw_fdb_set_vport_rule, esw_update_vport_rx_mode; vport.c:mlx5_vport_max_mac_list_size; esw/legacy.c:esw_create_legacy_fdb_table; lib/mpfs.c:mlx5_mpfs_init/mlx5_mpfs_add_mac |
| mlx4 (mlx4_en) | PF | per physical port MAC table shared by PF and all VFs: `table->max = 1 << caps.log_num_macs` (module param `log_num_mac`, default 7 -> 128, hard cap `MLX4_MAX_MAC_NUM` 128, further capped by firmware `log_max_macs`); PF quota in the resource tracker = `128 - 2 * max_vfs_per_port`, guaranteed 2. Only if steering mode != A0 (else no `IFF_UNICAST_FLT`, core promisc). | Fallback to promiscuous: `mlx4_register_mac` fails (`-ENOSPC` from `__mlx4_register_mac` when `table->total == table->max`, or `-EINVAL` after `mlx4_warn` "VF %d port %d res RES_MAC: quota exceeded, count %d alloc %d quota %d" from the resource tracker), `en_err` "Failed registering MAC %pM on port %d: %d", then `MLX4_EN_FLAG_FORCE_PROMISC` and `en_warn` "Forcing promiscuous mode on port:%d". Adds stop at the first failure (earlier list entries stay registered); promisc is retried only after something was removed. | yes, `DEVLINK_PARAM_GENERIC(MAX_MACS)` driverinit, default `1 << log_num_mac` (128), validated 1..128 power of 2; sets `caps.log_num_macs` -> `table->max`. Equals the port table size but NOT the per-function quota. | mlx4/en_netdev.c:mlx4_en_do_uc_filter, mlx4_en_do_set_rx_mode, mlx4_en_uc_steer_add; port.c:__mlx4_register_mac, mlx4_register_mac; resource_tracker.c:mlx4_init_resource_tracker (RES_MAC), mlx4_grant_resource, mac_alloc_res, mac_add_to_slave; main.c:mlx4_devlink_params, mlx4_devlink_set_params_init_values, mlx4_devlink_max_macs_validate |
| mlx4 (mlx4_en) | VF | same shared per-port table (max 128 minus whatever PF and other VFs hold); VF quota `MLX4_MAX_MAC_NUM` (128), guaranteed 2 per port; the flow-steering rule the VF attaches for the MAC is accepted by the PF only if the MAC was registered by that VF (`validate_eth_header_mac`, pr_err "MAC %pM doesn't belong to VF %d, Steering rule rejected"). No trust concept. | same as PF: `mlx4_register_mac` goes to the PF via ALLOC_RES; on failure the VF logs `en_err` "Failed registering MAC …" and forces promisc (`en_warn` "Forcing promiscuous mode on port:%d"). Whether the PF honours a VF's promisc flow rule (`MLX4_FS_ALL_DEFAULT`) was not verified: unknown (not found in resource_tracker.c). | registered unconditionally at probe (also on the VF's devlink instance) but only the PF's value sizes the table | as PF; resource_tracker.c:mlx4_QP_FLOW_STEERING_ATTACH_wrapper, validate_eth_header_mac |
| bnxt | PF | `BNXT_MAX_UC_ADDRS` = 4 including dev_addr -> 3 extra unicast filters (one HWRM_CFA_L2_FILTER_ALLOC each); firmware `max_l2_ctxs` is read but not used to raise this | Fallback to promiscuous, all-or-nothing: if `count(uc) > BNXT_MAX_UC_ADDRS - 1` the driver programs NONE of the extra addresses and sets `CFA_L2_SET_RX_MASK_REQ_MASK_PROMISCUOUS` silently (no log). A failed filter alloc logs `netdev_err` "HWRM vnic filter failure rc: %x" (or "FW busy while setting vnic filter, will retry"), truncates `uc_filter_count` and returns rc -> core retry/backoff messages. | no (`grep DEVLINK_PARAM_GENERIC_ID_MAX_MACS` finds nothing under broadcom/) | bnxt/bnxt.c:bnxt_set_rx_mode, bnxt_cfg_rx_mode, bnxt_uc_list_updated, bnxt_hwrm_set_vnic_filter, bnxt_hwrm_l2_filter_alloc; bnxt.h:BNXT_MAX_UC_ADDRS |
| bnxt | VF | same 4 (3 extra) in the VF driver; PF provisions `max_l2_ctxs = BNXT_VF_MAX_L2_CTX` = 4 per VF; PF sniffs every VF HWRM_CFA_L2_FILTER_ALLOC: untrusted VF with a PF-assigned MAC (`ip link set … vf N mac`) may allocate a filter ONLY for that MAC, any other address is answered with an error; trusted VF or VF without PF-assigned MAC: any valid MAC | >3 addresses: promisc bit is set as on the PF, but `bnxt_promisc_ok` clears it again for an untrusted VF without VLAN -> silent drop, only dev_addr is received. 1..3 addresses on an untrusted VF with PF-assigned MAC: `netdev_err` "HWRM vnic filter failure rc: …", `uc_filter_count` truncated, core retries then gives up. Trusted VF (`ip link set … vf N trust on`): works like PF, promisc allowed. | no | bnxt/bnxt.c as above, bnxt_promisc_ok, bnxt_vf_req_snif; bnxt_sriov.c:bnxt_vf_validate_set_mac, bnxt_vf_req_validate_snd, bnxt_hwrm_func_cfg / bnxt_hwrm_func_vf_resc_cfg (min/max_l2_ctxs), bnxt_is_trusted_vf; bnxt_sriov.h:BNXT_VF_MAX_L2_CTX |
| bnx2x | PF | CAM credit pool per function: E2/E3 `PF_MAC_CREDIT_E2 = (272 - 64*1)/func_num + num_vfs*1` (`MAX_MAC_CREDIT_E2` 272 per path, `GET_NUM_VFS_PER_PATH` fixed 64, `VF_MAC_CREDIT_CNT` 1, func_num = enabled functions on the path); E1H `256/(2*func_num)`; E1 `192/2 - 64`. Shared by dev_addr, uc list and the VFs' MACs. | Fallback to promiscuous: credit exhausted -> `bnx2x_validate_vlan_mac_add` returns -EINVAL (no log at that level) -> `BNX2X_ERR` "Set MAC failed" and "Failed to schedule ADD operations: %d" -> `rx_mode = BNX2X_RX_MODE_PROMISC` (`BNX2X_ACCEPT_UNMATCHED`). Addresses already scheduled stay. | no | bnx2x/bnx2x_main.c:bnx2x_set_rx_mode, bnx2x_set_rx_mode_inner, bnx2x_set_uc_list, bnx2x_set_mac_one, bnx2x_fill_accept_flags; bnx2x_sp.c:bnx2x_init_mac_credit_pool, bnx2x_validate_vlan_mac_add; bnx2x_sp.h:PF_MAC_CREDIT_E2; bnx2x_fw_defs.h:MAX_MAC_CREDIT_E2; bnx2x_cmn.h:bnx2x_get_path_func_num |
| bnx2x | VF | 0 extra: the VF driver never programs dev->uc at all (`bnx2x_set_rx_mode_inner` calls `bnx2x_set_uc_list` only under `IS_PF(bp)`; the VF branch schedules only `BNX2X_SP_RTNL_VFPF_MCAST`). Only dev_addr goes to the PF (`bnx2x_vfpf_config_mac`, `n_mac_vlan_filters = 1`); PF gives each VF `num_mac_filters = VF_MAC_CREDIT_CNT` = 1 credit. | Silent: `bridge fdb add … self` succeeds, nothing reaches the hardware, no log. VF promisc is ignored by the PF too ("Ignore VF requested mode; instead set a regular mode" -> ACCEPT_UNICAST only matched), so no fallback exists. | no | bnx2x/bnx2x_main.c:bnx2x_set_rx_mode_inner; bnx2x_vfpf.c:bnx2x_vfpf_config_mac, bnx2x_vfpf_storm_rx_mode, bnx2x_vf_mbx_qfilters; bnx2x_sriov.c:bnx2x_iov_static_resc (num_mac_filters), bnx2x_vf_mac_vlan_config; bnx2x_sriov.h:VF_MAC_CREDIT_CNT, vf_mac_rules_cnt |

## Notes per driver

**mlx5** — Capacity is `1 << MLX5_CAP_GEN(mdev, log_max_current_uc_list)` of the netdev's own
function (`MLX5_MAX_UC_PER_VPORT` in eswitch.h is the same macro). The devlink `max_macs` value is
this number and is applied to the HCA cap at driver init; the PF and each VF have their own cap,
so the PF's devlink setting does not resize a VF's list. The list sent to firmware always begins
with dev_addr; overflow drops addresses from the END of the hash walk, i.e. by MAC byte 5, not by
insertion order. The PF-side legacy eswitch mirrors the VF's list into the FDB with one rule per
MAC and no additional per-VF quota (FDB is firmware-sized); a trust flag only gates promisc/allmulti.
The MPFS "L2 table" (`log_max_l2_table`) is bypassed in legacy mode. There is no constant named
`MLX5E_MAX_UC_ADDRS` in this tree.

**mlx4** — Hardware limit is the per-port MAC table: `min(128, 1 << log_num_mac, 1 << fw log_max_macs)`
slots shared by the PF and every VF on that port (bonded dual-port devices mirror entries into the
other port's table, so a slot is consumed on both). Resource-tracker quotas on top: PF
`128 - 2*max_vfs_per_port`, each VF 128 with 2 guaranteed; "quota exceeded" is logged by the PF, the
table-full `-ENOSPC` is not. Both make the VF/PF netdev force promisc (dmesg "Forcing promiscuous
mode on port:N"). Steering mode A0 has no unicast filtering at all (core promisc). devlink
`max_macs` = table size, registered on every mlx4_core instance including VFs.

**bnxt** — `BNXT_MAX_UC_ADDRS` (4) is a driver constant covering dev_addr + 3 extra; firmware
`max_l2_ctxs` (PF: whatever FW reports; VF: 4 provisioned by the PF) is not consulted by
`bnxt_cfg_rx_mode`. The moment the list exceeds 3 extra addresses the driver drops ALL of them and
relies on promisc; on an untrusted VF that promisc is then vetoed by `bnxt_promisc_ok`, so the
overflow is a silent total loss. On an untrusted VF whose MAC was set by the PF, even 1..3 extra
addresses are rejected by the PF sniffer (`bnxt_vf_validate_set_mac`); with `vf N trust on` the VF
behaves like a PF. No devlink `max_macs`.

**bnx2x** — PF capacity is a CAM credit pool, formula above (e.g. E2 with 2 functions on the path
and 0 VFs: (272-64)/2 = 104 credits, minus dev_addr, iSCSI/FCoE MACs and whatever VFs consume).
Overflow flips the PF to promisc with BNX2X_ERR lines. A VF netdev never programs its dev->uc list
(only its primary MAC, 1 credit), and the PF ignores VF promisc, so extra unicast addresses on a
bnx2x VF are silently ineffective. No devlink `max_macs`.

---

## Unicast-filter capacity per driver: qede/qed, qlcnic, cxgb4/cxgb4vf, benet, sfc, nfp

Source: mainline sparse checkout at the kernel tree (drivers/net/ethernet, net/core), read 2026-09-02.
Path used by the daemon: `bridge fdb add <mac> dev <netdev> self` -> ndo_dflt_fdb_add -> dev_uc_add -> ndo_set_rx_mode.
Core facts that apply to every row:
- `__hw_addr_sync_dev` (net/core/dev_addr_lists.c:317) stops at the first `sync()` error and leaves the address unsynced; nothing is logged by the core, and the caller (`__dev_uc_sync`) return value is ignored by every driver below.
- `netif_uc_promisc_update` (net/core/dev_addr_lists.c:1232): if the netdev lacks `IFF_UNICAST_FLT`, the core switches the device to promiscuous mode as soon as `dev->uc` is non-empty (`dev->uc_promisc = true`), before the driver sees the list. This is the whole story for nfp, sfc/ef100 and sfc/siena.
- None of the six drivers registers `DEVLINK_PARAM_GENERIC_ID_MAX_MACS`; the only in-tree users are mlx4 and mlx5 (grep over drivers/net/ethernet).

| driver | role | capacity (secondary unicast MACs beyond dev_addr) | overflow behaviour | devlink max_macs | evidence (file:function) |
|---|---|---|---|---|---|
| qede/qed | PF | `num_mac_filters - 1`, where `num_mac_filters = RESC_NUM(QED_MAC) - total_vfs * 1`; `RESC_NUM(QED_MAC)` defaults to `ETH_NUM_MAC_FILTERS(512) / num_funcs` (MFW may override) | `uc_count >= num_mac_filters` -> no MAC programmed at all, vport set to `QED_FILTER_RX_MODE_TYPE_PROMISC` (unicast+multicast unmatched accepted). No log. Per-address add failure -> `goto out`, silent | no | qede/qede_filter.c:qede_config_rx_mode; qed/qed_l2.c:qed_fill_eth_dev_info; qed/qed_dev.c:qed_hw_get_dflt_resc_num; include/linux/qed/eth_common.h:59 |
| qede/qed | VF | **0** (`num_mac_filters` = `QED_ETH_VF_NUM_MAC_FILTERS` = 1, granted by PF in acquire: `min(p_vf->num_mac_filters, req)`) | Any secondary MAC -> VF asks for PROMISC. **Untrusted VF**: PF silently strips `QED_ACCEPT_UCAST_UNMATCHED` ("Untrusted VFs can't even be trusted to know that fact"), VF sees success, frames are dropped. **Trusted VF**: unicast-promiscuous vport. A direct VF MAC add beyond 1 hits `"No available place for MAC"` (DP_VERBOSE only) -> PFVF_STATUS_FAILURE -> VF gets -EAGAIN, no print | no | qed/qed_sriov.h:12; qed/qed_sriov.c:qed_iov_vf_mbx_acquire_resc, qed_iov_vp_update_rx_mode, qed_iov_vf_update_mac_shadow; qed/qed_vf.c:qed_vf_pf_filter_ucast |
| qlcnic | PF 82xx | `max_uc_count` = `(512-38)/n` if `n<=2`, else `(64-38)/n`; n = `ahw->total_nic_func` (e.g. 237 / 8) | `netdev_uc_count > max_uc_count` -> `VPORT_MISS_MODE_ACCEPT_ALL` (promisc) + driver MAC learning on. No log. Under the limit each add is a fire-and-forget descriptor (no status) | no | qlcnic/qlcnic_hw.c:__qlcnic_set_multi, qlcnic_82xx_sre_macaddr_change; qlcnic/qlcnic_main.c:qlcnic_82xx_set_mac_filter_count; qlcnic_hdr.h:673-674 |
| qlcnic | PF 83xx/84xx | `(4096-38)/n` if `n<=2`, else `(2048-38)/n` (e.g. 2029 / 502) | same as 82xx; mailbox rejections are logged only by the generic mailbox layer (`"Mailbox command failed, opcode=0x%x ..."`), and `qlcnic_nic_add_mac`'s return is ignored | no | qlcnic/qlcnic_83xx_hw.c:qlcnic_83xx_set_mac_filter_count, qlcnic_83xx_sre_macaddr_change; qlcnic_83xx_hw.h:411-415 |
| qlcnic | VF (83xx/84xx SR-IOV) | driver threshold `(4096-38)/1 = 4058` (VF sets `total_nic_func = 1`), but **PF firmware quota per VF = `QLCNIC_83XX_SRIOV_VF_MAX_MAC` = 2** (`num_allowed_vlans + 1` on non-83xx), so effectively **1 secondary MAC** | Beyond quota: firmware rejects the VF's `CONFIG_MAC_VLAN`; return ignored by `qlcnic_vf_add_mc_list` -> address silently missing. PF forwards VF promisc requests unchecked, but the VF driver only asks for promisc above 4058 | no | qlcnic/qlcnic_sriov_common.c:qlcnic_sriov_vf_set_multi, qlcnic_vf_add_mc_list, :536; qlcnic/qlcnic_sriov_pf.c:qlcnic_sriov_pf_cal_res_limit, qlcnic_sriov_pf_cfg_macvlan_cmd, qlcnic_sriov_pf_cfg_promisc_cmd; qlcnic_sriov.h:55 |
| cxgb4 | PF | Exact-match MPS TCAM, **adapter-wide, shared by all ports/PFs/VFs**: 336 (T4) / 512 (T5, T6) = `adap->params.arch.mps_tcam_size`; per-function quota `nexactf` from FW_PFVF_CMD (firmware config file; the no-config fallback `adap_init1` asks 16 for the PF). Driver does not check the quota itself | FW returns `-FW_ENOMEM` / idx >= max -> address is folded into a 64-bucket **unicast hash** (`hash_mac_addr`, 6 bit) and programmed via `cxgb4_set_addr_hash`; `cxgb4_mac_sync` returns 0. Imperfect filter, not promisc, no log | no | chelsio/cxgb4/cxgb4_main.c:set_rxmode, cxgb4_mac_sync, adap_init1 (t4_cfg_pfvf nexact=16); cxgb4_mps.c:cxgb4_alloc_mac_filt; t4_hw.c:t4_alloc_mac_filt, :9130-9155; t4_regs.h:3200-3201; cxgb4.h:hash_mac_addr |
| cxgb4vf | VF | same shared TCAM; VF quota `vfres->nexactf` (FW_PFVF_CMD) is only shown in debugfs "MAC Address Filters", enforced by firmware | identical: `t4vf_alloc_mac_filt` -> hash fallback via `cxgb4vf_set_addr_hash`, return 0, no log | no | chelsio/cxgb4vf/cxgb4vf_main.c:set_rxmode, cxgb4vf_mac_sync, cxgb4vf_set_addr_hash, :2320; t4vf_hw.c:t4vf_alloc_mac_filt, :1121-1124 |
| benet | PF | `be_max_uc(adapter) - 1` = `res.max_uc_mac - 1`; BE2/BE3: `BE_UC_PMAC_COUNT` = 30 -> **29**; Lancer/Skyhawk: `unicast_mac_count` from GET_PROFILE_CONFIG | `netdev_uc_count > max_uc - 1` -> `be_set_uc_promisc` (`BE_IF_FLAGS_PROMISCUOUS` on the iface), no log. Under the limit `be_uc_mac_add` ignores `be_cmd_pmac_add`'s status (incl. -EPERM/UNAUTHORIZED) -> silent | no | emulex/benet/be_main.c:be_set_uc_list, be_uc_mac_add, BEx_get_resources; be.h:372,694; be_cmds.c:4331 |
| benet | VF | BE2/BE3: `BE_VF_UC_PMAC_COUNT` = 2 -> **1**; Skyhawk: PF hands the VF `res.max_uc_mac / (num_vfs + 1)` when the field is modifiable | Same promisc path, but a BE3 VF iface is created with `BE_VF_IF_EN_FLAGS` (no PROMISCUOUS bit): `be_cmd_rx_filter` prints `"Cannot set rx filter flags 0x%x"` / `"Interface is capable of 0x%x flags only"`, returns -ENOTSUPP, ignored -> addresses silently dropped. VFs without `BE_PRIV_FILTMGMT` get -EPERM on pmac_add, silently | no | be_main.c:be_set_uc_list, be_calculate_vf_res (:4106), be_vf_setup (:4177), be.h:373, :139; be_cmds.c:be_cmd_rx_filter, be_cmd_pmac_add |
| sfc ef10 | PF and VF (same code) | `EFX_EF10_FILTER_DEV_UC_MAX` = 32 including dev_addr -> **31** | 32nd address: list truncated (`break`), `table->uc_promisc = true` -> unknown-unicast "mismatch" default filter inserted; individual filters kept. Insert failure (table 8192 rows, hash search limit, or -EPERM) -> `"efx_mcdi_filter_insert failed rc=%d"` (netif_info) and fallback to the uc_def filter. **Unprivileged VF**: the uc_def insert fails -EPERM, logged at debug only (`"... mismatch filter insert failed rc=%d"`), so addresses past 31 vanish silently. No ndo_set_vf_trust; privilege is MC firmware (`MC_CMD_PRIVILEGE_MASK`) | no | sfc/mcdi_filters.c:efx_mcdi_filter_uc_addr_list, efx_mcdi_filter_vlan_sync_rx_mode (~:989), efx_mcdi_filter_insert_addr_list, efx_mcdi_filter_insert_def (:885); mcdi_filters.h:17,116; sfc/efx.c:799 (IFF_UNICAST_FLT only for rev >= HUNT_A0) |
| sfc ef100 | PF and VF | 31 in the driver table (same mcdi_filters.c), but the netdev **does not set `IFF_UNICAST_FLT`** | Core `netif_uc_promisc_update` puts the device into promiscuous mode as soon as one secondary MAC exists | no | sfc/ef100_netdev.c (no priv_flags set); sfc/ef100_nic.c:442; net/core/dev_addr_lists.c:1232 |
| sfc siena | PF | **0** in the driver: `efx_farch_filter_sync_rx_mode` never reads `dev->uc` (only `unicast_filter = !promisc` + multicast hash); `IFF_UNICAST_FLT` is set only for rev >= HUNT_A0, never true in this driver | Core forces promiscuous mode on the first secondary MAC; driver then sets `unicast_filter = false` | no | sfc/siena/farch.c:efx_farch_filter_sync_rx_mode; sfc/siena/efx.c:719 |
| nfp | PF and VF | **0** - `nfp_net_set_rx_mode` only calls `__dev_mc_sync`; no `__dev_uc_sync`, no `netdev_for_each_uc_addr`, no `IFF_UNICAST_FLT` anywhere in netronome/ | Core forces promiscuous mode on the first secondary MAC (`NFP_NET_CFG_CTRL_PROMISC`). If the firmware lacks PROMISC capability: `"FW does not support promiscuous mode"` (nn_warn) and the addresses are simply not received | no | netronome/nfp/nfp_net_common.c:nfp_net_set_rx_mode; net/core/dev_addr_lists.c:netif_uc_promisc_update |

## Notes where the number is configuration-dependent

**qede/qed PF.** `qed_hw_get_dflt_resc_num` (qed_dev.c:3788): `QED_MAC` = `ETH_NUM_MAC_FILTERS / num_funcs` (512 per engine, `num_funcs` = PCI functions on that engine; the MFW resource-allocation reply can replace this default). `qed_fill_eth_dev_info` subtracts `total_vfs * QED_ETH_VF_NUM_MAC_FILTERS` (1 per VF). qede compares `uc_count < num_mac_filters` with `uc_count` = secondary addresses only (dev_addr goes in via `QED_FILTER_XCAST_TYPE_REPLACE` first). Example: one function per engine, 64 VFs -> 448 -> 447 secondaries before promisc.

**qede/qed VF.** Capacity 1 total means every `bridge fdb add ... self` on a qede VF ends in a promisc request. `qed_iov_vp_update_rx_mode` (qed_sriov.c:2984-3010) masks `QED_ACCEPT_UCAST_UNMATCHED | QED_ACCEPT_MCAST_UNMATCHED` unless `is_trusted_configured`; the VF is told everything succeeded. `ip link set ... vf N trust on` is therefore mandatory for this daemon on qede VFs, and then the VF becomes fully unicast-promiscuous (no per-MAC filtering at all).

**qlcnic.** `max_uc_count` is driver-side only; the firmware `max_mac_filters` (u8, from GET_NIC_INFO) is read into `ahw->max_mac_filters` but never consulted on the unicast path. `total_nic_func` is the count of NIC functions on the adapter (PF) or 1 (VF). The PF's per-VF firmware quota (`qlcnic_sriov_pf_cal_res_limit`) is 2 RX unicast filters on 83xx/84xx and `num_allowed_vlans + 1` otherwise; with guest VLANs each MAC is added once per allowed VLAN (`qlcnic_vf_add_mc_list`), so the quota is consumed faster.

**cxgb4 / cxgb4vf.** The exact-match table is one MPS TCAM per adapter (336 T4, 512 T5/T6). Per-function shares (`nexactf`) come from the firmware configuration file loaded at init (`FW_PFVF_CMD`); the driver does not read them back for enforcement, only the firmware does. Because of the hash fallback the netdev never fails a unicast add: past the exact-match share, frames for the extra MAC are matched by a 64-bit hash vector (all MACs sharing the 6-bit hash bucket are accepted). For the daemon this means "always accepted, imperfect filtering", never promisc, never an error.

**benet.** Threshold `netdev_uc_count > be_max_uc - 1` because `pmac_id[0]` is the primary. BE2/BE3 hard-code 30 (PF) / 2 (VF); Lancer and Skyhawk read `unicast_mac_count` from the profile (be_cmds.c:4331), and `be_calculate_vf_res` splits the PF's value evenly (`/ (num_vfs + 1)`) when SR-IOV is enabled. On BE3 VFs the unicast-promisc fallback is not available (iface created without `BE_IF_FLAGS_PROMISCUOUS`), so beyond 1 secondary MAC the VF silently receives nothing for the extra addresses.

**sfc ef10.** 32 entries including dev_addr is a fixed array (`dev_uc_list[EFX_EF10_FILTER_DEV_UC_MAX]`), independent of PF/VF. The actual MC filter table (8192 rows, `EFX_MCDI_FILTER_TBL_ROWS`) is shared adapter-wide. Beyond 31 the driver relies on the unknown-unicast mismatch filter, which the MC only grants to privileged functions; a plain VF gets -EPERM there (debug-level message only). No per-VF quota is enforced by the PF driver; the MC firmware decides.

**sfc ef100, sfc siena, nfp.** No `IFF_UNICAST_FLT` -> `netif_uc_promisc_update` in the core makes the device promiscuous whenever `dev->uc` is non-empty. Any MAC the daemon adds works, at the price of full promiscuous mode; on nfp without the PROMISC capability bit it does not work at all (one `nn_warn`).

---

## Unicast-filter capacity: Marvell / Cavium / HiSilicon / Huawei drivers

Source: mainline sparse checkout under `drivers/net/ethernet` (`E=` below), `net/core/dev_addr_lists.c`.
Core facts that drive several rows: (a) `__hw_addr_sync_dev` (dev_addr_lists.c:317) calls `sync()` per unsynced
address and **returns on the first error**, leaving that and all later addresses unsynced (retried on the next
`ndo_set_rx_mode`). (b) A netdev **without `IFF_UNICAST_FLT`** never gets its uc list programmed: `netif_uc_promisc_update`
(dev_addr_lists.c:1232) flips `IFF_PROMISC` on as soon as `dev->uc` is non-empty, so every `bridge fdb add ... self`
turns into a promiscuous-mode request. None of the drivers below registers `DEVLINK_PARAM_GENERIC_ID_MAX_MACS`
(only mlx4/mlx5 do in this tree).

| driver | role | capacity | overflow behaviour | devlink max_macs | evidence (file:function) |
|---|---|---|---|---|---|
| marvell/octeontx2 | PF | `flow_cfg->ucast_flt_cnt` extra MACs; default `OTX2_DEFAULT_UNICAST_FLOWS` = 4 (u8, runtime devlink driver param `unicast_filter_count`), only if AF granted the MCAM entries | Silent: `netdev_uc_count > ucast_flt_cnt` => `promisc = true`, `__dev_uc_sync` skipped, `NIX_RX_MODE_PROMISC` sent to AF; no log. Per-address `otx2_do_add_macfilter` returns -ENOMEM in the same case. | no | `E/marvell/octeontx2/nic/otx2_pf.c:otx2_do_set_rx_mode` (l.1851-1858); `otx2_flows.c:otx2_do_add_macfilter` (l.528); `otx2_common.h:348`; `otx2_devlink.c:otx2_dl_ucast_flt_cnt_set` |
| marvell/octeontx2 | VF | 0 (uc list never synced, no `IFF_UNICAST_FLT`) | Core forces `IFF_PROMISC`; VF sends `NIX_RX_MODE_PROMISC`; AF drops it: untrusted VF -> silent `return 0`; no `nix_rx_multicast` cap -> `dev_warn_ratelimited "VF promisc/multicast not supported"`. Trusted VF on RX-multicast-capable silicon -> promisc entry installed. | no | `E/marvell/octeontx2/nic/otx2_vf.c:otx2vf_do_set_rx_mode` (l.456-481); `E/marvell/octeontx2/af/rvu_nix.c:rvu_mbox_handler_nix_set_rx_mode` (l.4580-4590) |
| marvell/octeon_ep | PF | 0 (no `ndo_set_rx_mode`, no `IFF_UNICAST_FLT`) | Silent: kernel sets `IFF_PROMISC` but nothing is sent to firmware; frames to extra MACs are dropped by hardware. | no | `E/marvell/octeon_ep/octep_main.c:octep_netdev_ops` (l.1196-1205, no rx_mode op) |
| marvell/octeon_ep_vf | VF | 0 (same) | Silent, as above. | no | `E/marvell/octeon_ep_vf/octep_vf_main.c:octep_vf_netdev_ops` (l.930-937) |
| cavium/liquidio | PF | 0 dedicated (uc list never sent; no `IFF_UNICAST_FLT`) | Core forces `IFF_PROMISC` -> `get_new_flags` adds `OCTNET_IFFLAG_PROMISC` -> firmware promisc via `OCTNET_CMD_SET_MULTI_LIST`. Silent. | no | `E/cavium/liquidio/lio_main.c:get_new_flags` (l.1918), `liquidio_set_mcast_list` (l.1944) |
| cavium/liquidio | VF | `MAX_NCTRL_UDD` = 32 addresses per `OCTNET_CMD_SET_UC_LIST` (whole list resent each time) | > 32: `dev_err "too many MAC addresses in netdev uc list"`, returns without sending (firmware keeps the previous list). Independently the core forces `IFF_PROMISC` (no `IFF_UNICAST_FLT`) -> `OCTNET_IFFLAG_PROMISC` requested; whether firmware honours VF promisc / requires `ndo_set_vf_trust` is not visible in the driver. | no | `E/cavium/liquidio/lio_vf_main.c:liquidio_set_uc_list` (l.1030-1065), called from `liquidio_set_mcast_list` (l.1113); `octeon_nic.h:30` |
| cavium/thunder | PF | n/a: `nic_main.c` creates no netdev | - | no | `E/cavium/thunder/nic_main.c` (no `register_netdev`) |
| cavium/thunder | VF (nicvf) | 0 (only mc list is pushed; uc list ignored; no `IFF_UNICAST_FLT`). BGX DMAC CAM = `RX_DMAC_COUNT` 32 / `lmac_count` entries per LMAC, used for own MAC + multicast only. | Core forces `IFF_PROMISC` -> `mode = BCAST_ACCEPT|MCAST_ACCEPT` -> PF `bgx_set_xcast_mode` clears `CAM_ACCEPT` => whole LMAC accepts every DMAC (promisc shared by all VFs on that LMAC). No trust check on `NIC_MBOX_MSG_SET_XCAST`. CAM overflow itself is silent (`bgx_lmac_save_filter` returns -1). | no | `E/cavium/thunder/nicvf_main.c:nicvf_set_rx_mode` (l.2036-2075); `nic_main.c` l.1090-1122; `thunder_bgx.c:bgx_set_xcast_mode` (l.354-386), `bgx_lmac_save_filter` (l.301), l.1088 |
| hisilicon/hns3 | PF | per-vport private quota `priv_umv_size` + shared pool `share_umv_size` (see notes); own MAC counts. Default when firmware gives nothing: `HCLGE_DEFAULT_UMV_SPACE_PER_PF` = 3072/8 = 384 for the whole PF incl. its VFs. | `hclge_add_uc_addr_common`: `dev_err "UC MAC table full(%u)"` (once), -ENOSPC; sync loop stops; `hclge_update_overflow_flags` sets `HNAE3_OVERFLOW_UPE`; `hclge_sync_vport_promisc_mode` then enables **unicast promisc** for the PF. Unsynced entries retried every service-task period. | no | `E/hisilicon/hns3/hns3_enet.c:hns3_nic_set_rx_mode` (l.960); `hns3pf/hclge_main.c:hclge_add_uc_addr_common` (l.6376-6389), `hclge_sync_vport_mac_list` (l.6555), `hclge_update_overflow_flags` (l.6677), `hclge_sync_vport_promisc_mode` (l.10355-10360) |
| hisilicon/hns3 | VF | same quota formula, evaluated on the PF for the VF's vport (`priv_umv_size` private + shared pool) | VF mailbox `HCLGE_MBX_MAC_VLAN_UC_ADD` only queues on the PF (returns 0 - VF never sees the failure). PF logs `"UC MAC table full(%u)"` and sets `HNAE3_OVERFLOW_UPE` on the VF vport; promisc fallback **only if `vport->vf_info.trusted`**, untrusted VF: silent drop, retried forever. | no | `hns3vf/hclgevf_main.c:hclgevf_add_uc_addr` (l.998), `hclgevf_sync_mac_list` (l.1140); `hns3pf/hclge_mbx.c:hclge_set_vf_uc_mac_addr` (l.382); `hclge_main.c` l.10366-10372 |
| huawei/hinic | PF | unknown (not found): no constant in driver; one `HINIC_PORT_CMD_SET_MAC` per (MAC, VLAN) pair, limit lives in firmware | Firmware error -> `dev_err "Failed to change MAC, err: %d, status: 0x%x, out size: 0x%x"`, `netif_err "Failed to add mac"`, -EFAULT -> sync aborts at that address. In addition no `IFF_UNICAST_FLT`: core forces `IFF_PROMISC` -> `HINIC_RX_MODE_PROMISC`, so a PF with any extra MAC is promiscuous anyway. | no | `E/huawei/hinic/hinic_main.c:set_rx_mode` (l.780-789), `add_mac_addr` (l.655), `hinic_set_rx_mode` (l.803-806); `hinic_port.c:change_mac` (l.35-77) |
| huawei/hinic | VF | unknown (not found): firmware-limited; PF proxy adds no quota | Same firmware error path. If the PF assigned the VF MAC and VF is untrusted: PF `dev_warn "PF has already set VF %d MAC address"`, VF `dev_warn "PF has already set VF mac, ignore set operation"`, `change_mac` returns `HINIC_PF_SET_VF_ALREADY` (4, non-zero) -> treated as error by `__hw_addr_sync_dev`, never synced. VF never requests promisc (`if (!HINIC_IS_VF(...)) rx_mode |= PROMISC`) => silent drop. | no | `hinic_sriov.c:hinic_set_vf_mac_msg_handler` (l.340-372); `hinic_port.c:change_mac` (l.66-70); `hinic_main.c` l.803-806 |
| huawei/hinic3 | PF | unknown (not found): no constant; `L2NIC_CMD_SET_MAC` per address, limit in firmware | `hinic3_set_mac`: `dev_err "Failed to update MAC, err: %d, status: 0x%x"`, `netdev_err "Failed to add mac"`; `hinic3_mac_filter_sync` then **removes all previously synced uc MACs** ("there were errors, delete all mac in hw") and `hinic3_mac_filter_sync_all` sets `HINIC3_PROMISC_FORCE_ON` if firmware feature `HINIC3_NIC_F_PROMISC` -> promisc. `IFF_UNICAST_FLT` is set. | no | `E/huawei/hinic3/hinic3_netdev_ops.c:hinic3_nic_set_rx_mode` (l.839); `hinic3_filter.c:hinic3_mac_filter_sync` (l.243-268), `hinic3_mac_filter_sync_all` (l.279-297); `hinic3_nic_cfg.c:hinic3_set_mac` (l.322-332); `hinic3_main.c:284` |
| huawei/hinic3 | VF | unknown (not found): firmware-limited | Same error logs; on VF existing uc MACs are kept ("VF does not support promiscuous mode, don't delete any other uc mac"), the failed batch is dropped and retried; `PROMISC_FORCE_ON` only if firmware reports `HINIC3_NIC_F_PROMISC` for that function. PF-assigned MAC + VF: -EADDRINUSE, `dev_warn "PF has already set VF mac, Ignore set operation"`. | no | `hinic3_filter.c` l.250-253; `hinic3_nic_cfg.c:hinic3_check_vf_set_by_pf` (l.255), l.330-333 |

## Notes

### marvell/octeontx2
- Capacity = `pf->flow_cfg->ucast_flt_cnt` MCAM entries dedicated to DMAC matches (`otx2_flows.c:otx2_mcam_entry_init`
  requests `ucast_flt_cnt + OTX2_MAX_VLAN_FLOWS + total_vfs*OTX2_PER_VF_VLAN_FLOWS` entries from the AF). If the AF
  returns fewer, `netdev_info "Unable to allocate MCAM entries for ucast, vlan and vf_vlan"`, `OTX2_FLAG_UCAST_FLTR_SUPPORT`
  stays clear, `IFF_UNICAST_FLT` is not set (`otx2_pf.c:3255`) and the PF behaves like the VF row (core-forced promisc).
- `unicast_filter_count` is a driver-specific devlink u8 param (`otx2_devlink.c`), changeable only with no active ntuple
  rules; it reallocates the MCAM block. The generic `max_macs` param is not registered.
- The primary MAC is not in `dev->uc` and does not count. The separate CGX/RPM DMAC filter (`otx2_dmac_flt.c`,
  `dmacflt_max_flows` from `cgx_max_dmac_entries_get`) is an ethtool ntuple feature, not the uc list; when it is in use
  `otx2_add_macfilter` prints `netdev_warn "Add %pM to CGX/RPM DMAC filters list as well"`.
- VF promisc needs both `rvu->hw->cap.nix_rx_multicast` and `ndo_set_vf_trust`; otherwise the VF only ever receives its
  own MAC (plus mcast/bcast). A VF as bridge uplink therefore cannot carry other MACs unless trusted.

### cavium/thunder
- Per-LMAC DMAC CAM depth = `RX_DMAC_COUNT (32) / bgx->lmac_count` (`thunder_bgx.c:1088`), e.g. 8 with 4 LMACs; it is
  shared by all VFs mapped to the LMAC and holds the LMAC MAC plus multicast addresses only. Unicast filtering of extra
  MACs does not exist; the only way to receive them is the forced promiscuous mode, which disables DMAC filtering for
  every VF on that LMAC.

### hisilicon/hns3
- `max_umv_size` = size the firmware actually allocated in `hclge_set_umv_space` (warning
  `"failed to alloc umv space, want %u, get %u"` if less). Wanted size = `cfg.umv_space` from the firmware config block
  (`hclge_parse_cfg`, l.1224) or `dev_specs.umv_size` (l.1325), default `HCLGE_UMV_TBL_SIZE 3072 / HCLGE_MAX_PF_NUM 8`
  = 384.
- `priv_umv_size = max_umv_size / (num_alloc_vport + 1)`; `share_umv_size = priv_umv_size + max_umv_size % (num_alloc_vport + 1)`,
  with `num_alloc_vport` = 1 (PF) + number of VFs. A vport is "full" when `used_umv_num >= priv_umv_size` **and**
  `share_umv_size == 0` (`hclge_is_umv_space_full`), so a single vport can absorb the whole shared pool. The vport's own
  MAC uses one slot (`hns3_nic_uc_unsync` refuses to remove `dev_addr`).
- Example: 384 entries, PF + 2 VFs: priv = 384/4 = 96 each, shared = 96 + 0 = 96.
- Adds are asynchronous (service task); `bridge fdb add` always returns 0. Overflow is visible only as the PF-side
  `dev_err "UC MAC table full(%u)"` and, for the PF or a trusted VF, a switch to unicast promiscuous mode
  (`HNAE3_UPE = HNAE3_USER_UPE | HNAE3_OVERFLOW_UPE`).

### huawei/hinic, hinic3
- Neither driver holds a table size; the management firmware answers each `SET_MAC`. hinic programs one entry per
  configured VLAN for every MAC (`add_mac_addr` loops over `vlan_bitmap`), so VLAN filters multiply the consumption.
- hinic has no `IFF_UNICAST_FLT`: on the PF every extra MAC also enables firmware promisc; on the VF the promisc bit is
  never requested, so an entry the firmware refuses is simply not received.
- hinic3 sets `IFF_UNICAST_FLT`; its fallback to promisc depends on the firmware feature bit `HINIC3_NIC_F_PROMISC`
  (`hinic3_test_support`). On a PF the first failed add flushes all earlier uc entries from hardware before forcing
  promisc, so a partially filled table never persists.

---

## Unicast-filter capacity per driver (cloud NICs and others)

Source: mainline sparse checkout under the kernel tree (drivers/net/ethernet, net/core), read 2026-09-02.
Kernel path for `bridge fdb add <mac> dev X self permanent`: rtnl_fdb_add (NTF_SELF, no ndo_fdb_add) -> ndo_dflt_fdb_add -> dev_uc_add_excl -> __dev_set_rx_mode
(net/core/dev_addr_lists.c). __dev_set_rx_mode: if the netdev lacks IFF_UNICAST_FLT, netif_uc_promisc_update() flips IFF_PROMISC
(logs "<dev>: entered promiscuous mode", dev.c __dev_set_promiscuity); then ndo_set_rx_mode is called if present. No driver below
registers devlink `max_macs` (only mellanox/mlx4 and mlx5 do: grep DEVLINK_PARAM_GENERIC_ID_MAX_MACS).

| driver | role | capacity | overflow behaviour | devlink max_macs | evidence (file:function) |
|---|---|---|---|---|---|
| amazon/ena | PF and VF (same driver) | 0 usable: no ndo_set_rx_mode, dev->uc never read | Kernel accepts entries (IFF_UNICAST_FLT set, so no promisc fallback either); nothing programmed, no log | no | amazon/ena/ena_netdev.c: ena_netdev_ops (no rx_mode op), line 4048 `IFF_UNICAST_FLT` |
| alibaba/eea | PF (only role) | 0 usable: no ndo_set_rx_mode | Same as ena: accepted by kernel, never programmed, no promisc, no log | no | alibaba/eea/eea_net.c: eea_netdev_ops, line 624 `IFF_UNICAST_FLT` |
| amd/pds_core + pensando/ionic | PF and VF (ionic binds both PCI IDs; pds_core has no netdev) | `lif->identity->eth.max_ucast_filters` (FW LIF identity, per LIF), shared by unicast + multicast, own dev_addr counts as one | When nucast+nmcast >= max: add returns -ENOSPC internally, filter stays STATE_NEW, error swallowed (returns 0, so kernel marks it synced); ionic_lif_rx_mode then sets IONIC_RX_MODE_F_PROMISC and F_ALLMULTI (netdev_dbg only, no warn); retried only after a delete | no | pensando/ionic/ionic_lif.c: ionic_ndo_set_rx_mode, ionic_lif_rx_mode (lines 1382-1392); ionic_rx_filter.c: ionic_lif_filter_add (lines 353-355, 395-405) |
| cisco/enic | PF and VF (dynamic vNIC uses same ops) | ENIC_UNICAST_PERFECT_FILTERS = 32 | netdev_uc_count > 32: enic_set_rx_mode sets promisc=1 -> enic_dev_packet_filter(promisc) and skips __dev_uc_sync (no address programmed, no log). Guard in enic_uc_sync: at 32 synced it warns "Registering only %d out of %d unicast addresses" and returns -ENOSPC (stops sync) | no | cisco/enic/enic_res.h:27; enic_main.c: enic_set_rx_mode (1111-1136), enic_uc_sync (1008-1025) |
| freescale/enetc (v1, enetc_pf.c) | PF | 1 exact-match entry (EMETC_MAC_ADDR_FILT_RES) iff netdev_uc_count == 1; else 64-bin unicast hash (ENETC_MADDR_HASH_TBL_SZ = 64), unbounded | No truncation: >1 addresses all land in the hash (imprecise: other MACs hashing to set bins are admitted). EM write failure logs "fallback to HT filt (%d)" | no | freescale/enetc/enetc_pf.c: enetc_pf_set_rx_mode (115-170), enetc_sync_mac_filters (63-113); enetc.h:27 |
| freescale/enetc (v4, enetc4_pf.c) | PF | MAFT exact table, size from PSIMAFCAPR_NUM_MAC_AFTE cap register (code comment: 4 entries), minus entries already in use | mac_cnt > available -> -ENOSPC -> silent fallback to the 64-bin unicast hash filter for the whole list; no log | no | freescale/enetc/enetc4_pf.c: enetc4_pf_add_maft_entries (97-130), enetc4_pf_set_mac_filter (198-215), enetc4_pf_set_rx_mode (506-541); line 428 |
| freescale/enetc | VF (enetc_vf.c) | 0 usable: no ndo_set_rx_mode, no IFF_UNICAST_FLT | Kernel flips IFF_PROMISC ("entered promiscuous mode"), but VF has neither ndo_change_rx_flags nor ndo_set_rx_mode -> HW untouched; mailbox to PF only carries ENETC_MSG_SET_PRIMARY_MAC | no | freescale/enetc/enetc_vf.c: enetc_ndev_ops (214-223); enetc_msg.c: enetc_msg_handle_mac_filter (91-101) |
| fungible/funeth | PF and VF (same driver) | 0 usable: no ndo_set_rx_mode, no IFF_UNICAST_FLT | Kernel flips IFF_PROMISC (log), nothing programmed (no ndo_change_rx_flags either) | no | fungible/funeth/funeth_main.c: fun_netdev_ops (1323-1339) |
| microsoft/mana | VF (only role in Azure guest) | 0 usable: no ndo_set_rx_mode, no IFF_UNICAST_FLT | Kernel flips IFF_PROMISC (log), nothing programmed | no | microsoft/mana/mana_en.c: mana_devops (1011-1025); gdma_main.c:2698 mana_sriov_configure |
| wangxun/ngbe (libwx) | PF | free RARs: NGBE_RAR_ENTRIES = 32 minus own MAC (RAR0), minus one RAR per VF MAC, minus VF macvlans in use (wx_available_rars counts state == 0) | netdev_uc_count > free RARs -> wx_write_uc_addr_list returns -ENOMEM -> nothing written, pool 0 gets WX_PSR_VM_L2CTL_UPE (unicast promiscuous), no log | no | wangxun/ngbe/ngbe_type.h:105; libwx/wx_hw.c: wx_set_rx_mode (1687-1777, esp. 1746-1750), wx_write_uc_addr_list (1083-1100), wx_available_rars (1061) |
| wangxun/txgbe (libwx) | PF | same formula with TXGBE_RAR_ENTRIES = 128 | identical to ngbe (UPE fallback, silent) | no | wangxun/txgbe/txgbe_type.h:194; libwx/wx_hw.c as above |
| wangxun/ngbevf, txgbevf (libwx) | VF | PF-side pool shared by ALL VFs: num_rar_entries - (WX_MAX_PF_MACVLANS 15 + 1 + num_vfs) => ngbe 16 - num_vfs, txgbe 112 - num_vfs, first come first served | VF has NO ndo_set_rx_mode: dev->uc is only pushed at open/reset (wx_configure_vf -> wx_set_rx_mode_vf), so a runtime `fdb add` changes nothing until the next open. No IFF_UNICAST_FLT -> kernel flips IFF_PROMISC; at next open the VF requests WXVF_XCAST_MODE_PROMISC and the PF grants UPE for that pool without trust check. Per-address: PF answers NACK/-ENOSPC and logs "VF %d request MACVLAN filter but there is no space" (or "... but is denied" if PF set the VF MAC); VF ignores the return value (silent) | no | libwx/wx_vf_common.c: wx_set_rx_mode_vf (156-181), wx_configure_vf (216); wx_vf_lib.c: wx_write_uc_addr_list_vf (90-108); wx_vf.c: wx_set_uc_addr_vf (349-375); wx_sriov.c: wx_alloc_vf_macvlans (22-45), wx_set_vf_macvlan (538-580), wx_set_vf_macvlan_msg (639-672), wx_update_vf_xcast_mode (709-750); ngbevf/ngbevf_main.c:45, txgbevf/txgbevf_main.c:41 |

## Notes

**Kernel side (applies to every row).** dev_uc_add_excl always succeeds if the address is new, regardless of the driver
(net/core/dev_addr_lists.c:792). __hw_addr_sync_dev (dev_addr_lists.c:317) stops at the first sync() error, leaves the
remaining entries unsynced (sync_cnt == 0) and retries them at the next ndo_set_rx_mode call; the return value is dropped by
every driver here. A driver that returns 0 despite not programming the address (ionic, wangxun VF) makes the kernel believe
the address is in hardware.

**ena / eea.** No rx-mode handling at all; both set IFF_UNICAST_FLT, so the kernel neither programs anything nor falls back
to promiscuous. `bridge fdb add ... self` succeeds and is a no-op on the wire. The ENA admin interface has no filter/promisc
command (ena_admin_defs.h only carries the device's own MAC at line 555).

**ionic.** Capacity is `eth.max_ucast_filters` from the LIF identity (ionic_if.h:570), printed at probe with dynamic debug
("eth.max_ucast_filters %d", ionic_lif.c:4015). The check is `nucast + nmcast >= nfilters` (ionic_lif.c:1384 and
ionic_rx_filter.c:354), so unicast and multicast share the budget and reaching the limit exactly already flips the LIF into
PROMISC|ALLMULTI. The VF netdev is the same driver with its own LIF identity; the PF's ndo_set_vf_mac only sets the primary MAC.
pds_core itself exposes no netdev and has no unicast-list code.

**enic.** 32 perfect unicast filters (enic_res.h). Above 32 the device is switched to promiscuous via CMD_PACKET_FILTER and the
uc list is not programmed at all. vnic_dev_add_addr logs "Can't add addr [%pM], %d" on a firmware error, but enic_uc_sync ignores
that return. sriov_configure exists but is not yet wired into enic_driver (enic_main.c:2918 comment).

**enetc.** PF v1: exactly one address is exact-matched; two or more addresses go into a 64-bit hash (never rejected, never
logged, may admit foreign MACs). PF v4 (i.MX95): `maft_num_entries` from PSIMAFCAPR_NUM_MAC_AFTE (enetc4_pf.c:428); overflow
falls back to the same 64-bit hash silently. VF: no rx-mode op at all; only the primary MAC reaches the PF via mailbox.

**wangxun PF.** RAR table shared between PF primary MAC, PF secondary unicast (pool VMDQ_P(0)), each VF's primary MAC and VF
macvlans. Formula for PF uc capacity: `free = num_rar_entries - 1 - num_vfs - (VF macvlans in use)`; if netdev_uc_count > free,
nothing is written and pool 0 gets UPE (unicast promiscuous) silently (wx_hw.c:1746-1750). ngbe: 32 RARs, txgbe: 128 RARs.

**wangxun VF.** Pool of `num_rar_entries - (15 + 1 + num_vfs)` macvlan slots for all VFs together (wx_sriov.c:30). Each rx-mode
pass first clears the VF's macvlans (index <= 1) and re-adds the list. The VF drivers do not register ndo_set_rx_mode, so
dev->uc only reaches the PF on open/reset; between those, entries are accepted by the kernel and idle. Because IFF_UNICAST_FLT
is not set, a non-empty dev->uc makes the kernel set IFF_PROMISC, which at the next open turns into XCAST PROMISC = UPE on the
VF pool (wx_sriov.c:734-738, no trust gating) -- effectively unicast-promiscuous rather than a filter list.

**mana / funeth.** No rx-mode op, no IFF_UNICAST_FLT: the kernel logs "entered promiscuous mode" and sets the flag, but no
ndo_change_rx_flags/ndo_set_rx_mode exists, so the hardware filter is untouched and the fdb entries are dead.
