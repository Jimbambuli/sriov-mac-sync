# sriov-mac-sync

Make hosts that sit *behind* a Linux bridge reachable from an SR-IOV virtual
function.

```
        +-----------+  +-----------+  +-----------+  +-----------+
guests  |   guest   |  |   guest   |  |    VM     |  | container |
        +-----+-----+  +-----+-----+  +-----+-----+  +-----+-----+
              | VF1          | VF2          | tap          | veth
              |              |   +----------+--------------+-------+
bridge        |              |   |               br0               |
              |              |   +----+-----------------------+----+
              |              |        | PF                    | eth1
         +----+--------------+--------+----+             +----+----+
NICs     |              NIC 1              |             |  NIC 2  |
         +----------------+----------------+             +----+----+
                          |                                   |
wires                  wire A                              wire B
```

`VF1` and `VF2` go straight to their guests, past `br0`. NIC 1 is a switch in
its own right, and the only addresses it knows are the three interfaces hanging
off it — `PF`, `VF1`, `VF2`. Everything in the box above is invisible to it, so
a frame from `VF1` to the `tap`, the `veth`, the host or wire B misses and goes
out on the wire, where none of them are.

You notice it like this:

- A guest with a VF reaches everything on the physical switch, but not a
  container, a second VM, or a device on another NIC in the same host.
- Ping times out. Nothing is logged, nothing is firewalled.
- ARP or ND for the very same address resolves fine — broadcast is flooded to
  every vport — which makes it look like MTU or filtering. It is neither.

The fix is to put those addresses in the uplink's unicast filter, which iproute2
spells `bridge fdb add <mac> dev <uplink> self permanent`. That works for
addresses you know in advance; guests are knowable, wireless clients coming and
going are not. This daemon watches what the bridges learn and keeps the filter
in step.

Confirmed end to end on ConnectX-4 Lx (`mlx5_core`), ConnectX-3 Pro
(`mlx4_core`), Intel 82599ES (`ixgbe`) and X710 (`i40e`). The daemon itself is
driver-agnostic. None of those can present a VF as a real bridge port, which is
the proper answer where the hardware has it — see
[not a switchdev replacement](#not-a-switchdev-replacement).

## Install

Statically linked, depends on nothing — no runtime, no libc, no configuration.

```
# Debian, Ubuntu, Proxmox VE — binary, systemd unit, commented config; enabled and started
curl -LO https://github.com/Jimbambuli/sriov-mac-sync/releases/latest/download/sriov-mac-sync_amd64.deb
dpkg -i sriov-mac-sync_amd64.deb

# OpenWrt 24.10+ (apk) — the flags are the price of a package outside a repository
curl -LO https://github.com/Jimbambuli/sriov-mac-sync/releases/latest/download/sriov-mac-sync_x86_64.apk
apk add --allow-untrusted --force-non-repository ./sriov-mac-sync_x86_64.apk

# OpenWrt 23.05 and older (opkg)
opkg install ./sriov-mac-sync_x86_64.ipk

# anywhere else — x86_64 or aarch64
curl -LO https://github.com/Jimbambuli/sriov-mac-sync/releases/latest/download/sriov-mac-sync-$(uname -m)
install -m 755 sriov-mac-sync-$(uname -m) /usr/local/sbin/sriov-mac-sync
```

`cargo install sriov-mac-sync` works too. Building from source is in
[CONTRIBUTING.md](CONTRIBUTING.md). File names carry no version — they are
fetched through `/releases/latest/download/`, so these commands do not go stale.

## Use

Look before installing:

```
sriov-mac-sync --check              does this NIC accept filter entries at all?
sriov-mac-sync --once --dry-run     what would be registered, and why
sriov-mac-sync --status             what is detected, wanted and registered
```

If `--check` passes and `--dry-run` names the addresses you expected, enable the
unit. `--check` only proves the *kernel* took the entry — whether the card acts
on it is [a question for traffic](#does-it-work-on-your-card).

```
sriov-mac-sync --once               reconcile and exit; the exit code says
                                    whether every change went through
sriov-mac-sync --flush              remove what this daemon registered
sriov-mac-sync --interval SEC       seconds between timed passes (default 300)
sriov-mac-sync --max NUM            warn above this many addresses (default 128)
sriov-mac-sync --timings            after every pass, what each phase cost
sriov-mac-sync --extra <macs>       register these unconditionally, for a
                                    device that never speaks first
sriov-mac-sync --exclude <macs>     never register these
sriov-mac-sync -v, --verbose ...    explain what is skipped, and list addresses
sriov-mac-sync --version            print the version
```

Uplinks are found automatically: any interface with VFs — or itself a VF — that
ends up in a bridge, following bonds. Override with `--pair DEV:BRIDGE`.
`/etc/sriov-mac-sync.conf` may set `PAIRS`, `RESYNC`, `MAX_MACS`, `EXCLUDE` and
`EXTRA`; a commented copy ships as `dist/sriov-mac-sync.conf.example`, and the
Debian package installs `sriov-mac-sync(8)`.

## What gets registered

Only what is reachable *behind* the bridge: everything learnt on ports other
than the uplink, everything learnt by bridges stacked on top of it (VLAN-aware
setups, Proxmox SDN vnets — a container's address is often never learnt by the
lower bridge at all), and the host's own L3 endpoints there.

Deliberately **not** registered: anything learnt on the uplink itself. Those
peers live on the wire, and registering them would divert their traffic to the
bridge, which cannot send it back out of the port it came in on. Nor a VF's own
address — that tells the eSwitch the guest lives behind the bridge, and its
traffic is sent past it.

Nothing is decided by interface name. The direction of the uplink comes from
the device stacking the kernel reports.

## Does it work on your card?

Whether the NIC acts on an accepted address is a property of the driver and
there is no way to ask. Test with traffic:

1. From inside the VF's guest, ping something behind the bridge — should fail.
2. `bridge fdb add <that mac> dev <uplink> self permanent`
3. Ping again — should work.
4. `bridge fdb del ...` — should fail again.

If step 3 changes nothing, this daemon will not help you. Reports for other
hardware are welcome; those four steps are the whole test.

## Limits

- **The filter list is finite, and past its end the driver drops addresses
  silently.** Where the card reports its capacity through devlink the daemon
  asks and warns against that; where it does not, it assumes 128, which is what
  a ConnectX-4 Lx holds. `--max` overrides both.
- **It knows nothing about VLANs.** One entry covers a MAC in every VLAN. So
  registering is all-or-nothing, and an address learnt on the uplink in *any*
  VLAN is left out entirely.
- **A quiet guest stays registered.** Bridge entries age out, 300 s by
  default, but a router that caches ARP longer keeps sending unicast without
  asking again (FreeBSD holds it 1200 s), and those frames went out on the
  wire. A miss is a delivery only for peers on the uplink port's own wire;
  everywhere the bridge would have carried the frame, it is a blackhole. So
  an aged-out address is simply kept while the port it was learnt behind
  still hangs in the bridge - ageing is the bridge managing its table, not
  news about the device. The entry goes when its port goes, when the
  address moves out to the wire, or under filter pressure: as the list
  nears its capacity the longest-missing entries are released first, and
  every fresh learn makes an entry young again. The memory lives in the
  daemon: after a restart, or beside a hand-run `--once`, an already-aged
  address falls back to the old behaviour until the next ARP. `EXTRA` still
  pins an address outright.
- **Stopping the daemon leaves the filter as it is**, which is what makes a
  restart invisible to every guest. `--flush` clears the card.
- **It only removes what it added**, from a note in `/run/sriov-mac-sync/`.
  Entries put there by anything else are left alone.

Driver-specific behaviour — what ixgbe costs, why a VF makes a better bridge
port than a PF, Intel's VF link state, FreeBSD guests — is in
[docs/hardware-notes.md](docs/hardware-notes.md). How it works inside, what a
pass costs, and the trial harness are in
[docs/internals.md](docs/internals.md).

## Not a switchdev replacement

Where the hardware can represent VFs as real bridge ports, use that instead.
This exists for the cards that cannot, and they are not a shrinking remainder:
`ixgbe`, `i40e` and `mlx4` carry no switchdev support at all — not *yet*, but at
all. `mlx5` and `ice` do, but on `mlx5` it is a per-card property; a ConnectX-4
Lx answers the mode change with `Failed setting eswitch to offloads` on
firmware 14.32.1912, with or without a bound VF.

Do not try it on a machine you care about just to see. The driver tears the
legacy eswitch down *before* building the offloads one, and when the second step
fails the first is not undone: the VFs stay dark and the host needs a reboot.

## How this was written

Most of the code, the tests and much of this documentation were written by
Claude, Anthropic's model, working from my direction and on my hardware. I set
the goals, reviewed the work, ran the machines and decided what shipped. The
commit trailers say so, and so does the contributor list.

What is not generated is the evidence. Every hardware claim in these pages is a
measurement taken on the cards named, across four driver families, with the
trial harness in `bench/` and integration checks against a real kernel. Where
something could not be measured, it says so.

## Versions

Dated: `YEAR.MONTH.N`, where `N` counts releases within that month — the number
tells you how old a build is, which is the question people ask about a daemon.
Releases up to 1.5.0 used semantic versions; `dpkg`, `apk` and cargo all order
2026 after 1, so upgrading works.

## License

MIT.
