# Contributing

## Build

```
cargo build --release
install -m 755 target/release/sriov-mac-sync    /usr/local/sbin/
install -m 644 dist/sriov-mac-sync.service      /etc/systemd/system/  # see below
install -m 644 dist/sriov-mac-sync.conf.example /etc/sriov-mac-sync.conf  # optional
systemctl enable --now sriov-mac-sync
```

A unit in `/etc/systemd/system/` takes precedence over the packaged one in
`/usr/lib/systemd/system/` for good: install a `.deb` later and `dpkg -l`
reports the new version while the machine goes on running whatever the
`/etc` unit points at. Remove it before switching to packages — the
postinst says so too.

One dependency, `libc`. For a binary that runs on an older distribution than the
one you built on, `RUSTFLAGS="-C target-feature=+crt-static" cargo build
--release`.

## Packaging

Everything a release ships — static binaries, `.deb`, `.ipk` and `.apk`, for
both architectures — from a machine with the two musl targets installed. The
`.apk` is what OpenWrt 24.10 and newer install, and the README's download URL
names it, so `APK=` is not optional: without it `package.sh` builds everything
else and the release ships a documented download that 404s.

```
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
APK=/path/to/apk.static ./dist/package.sh
```

The result lands in `dist/out`. Nothing is cross-compiled against a sysroot or a
container; the musl targets link with `rust-lld` and need no toolchain beyond
cargo. The packages install the binary to `/usr/sbin`, where a package owns it,
rather than the `/usr/local/sbin` a source build uses.

`x86_64` and `aarch64` are the architectures that exist. There is no 32-bit ARM
build, and that is not an oversight: SR-IOV needs a PCIe root complex that
implements it, and hardware pairing that with an armv7 CPU is not something you
will meet. The `.ipk` is built for `x86_64` and `aarch64_generic`; because the
binary is static, `opkg install --force-architecture` puts the aarch64 one on a
`cortex-a53` or `cortex-a72` build just as well. The `.apk` is built for the
same two.

## Tests

```
cargo test        # topology and parsing logic, no hardware needed
cargo clippy --all-targets -- -D warnings
cargo fmt --check
sudo bench/integration.sh target/release/sriov-mac-sync   # against a real kernel
```

The parts most likely to be wrong on unfamiliar hardware are the ones that
decide *which way the wire is* and *which addresses count*, and those are pure
functions over a topology the tests build by hand — bonds, stacked VLAN
interfaces, vnet bridges, a second unrelated bridge, a bridge carrying its own
address. The integration script holds the built binary to every mode's promise
against the kernel itself, in a throwaway network namespace — real netlink, real
`/sys`, veth standing in for the uplink — and refuses to run on a host where a
daemon is already at work.

`bench/trial.py` puts a *running* daemon on trial against real hardware; see
[docs/internals.md](docs/internals.md).

CI runs all of the above, an MSRV build and a static build on every push to main
and on pull requests.

## Releasing

The order matters, and every step has a reason it is where it is.

1. **Push the work first, and wait for CI.** A version bump on top of a red
   build is a release nobody can trust. Tests here guard the README, the manual
   page, the unit file and the example configuration against the code, so even
   a documentation-only change can fail — run `cargo test` before every push.
2. **Bump the version** in `Cargo.toml` (`YEAR.MONTH.N`), commit, push, wait
   for CI again. The bump comes before the hardware round because any commit
   after the round voids it.
3. **Put it on real hardware.** No release goes out without a full
   `bench/trial.py` run on all four driver families — `mlx5`, `mlx4`, `i40e`,
   `ixgbe` — *with the bumped binary the release will ship*.
4. **Build the artefacts:** `APK=/path/to/apk.static ./dist/package.sh`. Without
   apk-tools v3 the script prints a SKIPPED line for the `.apk` packages but
   still exits 0 — easy to miss — and the OpenWrt 24.10 install path the README
   documents then 404s at `/releases/latest/download/`. Debian has no such
   package; a static `apk.static` from Alpine's `apk-tools-static` does the
   job.
5. **Tag and publish:** `git tag -a vYEAR.MONTH.N`, push the tag,
   `gh release create ... dist/out/*`.
6. **`cargo publish`.** The README advertises `cargo install sriov-mac-sync`,
   and `readme = "README.md"` makes this file's twin the crates.io page. Skip
   this and the registry quietly serves an older build to anyone who follows
   the README — which is exactly what happened between 2026.8.2 and 2026.8.4.
   Check `cargo publish --dry-run` first; a published version can be yanked but
   never replaced.
7. **Roll out the package**, not a hand-copied binary: `dpkg -i` the built
   `.deb`. Copying the bare binary over a package-managed path leaves
   `dpkg -V` reporting a modified file, and the next `apt` upgrade silently
   reverts it.

If the release moves `PORTS_FORMAT` — the first line of the quiet-keep memory
file, `sriov-mac-sync ports N` — say so in the release notes. A file the new
build does not recognise is no memory at all, which is deliberate: reading old
stamps under new rules is worse than starting again. The visible effect is that
the first restart on each node re-learns its keeps, so a guest that was silent
across exactly that window loses its entry until it speaks.
