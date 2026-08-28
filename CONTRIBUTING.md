# Contributing

## Build

```
cargo build --release
install -m 755 target/release/sriov-mac-sync    /usr/local/sbin/
install -m 644 dist/sriov-mac-sync.service      /etc/systemd/system/
install -m 644 dist/sriov-mac-sync.conf.example /etc/sriov-mac-sync.conf  # optional
systemctl enable --now sriov-mac-sync
```

One dependency, `libc`. For a binary that runs on an older distribution than the
one you built on, `RUSTFLAGS="-C target-feature=+crt-static" cargo build
--release`.

## Packaging

Everything a release ships — static binaries, `.deb` and `.ipk`, for both
architectures — from a machine with the two musl targets installed:

```
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
./dist/package.sh
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
`cortex-a53` or `cortex-a72` build just as well.

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
