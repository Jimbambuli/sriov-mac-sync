#!/bin/sh
# Build the release artefacts: a static binary, a .deb and an OpenWrt .ipk,
# for x86_64 and aarch64. Everything lands in dist/out/.
#
#   ./dist/package.sh [version]
#
# Needs cargo with the two musl targets installed, plus ar, tar, gzip and
# dpkg-deb. The binaries are static, so the packages depend on nothing at all -
# which is why the same .ipk runs on any aarch64 OpenWrt regardless of the CPU
# name opkg was configured with.
set -eu

# Not the builder's umask: it ends up on every directory and file in the
# package, and a 0002 umask ships world-writable-by-group directories.
umask 022

cd "$(dirname "$0")/.."

VERSION=${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)}
OUT=dist/out
MAINT="Jimbambuli <30672094+Jimbambuli@users.noreply.github.com>"
DESC="Make hosts behind a Linux bridge reachable from an SR-IOV virtual function"
LONG=" A NIC in SR-IOV mode forwards between its functions with a table it is
 told about, not one it learns, so a peer behind the host's bridge is a miss and
 the frame leaves on the wire. This daemon watches the bridge's forwarding
 database over netlink and keeps the uplink's unicast filter in step with it."

# The file names carry no version on purpose: they are downloaded through
# /releases/latest/download/, so the command in the README stays the same
# forever. Which version a file is stays inside it, where dpkg -I, apk info and
# opkg info can all say so.
rm -rf "$OUT"
mkdir -p "$OUT"

build() {   # target
	echo "== building $1"
	RUSTFLAGS="-C linker=rust-lld" cargo build --release --target "$1" >/dev/null
	cp "target/$1/release/sriov-mac-sync" "$OUT/sriov-mac-sync-$2"
}

# The repository's unit installs from /usr/local/sbin, which is where a build
# from source belongs. A package owns /usr/sbin instead.
unit_for_package() {
	sed 's|/usr/local/sbin/sriov-mac-sync|/usr/sbin/sriov-mac-sync|' \
		dist/sriov-mac-sync.service
}

deb() {     # arch-suffix debian-arch
	echo "== .deb for $2"
	root=$(mktemp -d)
	chmod 755 "$root"   # mktemp makes it 0700, and in a .deb that is the mode of /
	mkdir -p "$root/DEBIAN" "$root/usr/sbin" "$root/usr/lib/systemd/system" \
		"$root/etc" "$root/usr/share/doc/sriov-mac-sync"

	install -m 755 "$OUT/sriov-mac-sync-$1" "$root/usr/sbin/sriov-mac-sync"
	# /usr/lib, not /lib: on a merged-usr system - which every supported
	# Debian now is - /lib is an alias, and shipping files through an aliased
	# path is what dpkg spent the transition learning to refuse.
	unit_for_package > "$root/usr/lib/systemd/system/sriov-mac-sync.service"
	chmod 644 "$root/usr/lib/systemd/system/sriov-mac-sync.service"
	# Every line in it is commented out, so shipping it changes no behaviour -
	# it is there to be read and edited in place.
	install -m 644 dist/sriov-mac-sync.conf.example "$root/etc/sriov-mac-sync.conf"
	install -m 644 README.md "$root/usr/share/doc/sriov-mac-sync/README.md"
	install -m 644 LICENSE "$root/usr/share/doc/sriov-mac-sync/copyright"
	# Debian wants manual pages compressed, and -n so the timestamp inside the
	# gzip stream does not make two builds of the same source differ.
	mkdir -p "$root/usr/share/man/man8"
	gzip -9nc dist/sriov-mac-sync.8 > "$root/usr/share/man/man8/sriov-mac-sync.8.gz"
	chmod 644 "$root/usr/share/man/man8/sriov-mac-sync.8.gz"

	echo /etc/sriov-mac-sync.conf > "$root/DEBIAN/conffiles"
	cat > "$root/DEBIAN/control" <<EOF
Package: sriov-mac-sync
Version: $VERSION
Architecture: $2
Maintainer: $MAINT
Section: net
Priority: optional
Homepage: https://github.com/Jimbambuli/sriov-mac-sync
Description: $DESC
$LONG
EOF
	# Enabled and started, which is what installing a service on Debian means.
	# deb-systemd-invoke rather than systemctl start, because it is the one
	# that honours policy-rc.d - in a chroot or an image build, nothing should
	# come up.
	cat > "$root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
	if [ -x /usr/bin/deb-systemd-helper ]; then
		deb-systemd-helper unmask sriov-mac-sync.service >/dev/null || true
		deb-systemd-helper enable sriov-mac-sync.service >/dev/null || true
	fi
	if [ -d /run/systemd/system ]; then
		systemctl daemon-reload || true
		if [ -x /usr/bin/deb-systemd-invoke ]; then
			deb-systemd-invoke start sriov-mac-sync.service || true
		else
			systemctl enable --now sriov-mac-sync.service || true
		fi
	fi
	cat <<'MSG'
sriov-mac-sync is running. What it decided:

    sriov-mac-sync --status

It registers nothing it did not learn from the bridge, and removing this
package takes its entries back out of the card.
MSG
fi
EOF
	# Stop first, then flush: a running daemon would put back what --flush
	# removes on its very next pass. Removing the package undoes its effect on
	# the hardware, which is the other half of being allowed to start by
	# default.
	cat > "$root/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ]; then
	if [ -d /run/systemd/system ]; then
		deb-systemd-invoke stop sriov-mac-sync.service >/dev/null 2>&1 \
			|| systemctl stop sriov-mac-sync.service >/dev/null 2>&1 || true
	fi
	[ -x /usr/sbin/sriov-mac-sync ] && /usr/sbin/sriov-mac-sync --flush || true
fi
EOF
	cat > "$root/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
fi
if [ "$1" = purge ] && [ -x /usr/bin/deb-systemd-helper ]; then
	deb-systemd-helper purge sriov-mac-sync.service >/dev/null || true
	deb-systemd-helper unmask sriov-mac-sync.service >/dev/null || true
fi
EOF
	chmod 755 "$root/DEBIAN/postinst" "$root/DEBIAN/prerm" "$root/DEBIAN/postrm"

	dpkg-deb --root-owner-group --build "$root" \
		"$OUT/sriov-mac-sync_$2.deb" >/dev/null
	rm -rf "$root"
}

ipk() {     # arch-suffix opkg-arch
	echo "== .ipk for $2"
	root=$(mktemp -d)
	chmod 755 "$root"
	mkdir -p "$root/data/usr/sbin" "$root/data/etc/init.d" "$root/data/etc" "$root/control"

	install -m 755 "$OUT/sriov-mac-sync-$1" "$root/data/usr/sbin/sriov-mac-sync"
	install -m 755 dist/openwrt/sriov-mac-sync.init "$root/data/etc/init.d/sriov-mac-sync"
	install -m 644 dist/sriov-mac-sync.conf.example "$root/data/etc/sriov-mac-sync.conf"

	cat > "$root/control/control" <<EOF
Package: sriov-mac-sync
Version: $VERSION
Depends:
Section: net
Architecture: $2
Maintainer: $MAINT
Description: $DESC
$LONG
EOF
	cat > "$root/control/conffiles" <<'EOF'
/etc/sriov-mac-sync.conf
EOF
	# Same behaviour as the .deb: enabled and started. IPKG_INSTROOT is set
	# when the package is being unpacked into an image being built rather than
	# onto a running system, and then nothing may be started.
	cat > "$root/control/postinst" <<'EOF'
#!/bin/sh
[ -n "$IPKG_INSTROOT" ] && exit 0
/etc/init.d/sriov-mac-sync enable
/etc/init.d/sriov-mac-sync start
echo "sriov-mac-sync is running. What it decided:  sriov-mac-sync --status"
exit 0
EOF
	chmod 755 "$root/control/postinst"

	( cd "$root/data" && tar --owner=root --group=root -czf ../data.tar.gz ./* )
	( cd "$root/control" && tar --owner=root --group=root -czf ../control.tar.gz ./* )
	echo "2.0" > "$root/debian-binary"
	# opkg reads the members in order, so debian-binary has to come first.
	( cd "$root" && ar rc "sriov-mac-sync_$2.ipk" \
		debian-binary control.tar.gz data.tar.gz )
	mv "$root/sriov-mac-sync_$2.ipk" "$OUT/"
	rm -rf "$root"
}

apk() {    # arch-suffix apk-arch
	if [ -z "${APK:-}" ]; then
		echo "== .apk for $2 SKIPPED (no apk-tools with mkpkg; set APK=/path/to/apk)"
		return 0
	fi
	echo "== .apk for $2"
	root=$(mktemp -d)
	chmod 755 "$root"
	mkdir -p "$root/usr/sbin" "$root/etc/init.d"

	install -m 755 "$OUT/sriov-mac-sync-$1" "$root/usr/sbin/sriov-mac-sync"
	install -m 755 dist/openwrt/sriov-mac-sync.init "$root/etc/init.d/sriov-mac-sync"
	install -m 644 dist/sriov-mac-sync.conf.example "$root/etc/sriov-mac-sync.conf"

	# apk records the ownership it finds on disk, and a package whose files
	# belong to whoever happened to build it installs them as nobody:nogroup.
	# fakeroot is the only part of this script that is not tar and a compiler;
	# without it the packages are still built, just say so rather than ship
	# them wrong.
	if command -v fakeroot >/dev/null 2>&1; then
		fakeroot sh -c "chown -R 0:0 '$root' && '$APK' mkpkg \
			--info name:sriov-mac-sync \
			--info version:$VERSION-r0 \
			--info description:'$DESC' \
			--info arch:$2 \
			--info license:MIT \
			--info url:https://github.com/Jimbambuli/sriov-mac-sync \
			--files '$root' \
			--output '$OUT/sriov-mac-sync_$2.apk'"
	else
		echo "   WARNING: no fakeroot, files will not be owned by root"
		"$APK" mkpkg \
			--info name:sriov-mac-sync \
			--info version:"$VERSION-r0" \
			--info description:"$DESC" \
			--info arch:"$2" \
			--info license:MIT \
			--info url:https://github.com/Jimbambuli/sriov-mac-sync \
			--files "$root" \
			--output "$OUT/sriov-mac-sync_$2.apk"
	fi
	rm -rf "$root"
}

build x86_64-unknown-linux-musl  x86_64
build aarch64-unknown-linux-musl aarch64
deb x86_64  amd64
deb aarch64 arm64
ipk x86_64  x86_64
ipk aarch64 aarch64_generic
# OpenWrt 24.10 dropped opkg for apk, and its apk reads only the v3 format.
# The .ipk above stays for 23.05 and older, which is most of the installed base.
apk x86_64  x86_64
apk aarch64 aarch64_generic

( cd "$OUT" && sha256sum ./* > SHA256SUMS )
echo
echo "== $OUT"
ls -la "$OUT"
