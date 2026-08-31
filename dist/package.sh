#!/bin/sh
# Build the release artefacts: a static binary, a .deb, an OpenWrt .ipk and
# (with APK= set) an .apk for OpenWrt 24.10's apk-based opkg successor - NOT
# for Alpine: it ships the procd init and OpenWrt arch names. Everything
# lands in dist/out/, for x86_64 and aarch64.
#
#   [APK=/path/to/apk.static] ./dist/package.sh
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

# A failed run must not leave half a dist/out that an operator uploads, nor
# scatter mktemp roots. SHA256SUMS is written last, so its absence marks an
# incomplete set - remove the set with it.
TMPROOTS=""
OUT=dist/out
on_exit() {
	st=$?
	# Word splitting is the point: TMPROOTS is a space-joined list.
	# shellcheck disable=SC2086
	rm -rf $TMPROOTS
	if [ "$st" -ne 0 ] && [ ! -f "$OUT/SHA256SUMS" ]; then
		rm -rf "$OUT"
	fi
	exit "$st"
}
trap on_exit EXIT

# Cargo.toml is the one place a version lives: the binary reports it from
# there, so a number from anywhere else would stamp control files the
# binary's --version contradicts.
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
if [ -n "${1:-}" ]; then
	echo "error: this takes no arguments - the version comes from Cargo.toml" >&2
	exit 2
fi
# Reproducibility: dpkg-deb clamps its mtimes to this natively; the ipk tar
# invocations pin it explicitly below.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}"
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
	TMPROOTS="$TMPROOTS $root"
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
	# A source install puts the unit in /etc/systemd/system, which wins
	# over the packaged one for good: dpkg would report the new version
	# while the machine goes on running whatever that unit points at.
	if [ -e /etc/systemd/system/sriov-mac-sync.service ]; then
		echo "warning: /etc/systemd/system/sriov-mac-sync.service shadows this" >&2
		echo "         package's unit - remove it, or the packaged binary" >&2
		echo "         will not be the one that runs." >&2
	fi
	if [ -d /run/systemd/system ]; then
		systemctl daemon-reload || true
		# On an upgrade $2 carries the old version, the daemon is already
		# running the old binary, and `start` on a running unit is a no-op -
		# the fix the upgrade brings would wait for a reboot.
		if [ -n "$2" ]; then
			deb-systemd-invoke restart sriov-mac-sync.service >/dev/null 2>&1 \
				|| systemctl restart sriov-mac-sync.service || true
		elif [ -x /usr/bin/deb-systemd-invoke ]; then
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
	# Stopping is not the same as stopped. deb-systemd-invoke exits 0
	# without doing anything when a policy-rc.d says services may not be
	# touched - a container image build, a chroot - so the fallback never
	# runs and the check below is the only thing between a live daemon
	# and a --flush it would undo on its next pass, with the binary gone
	# by then and nothing left able to take the entries out.
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		pgrep -x sriov-mac-sync >/dev/null 2>&1 || break
		sleep 0.5
	done
	if pgrep -x sriov-mac-sync >/dev/null 2>&1; then
		echo "sriov-mac-sync did not stop; not flushing - run" >&2
		echo "  sriov-mac-sync --flush" >&2
		echo "once it is down, or its entries stay in the card." >&2
		exit 0
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
	TMPROOTS="$TMPROOTS $root"
	chmod 755 "$root"
	mkdir -p "$root/data/usr/sbin" "$root/data/etc/init.d" "$root/control"

	install -m 755 "$OUT/sriov-mac-sync-$1" "$root/data/usr/sbin/sriov-mac-sync"
	install -m 755 dist/openwrt/sriov-mac-sync.init "$root/data/etc/init.d/sriov-mac-sync"
	install -m 644 dist/sriov-mac-sync.conf.example "$root/data/etc/sriov-mac-sync.conf"

	cat > "$root/control/control" <<EOF
Package: sriov-mac-sync
Version: $VERSION
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
# On an upgrade procd's `start` is a no-op - it compares the instance
# definition, never the binary - so without this restart the OLD daemon
# runs until reboot: the very bug the .deb postinst names. The restart is
# safe now precisely because the quiet-keep memory is handed over.
if [ "${PKG_UPGRADE:-0}" = 1 ]; then
	# Re-enable only what was enabled: the START level may move between
	# versions, leaving the old rc.d symlink behind - but a service the
	# operator switched off deliberately stays off.
	ls /etc/rc.d/[SK]??sriov-mac-sync >/dev/null 2>&1 &&
		/etc/init.d/sriov-mac-sync enable
	# And restart only what was running. `restart` starts a stopped
	# service, so an operator who took the daemon down on purpose - to
	# hand the card to something else, to debug - would find it back and
	# writing to the filter after an unrelated `opkg upgrade`. The old
	# daemon is still up at this point, which is what makes the question
	# answerable here.
	if pgrep -x sriov-mac-sync >/dev/null 2>&1; then
		/etc/init.d/sriov-mac-sync restart 2>/dev/null
		echo "sriov-mac-sync restarted on the new binary."
	else
		echo "sriov-mac-sync was not running; left stopped."
	fi
	exit 0
fi
/etc/init.d/sriov-mac-sync enable
/etc/init.d/sriov-mac-sync start
echo "sriov-mac-sync is running. What it decided:  sriov-mac-sync --status"
exit 0
EOF
	chmod 755 "$root/control/postinst"
	# Stop first, then flush, then disable - same reasoning as the .deb:
	# removing the package undoes its effect on the hardware, and a running
	# daemon would put back what --flush removes.
	cat > "$root/control/prerm" <<'EOF'
#!/bin/sh
[ -n "$IPKG_INSTROOT" ] && exit 0
# On an upgrade opkg runs the OLD package's prerm too - and flushing there
# would blackhole every guest for the takeover window, exactly the outage
# the init script's comment forbids. opkg exports PKG_UPGRADE=1 for it.
[ "${PKG_UPGRADE:-0}" = 1 ] && exit 0
/etc/init.d/sriov-mac-sync stop 2>/dev/null
# procd's stop returns before the process dies; a --flush racing the dying
# daemon's last pass could see its entries put straight back.
for _ in 1 2 3 4 5 6 7 8 9 10; do
	pgrep -x sriov-mac-sync >/dev/null 2>&1 || break
	sleep 0.5
done
# Still up? Then --flush would take entries out from under a live daemon,
# which puts them straight back - and the package is gone by then, so
# nothing owns what stays in the card. Say so and leave it alone.
if pgrep -x sriov-mac-sync >/dev/null 2>&1; then
	echo "sriov-mac-sync did not stop; not flushing - run" >&2
	echo "  sriov-mac-sync --flush" >&2
	echo "once it is down, or its entries stay in the card." >&2
	exit 0
fi
/etc/init.d/sriov-mac-sync disable 2>/dev/null
[ -x /usr/sbin/sriov-mac-sync ] && /usr/sbin/sriov-mac-sync --flush || true
exit 0
EOF
	chmod 755 "$root/control/prerm"

	# Pinned mtimes, sorted names, no gzip timestamp: two builds of the same
	# source agree byte for byte, so SHA256SUMS can be confirmed by rebuilding.
	( cd "$root/data" && tar --owner=root --group=root --sort=name \
		--mtime="@$SOURCE_DATE_EPOCH" -cf - ./* | gzip -9n > ../data.tar.gz )
	( cd "$root/control" && tar --owner=root --group=root --sort=name \
		--mtime="@$SOURCE_DATE_EPOCH" -cf - ./* | gzip -9n > ../control.tar.gz )
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
	# The maintainer scripts live beside the root, not in it, so the trap
	# has to name them too or a failed mkpkg scatters three files per
	# architecture.
	TMPROOTS="$TMPROOTS $root $root.post-install $root.pre-deinstall $root.post-upgrade"
	chmod 755 "$root"
	mkdir -p "$root/usr/sbin" "$root/etc/init.d"

	install -m 755 "$OUT/sriov-mac-sync-$1" "$root/usr/sbin/sriov-mac-sync"
	install -m 755 dist/openwrt/sriov-mac-sync.init "$root/etc/init.d/sriov-mac-sync"
	install -m 644 dist/sriov-mac-sync.conf.example "$root/etc/sriov-mac-sync.conf"

	# The same behaviour as .deb and .ipk: enabled and started on install,
	# stopped and flushed on removal. mkpkg embeds these; they live outside
	# $root so they do not become package files.
	cat > "$root.post-install" <<'EOF'
#!/bin/sh
/etc/init.d/sriov-mac-sync enable 2>/dev/null
/etc/init.d/sriov-mac-sync start 2>/dev/null
echo "sriov-mac-sync is running. What it decided:  sriov-mac-sync --status"
exit 0
EOF
	cat > "$root.pre-deinstall" <<'EOF'
#!/bin/sh
/etc/init.d/sriov-mac-sync stop 2>/dev/null
for _ in 1 2 3 4 5 6 7 8 9 10; do
	pgrep -x sriov-mac-sync >/dev/null 2>&1 || break
	sleep 0.5
done
# Still up? Then --flush would take entries out from under a live daemon,
# which puts them straight back - and the package is gone by then, so
# nothing owns what stays in the card. Say so and leave it alone.
if pgrep -x sriov-mac-sync >/dev/null 2>&1; then
	echo "sriov-mac-sync did not stop; not flushing - run" >&2
	echo "  sriov-mac-sync --flush" >&2
	echo "once it is down, or its entries stay in the card." >&2
	exit 0
fi
/etc/init.d/sriov-mac-sync disable 2>/dev/null
[ -x /usr/sbin/sriov-mac-sync ] && /usr/sbin/sriov-mac-sync --flush || true
exit 0
EOF
	# apk runs the upgrade scripts on upgrade, not install/deinstall: without
	# this, an upgrade would replace the binary and leave the old daemon
	# running until reboot - the .deb postinst restart, spelled apk.
	cat > "$root.post-upgrade" <<'EOF'
#!/bin/sh
ls /etc/rc.d/[SK]??sriov-mac-sync >/dev/null 2>&1 &&
	/etc/init.d/sriov-mac-sync enable
# Only what was running, for the reason the .ipk post-install spells out:
# `restart` would start a daemon the operator stopped on purpose.
if pgrep -x sriov-mac-sync >/dev/null 2>&1; then
	/etc/init.d/sriov-mac-sync restart 2>/dev/null
fi
exit 0
EOF

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
			--script post-install:'$root.post-install' \
			--script pre-deinstall:'$root.pre-deinstall' \
			--script post-upgrade:'$root.post-upgrade' \
			--files '$root' \
			--output '$OUT/sriov-mac-sync_$2.apk'"
	else
		echo "== .apk for $2 SKIPPED (no fakeroot - the files would install \
owned by the build user, and a release checksum must not cover a wrong build)"
		rm -rf "$root" "$root.post-install" "$root.pre-deinstall" "$root.post-upgrade"
		return 0
	fi
	rm -rf "$root" "$root.post-install" "$root.pre-deinstall" "$root.post-upgrade"
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
