#!/bin/sh
# Build the userland of the OpenZFS port in the VM, on the stock kernel,
# while there is a network and a compiler matching the userland.  The
# module comes from the cross build, against the kernel under test.
#   zfs-user.sh SHA
set -eu
SHA=$1; W=/var/tmp/zu
export TERM=vt100
export PKG_PATH=http://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/x86_64/11.0/All
/usr/sbin/pkg_add -u pkgin >/dev/null || :
/usr/pkg/bin/pkgin -y update >/dev/null
/usr/pkg/bin/pkgin -y install autoconf automake libtool-base gmake pkgconf \
    git-base gettext-tools gettext-m4 >/dev/null
export PATH=$PATH:/usr/pkg/bin:/usr/pkg/sbin
mkdir -p "$W"; cd "$W"
git init -q zfs; cd zfs
git fetch -q --depth 1 https://github.com/zakinko/zfs "$SHA"
git checkout -q FETCH_HEAD
sh autogen.sh >"$W/log" 2>&1
PKG_CONFIG_LIBDIR=/usr/lib/pkgconfig PKG_CONFIG_PATH= MAKE=gmake \
    ./configure --with-config=user --prefix=/usr --exec-prefix= \
    --sysconfdir=/etc --localstatedir=/var --disable-nls \
    --with-mounthelperdir=/sbin >>"$W/log" 2>&1 || { tail -30 "$W/log"; exit 1; }
gmake -j2 >>"$W/log" 2>&1 || { tail -30 "$W/log"; exit 1; }
gmake install >>"$W/log" 2>&1
# For in-vm.sh: base has a zpool of its own, which the module refuses.
touch "$W/installed"
zpool version || :
