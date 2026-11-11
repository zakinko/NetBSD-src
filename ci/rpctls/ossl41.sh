#!/bin/sh
# OpenSSL 4.1, for DTLS 1.3 (RFC 9147), in the NetBSD VM: rpc.tlsservd and
# dtlsclient link it statically from /usr/local/openssl41.  The tarball is
# fetched and checked on the runner and handed over in $1.
#   ossl41.sh TARBALL
set -eu
P=/usr/local/openssl41
[ -f "$P/lib/libssl.a" ] && exit 0
export PKG_PATH=http://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/x86_64/11.0/All
export PATH=$PATH:/usr/pkg/bin
command -v perl >/dev/null || /usr/pkg/bin/pkgin -y install perl >/dev/null
W=/var/tmp/ossl41
rm -rf "$W"; mkdir -p "$W"
tar -C "$W" -xzf "$1"
cd "$W"/openssl-*
./Configure --prefix="$P" --libdir=lib --openssldir="$P/ssl" \
    no-shared no-docs no-tests no-apps >"$W/configure.log" 2>&1
make -j"$(sysctl -n hw.ncpu)" >"$W/build.log" 2>&1 || {
	tail -40 "$W/build.log"; exit 1; }
make install_sw >"$W/install.log" 2>&1
"$P"/bin/openssl version 2>/dev/null || ls "$P/lib"
