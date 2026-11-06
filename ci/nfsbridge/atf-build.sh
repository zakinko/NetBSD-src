#!/bin/sh
# The userland of this tree, with rump's NFS server built on the RPC
# layer, for tests/fs/nfs and the nfs cases of tests/fs/vfs.  The stock
# userland of the VM would test the old code in its own librump.
#   atf-build.sh WORK OUT
set -eu
W=$1; OUT=$2
T=$W/tools; O=$W/obj; D=$W/dest; J=$(nproc)
mkdir -p "$OUT"
B="./build.sh -U -m amd64 -j $J -O $O -T $T -D $D -V NFSSERVER_ONCRPC=1 -V MKDEBUG=no -V MKX11=no -V MKKYUA=no -V MKLLVM=no"
printf 'include "arch/amd64/conf/GENERIC"\noptions NFSSERVER_ONCRPC\n' \
    >sys/arch/amd64/conf/NFSBRON
[ -x "$T/bin/nbmake-amd64" ] || $B tools >"$OUT/atf-build.log" 2>&1
# The set lists do not know this branch's modules.  checkflist comes last,
# so DESTDIR is whole when it is the one to fail.
$B -u distribution >"$OUT/atf-build.log" 2>&1 ||
    grep -q '\[checkflist\] Error' "$OUT/atf-build.log" ||
    { tail -60 "$OUT/atf-build.log"; exit 1; }
$B -u kernel=NFSBRON >>"$OUT/atf-build.log" 2>&1
cp "$O/sys/arch/amd64/compile/NFSBRON/netbsd" "$OUT/netbsd.atf"
nm -D "$D/usr/lib/librumpfs_nfsserver.so" | grep -c nfs_oncrpc_addsock
# The same library without the option, as the control.
sed '/NFSSERVER_ONCRPC/d' "$T/bin/nbmake-amd64" >"$T/bin/nbmake-stock"
(cd sys/rump/fs/lib/libnfsserver && sh "$T/bin/nbmake-stock" cleandir &&
    sh "$T/bin/nbmake-stock" -j "$J" MKDEBUG=no dependall) \
    >>"$OUT/atf-build.log" 2>&1
so=$(ls "$O"/sys/rump/fs/lib/libnfsserver/librumpfs_nfsserver.so.*.* | head -1)
if nm -D "$so" | grep -q nfs_oncrpc_addsock; then echo control has the bridge; exit 1; fi
cp "$so" "$D/usr/lib/stock-nfsserver.so"
tar -C "$D" -cf - . | zstd -3 -T0 >"$OUT/dest.tar.zst"
ls -l "$OUT"
