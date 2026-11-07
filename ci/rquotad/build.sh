#!/bin/sh
# Build this tree as it is, then librump again with lwproc.diff alone.
#   build.sh WORK OUT
set -eu
W=$1; OUT=$2
T=$W/tools; O=$W/obj; D=$W/dest; J=$(nproc)
mkdir -p "$OUT"
B="./build.sh -U -m amd64 -j $J -O $O -T $T -D $D -V MKDEBUG=no -V MKX11=no -V MKKYUA=no -V MKLLVM=no"
log() { "$@" >>"$OUT/build.log" 2>&1 || { tail -60 "$OUT/build.log"; exit 1; }; }
[ -x "$T/bin/nbmake-amd64" ] || log $B tools
$B -u distribution >>"$OUT/build.log" 2>&1 ||
    grep -q '\[checkflist\] Error' "$OUT/build.log" ||
    { tail -60 "$OUT/build.log"; exit 1; }
printf 'include "arch/amd64/conf/GENERIC"\n' >sys/arch/amd64/conf/RQTRUNK
log $B -u kernel=RQTRUNK
cp "$O/sys/arch/amd64/compile/RQTRUNK/netbsd" "$OUT/netbsd"
so=$(ls "$D"/usr/lib/librump.so.*.* | head -1)
cp "$so" "$D/usr/lib/rump-trunk.so"
patch -f -p1 <ci/rquotad/lwproc.diff
(cd sys/rump/librump/rumpkern && "$T/bin/nbmake-amd64" -j "$J" MKDEBUG=no dependall) \
    >>"$OUT/build.log" 2>&1 || { tail -40 "$OUT/build.log"; exit 1; }
n=$(ls "$O"/sys/rump/librump/rumpkern/librump.so.*.* | head -1)
cp "$n" "$D/usr/lib/rump-fixed.so"
cmp "$D/usr/lib/rump-trunk.so" "$D/usr/lib/rump-fixed.so" && { echo same library; exit 1; } || :
tar -C "$D" -cf - . | zstd -3 -T0 >"$OUT/dest.tar.zst"
rm -f "$OUT/build.log"
ls -l "$OUT"
