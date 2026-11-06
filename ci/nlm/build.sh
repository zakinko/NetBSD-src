#!/bin/sh
# Cross build the kernel and the modules under test.  build.sh WORK OUT
#   netbsd.on   GENERIC with NFSSERVER_ONCRPC, netbsd.off plain GENERIC,
#   nlm.kmod and what it needs, xdr and oncrpc only for the plain one
set -eu
W=$1; OUT=$2
T=$W/tools; O=$W/obj; J=$(nproc)
mkdir -p "$W" "$OUT/modules"
log() { "$@" >"$OUT/step.log" 2>&1 || { tail -60 "$OUT/step.log"; exit 1; }; }
printf 'include "arch/amd64/conf/GENERIC"\noptions NFSSERVER_ONCRPC\n' \
    >sys/arch/amd64/conf/NLMON
printf 'include "arch/amd64/conf/GENERIC"\n' >sys/arch/amd64/conf/NLMOFF
[ -x "$T/bin/nbmake-amd64" ] ||
    log ./build.sh -U -m amd64 -j "$J" -O "$O" -T "$T" tools
log ./build.sh -U -m amd64 -j "$J" -O "$O" -T "$T" -u kernel=NLMON
cp "$O/sys/arch/amd64/compile/NLMON/netbsd" "$OUT/netbsd.on"
log ./build.sh -U -m amd64 -j "$J" -O "$O" -T "$T" -u kernel=NLMOFF
cp "$O/sys/arch/amd64/compile/NLMOFF/netbsd" "$OUT/netbsd.off"
for d in sys/modules/xdr sys/modules/oncrpc sys/modules/nfsv4 sys/modules/nlm; do
	m=${d##*/}
	(cd "$d" && "$T/bin/nbmake-amd64" MKDEBUG=no obj &&
	    "$T/bin/nbmake-amd64" -j "$J" MKDEBUG=no dependall) \
	    >"$OUT/$m.log" 2>&1 || { tail -40 "$OUT/$m.log"; exit 1; }
	cp "$O/$d/$m.kmod" "$OUT/modules/"
done
mkdir -p "$OUT/offmods"
mv "$OUT/modules/xdr.kmod" "$OUT/modules/oncrpc.kmod" "$OUT/offmods/"
ls -l "$OUT" "$OUT/modules"
