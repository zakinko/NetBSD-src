#!/bin/sh
# Cross build the kernels and modules under test.  build.sh WORK OUT
#   netbsd.on   GENERIC with NFSSERVER_ONCRPC, netbsd.off plain GENERIC
set -eu
W=$1; OUT=$2
T=$W/tools; O=$W/obj; J=$(nproc)
mkdir -p "$W" "$OUT/modules"
log() { "$@" >"$OUT/step.log" 2>&1 || { tail -60 "$OUT/step.log"; exit 1; }; }
printf 'include "arch/amd64/conf/GENERIC"\noptions NFSSERVER_ONCRPC\n' \
    >sys/arch/amd64/conf/NFSBRON
printf 'include "arch/amd64/conf/GENERIC"\n' >sys/arch/amd64/conf/NFSBROFF
[ -x "$T/bin/nbmake-amd64" ] ||
    log ./build.sh -U -m amd64 -j "$J" -O "$O" -T "$T" tools
log ./build.sh -U -m amd64 -j "$J" -O "$O" -T "$T" -u kernel=NFSBROFF
cp "$O/sys/arch/amd64/compile/NFSBROFF/netbsd" "$OUT/netbsd.off"
log ./build.sh -U -m amd64 -j "$J" -O "$O" -T "$T" -u kernel=NFSBRON
cp "$O/sys/arch/amd64/compile/NFSBRON/netbsd" "$OUT/netbsd.on"
for d in sys/modules/xdr sys/modules/oncrpc sys/modules/nfsxattr sys/modules/nfsv4; do
	m=${d##*/}
	(cd "$d" && "$T/bin/nbmake-amd64" MKDEBUG=no obj &&
	    "$T/bin/nbmake-amd64" -j "$J" MKDEBUG=no dependall) \
	    >"$OUT/$m.log" 2>&1 || { tail -40 "$OUT/$m.log"; exit 1; }
	cp "$O/$d/$m.kmod" "$OUT/modules/"
done
# With the option as a module, for what only a module build catches.
(cd sys/modules/nfsserver && "$T/bin/nbmake-amd64" MKDEBUG=no obj &&
    "$T/bin/nbmake-amd64" -j "$J" MKDEBUG=no NFSSERVER_ONCRPC=1 dependall) \
    >"$OUT/nfsserver.log" 2>&1 || { tail -40 "$OUT/nfsserver.log"; exit 1; }
ls -l "$OUT" "$OUT/modules"
