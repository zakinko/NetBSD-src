#!/bin/sh
# Cross build a trunk kernel if the cache has none (kernel), or the
# modules under test (modules).  build.sh kernel|modules WORK OUT
set -eu
WHAT=$1; W=$2; OUT=$3
T=$W/tools; O=$W/obj; J=$(nproc)
mkdir -p "$W" "$OUT/modules"
log() { "$@" >"$OUT/step.log" 2>&1 || { tail -60 "$OUT/step.log"; exit 1; }; }
if [ "$WHAT" = kernel ]; then
	[ -f "$W/netbsd" ] && exit 0
	printf 'include "arch/amd64/conf/GENERIC"\n' >sys/arch/amd64/conf/NFSV4T
	[ -x "$T/bin/nbmake-amd64" ] ||
	    log ./build.sh -U -m amd64 -j "$J" -O "$O" -T "$T" tools
	log ./build.sh -U -m amd64 -j "$J" -O "$O" -T "$T" -u kernel=NFSV4T
	cp "$O/sys/arch/amd64/compile/NFSV4T/netbsd" "$W/netbsd"
	exit 0
fi
cp "$W/netbsd" "$OUT/netbsd"
for d in sys/modules/xdr sys/modules/oncrpc sys/modules/nfsv4; do
	m=${d##*/}
	(cd "$d" && "$T/bin/nbmake-amd64" MKDEBUG=no obj &&
	    "$T/bin/nbmake-amd64" -j "$J" MKDEBUG=no dependall) \
	    >"$OUT/$m.log" 2>&1 || { tail -40 "$OUT/$m.log"; exit 1; }
	cp "$O/$d/$m.kmod" "$OUT/modules/"
done
# DTrace, for tests that count what the kernel does (blk.py); its
# failing to build leaves the rest standing.
for d in sys/modules/solaris sys/modules/cyclic sys/modules/dtrace/dtrace \
    sys/modules/dtrace/fbt sys/modules/dtrace/sdt sys/modules/dtrace/profile; do
	m=${d##*/}
	(cd "$d" && "$T/bin/nbmake-amd64" MKDEBUG=no obj &&
	    "$T/bin/nbmake-amd64" -j "$J" MKDEBUG=no dependall) \
	    >"$OUT/dt-$m.log" 2>&1 && cp "$O/$d/"*.kmod "$OUT/modules/" ||
	    { echo "no $d"; tail -20 "$OUT/dt-$m.log"; }
done
ls -l "$OUT" "$OUT/modules"
