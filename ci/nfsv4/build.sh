#!/bin/sh
# Cross build a trunk kernel if the cache has none, and the modules under
# test always.  build.sh WORK OUT
set -eu
W=$1; OUT=$2
T=$W/tools; O=$W/obj; J=$(nproc)
mkdir -p "$W" "$OUT/modules"
log() { "$@" >"$OUT/step.log" 2>&1 || { tail -60 "$OUT/step.log"; exit 1; }; }
if [ ! -f "$W/netbsd" ]; then
	printf 'include "arch/amd64/conf/GENERIC"\n' >sys/arch/amd64/conf/NFSV4T
	[ -x "$T/bin/nbmake-amd64" ] ||
	    log ./build.sh -U -m amd64 -j "$J" -O "$O" -T "$T" tools
	log ./build.sh -U -m amd64 -j "$J" -O "$O" -T "$T" -u kernel=NFSV4T
	cp "$O/sys/arch/amd64/compile/NFSV4T/netbsd" "$W/netbsd"
fi
cp "$W/netbsd" "$OUT/netbsd"
for d in sys/modules/xdr sys/modules/oncrpc sys/modules/nfsv4; do
	m=${d##*/}
	(cd "$d" && "$T/bin/nbmake-amd64" -j "$J" MKDEBUG=no obj dependall) \
	    >"$OUT/$m.log" 2>&1 || { tail -40 "$OUT/$m.log"; exit 1; }
	cp "$O/$d/$m.kmod" "$OUT/modules/"
done
ls -l "$OUT" "$OUT/modules"
