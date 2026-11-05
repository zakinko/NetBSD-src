#!/bin/sh
# Cross build a trunk kernel and the modules under test.  build.sh WORK OUT
set -eu
W=$1; OUT=$2
T=$W/tools; O=$W/obj; J=$(nproc)
mkdir -p "$W" "$OUT/modules"
log() { "$@" >"$OUT/step.log" 2>&1 || { tail -60 "$OUT/step.log"; exit 1; }; }
for k in ONCRPCT ONCRPCS; do
	printf 'include "arch/amd64/conf/GENERIC"\n' >sys/arch/amd64/conf/$k
done
# Built in as well as a module; the test kernel keeps it out so that
# the module path is what runs.
printf 'options 	ONCRPC\n' >>sys/arch/amd64/conf/ONCRPCS
[ -x "$T/bin/nbmake-amd64" ] || log ./build.sh -U -m amd64 -j "$J" -O "$O" -T "$T" tools
log ./build.sh -U -m amd64 -j "$J" -O "$O" -T "$T" -u kernel=ONCRPCT kernel=ONCRPCS
cp "$O/sys/arch/amd64/compile/ONCRPCT/netbsd" "$OUT/netbsd"
"$T/bin/x86_64--netbsd-nm" "$O/sys/arch/amd64/compile/ONCRPCS/netbsd" |
    grep -E ' T (oncrpc_svc_create|oncrpc_xdrmbuf_create|xdr_u_int)$' || :
for d in sys/modules/xdr sys/modules/oncrpc sys/modules/solaris \
    tests/modules/k_oncrpc; do
	[ -d "$d" ] || continue
	m=${d##*/}
	(cd "$d" && "$T/bin/nbmake-amd64" -j "$J" MKDEBUG=no obj dependall) \
	    >"$OUT/$m.log" 2>&1 || { tail -40 "$OUT/$m.log"; exit 1; }
	cp "$O/$d/$m.kmod" "$OUT/modules/"
done
ls -l "$OUT" "$OUT/modules"
