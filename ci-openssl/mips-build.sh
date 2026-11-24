#!/bin/sh
# Cross-build for evbmips-mipsn64el: a MALTA64 kernel with piixide, and
# libcrypto from BASE (tree-base) and from this tree; results in out/.
# The stock MALTA kernels only have the generic pciide, whose compat probe
# (pciide_common.c default_chip_map) turns I/O decode off and probes again;
# qemu's PIIX4 still answers, and both channels are dropped as "other
# hardware responding".  piixide uses pciide_mapchan, which does not.
set -eux
top=$PWD
rel=https://github.com/zakinko/netbsd-ci-images/releases/download/images/evbmips-mipsn64el-daily-20261113
T=$top/tools O=$top/obj
mkdir -p $top/out
./build.sh -U -m evbmips -a mipsn64el -j4 -T $T -O $O -V MKCTF=no tools > $top/build-tools.log 2>&1 ||
	{ tail -40 $top/build-tools.log; exit 1; }
cat > sys/arch/evbmips/conf/MALTA64PIIX <<'EOC'
include "arch/evbmips/conf/MALTA64"
piixide*	at pci? dev ? function ? flags 0x0000
EOC
./build.sh -U -m evbmips -a mipsn64el -j4 -T $T -O $O -V MKCTF=no kernel=MALTA64PIIX > $top/build-kernel.log 2>&1 ||
	{ tail -40 $top/build-kernel.log; exit 1; }
cp $O/sys/arch/evbmips/compile/MALTA64PIIX/netbsd $top/out/netbsd-MALTA64PIIX

mkdir -p $top/dl $top/destdir
for s in base comp; do
	curl -fsSL -o $top/dl/$s.tgz $rel-$s.tgz
	tar -xzf $top/dl/$s.tgz -C $top/destdir 2>/dev/null || true
done
ls $top/destdir/usr/lib/libc.so $top/destdir/usr/include/stdio.h
for t in base:$top/tree-base new:$top; do
	n=${t%%:*} src=${t#*:}
	mkdir -p $top/obj-$n $top/out/obj-$n
	(cd $src/crypto/external/apache2/openssl/lib/libcrypto &&
	 $T/bin/nbmake-evbmips -j4 NETBSDSRCDIR=$src MAKEOBJDIR=$top/obj-$n DESTDIR=$top/destdir \
	    MKDOC=no MKMAN=no MKPROFILE=no MKSTATICLIB=no MKLINT=no \
	    MKDEBUGLIB=no MKDEBUG=no MKCTF=no LIBDO.crypt=_external dependall) > $top/build-$n.log 2>&1 ||
		{ tail -40 $top/build-$n.log; exit 1; }
	cp $top/obj-$n/libcrypto.so.16.0 $top/out/obj-$n/
	echo "$n: $(grep -c -- '-DPOLY1305_ASM' $top/build-$n.log || true) lines with -DPOLY1305_ASM"
	$T/bin/mipsn64el--netbsd-nm $top/obj-$n/libcrypto.so.16.0 | grep -i ' poly1305_' || true
done
