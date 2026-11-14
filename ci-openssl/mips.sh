#!/bin/sh
# evbmips-mipsn64el: cross-build the tools, a MALTA64 kernel with piixide,
# and libcrypto from BASE and FIX against the daily sets; boot the image
# under qemu's malta and compare the two libraries inside it.
#
# The stock MALTA kernels have only the generic pciide, whose compat probe
# (pciide_common.c default_chip_map) turns the PCI I/O decode off and
# probes again; qemu's PIIX4 still answers on the legacy ports, so both
# channels are dropped as "other hardware responding".  piixide maps the
# channels with pciide_mapchan, which does not make that check.
#
# Usage: mips.sh  (in the checkout, with tree-base/ prepared by the workflow)
set -eux
top=$PWD
ci=$top/ci-openssl
daily=https://nycdn.netbsd.org/pub/NetBSD-daily/HEAD/20261113042327Z/evbmips-mipsn64el/binary
img=https://github.com/zakinko/netbsd-ci-images/releases/download/images/evbmips-mipsn64el-daily-20261113.qcow2
T=$top/tools O=$top/obj

# tools and kernel, from the fix tree (the kernel does not depend on it)
start=$(date +%s)
./build.sh -U -m evbmips -a mipsn64el -j4 -T $T -O $O -V MKCTF=no tools > $top/build-tools.log 2>&1 ||
	{ tail -40 $top/build-tools.log; exit 1; }
echo "tools took $(( $(date +%s) - start )) s"
cat > sys/arch/evbmips/conf/MALTA64PIIX <<'EOF'
include "arch/evbmips/conf/MALTA64"
piixide*	at pci? dev ? function ? flags 0x0000
EOF
./build.sh -U -m evbmips -a mipsn64el -j4 -T $T -O $O -V MKCTF=no kernel=MALTA64PIIX > $top/build-kernel.log 2>&1 ||
	{ tail -40 $top/build-kernel.log; exit 1; }
k=$(ls $O/sys/arch/evbmips/compile/MALTA64PIIX/netbsd)
ls -l $k

# the daily base and comp sets are the DESTDIR the library links against
mkdir -p $top/dl $top/destdir
for s in base comp; do
	curl -fsSL -o $top/dl/$s.tgz $daily/sets/$s.tgz
	tar -xzf $top/dl/$s.tgz -C $top/destdir 2>/dev/null || true
done
ls $top/destdir/usr/lib/libc.so* $top/destdir/usr/include/stdio.h

nbmake=$T/bin/nbmake-evbmips
for t in base:$top/tree-base new:$top; do
	n=${t%%:*} src=${t#*:}
	mkdir -p $top/obj-$n
	(cd $src/crypto/external/apache2/openssl/lib/libcrypto &&
	 $nbmake -j4 NETBSDSRCDIR=$src MAKEOBJDIR=$top/obj-$n DESTDIR=$top/destdir \
	    MKDOC=no MKMAN=no MKPROFILE=no MKSTATICLIB=no MKLINT=no \
	    MKDEBUGLIB=no MKDEBUG=no MKCTF=no dependall) > $top/build-$n.log 2>&1 ||
		{ tail -40 $top/build-$n.log; exit 1; }
	ls -l $top/obj-$n/libcrypto.so.16.0
	c=$(grep -c -- '-DPOLY1305_ASM' $top/build-$n.log || true)
	echo "$n: -DPOLY1305_ASM on $c command lines"
done
file $top/obj-new/libcrypto.so.16.0

# boot
curl -fsSL -o $top/disk.qcow2 $img
ssh-keygen -q -t ed25519 -N '' -f $top/id
mkdir -p $top/seed && cp $top/id.pub $top/seed/authorized_keys
(cd $top/seed && exec python3 -m http.server 8123 --bind 127.0.0.1 > $top/http.log 2>&1) &
qemu-system-mips64el -M malta -cpu 5Kf -m 1024 -kernel $k \
    -drive file=$top/disk.qcow2,format=qcow2,if=ide \
    -nic user,model=pcnet,hostfwd=tcp:127.0.0.1:2222-:22 \
    -display none -serial file:$top/mips.console -monitor none \
    -pidfile $top/qemu.pid -daemonize
SSH="ssh -q -i $top/id -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 -o ServerAliveInterval=30 root@127.0.0.1"
set +x
i=0
until $SSH true 2>/dev/null; do
	i=$((i+1))
	if [ $i -gt 90 ] || grep -q -e panic -e 'root device:' $top/mips.console; then
		tail -60 $top/mips.console; exit 1
	fi
	sleep 20
done
set -x
grep -E 'piixide|wd0|root on' $top/mips.console | head
$SSH "uname -a; sysctl hw.machine_arch; mkdir -p /root/nb/obj-base /root/nb/obj-new"
put() { $SSH "cat > $2" < "$1"; }
for n in base new; do
	put $top/obj-$n/libcrypto.so.16.0 /root/nb/obj-$n/libcrypto.so.16.0
	$SSH "cd /root/nb/obj-$n && ln -sf libcrypto.so.16.0 libcrypto.so.16 && ln -sf libcrypto.so.16.0 libcrypto.so"
done
put $ci/nbtest.sh /root/nb/nbtest.sh
put $ci/evpcheck.c /root/nb/evpcheck.c
printf 'cd /root/nb && sh nbtest.sh /root/nb/obj-base /root/nb/obj-new poly1305_init:POLY1305 poly1305_init:ChaCha20-Poly1305\n' > $top/cmd.sh
put $top/cmd.sh /root/nb/cmd.sh
$SSH sh /root/nb/cmd.sh 2>&1 | tee $top/test-mips.log
$SSH /sbin/shutdown -p now || true
j=0; while kill -0 $(cat $top/qemu.pid) 2>/dev/null && [ $j -lt 60 ]; do sleep 5; j=$((j+1)); done
tail -1 $top/test-mips.log | grep -qx PASS
