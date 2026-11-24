#!/bin/sh
# Boot the evbmips-mipsn64el image on qemu's malta and compare the two
# libraries in out/ there:  QEMU=qemu-system-mips64el sh mips-boot.sh
# qemu 8.2 will not do: the kernel fails to assign PCI I/O space on it.
set -u
top=$PWD ci=$(cd "$(dirname "$0")" && pwd)
QEMU=${QEMU:-qemu-system-mips64el}
port=${PORT:-2222}
$QEMU --version | head -1
[ -s disk.qcow2 ] || curl -fsSL -o disk.qcow2 https://github.com/zakinko/netbsd-ci-images/releases/download/images/evbmips-mipsn64el-daily-20261113.qcow2 || exit 1
[ -s id ] || ssh-keygen -q -t ed25519 -N '' -f id
mkdir -p seed && cp id.pub seed/authorized_keys
(cd seed && exec python3 -m http.server 8123 --bind 127.0.0.1) > http.log 2>&1 &
http=$!
$QEMU -M malta -cpu 5Kf -m 1024 -kernel out/netbsd-MALTA64PIIX \
    -drive file=disk.qcow2,format=qcow2,if=ide,snapshot=on \
    -nic user,model=pcnet,hostfwd=tcp:127.0.0.1:$port-:22 \
    -display none -serial file:mips.console -monitor none &
q=$!
trap 'kill $q $http 2>/dev/null' EXIT
SSH="ssh -q -i id -p $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30 -o ServerAliveInterval=30 root@127.0.0.1"
i=0
until $SSH true 2>/dev/null; do
	i=$((i+1))
	if [ $i -gt 120 ] || ! kill -0 $q 2>/dev/null || grep -q -e 'panic:' -e 'root device:' -e 'unable to assign' mips.console; then
		echo "did not come up"; grep -v 'reset failed' mips.console | tail -60; exit 1
	fi
	sleep 15
done
grep -E 'piixide|wd0|pcn0|root on' mips.console
$SSH "uname -a; sysctl hw.machine_arch; mkdir -p /root/nb/obj-base /root/nb/obj-new"
put() { $SSH "cat > $2" < "$1" || exit 1; }
for n in base new; do
	put out/obj-$n/libcrypto.so.16.0 /root/nb/obj-$n/libcrypto.so.16.0
	$SSH "cd /root/nb/obj-$n && ln -sf libcrypto.so.16.0 libcrypto.so.16 && ln -sf libcrypto.so.16.0 libcrypto.so"
done
put $ci/nbtest.sh /root/nb/nbtest.sh
put $ci/evpcheck.c /root/nb/evpcheck.c
$SSH "cd /root/nb && sh nbtest.sh /root/nb/obj-base /root/nb/obj-new poly1305_init:POLY1305 poly1305_init:ChaCha20-Poly1305" 2>&1 | tee test-mips.log
$SSH /sbin/shutdown -p now
j=0; while kill -0 $q 2>/dev/null && [ $j -lt 60 ]; do sleep 5; j=$((j+1)); done
tail -1 test-mips.log | grep -qx PASS
