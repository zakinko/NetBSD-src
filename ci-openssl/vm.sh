#!/bin/sh
# Boot a vmactions NetBSD 11.1 image under TCG on an Ubuntu runner.
#   vm.sh start <arch> [cpu]   waits until ssh answers
#   vm.sh ssh <arch> cmd...
#   vm.sh put <arch> <file>... copies into /root/nb
#   vm.sh stop <arch>          shutdown -p, then waits for qemu to exit
# Images and keys are in $VMDIR (default ./vm), fetched by fetch.sh.
VMDIR=${VMDIR:-$PWD/vm}
op=$1 arch=$2; shift 2
port=2222
img=$VMDIR/netbsd-11.1-$arch.qcow2
key=$VMDIR/netbsd-11.1-$arch.host.id_rsa
SSH="ssh -q -i $key -p $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 -o ServerAliveInterval=30 root@127.0.0.1"

case $op in
start)
	cpu=${1:-}
	net="-netdev user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22"
	case $arch in
	aarch64)
		cp /usr/share/AAVMF/AAVMF_CODE.fd $VMDIR/code.fd
		cp /usr/share/AAVMF/AAVMF_VARS.fd $VMDIR/vars.fd
		set -- qemu-system-aarch64 -M virt,gic-version=3 -cpu ${cpu:-max} \
		    -m 8192 -smp 4 -accel tcg,thread=multi $net \
		    -device virtio-net-pci,netdev=net0 \
		    -drive if=pflash,format=raw,readonly=on,file=$VMDIR/code.fd \
		    -drive if=pflash,format=raw,file=$VMDIR/vars.fd \
		    -drive file=$img,format=qcow2,if=none,id=d0 \
		    -device virtio-blk-pci,drive=d0
		;;
	riscv64)
		set -- qemu-system-riscv64 -M virt,acpi=off -cpu ${cpu:-rv64} \
		    -m 8192 -smp 4 -accel tcg,thread=multi $net \
		    -device virtio-net-device,netdev=net0 \
		    -kernel /usr/lib/u-boot/qemu-riscv64_smode/uboot.elf \
		    -drive file=$img,format=qcow2,if=none,id=d0 \
		    -device virtio-blk-device,drive=d0
		;;
	sparc64)
		q=$VMDIR/qemu-sparc64/qemu10-sparc64
		set -- $q/bin/qemu-system-sparc64 -L $q/share/qemu -M sun4u \
		    -m 2048 -vga none $net -device e1000,netdev=net0,bus=pciB \
		    -drive file=$img,format=qcow2,if=ide,index=0 -boot order=c
		;;
	*) echo "unknown arch $arch"; exit 1 ;;
	esac
	"$@" -display none -serial file:$VMDIR/$arch.console -monitor none \
	    -pidfile $VMDIR/$arch.pid -daemonize || exit 1
	echo "$(date -u +%FT%TZ) started $arch cpu=${cpu:-default}"
	i=0
	until $SSH true 2>/dev/null; do
		i=$((i+1))
		if [ $i -gt 90 ] || ! kill -0 "$(cat $VMDIR/$arch.pid)" 2>/dev/null; then
			echo "no ssh"; tail -40 $VMDIR/$arch.console; exit 1
		fi
		sleep 20
	done
	echo "$(date -u +%FT%TZ) ssh up"
	$SSH "uname -a; sysctl -n hw.ncpu; mkdir -p /root/nb"
	;;
ssh)
	exec $SSH "$@"
	;;
put)
	for f; do
		$SSH "cat > /root/nb/$(basename "$f")" < "$f" || exit 1
	done
	;;
stop)
	p=$(cat $VMDIR/$arch.pid)
	$SSH /sbin/shutdown -p now >/dev/null 2>&1
	i=0
	while kill -0 "$p" 2>/dev/null; do
		i=$((i+1)); [ $i -gt 60 ] && { echo "qemu still up"; exit 1; }
		sleep 10
	done
	echo "$(date -u +%FT%TZ) stopped $arch"
	;;
esac
