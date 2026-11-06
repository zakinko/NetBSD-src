#!/bin/sh
# The Linux client of the runner, over a real IP link so that the server
# can call it back.  linux.sh OUT
OUT=$1
sudo apt-get install -y -q nfs-common >/dev/null 2>&1
sudo modprobe nfs || {
	sudo apt-get install -y -q "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
	sudo modprobe nfs
}
sudo modprobe nfsv3; sudo modprobe nfsv4
fails=0
t() {
	echo "\$ $*"
	if timeout 200 "$@"; then echo ok; else echo "FAILED ($?)"; fails=$((fails + 1)); fi
}
{
	uname -a
	sh ci/nlm/tun-up.sh "$OUT"
	t ping -c 2 10.77.0.2
	sudo systemctl start rpcbind rpc-statd
	rpcinfo -p 10.77.0.2 | grep -E 'nfs|nlockmgr'
	python3 ci/nlm/t_kernel.py 2>&1 | tee "$OUT/t_kernel.txt"
	grep -q '^t_kernel failures: 0$' "$OUT/t_kernel.txt" || fails=$((fails + 1))
	sudo mkdir -p /mnt/v3 /mnt/v4
	t sudo mount -v -t nfs -o vers=3,proto=tcp,noresvport 10.77.0.2:/export/ffs /mnt/v3
	t sudo mount -v -t nfs -o vers=4.0,proto=tcp,clientaddr=10.77.0.1,noresvport,sec=sys 10.77.0.2:/export/ffs /mnt/v4
	grep -E '/mnt/v' /proc/mounts
	sudo mkdir /mnt/v3/lk
	sudo chmod 1777 /mnt/v3/lk
	dd if=/dev/zero of=/mnt/v3/lk/f bs=4k count=2 status=none
	t python3 ci/nlm/locks.py /mnt/v3/lk/f /mnt/v4/lk/f
	# IPv6: the client and the callback by rpcbind's GETADDR.
	t ping -6 -c 2 fd77::2
	sudo mkdir -p /mnt/v6
	t sudo mount -v -t nfs -o vers=3,proto=tcp6,noresvport '[fd77::2]:/export/ffs' /mnt/v6
	grep /mnt/v6 /proc/mounts
	t python3 ci/nlm/locks6.py /mnt/v6/lk/f
	ssh netbsd 'netstat -an -f inet6 | grep fd77 | head -5; sysctl vfs.nlm'
	t sudo umount /mnt/v6
	ssh netbsd 'sysctl vfs.nlm'
	# A lock of the client seen from a process on the server.
	python3 -c "
import fcntl, time
f = open('/mnt/v3/lk/f', 'r+')
fcntl.lockf(f, fcntl.LOCK_EX, 1, 1000)
time.sleep(30)" &
	h=$!
	sleep 3
	echo '$ a process on the server meets the lock of the client'
	if ssh netbsd '/var/tmp/try /export/ffs/lk/f 1000'; then
		echo 'FAILED: granted'; fails=$((fails + 1))
	else
		echo ok
	fi
	t ssh netbsd '/var/tmp/try /export/ffs/lk/f 1001'
	kill $h
	wait $h 2>/dev/null
	# The grace period reaches version 4.
	ssh netbsd 'pkill -x rpc.lockd; sleep 1; modunload nlm; modload nlm; sysctl -w vfs.nlm.grace=20; /var/tmp/nlm/rpc.lockd/rpc.lockd'
	s=$(date +%s)
	t python3 -c "
import fcntl
f = open('/mnt/v4/lk/f', 'r+')
fcntl.lockf(f, fcntl.LOCK_EX, 1, 3000)"
	echo "the version 4 lock took $(( $(date +%s) - s )) s, grace 20"
	t sudo rm -rf /mnt/v3/lk
	t sudo umount /mnt/v3
	t sudo umount /mnt/v4
	echo "failures: $fails"
	sudo dmesg | grep -iE 'lockd|nfs|rpc' | tail -20
} >"$OUT/linux.txt" 2>&1
cat "$OUT/linux.txt"
test "$(grep "^failures: " "$OUT/linux.txt" | tail -1)" = "failures: 0"
