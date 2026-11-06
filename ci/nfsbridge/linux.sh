#!/bin/sh
# The Linux client of the runner, through the tunnel: version 3 and 4.0
# mounted at once on the one port.  linux.sh OUT
OUT=$1
BIN=$OUT/lc.bin
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
	grep -E 'NFS_V2|DISABLE_UDP' "/boot/config-$(uname -r)"
	sudo mkdir -p /mnt/v3 /mnt/v4 /mnt/v3u
	t sudo mount -v -t nfs -o vers=3,proto=tcp,port=2049,mountport=1234,mountproto=tcp,noresvport,nolock,addr=127.0.0.1 127.0.0.1:/export/ffs /mnt/v3
	t sudo mount -v -t nfs -o vers=4.0,proto=tcp,port=2049,addr=127.0.0.1,clientaddr=127.0.0.1,noresvport,sec=sys 127.0.0.1:/export/ffs /mnt/v4
	grep -E '/mnt/v[34]' /proc/mounts
	ssh netbsd 'netstat -an -f inet | grep "\.2049 .*ESTABLISHED"'
	t dd if=/dev/urandom of="$BIN" bs=1M count=64 status=none
	t sudo mkdir /mnt/v3/lc
	t sudo chmod 1777 /mnt/v3/lc
	# Each sees the other's work, and both run at once.
	t cp "$BIN" /mnt/v3/lc/a
	t sudo sh -c 'sync; echo 3 >/proc/sys/vm/drop_caches'
	t cmp "$BIN" /mnt/v4/lc/a
	cp "$BIN" /mnt/v3/lc/b &
	p3=$!
	cp "$BIN" /mnt/v4/lc/c &
	p4=$!
	wait $p3 || { echo FAILED v3 cp; fails=$((fails + 1)); }
	wait $p4 || { echo FAILED v4 cp; fails=$((fails + 1)); }
	t sudo sh -c 'sync; echo 3 >/proc/sys/vm/drop_caches'
	t cmp "$BIN" /mnt/v4/lc/b
	t cmp "$BIN" /mnt/v3/lc/c
	t mv /mnt/v3/lc/b /mnt/v3/lc/b2
	t test -f /mnt/v4/lc/b2
	t ln -s a /mnt/v3/lc/s
	t test "$(readlink /mnt/v4/lc/s)" = a
	t mkdir -p /mnt/v3/lc/d/e
	t sh -c 'for i in 1 2 3 4 5 6 7 8 9 10; do : >/mnt/v3/lc/d/n$i; done'
	t rm -rf /mnt/v3/lc/d
	t flock -n /mnt/v4/lc/a true
	# The last nfsd goes: the version 4 connection stays and works.
	c() { ssh netbsd 'netstat -an -f inet' 2>/dev/null | grep '127.0.0.1.2049 .*ESTABLISHED' | sort; }
	# Which connection is which, by traffic while only one mount is used.
	echo '$ connections, both up'
	c | tee "$OUT/conn0"
	t sudo sh -c 'echo before >/mnt/v4/lc/k'
	ssh netbsd 'pkill -x nfsd; sleep 3; ps -ax | grep "[n]fsd" || echo no nfsd'
	echo '$ connections, nfsd gone'
	c | tee "$OUT/conn1"
	t test "$(wc -l <"$OUT/conn1")" -ge 1
	t timeout 30 sudo sh -c 'echo during >/mnt/v4/lc/k2; sync'
	t sudo sh -c 'echo 3 >/proc/sys/vm/drop_caches'
	t test "$(timeout 30 cat /mnt/v4/lc/k2)" = during
	t timeout 60 cp "$BIN" /mnt/v4/lc/e
	t sudo sh -c 'sync; echo 3 >/proc/sys/vm/drop_caches'
	t timeout 60 cmp "$BIN" /mnt/v4/lc/e
	t ssh netbsd 'test "$(cat /export/ffs/lc/k2)" = during'
	# Version 3 waits, as a hard mount does, and comes back with nfsd.
	timeout 150 ls /mnt/v3/lc >"$OUT/v3back" 2>&1 &
	v3=$!
	t ssh netbsd '/usr/sbin/nfsd -t -u -n 4; sleep 2; ps -ax | grep -c "[n]fsd"'
	wait $v3 || { echo FAILED v3 did not come back; fails=$((fails + 1)); }
	t grep -q k2 "$OUT/v3back"
	echo '$ connections, nfsd back'
	c | tee "$OUT/conn2"
	t sh -c "grep -Fxf '$OUT/conn1' '$OUT/conn2' >/dev/null"
	t sudo rm -rf /mnt/v3/lc
	t sudo umount /mnt/v3
	t sudo umount /mnt/v4
	echo "failures: $fails"
	sudo dmesg | grep -iE 'nfs|rpc' | tail -20
} >"$OUT/linux.txt" 2>&1
rm -f "$BIN"
cat "$OUT/linux.txt"
[ "$(grep -c '^failures: 0$' "$OUT/linux.txt")" = 1 ]
