#!/bin/sh
# The NetBSD client through the server's lock manager, audit item 8: a
# lock taken on the mount has to be seen by the server's own processes,
# which it never was.  Client and server are one kernel.
T=/var/tmp/try
fails=0
ok()   { echo "\$ $*"; if "$@"; then echo ok; else echo "FAILED"; fails=$((fails + 1)); fi; }
no()   { echo "\$ ! $*"; if "$@"; then echo "FAILED: granted"; fails=$((fails + 1)); else echo ok; fi; }
one() {	# flag, label
	m=/mnt/nlm$2
	mkdir -p $m
	ok mount_nfs $1 -U 127.0.0.1:/export/ffs $m
	f=$m/cl$2
	touch $f
	$T -h 6 $f 0 &
	h=$!
	sleep 2
	no $T /export/ffs/cl$2 0
	no $T $f 0
	ok $T $f 100
	sysctl vfs.nlm.nholds
	wait $h
	ok $T /export/ffs/cl$2 0
	$T -h 6 /export/ffs/cl$2 200 &
	h=$!
	sleep 2
	no $T $f 200
	s=$(date +%s)
	ok $T -w $f 200
	echo "waited $(( $(date +%s) - s )) s"
	wait $h
	$T -h 40 $f 300 &
	h=$!
	sleep 1
	$T -w $f 300 &
	w=$!
	sleep 2
	sysctl vfs.nlm.nwaiters
	kill $w
	wait $w
	sleep 1
	sysctl vfs.nlm.nwaiters
	kill $h
	wait $h
	sleep 1
	ok $T /export/ffs/cl$2 300
	ok umount $m
}
ok sysctl -w vfs.nlm.client=1
one -3 v3
one -2 v2
ok sysctl -w vfs.nlm.client=0
mkdir -p /mnt/nlmoff
ok mount_nfs -3 -U 127.0.0.1:/export/ffs /mnt/nlmoff
touch /mnt/nlmoff/cloff
$T -h 4 /mnt/nlmoff/cloff 0 &
sleep 1
echo '$ with it off the server does not see the lock, as before'
ok $T /export/ffs/cloff 0
wait
ok umount /mnt/nlmoff
echo "failures: $fails"
[ $fails = 0 ]
