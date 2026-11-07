#!/bin/sh
# Inside the chroot of the tree under test.  Nothing here is cut.
so=$(ls /usr/lib/librump.so.*.* | head -1)
diag() {
	echo "=== rump_server by hand: $1"
	rm -rf /var/tmp/diag; mkdir -p /var/tmp/diag; cd /var/tmp/diag
	newfs -q user -B be -O 1 -s 4000 -F fsimage >/dev/null
	export RUMP_SERVER=unix://diagsock RUMP_VERBOSE=1
	rump_server -s -v -lrumpvfs -lrumpdev -lrumpnet -lrumpnet_net \
	    -lrumpnet_netinet -lrumpnet_netinet6 -lrumpnet_local \
	    -lrumpnet_shmif -lrumpdev_disk -lrumpfs_ffs -lrumpfs_nfs \
	    -lrumpfs_nfsserver -d key=/dk,hostpath=fsimage,size=host \
	    $RUMP_SERVER >rs.log 2>&1 &
	p=$!
	sleep 3
	for a in "create" "linkstr shmbus" "inet 10.1.1.1"; do
		echo "\$ rump.ifconfig shmif0 $a"
		timeout 20 rump.ifconfig shmif0 $a; echo "exit $?"
		kill -0 $p 2>/dev/null && echo server alive || echo server gone
		sleep 1
	done
	timeout 20 rump.halt; echo "halt $?"
	sleep 1; kill -9 $p 2>/dev/null; wait $p; echo "server status $?"
	cat rs.log
	ls -la
	[ -f rump_server.core ] && gdb -batch -ex 'bt 30' -ex 'x/i $pc' \
	    -ex 'info registers' "$(command -v rump_server)" \
	    rump_server.core 2>&1
	unset RUMP_SERVER RUMP_VERBOSE
}
one() {
	cp /usr/lib/rump-$1.so $so
	sha256 $so
	diag $1
	echo "=== t_rquotad: $1"
	cd /usr/tests/fs/nfs
	atf-run t_rquotad | tee /var/tmp/raw.$1 | atf-report
	echo "=== raw: $1"
	cat /var/tmp/raw.$1
}
uname -a
one trunk
one fixed
echo '=== end'
