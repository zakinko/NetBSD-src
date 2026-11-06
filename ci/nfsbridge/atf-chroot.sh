#!/bin/sh
# Inside the chroot.  Nothing here is cut: the raw logs are the record.
# What t_rquotad starts with, in the foreground, so that its end is seen.
diag() {
	echo "=== rump_server by hand: $1"
	mkdir -p /var/tmp/diag; cd /var/tmp/diag
	rm -f fsimage rs.log; newfs -q user -B be -O 1 -s 4000 -F fsimage >/dev/null
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
		rump.ifconfig shmif0 $a; echo "exit $?"
		kill -0 $p 2>/dev/null && echo server alive || echo server gone
	done
	rump.halt 2>/dev/null
	sleep 1; kill $p 2>/dev/null; wait $p; echo "server status $?"
	cat rs.log
	ls -la
	[ -f rump_server.core ] && gdb -batch -ex 'bt 30' -ex 'info threads' \
	    "$(command -v rump_server)" rump_server.core 2>&1
	rm -f rump_server.core
	unset RUMP_SERVER RUMP_VERBOSE
}
diag bridge
cd /usr/tests/fs/nfs
atf-run | tee /var/tmp/raw.bridge | atf-report
echo '=== raw, bridge'
cat /var/tmp/raw.bridge
f=$(grep -cE '^tc-end:.*, (failed|broken),' /var/tmp/raw.bridge)
cd /usr/tests/fs/vfs
for t in t_vfsops t_vnops t_rmdirrace t_renamerace t_ro; do
	[ -x $t ] || continue
	for c in $(./$t -l | sed -n 's/^ident: //p' | grep '^nfs'); do
		r=$(./$t -r /var/tmp/res.$$ $c >/dev/null 2>&1; head -1 /var/tmp/res.$$)
		echo "$t:$c: $r"
		case $r in failed*|broken*) f=$((f + 1)) ;; esac
	done
done
echo "bridge failures: $f"
so=$(ls /usr/lib/librumpfs_nfsserver.so.*.* | head -1)
cp $so /usr/lib/bridge-nfsserver.so
cp /usr/lib/stock-nfsserver.so $so
diag stock
echo '=== control: stock library'
cd /usr/tests/fs/nfs
atf-run | tee /var/tmp/raw.stock | atf-report
echo '=== raw, stock'
cat /var/tmp/raw.stock
cp /usr/lib/bridge-nfsserver.so $so
