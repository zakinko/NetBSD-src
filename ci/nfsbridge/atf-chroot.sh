#!/bin/sh
# Inside the chroot.  Nothing here is cut: the raw logs are the record.
# What t_rquotad starts with, in the foreground, so that its end is seen.
diag() {
	echo "=== rump_server by hand: $1"
	mkdir -p /var/tmp/diag; cd /var/tmp/diag
	rm -f fsimage rs.log diagsock; newfs -q user -B be -O 1 -s 4000 -F fsimage >/dev/null
	export RUMP_SERVER=unix://diagsock RUMP_VERBOSE=1
	rump_server -s -v -lrumpvfs -lrumpdev -lrumpnet -lrumpnet_net \
	    -lrumpnet_netinet -lrumpnet_netinet6 -lrumpnet_local \
	    -lrumpnet_shmif -lrumpdev_disk -lrumpfs_ffs -lrumpfs_nfs \
	    -lrumpfs_nfsserver -lrumpkern_crypto -d key=/dk,hostpath=fsimage,size=host \
	    $RUMP_SERVER >rs.log 2>&1 &
	p=$!
	sleep 3
	for a in "create" "linkstr shmbus" "inet 10.1.1.1"; do
		echo "\$ rump.ifconfig shmif0 $a"
		timeout 20 rump.ifconfig shmif0 $a; echo "exit $?"
		kill -0 $p 2>/dev/null && echo server alive || echo server gone
	done
	timeout 20 rump.halt; echo "halt $?"
	sleep 1; kill -9 $p 2>/dev/null; wait $p; echo "server status $?"
	cat rs.log
	ls -la
	[ -f rump_server.core ] && gdb -batch -ex 'bt 30' -ex 'x/i $pc' -ex 'info registers' \
	    "$(command -v rump_server)" rump_server.core 2>&1
	rm -f rump_server.core
	unset RUMP_SERVER RUMP_VERBOSE
}
# The nfs cases of tests/fs/vfs, adding their failures to f.
vfs_cases()
{
	cd /usr/tests/fs/vfs
	for t in t_vfsops t_vnops t_rmdirrace t_renamerace t_ro; do
		[ -x $t ] || continue
		for c in $(./$t -l | sed -n 's/^ident: //p' | grep '^nfs'); do
			# Run directly, a case has no atf timeout of its own: t_vfsops
			# nfs_tfhremove hung until the 40-minute bound of the whole run
			# in run 43130006853, and nothing after it was measured.
			# A hung case left its rumpnfsd behind, and every case after
			# nfs_dir_rmdirdotdot hung in run 43149505709; the stacks of a
			# hung one are taken before it is killed.
			rm -f /var/tmp/res.$$
			./$t -r /var/tmp/res.$$ $c >/var/tmp/out.$$ 2>&1 &
			tp=$!; n=0
			while kill -0 $tp 2>/dev/null && [ $n -lt 300 ]; do
				sleep 1; n=$((n + 1))
			done
			if kill -0 $tp 2>/dev/null; then
				for p in $tp $(pgrep -x rumpnfsd); do
					echo "--- stacks of $p, $(ps -o comm= -p $p)"
					gdb -batch -p $p -ex 'thread apply all bt 30' 2>&1 |
					    grep -E '^(Thread|#)' | head -200
				done
				kill -9 $tp 2>/dev/null
			fi
			wait $tp 2>/dev/null
			pkill -9 -x rumpnfsd 2>/dev/null; sleep 1
			r=$(head -1 /var/tmp/res.$$ 2>/dev/null)
			case $r in '') r="broken: no result, hung or killed"; tail -20 /var/tmp/out.$$ ;; esac
			echo "$t:$c: $r"
			case $r in failed*|broken*) f=$((f + 1)) ;; esac
		done
	done
}
diag bridge
cd /usr/tests/fs/nfs
atf-run | tee /var/tmp/raw.bridge | atf-report
echo '=== raw, bridge'
cat /var/tmp/raw.bridge
f=$(grep -cE '^tc-end:.*, (failed|broken),' /var/tmp/raw.bridge)
vfs_cases
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
# The same vfs cases on the stock library, so that a failure there tells
# a flaky case from one the bridge brings.
f=0
vfs_cases
echo "stock vfs failures: $f"
cp /usr/lib/bridge-nfsserver.so $so
