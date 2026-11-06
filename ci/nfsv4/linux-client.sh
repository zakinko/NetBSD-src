#!/bin/sh
# Mount the server from the Linux client of the runner, through the
# tunnel, version 4.0 by name or VERS, and do what a user does on both
# exports.  The failures are the measurement.  linux-client.sh OUT
OUT=$1
VERS=${VERS:-4.0}
LOG=$OUT/linux-client-$VERS.txt
CONFLICT=$(cd "$(dirname "$0")" && pwd)/conflict41.py
BIN=$OUT/lc.bin
sudo apt-get install -y -q nfs-common nfs4-acl-tools >/dev/null 2>&1
sudo modprobe nfs || {
	sudo apt-get install -y -q "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
	sudo modprobe nfs
}
sudo modprobe nfsv4
# The server calls back through the tunnel, to a port it can be told.
echo 40100 | sudo tee /sys/module/nfs/parameters/callback_tcpport >/dev/null
fails=0
t() {
	echo "\$ $*"
	if timeout 120 "$@"; then echo "ok"; else echo "FAILED ($?)"; fails=$((fails + 1)); fi
}
one() {
	export_=$1
	m=/mnt/nfsv4$(basename "$export_")
	sudo mkdir -p "$m"
	t sudo mount -v -t nfs -o vers=$VERS,proto=tcp,port=2049,addr=127.0.0.1,clientaddr=127.0.0.1,sec=sys,hard,timeo=100,retrans=2 \
	    "127.0.0.1:$export_" "$m"
	grep "$m" /proc/mounts || return
	t sudo mkdir "$m/lc"
	t sudo chmod 1777 "$m/lc"
	t sh -c "echo hello >$m/lc/a"
	t test "$(cat "$m/lc/a")" = hello
	t ls -la "$m/lc"
	t dd if=/dev/urandom of="$BIN" bs=1M count=8 status=none
	t cp "$BIN" "$m/lc/b"
	t sh -c "sync; sudo sh -c 'echo 3 >/proc/sys/vm/drop_caches'"
	t cmp "$BIN" "$m/lc/b"
	t mv "$m/lc/b" "$m/lc/c"
	t cmp "$BIN" "$m/lc/c"
	t ln -s c "$m/lc/s"
	t ln "$m/lc/c" "$m/lc/h"
	t test "$(stat -c %h "$m/lc/c")" = 2
	t chmod 640 "$m/lc/c"
	t test "$(stat -c %a "$m/lc/c")" = 640
	t truncate -s 1000 "$m/lc/c"
	t test "$(stat -c %s "$m/lc/h")" = 1000
	t touch -d '2001-02-03 04:05:06' "$m/lc/a"
	t test "$(stat -c %Y "$m/lc/a")" = "$(date -d '2001-02-03 04:05:06' +%s)"
	t mkdir -p "$m/lc/d/e/f"
	t sh -c "for i in 1 2 3 4 5 6 7 8 9 10; do : >$m/lc/d/n\$i; done"
	t test "$(ls "$m/lc/d" | wc -l)" = 11
	t rm -rf "$m/lc/d"
	t flock -n "$m/lc/a" true
	# Held on the server by a process there, so the server must say no.
	ssh netbsd "flock -n '$export_/lc/a' sleep 8" &
	h=$!
	sleep 3
	echo '$ flock -n, held by a process on the server'
	if flock -n "$m/lc/a" true; then
		echo 'FAILED: granted'; fails=$((fails + 1))
	else
		echo ok
	fi
	wait $h
	t flock -n "$m/lc/a" true
	# And the other way.
	flock "$m/lc/a" sleep 8 &
	h=$!
	sleep 3
	echo '$ flock -n on the server, held by the client'
	if ssh netbsd "flock -n '$export_/lc/a' true"; then
		echo 'FAILED: granted'; fails=$((fails + 1))
	else
		echo ok
	fi
	wait $h
	# fcntl byte ranges, two processes.
	t python3 -c "
import fcntl,os,sys
f=open('$m/lc/a','r+')
fcntl.lockf(f,fcntl.LOCK_EX,10,0)
p=os.fork()
if p==0:
    g=open('$m/lc/a','r+')
    try:
        fcntl.lockf(g,fcntl.LOCK_EX|fcntl.LOCK_NB,10,5); os._exit(1)
    except OSError: pass
    fcntl.lockf(g,fcntl.LOCK_EX|fcntl.LOCK_NB,10,10); os._exit(0)
sys.exit(os.waitpid(p,0)[1]!=0)"
	t sudo rm -rf "$m/lc"
	t sudo umount "$m"
}
# The acl attribute, from the client's tools and read back on the server.
acl() {
	x=$1
	m=/mnt/nfsv4$(basename "$x")
	sudo mkdir -p "$m"
	t sudo mount -v -t nfs -o vers=$VERS,proto=tcp,port=2049,addr=127.0.0.1,clientaddr=127.0.0.1,noresvport,nolock \
	    "127.0.0.1:$x" "$m"
	grep "$m" /proc/mounts || return
	t sudo sh -c "echo hello >$m/f; chmod 640 $m/f"
	t sudo mkdir "$m/d"
	echo '$ nfs4_getfacl f'
	sudo nfs4_getfacl "$m/f"
	t sudo nfs4_setfacl -a 'A::1234:rtncy' "$m/f"
	t sudo nfs4_setfacl -a 'A:g:5678:rwatTnNcy' "$m/f"
	t sudo nfs4_setfacl -a 'D::4321:w' "$m/f"
	t sudo nfs4_setfacl -a 'A:fd:1234:rxtncy' "$m/d"
	echo '$ nfs4_getfacl f, after'
	sudo nfs4_getfacl "$m/f" | tee "$OUT/acl-client.txt"
	t grep -q 'A::1234:' "$OUT/acl-client.txt"
	t grep -q 'A:g:5678:' "$OUT/acl-client.txt"
	t grep -q 'D::4321:' "$OUT/acl-client.txt"
	echo '$ getfacl on the server'
	ssh netbsd "getfacl $x/f $x/d" | tee "$OUT/acl-server.txt"
	t grep -q 'user:1234:' "$OUT/acl-server.txt"
	t grep -q 'group:5678:' "$OUT/acl-server.txt"
	# Enforced: the named user reads, an unnamed one does not.
	t sudo chmod 600 "$m/f"
	echo '$ after chmod 600'
	sudo nfs4_getfacl "$m/f"
	t ssh netbsd "getfacl $x/f"
	t sudo sh -c "echo inherited >$m/d/n"
	echo '$ inherited'
	sudo nfs4_getfacl "$m/d/n"
	t sudo rm -rf "$m/f" "$m/d"
	t sudo umount "$m"
}
# How many DELEGRETURNs the mount at $1 has sent.
dreturns() {
	awk -v m=" $1 " 'index($0, "device ") == 1 { on = index($0, m) != 0 }
	    on && $1 == "DELEGRETURN:" { print $2; exit }' /proc/self/mountstats
}
# With delegations in mind.  How many came back is the measurement.
deleg() {
	m=/mnt/nfsv4deleg
	sudo mkdir -p "$m"
	t sudo mount -v -t nfs -o vers=$VERS,proto=tcp,port=2049,addr=127.0.0.1,clientaddr=127.0.0.1,sec=sys,hard,timeo=100,retrans=2 \
	    127.0.0.1:/export/pynfs "$m"
	sleep 3
	t sudo mkdir "$m/dg"
	t sudo chmod 1777 "$m/dg"
	t dd if=/dev/urandom of="$BIN" bs=1M count=4 status=none
	t cp "$BIN" "$m/dg/a"
	t cmp "$BIN" "$m/dg/a"
	t sh -c "exec 3<>$m/dg/a; sleep 1; echo x >&3"
	t python3 -c "
import fcntl
f=open('$m/dg/a','r+')
fcntl.lockf(f,fcntl.LOCK_EX,10,0)
fcntl.lockf(f,fcntl.LOCK_UN,10,0)"
	if [ "$VERS" = 4.1 ]; then
		# A delegation held, recalled by another client, RFC 8881 s10.4.
		r0=$(dreturns "$m")
		exec 3<"$m/dg/a"
		sleep 1
		echo '$ conflict, with the file held open'
		t sh -c "cd $HOME/pynfs/nfs4.1 && cp $CONFLICT . && python3 ./conflict41.py /export/pynfs dg/a"
		exec 3<&-
		echo "DELEGRETURN before $r0 after $(dreturns "$m")"
		t test "$(dreturns "$m")" -gt "$r0"
		# The connection goes, and with it the backchannel, s2.10.13.1.2.
		t sudo pkill -f 'ssh -f -N .*2049:127.0.0.1:2049'
		t ssh -f -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=10 \
		    -L 2049:127.0.0.1:2049 netbsd
		sleep 2
		t sh -c "cat $m/dg/a >/dev/null"
		sleep 5
		r0=$(dreturns "$m")
		exec 3<"$m/dg/a"
		sleep 1
		echo '$ conflict, after the connection was lost'
		t sh -c "cd $HOME/pynfs/nfs4.1 && cp $CONFLICT . && python3 ./conflict41.py /export/pynfs dg/a"
		exec 3<&-
		echo "DELEGRETURN before $r0 after $(dreturns "$m")"
		t test "$(dreturns "$m")" -gt "$r0"
	fi
	t mv "$m/dg/a" "$m/dg/b"
	t sudo rm -rf "$m/dg"
	grep -E 'DELEGRETURN|OPEN:' /proc/self/mountstats | tail -4
	t sudo umount "$m"
}
{
	uname -a
	deleg
	one /export/pynfs
	one /export/tmpfs
	one /tank/x
	acl /export/acl
	acl /tank/x
	echo "failures: $fails"
	sudo dmesg | grep -iE 'nfs|rpc' | tail -20
	if sudo dmesg | grep -q 'bad sequence-id'; then
		echo 'FAILED: the client saw a bad seqid'
	fi
} >"$LOG" 2>&1
rm -f "$BIN"
cat "$LOG"
