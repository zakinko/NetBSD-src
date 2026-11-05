#!/bin/sh
# Mount the server from the Linux client of the runner, through the
# tunnel, version 4.0 by name, and do what a user does on both exports.
# The failures are the measurement.  linux-client.sh OUT
OUT=$1
LOG=$OUT/linux-client.txt
BIN=$OUT/lc.bin
sudo apt-get install -y -q nfs-common >/dev/null 2>&1
sudo modprobe nfs || {
	sudo apt-get install -y -q "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
	sudo modprobe nfs
}
sudo modprobe nfsv4
fails=0
t() {
	echo "\$ $*"
	if timeout 120 "$@"; then echo "ok"; else echo "FAILED ($?)"; fails=$((fails + 1)); fi
}
one() {
	export_=$1
	m=/mnt/nfsv4$(basename "$export_")
	sudo mkdir -p "$m"
	t sudo mount -v -t nfs -o vers=4.0,proto=tcp,port=2049,addr=127.0.0.1,clientaddr=127.0.0.1,sec=sys,hard,timeo=100,retrans=2 \
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
{
	uname -a
	one /export/pynfs
	one /export/tmpfs
	echo "failures: $fails"
	sudo dmesg | grep -iE 'nfs|rpc' | tail -20
	if sudo dmesg | grep -q 'bad sequence-id'; then
		echo 'FAILED: the client saw a bad seqid'
	fi
} >"$LOG" 2>&1
rm -f "$BIN"
cat "$LOG"
