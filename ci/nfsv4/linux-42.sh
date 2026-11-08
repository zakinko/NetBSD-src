#!/bin/sh
# What version 4.2 adds, from the Linux client of the runner, through
# the tunnel.  The failures are the measurement.  What the server is
# expected not to do on a file system is looked for as well, so that
# refusing to is not mistaken for working or the other way round.
#   linux-42.sh OUT
OUT=$1
LOG=$OUT/linux-42.txt
sudo apt-get install -y -q attr >/dev/null 2>&1
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q tshark >/dev/null 2>&1
fails=0
t() {
	echo "\$ $*"
	if timeout 180 "$@"; then echo "ok"; else echo "FAILED ($?)"; fails=$((fails + 1)); fi
}
# The other way round: it must fail, and say why it did.
n() {
	echo "\$ (must fail) $*"
	if timeout 180 "$@"; then echo "FAILED: it worked"; fails=$((fails + 1)); else echo "ok ($?)"; fi
}
flush() {
	sync
	sudo sh -c 'echo 3 >/proc/sys/vm/drop_caches'
}
cat >"$OUT/seekcheck.py" <<'P'
import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
d = os.lseek(fd, 0, os.SEEK_DATA)
h = os.lseek(fd, d, os.SEEK_HOLE)
print("data", d, "hole", h)
assert d <= 1048576 < h <= 4194304
if sys.argv[2] == "holes":
    assert d > 0 and h < 4194304
P
cat >"$OUT/seekcheck-da.py" <<'P'
import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
h = os.lseek(fd, 0, os.SEEK_HOLE)
d = os.lseek(fd, h, os.SEEK_DATA)
print("hole", h, "data", d)
assert 70000 <= h + 65536 and h < 1170000 < d + 65536
P
# Which operations the client really sent.
ops() {
	grep -E "^ *($1):" /proc/self/mountstats | sort -u
}
one() {
	x=$1 holes=$2 alloc=$3 clone=$4 xattr=$5
	m=/mnt/v42$(basename "$x")
	sudo mkdir -p "$m"
	t sudo mount -v -t nfs -o vers=4.2,proto=tcp,port=2049,addr=127.0.0.1,clientaddr=127.0.0.1,sec=sys,hard,timeo=100,retrans=2 \
	    "127.0.0.1:$x" "$m"
	grep "$m" /proc/mounts || return
	t sudo mkdir "$m/v42"
	t sudo chmod 1777 "$m/v42"
	d=$m/v42

	# SEEK, and READ_PLUS on the same file.
	t truncate -s 4M "$d/sp"
	t sh -c "printf x | dd of='$d/sp' bs=1 seek=1048576 conv=notrunc status=none"
	flush
	t python3 "$OUT/seekcheck.py" "$d/sp" "$holes"
	t sh -c "python3 -c \"import sys;b=bytearray(4194304);b[1048576]=120;sys.stdout.buffer.write(b)\" >'$OUT/sp'"
	t cmp "$d/sp" "$OUT/sp"

	# ALLOCATE
	if [ "$alloc" = yes ]; then
		t fallocate -o 1M -l 1M "$d/al"
		t test "$(stat -c %s "$d/al")" = 2097152
		t sh -c "dd if=/dev/zero bs=1M count=2 status=none | cmp - '$d/al'"
		flush
		[ "$holes" = holes ] && t test "$(stat -c %b "$d/al")" -ge 2048
	else
		n fallocate -o 1M -l 1M "$d/al"
	fi

	# DEALLOCATE
	t dd if=/dev/urandom of="$OUT/da" bs=1M count=3 status=none
	t cp "$OUT/da" "$d/da"
	t fallocate -p -o 70000 -l 1100000 "$d/da"
	t python3 -c "
b=bytearray(open('$OUT/da','rb').read())
b[70000:1170000]=bytes(1100000)
open('$OUT/da','wb').write(b)"
	flush
	t cmp "$d/da" "$OUT/da"
	t test "$(stat -c %s "$d/da")" = 3145728
	if [ "$holes" = holes ]; then
		# s15.4.3: FFS really gives the blocks back, and says so.
		t test "$(stat -c %b "$d/da")" -lt 5000
		t python3 "$OUT/seekcheck-da.py" "$d/da"
	fi

	# COPY, past where a short result comes.
	t dd if=/dev/urandom of="$OUT/co" bs=1M count=70 status=none
	t cp "$OUT/co" "$d/co"
	t cp --reflink=never "$d/co" "$d/co2"
	flush
	t cmp "$OUT/co" "$d/co2"
	t python3 -c "
import os
a=os.open('$d/co',os.O_RDONLY);b=os.open('$d/co3',os.O_WRONLY|os.O_CREAT)
n=os.copy_file_range(a,b,3000000,1000000,5)
print(n);assert n>0"
	flush
	t python3 -c "
a=open('$OUT/co','rb').read();b=open('$d/co3','rb').read()
n=len(b)-5;assert b[:5]==bytes(5) and b[5:]==a[1000000:1000000+n] and n>0;print(n)"
	rm -f "$OUT/co"

	# CLONE
	if [ "$clone" = yes ]; then
		t cp --reflink=always "$d/co2" "$d/cl"
		t cmp "$d/co2" "$d/cl"
		t sh -c "printf changed | dd of='$d/co2' bs=1 seek=4096 conv=notrunc status=none"
		flush
		n cmp "$d/co2" "$d/cl"
	else
		n cp --reflink=always "$d/co2" "$d/cl"
	fi

	# Extended attributes.
	if [ "$xattr" = yes ]; then
		t touch "$d/xa"
		t setfattr -n user.one -v hello "$d/xa"
		t setfattr -n user.two -v world "$d/xa"
		t test "$(getfattr --only-values -n user.one "$d/xa")" = hello
		t sh -c "getfattr -d '$d/xa' | grep -q user.two"
		t setfattr -x user.one "$d/xa"
		n getfattr -n user.one "$d/xa"
		n setfattr -x user.one "$d/xa"
		ssh netbsd "getextattr -q user two '$x/v42/xa'"
	else
		t touch "$d/xa"
		n setfattr -n user.one -v hello "$d/xa"
	fi

	ops 'ALLOCATE|DEALLOCATE|SEEK|READ_PLUS|COPY|CLONE|GETXATTR|SETXATTR|LISTXATTRS|REMOVEXATTR'
	t sudo rm -rf "$d"
	t sudo umount "$m"
}
# What a hole punch leaves, read by fsck with the file still there: a
# block both free and in the file, or in neither, is what would show.
# The control is fsck of the same image fresh from newfs.
punchfsck() {
	x=$1 v=$2 o=$3
	p=/mnt/v42fsck
	sudo mkdir -p "$p"
	t sudo mount -t nfs -o vers=4.2,proto=tcp,port=2049,addr=127.0.0.1,clientaddr=127.0.0.1,sec=sys "127.0.0.1:$x" "$p"
	t sudo dd if=/dev/urandom of="$p/punched" bs=1M count=64 status=none
	t sudo fallocate -p -o 100000 -l 20000000 "$p/punched"
	t sudo fallocate -p -o 30000000 -l 4096 "$p/punched"
	t sudo umount "$p"
	ssh netbsd "sync; umount -f $x; fsck_ffs -fn /dev/r${v}d; mount $o /dev/${v}d $x; rm -f $x/punched; kill -HUP \$(cat /var/run/mountd.pid)" >"$OUT/fsck-$v.txt" 2>&1
	cat "$OUT/fsck-$v.txt"
	t grep -q 'Phase 5' "$OUT/fsck-$v.txt"
	n grep -E 'BAD|DUP|MISSING|UNREF|INCORRECT BLOCK' "$OUT/fsck-$v.txt"
}
# A file locked on the server, and flock from a client of version $1 with
# vfs.nfsv4.delegations at $2.  Whether a delegation is what lets it by.
flockab() {
	p=/mnt/v42ab
	sudo mkdir -p "$p"
	cap=""
	if [ "$2" = 2 ]; then
		# The backchannel rides the forechannel's connection: one
		# capture shows the OPEN's delegation and any CB_RECALL.
		cap=$OUT/flock-$1.pcap
		sudo rpcdebug -m nfs -s callback >/dev/null 2>&1 || :
		sudo dmesg -C 2>/dev/null || :
		sudo tcpdump -i lo -s 0 -U -w "$cap" tcp port 2049 >/dev/null 2>&1 &
		tp=$!
		sleep 1
	fi
	ssh netbsd "sysctl -w vfs.nfsv4.delegations=$2"
	t sudo mount -t nfs -o vers=$1,proto=tcp,port=2049,addr=127.0.0.1,clientaddr=127.0.0.1,sec=sys 127.0.0.1:/export/pynfs "$p"
	sleep 3
	t sudo sh -c "echo x >$p/ab"
	t sudo chmod 666 "$p/ab"
	cat "$p/ab" >/dev/null
	ssh netbsd "flock -n /export/pynfs/ab sleep 8" &
	h=$!
	sleep 3
	echo "\$ flock -n, vers=$1 delegations=$2"
	if flock -n "$p/ab" true; then
		echo "FAILED: granted vers=$1 delegations=$2"; fails=$((fails + 1))
	else
		echo "refused vers=$1 delegations=$2"
	fi
	wait $h
	grep -E 'DELEGRETURN|  LOCK:' /proc/self/mountstats | sort -u | head -4
	sudo rm -f "$p/ab"
	sudo umount "$p"
	if [ -n "$cap" ]; then
		sleep 1
		sudo kill "$tp" 2>/dev/null; wait "$tp" 2>/dev/null
		echo "--- what went over the wire, vers=$1 delegations=$2"
		sudo tshark -r "$cap" -Y 'nfs' -V 2>/dev/null |
		    grep -E 'Opcode:|Delegation Type|delegation_type|Status:|CB_RECALL|Callback|Program Version|minorversion' |
		    sed 's/^[[:space:]]*//' | uniq | head -120
		echo "--- the client's callback log"
		sudo dmesg 2>/dev/null | grep -iE 'callback|cb_|recall|deleg' | tail -30
		sudo rpcdebug -m nfs -c callback >/dev/null 2>&1 || :
	fi
	ssh netbsd "sysctl -w vfs.nfsv4.delegations=2"
}
{
	uname -a
	flockab 4.1 2
	flockab 4.2 2
	flockab 4.1 0
	flockab 4.2 0
	echo '$ fsck of FFSv1 fresh from newfs, the control'
	ssh netbsd cat /var/tmp/nfsv4/fsck-control.txt
	echo '$ fsck of UFS2ea fresh from newfs, the control'
	ssh netbsd cat /var/tmp/nfsv4/fsck-control-ea.txt
	grep -E 'READ_PLUS' "/boot/config-$(uname -r)" || :
	#   export          holes  allocate clone xattr
	one /export/pynfs   holes  yes      no    no
	one /export/tmpfs   none   yes      no    no
	one /export/acl     holes  yes      no    yes
	one /tank/x         any    no       yes   yes
	punchfsck /export/acl vnd1 -o\ nfs4acls
	punchfsck /export/ffs1 vnd3 ""
	echo "failures: $fails"
	sudo dmesg | grep -iE 'nfs|rpc' | tail -20
} >"$LOG" 2>&1
rm -f "$OUT/sp" "$OUT/da" "$OUT/seekcheck.py" "$OUT/seekcheck-da.py"
cat "$LOG"
