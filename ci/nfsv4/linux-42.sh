#!/bin/sh
# What version 4.2 adds, from the Linux client of the runner, through
# the tunnel.  The failures are the measurement.  What the server is
# expected not to do on a file system is looked for as well, so that
# refusing to is not mistaken for working or the other way round.
#   linux-42.sh OUT
OUT=$1
LOG=$OUT/linux-42.txt
sudo apt-get install -y -q attr >/dev/null 2>&1
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
seekcheck() {
	python3 - "$1" "$2" <<'P'
import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
d = os.lseek(fd, 0, os.SEEK_DATA)
h = os.lseek(fd, d, os.SEEK_HOLE)
print("data", d, "hole", h)
assert d <= 1048576 < h <= 4194304
if sys.argv[2] == "holes":
    assert d > 0 and h < 4194304
P
}
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
	t seekcheck "$d/sp" "$holes"
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
{
	uname -a
	grep -E 'READ_PLUS' "/boot/config-$(uname -r)" || :
	#   export          holes  allocate clone xattr
	one /export/pynfs   holes  yes      no    no
	one /export/tmpfs   none   yes      no    no
	one /export/acl     holes  yes      no    yes
	one /tank/x         any    no       yes   yes
	echo "failures: $fails"
	sudo dmesg | grep -iE 'nfs|rpc' | tail -20
} >"$LOG" 2>&1
rm -f "$OUT/sp" "$OUT/da"
cat "$LOG"
