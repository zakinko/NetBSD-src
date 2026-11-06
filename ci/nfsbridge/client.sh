#!/bin/sh
# The NetBSD client, on the server itself: versions 2 and 3, TCP and
# UDP, what a user does and the large transfers.  client.sh OUT
OUT=$1
D=/var/tmp/nfsbridge
fails=0
t() {
	echo "\$ $*"
	if "$@"; then echo ok; else echo "FAILED ($?)"; fails=$((fails + 1)); fi
}
BIN=/var/tmp/bin.64m
dd if=/dev/urandom of=$BIN bs=1m count=64 2>/dev/null
one() {	# version flag, transport flag, label, export
	m=/mnt/nb$3
	mkdir -p $m
	t mount_nfs $1 $2 -i 127.0.0.1:$4 $m
	mount | grep -q " $m " || return
	mkdir -p $m/w
	t cp $BIN $m/w/a
	t cmp $BIN $m/w/a
	t mv $m/w/a $m/w/b
	t cmp $BIN $m/w/b
	t dd if=$m/w/b of=/dev/null bs=64k
	t ln -s b $m/w/s
	t ln $m/w/b $m/w/h
	t chmod 640 $m/w/b
	t mkdir -p $m/w/d/e
	i=0; while [ $i -lt 200 ]; do : >$m/w/d/n$i; i=$((i + 1)); done
	t test "$(ls $m/w/d | wc -l)" -eq 201
	t rm -rf $m/w
	t umount $m
}
main() {
	uname -v
	one -3 -T v3tcpffs /export/ffs
	one -3 -T v3tcptmp /export/tmpfs
	one -2 -T v2tcpffs /export/ffs
	one -3 -U v3udpffs /export/ffs
	one -3 -U v3udptmp /export/tmpfs
	one -2 -U v2udpffs /export/ffs
	# Large sizes, stated.
	mkdir -p /mnt/nbr
	t mount_nfs -3 -T -r 65536 -w 65536 127.0.0.1:/export/ffs /mnt/nbr
	t cp $BIN /mnt/nbr/l; t cmp $BIN /mnt/nbr/l; t rm /mnt/nbr/l
	t umount /mnt/nbr
	t mount_nfs -3 -U -r 32768 -w 32768 127.0.0.1:/export/ffs /mnt/nbr
	t cp $BIN /mnt/nbr/l; t cmp $BIN /mnt/nbr/l; t rm /mnt/nbr/l
	t umount /mnt/nbr
	# Write gathering: version 2, several writers.
	nfsstat -s
	t mount_nfs -2 -U -w 8192 127.0.0.1:/export/ffs /mnt/nbr
	for j in 1 2 3 4; do
		dd if=/dev/zero of=/mnt/nbr/g$j bs=8k count=512 2>/dev/null &
	done
	wait
	t rm /mnt/nbr/g1 /mnt/nbr/g2 /mnt/nbr/g3 /mnt/nbr/g4
	t umount /mnt/nbr
	nfsstat -s
	# Replays and bad calls.
	cc -g -Wall -o /var/tmp/rawrpc $D/rawrpc.c
	G=
	case $(uname -v) in *'(NFSBRON)'*) G=garbage ;; esac
	t /var/tmp/rawrpc tcp /export/ffs $G
	t /var/tmp/rawrpc udp /export/ffs $G
	nfsstat -s
	# nfsd comes back on its ports.
	pkill -x nfsd; sleep 3
	ps -ax | grep '[n]fsd' || echo no nfsd
	t /usr/sbin/nfsd -t -u -n 4
	sleep 2
	t mount_nfs -3 -U 127.0.0.1:/export/ffs /mnt/nbr
	t ls /mnt/nbr
	t umount /mnt/nbr
	echo "failures: $fails"
}
main 2>&1 | tee $OUT/client.txt
rm -f $BIN
tail -1 $OUT/client.txt | grep -q '^failures: 0$'
