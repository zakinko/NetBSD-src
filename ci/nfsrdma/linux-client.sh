#!/bin/sh
# The Linux client, by xprtrdma on siw, against the NetBSD server, through
# the tunnel.  siw is plain TCP underneath, so the far end of the tunnel
# sees what siw sends; rxe would be UDP, which ssh does not carry.
# Every check counts; the failures are the measurement.
# linux-client.sh OUT
OUT=$1
LOG=$OUT/linux-client.txt
BIN=$HOME/lc.bin
M=/mnt/rdma
A=192.0.2.1	# RFC 5737, on dummy0
exec >"$LOG" 2>&1
sudo apt-get update -q >/dev/null
sudo apt-get install -y -q rdma-core nfs-common tcpdump >/dev/null 2>&1
sudo modprobe siw && sudo modprobe rdma_ucm && sudo modprobe rpcrdma
# On an interface of its own: rdma_cm does not take siw on lo for
# 127.0.0.1 (ENODEV), and the runner's eth0 may have a mana or mlx5 on it.
# The tunnel listens here too; see the workflow.
rdma link
sudo rdma link add siwd type siw netdev dummy0
rdma link
sudo tcpdump -i lo -s 512 -c 200000 -w "$OUT/rdma.pcap" tcp port 20049 >/dev/null 2>&1 &
DUMP=$!
sleep 1
fails=0
t() {
	echo "\$ $*"
	if timeout 120 "$@"; then echo ok; else echo "FAILED ($?)"; fails=$((fails + 1)); fi
}
sudo mkdir -p "$M"
t sudo mount -v -t nfs -o vers=4.0,proto=rdma,port=20049,addr=$A,clientaddr=$A,sec=sys,hard,timeo=100,retrans=2 \
    $A:/export/x "$M"
if mountpoint -q "$M"; then
	grep "$M" /proc/mounts
	sudo grep -E 'device|xprt:' /proc/self/mountstats | grep -A1 "$M"
	t sudo mkdir "$M/d"
	t sudo chmod 1777 "$M/d"
	# Short messages.
	t sh -c "echo hello >$M/d/a"
	t test "$(cat "$M/d/a")" = hello
	# READLINK and SYMLINK, s6.1.
	t ln -s a "$M/d/s"
	t test "$(readlink "$M/d/s")" = a
	long=$(printf 'x%.0s' $(seq 1 900))
	t ln -s "$long" "$M/d/ls"
	t test "$(readlink "$M/d/ls")" = "$long"
	# Large data: Read chunks for WRITE, Write chunks for READ.
	for n in 1 8; do
		t dd if=/dev/urandom of="$BIN" bs=1M count=$n status=none
		t cp "$BIN" "$M/d/b$n"
		t sh -c "sync; sudo sh -c 'echo 3 >/proc/sys/vm/drop_caches'"
		t cmp "$BIN" "$M/d/b$n"
		ssh netbsd "cksum -a sha256 /export/x/d/b$n" | sed 's/.*= //' >"$OUT/remote.sum"
		t test "$(cat "$OUT/remote.sum")" = "$(sha256sum "$BIN" | cut -d' ' -f1)"
	done
	# A size that needs the roundup: 4097 bytes.
	t dd if=/dev/urandom of="$BIN" bs=4097 count=1 status=none
	t cp "$BIN" "$M/d/odd"
	t sh -c "sync; sudo sh -c 'echo 3 >/proc/sys/vm/drop_caches'"
	t cmp "$BIN" "$M/d/odd"
	# A directory bigger than an inline reply: a Reply chunk.
	t sh -c "cd $M/d && mkdir big && cd big && for i in \$(seq 1 400); do : >file-with-a-rather-long-name-\$i; done"
	t sudo sh -c 'echo 3 >/proc/sys/vm/drop_caches'
	t test "$(ls "$M/d/big" | wc -l)" = 400
	t rm -rf "$M/d/big"
	sudo grep -E 'xprt:' /proc/self/mountstats
	sudo grep -A3 -E 'READ:|WRITE:' /proc/self/mountstats | head -20
	t sudo umount "$M"
fi
sudo kill "$DUMP"
sudo dmesg | grep -iE 'rdma|siw|nfs|rpc' | tail -40
echo "FAILURES: $fails"
ssh netbsd 'netstat -an -f inet | grep 20049; dmesg | tail -20'
