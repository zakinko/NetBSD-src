#!/bin/sh
# The Linux client, by xprtrdma on siw, against the NetBSD server, through
# the tunnel.  siw is plain TCP underneath, so the far end of the tunnel
# sees what siw sends; rxe would be UDP, which ssh does not carry.
# Every check counts; the failures are the measurement, one count for
# each version.  linux-client.sh OUT [VERSION...]
OUT=$1
shift
VERSIONS=${*:-4.0 3 4.1 4.2}
LOG=$OUT/linux-client.txt
BIN=$HOME/lc.bin
M=/mnt/rdma
A=192.0.2.1	# RFC 5737, on dummy0
CONFLICT=$(cd "$(dirname "$0")/../nfsv4" && pwd)/conflict41.py
exec >"$LOG" 2>&1
sudo apt-get update -q >/dev/null
sudo apt-get install -y -q rdma-core nfs-common tcpdump >/dev/null 2>&1
sudo modprobe siw && sudo modprobe rdma_ucm && sudo modprobe rpcrdma
sudo modprobe nfsv3; sudo modprobe nfsv4
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
# How many DELEGRETURNs the mount at $1 has sent.
dreturns() {
	awk -v m=" $1 " 'index($0, "device ") == 1 { on = index($0, m) != 0 }
	    on && $1 == "DELEGRETURN:" { print $2; exit }' /proc/self/mountstats
}
sudo mkdir -p "$M"
for V in $VERSIONS; do
	fails=0
	echo "=== version $V"
	case $V in
	3)	# RFC 8267 s5.1: MOUNT, NLM and NSM stay on TCP.  MOUNT is on
		# the port mountd was given, NLM and NSM over the link of
		# nlm-up.sh.
		o="vers=3,proto=rdma,port=20049,mountport=1234,mountproto=tcp" ;;
	*)	o="vers=$V,proto=rdma,port=20049,clientaddr=$A" ;;
	esac
	t sudo mount -v -t nfs -o $o,addr=$A,sec=sys,hard,timeo=100,retrans=2 \
	    $A:/export/x "$M"
	if mountpoint -q "$M"; then
		grep "$M" /proc/mounts
		sudo grep -E 'device|xprt:' /proc/self/mountstats | grep -A1 "$M"
		d=$M/d$V
		t sudo mkdir "$d"
		t sudo chmod 1777 "$d"
		# Short messages.
		t sh -c "echo hello >$d/a"
		t test "$(cat "$d/a")" = hello
		# READLINK and SYMLINK, RFC 8267 s4 and s6.1.
		t ln -s a "$d/s"
		t test "$(readlink "$d/s")" = a
		long=$(printf 'x%.0s' $(seq 1 900))
		t ln -s "$long" "$d/ls"
		t sh -c 'echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null'
		t test "$(readlink "$d/ls")" = "$long"
		# Large data: Read chunks for WRITE, Write chunks for READ.
		for n in 1 8; do
			t dd if=/dev/urandom of="$BIN" bs=1M count=$n status=none
			t cp "$BIN" "$d/b$n"
			t sh -c "sync; sudo sh -c 'echo 3 >/proc/sys/vm/drop_caches'"
			t cmp "$BIN" "$d/b$n"
			ssh netbsd "cksum -a sha256 /export/x/d$V/b$n" | sed 's/.*= //' >"$OUT/remote.sum"
			t test "$(cat "$OUT/remote.sum")" = "$(sha256sum "$BIN" | cut -d' ' -f1)"
		done
		# A size that needs the roundup: 4097 bytes.
		t dd if=/dev/urandom of="$BIN" bs=4097 count=1 status=none
		t cp "$BIN" "$d/odd"
		t sh -c "sync; sudo sh -c 'echo 3 >/proc/sys/vm/drop_caches'"
		t cmp "$BIN" "$d/odd"
		# A directory bigger than an inline reply: a Reply chunk.
		t sh -c "cd $d && mkdir big && cd big && for i in \$(seq 1 400); do : >file-with-a-rather-long-name-\$i; done"
		t sudo sh -c 'echo 3 >/proc/sys/vm/drop_caches'
		t test "$(ls "$d/big" | wc -l)" = 400
		t rm -rf "$d/big"
		# A lock: by the protocol itself from 4.0 on, by NLM under 3.
		t python3 -c "
import fcntl
f=open('$d/a','r+')
fcntl.lockf(f,fcntl.LOCK_EX,10,0)
fcntl.lockf(f,fcntl.LOCK_UN,10,0)"
		# NLM, seen from the server, and a lock the server grants by
		# calling back, NLM_GRANTED.
		if [ "$V" = 3 ]; then
			python3 -c "
import fcntl, time
f = open('$d/a', 'r+')
fcntl.lockf(f, fcntl.LOCK_EX, 1, 0)
time.sleep(20)" &
			h=$!
			sleep 3
			echo '$ a process on the server meets the lock of the client'
			if ssh netbsd '/var/tmp/try /export/x/d3/a 0'; then
				echo 'FAILED (granted)'; fails=$((fails + 1))
			else
				echo ok
			fi
			t ssh netbsd '/var/tmp/try /export/x/d3/a 1'
			kill $h; wait $h 2>/dev/null
			ssh netbsd '/var/tmp/try -h 8 /export/x/d3/a 5' &
			h=$!
			sleep 3
			s0=$(date +%s)
			t python3 -c "
import fcntl
f = open('$d/a', 'r+')
fcntl.lockf(f, fcntl.LOCK_EX, 1, 5)
fcntl.lockf(f, fcntl.LOCK_UN, 1, 5)"
			echo "waited $(( $(date +%s) - s0 ))s for the grant"
			wait $h
			ssh netbsd 'rpcinfo -p | grep -E "nlockmgr|status"'
		fi
		# A delegation recalled by a second client on TCP, which the
		# server asks for on the backchannel of this connection,
		# RFC 8267 s6.5.2 and RFC 8167.
		case $V in
		4.[12])
			t dd if=/dev/urandom of="$BIN" bs=64k count=1 status=none
			t cp "$BIN" "$d/dg"
			t sh -c "sync; sudo sh -c 'echo 3 >/proc/sys/vm/drop_caches'"
			r0=$(dreturns "$M")
			exec 3<"$d/dg"
			sleep 1
			echo '$ conflict, with the file held open'
			if [ -d "$HOME/pynfs/nfs4.1" ]; then
				t sh -c "cd $HOME/pynfs/nfs4.1 && cp $CONFLICT . && python3 ./conflict41.py /export/x d$V/dg"
			else
				echo "FAILED (no pynfs)"; fails=$((fails + 1))
			fi
			exec 3<&-
			echo "DELEGRETURN before $r0 after $(dreturns "$M")"
			t test "$(dreturns "$M")" -gt "$r0"
			;;
		esac
		sudo grep -E 'xprt:' /proc/self/mountstats
		sudo grep -A3 -E 'READ:|WRITE:|DELEGRETURN:' /proc/self/mountstats | head -24
		t sudo umount "$M"
	fi
	echo "FAILURES $V: $fails"
done
sudo kill "$DUMP"
sudo dmesg | grep -iE 'rdma|siw|nfs|rpc' | tail -60
ssh netbsd 'netstat -an -f inet | grep 20049; dmesg | tail -30'
