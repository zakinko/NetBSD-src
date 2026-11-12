#!/bin/sh
# The client of Linux on the pNFS file layout (RFC 8881 s13), with this
# server as its own data server: does it get layouts and send its I/O by
# them.  Counts from /proc/self/mountstats, and on the wire: the data
# server is the same server on another port, 2051 (a second nfsv4d),
# so tcpdump on the runner's loopback tells its traffic from the
# metadata server's on 2049.  Twice: with vfs.nfsv4.ds_owner 0, the
# RFC's one server owner, and 1, a server owner of 2051's own.
uname -r
sudo modprobe nfs 2>/dev/null || {
	sudo apt-get install -y -q "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
	sudo modprobe nfs
}
sudo modprobe nfsv4
sudo modprobe nfs_layout_nfsv41_files 2>/dev/null || echo "no nfs_layout_nfsv41_files module"
# Not pgrep -f 'nfsv4d - 2051': it matched the shell that ran it, whose
# command line holds the same words, so the data server was never
# started and the client's connections to 2051 were reset by the tunnel
# (run 43137307767).  The listening socket is what is asked.
ssh -o LogLevel=ERROR netbsd "cd /var/tmp/nfsv4 &&
{ netstat -an -f inet | grep -q '\.2051 .*LISTEN' ||
    nohup ./nfsv4d - 2051 </dev/null >nfsv4d-ds.log 2>&1 & }
sleep 1
sysctl -w 'vfs.nfsv4.pnfs_ds=tcp 127.0.0.1.8.3'
netstat -an -f inet | grep '\.2051 '; cat nfsv4d-ds.log"
command -v tcpdump || sudo apt-get install -y -q tcpdump 2>&1 | tail -2
command -v tshark || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q tshark 2>&1 | tail -2
# The client's own account of the layouts: filelayout and pnfs messages.
sudo rpcdebug -m nfs -s pnfs 2>/dev/null
sudo dmesg -C
# tcpdump was refused a mktemp file in /tmp ("Permission denied").  Either
# of two rules would do that: fs.protected_regular, against root opening
# with O_CREAT another user's file in a sticky directory, and the AppArmor
# profile of tcpdump, which writes only names ending in .pcap; both are
# printed, and neither applies to a new .pcap in a directory of our own.
sysctl fs.protected_regular; sudo aa-status 2>/dev/null | grep tcpdump
# measure OWNER: one mount, 4 MiB written and read back, with
# vfs.nfsv4.ds_owner set to OWNER.
measure() {
	echo "=== vfs.nfsv4.ds_owner=$1"
	ssh -o LogLevel=ERROR netbsd "sysctl -w vfs.nfsv4.ds_owner=$1"
	capd=$(mktemp -d)
	cap=$capd/lo.pcap
	sudo tcpdump -Z root -i lo -nn -q -U -w "$cap" 'tcp port 2049 or tcp port 2051' 2>"$cap.err" &
	tp=$!
	sleep 1
	given() { ssh -o LogLevel=ERROR netbsd "sysctl -n vfs.nfsv4.layouts_given"; }
	g0=$(given)
	m=/mnt/nfsv4pnfs
	sudo mkdir -p "$m"
	sudo mount -t nfs -o vers=4.1,proto=tcp,port=2049,addr=127.0.0.1,clientaddr=127.0.0.1,sec=sys,hard 127.0.0.1:/export/pynfs "$m" || exit 1
	f=$m/pnfs.$$
	src=$(mktemp)
	dd if=/dev/urandom of="$src" bs=64k count=64 2>/dev/null
	sudo dd if="$src" of="$f" bs=64k conv=fsync 2>/dev/null
	sudo sh -c "echo 3 >/proc/sys/vm/drop_caches"
	if sudo cmp -s "$src" "$f"; then echo "ok     data read back through the layout"
	else echo "FAILED data read back through the layout"; fi
	st() { awk -v op="$1:" '$1 == op { n += $2 } END { print n + 0 }' /proc/self/mountstats; }
	grep -E '^[[:space:]]+(LAYOUTGET|GETDEVICEINFO|LAYOUTRETURN|LAYOUTCOMMIT|READ|WRITE|COMMIT):' /proc/self/mountstats
	# The client of Linux may send LAYOUTGET inside the OPEN's COMPOUND,
	# which mountstats counts as OPEN (run 43078420981: 0 alone, but a
	# GETDEVICEINFO); the server's count says whether it gave layouts.
	lg=$(st LAYOUTGET) di=$(st GETDEVICEINFO) g1=$(given)
	echo "LAYOUTGET alone $lg GETDEVICEINFO $di layouts given $g0 -> $g1"
	[ "$g1" -gt "$g0" ] && echo "ok     layouts given" || echo "FAILED layouts given"
	[ "$di" -gt 0 ] && echo "ok     GETDEVICEINFO sent" || echo "FAILED GETDEVICEINFO sent"
	sudo rm -f "$f"
	rm -f "$src"
	sudo umount "$m"
	sudo rpcdebug -m nfs -c pnfs 2>/dev/null
	echo "--- client dmesg (pnfs)"
	sudo dmesg | grep -v 'NFS reply\|NFS call ' | tail -60
	sudo kill "$tp"
	wait "$tp" 2>/dev/null
	cat "$cap.err"; ls -l "$cap"
	port() {
		tcpdump -r "$cap" -nn -q "tcp port $1" 2>/dev/null |
		    awk '{ n += $NF } END { print n + 0 }'
	}
	b49=$(port 2049) b51=$(port 2051)
	echo "bytes over 2049 (metadata server) $b49, over 2051 (data server) $b51"
	# 4 MiB written and read back: 8 MiB of data, if all of it went there.
	# With one server owner the client may trunk the two (RFC 8881 s2.10.5),
	# so that is only shown; with ds_owner it is the measurement.
	if [ "$1" = 1 ]; then
		[ "$b51" -gt 6291456 ] && ok=ok || ok=FAILED
		printf '%-6s %s\n' "$ok" "READ and WRITE went to the data server"
		[ "$b49" -lt 1048576 ] && ok=ok || ok=FAILED
		printf '%-6s %s\n' "$ok" "little went to the metadata server"
	fi
	# What went over each port, decoded: the operations, the EXCHANGE_ID
	# replies (flags, client ID, server owner) and GETDEVICEINFO's address.
	ts() { tshark -r "$cap" -d tcp.port==2049,rpc -d tcp.port==2051,rpc "$@" 2>/dev/null; }
	echo "--- operations by port (src dst type ops)"
	ts -Y nfs -T fields -e tcp.srcport -e tcp.dstport -e rpc.msgtyp \
	    -e nfs.opcode | sed 's/^2049\t[0-9]*/from 2049/; s/^[0-9]*\t2049/to 2049/;
	    s/^2051\t[0-9]*/from 2051/; s/^[0-9]*\t2051/to 2051/' | sort | uniq -c |
	    sort -rn | head -40
	echo "--- EXCHANGE_ID and CREATE_SESSION replies"
	ts -Y 'rpc.msgtyp == 1 && (nfs.opcode == 42 || nfs.opcode == 43)' -V |
	    grep -E 'Src Port|Dst Port|Opcode|[Ff]lags|clientid|major|minor_id|scope|Status' |
	    head -80
	echo "--- GETDEVICEINFO replies"
	ts -Y 'rpc.msgtyp == 1 && nfs.opcode == 47' -V |
	    sed -n '/GETDEVICEINFO/,/^$/p' | head -60
	mkdir -p out && cp "$cap" "out/pnfs-linux-$1.pcap"
	rm -rf "$capd"
}
measure 0
measure 1
ssh -o LogLevel=ERROR netbsd "sysctl -w vfs.nfsv4.pnfs_ds=; sysctl -w vfs.nfsv4.ds_owner=0; dmesg | tail -5"
