#!/bin/sh
# The client of Linux on the pNFS file layout (RFC 8881 s13), with this
# server as its own data server: does it get layouts and send its I/O by
# them.  Counts from /proc/self/mountstats, and on the wire: the data
# server is the same server on another port, 2051 (a second nfsv4d),
# so tcpdump on the runner's loopback tells its traffic from the
# metadata server's on 2049.
uname -r
sudo modprobe nfs 2>/dev/null || {
	sudo apt-get install -y -q "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
	sudo modprobe nfs
}
sudo modprobe nfsv4
sudo modprobe nfs_layout_nfsv41_files 2>/dev/null || echo "no nfs_layout_nfsv41_files module"
ssh -o LogLevel=ERROR netbsd "cd /var/tmp/nfsv4 && { pgrep -f 'nfsv4d - 2051' >/dev/null ||
    nohup ./nfsv4d - 2051 </dev/null >nfsv4d-ds.log 2>&1 & }
sleep 1
sysctl -w 'vfs.nfsv4.pnfs_ds=tcp 127.0.0.1.8.3'
netstat -an -f inet | grep '\.2051 '"
command -v tcpdump || sudo apt-get install -y -q tcpdump 2>&1 | tail -2
# tcpdump was refused a mktemp file in /tmp ("Permission denied").  Either
# of two rules would do that: fs.protected_regular, against root opening
# with O_CREAT another user's file in a sticky directory, and the AppArmor
# profile of tcpdump, which writes only names ending in .pcap; both are
# printed, and neither applies to a new .pcap in a directory of our own.
sysctl fs.protected_regular; sudo aa-status 2>/dev/null | grep tcpdump
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
[ "$b51" -gt 6291456 ] && ok=ok || ok=FAILED
printf '%-6s %s\n' "$ok" "READ and WRITE went to the data server"
[ "$b49" -lt 1048576 ] && ok=ok || ok=FAILED
printf '%-6s %s\n' "$ok" "little went to the metadata server"
rm -rf "$capd"
ssh -o LogLevel=ERROR netbsd "sysctl -w vfs.nfsv4.pnfs_ds=; dmesg | tail -5"
