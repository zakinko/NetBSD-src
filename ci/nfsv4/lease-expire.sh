#!/bin/sh
# The client of Linux loses its lease while it holds a layout and an
# open: its connection to the server is cut for longer than the lease
# (NFSV4_LEASE, 90 s).  After, RFC 8881 s8.4.3: the stateids it held
# answer NFS4ERR_EXPIRED until it frees them or makes a new client ID,
# and nothing else need fail.  Does it come back: a new file can be made
# and read, within a time.  The operations and their statuses on 2049
# are kept (out/lease-expire.pcap) to see how.
vm() { ssh -o LogLevel=ERROR netbsd "$@"; }
T="timeout -k 5 120"
uname -r
sudo modprobe nfsv4
sudo modprobe nfs_layout_nfsv41_files 2>/dev/null || :
command -v tcpdump || sudo apt-get install -y -q tcpdump 2>&1 | tail -2
# The file layout with this server as its own data server, at 2049.
vm "sysctl -w 'vfs.nfsv4.pnfs_ds=tcp 127.0.0.1.8.1'"
capd=$(mktemp -d)
cap=$capd/lo.pcap
sudo tcpdump -Z root -i lo -nn -q -U -w "$cap" 'tcp port 2049' 2>"$cap.err" &
tp=$!
sleep 1
m=/mnt/nfsv4exp
sudo mkdir -p "$m"
sudo $T mount -t nfs -o vers=4.1,proto=tcp,port=2049,addr=127.0.0.1,clientaddr=127.0.0.1,sec=sys,hard 127.0.0.1:/export/pynfs "$m" || echo "FAILED mount"
mountpoint -q "$m" || m=/nonexistent
f=$m/exp.$$
sudo $T dd if=/dev/urandom of="$f" bs=64k count=16 conv=fsync 2>/dev/null
sudo sh -c "echo 3 >/proc/sys/vm/drop_caches"
# Held open, read through its layout.
sudo sh -c "exec 3<'$f'; cat <&3 >/dev/null; sleep 600" &
holder=$!
sleep 2
echo "layouts given $(vm 'sysctl -n vfs.nfsv4.layouts_given')"
# Cut 2049 on the runner for two leases.
sudo iptables -I OUTPUT -o lo -p tcp --dport 2049 -j DROP
sudo iptables -I INPUT -i lo -p tcp --sport 2049 -j DROP
echo "cut at $(date +%s)"
sleep 200
sudo iptables -D OUTPUT -o lo -p tcp --dport 2049 -j DROP
sudo iptables -D INPUT -i lo -p tcp --sport 2049 -j DROP
echo "joined at $(date +%s)"
t0=$(date +%s)
if sudo $T sh -c "echo after >'$m/exp2.$$' && cat '$m/exp2.$$'" | grep -q after; then
	echo "ok     a new file made and read after the lease ($(( $(date +%s) - t0 )) s)"
else
	echo "FAILED a new file made and read after the lease ($(( $(date +%s) - t0 )) s)"
fi
sudo kill "$holder" 2>/dev/null
sudo $T rm -f "$f" "$m/exp2.$$"
sudo $T umount "$m" || sudo umount -f -l "$m"
sudo kill "$tp"; wait "$tp" 2>/dev/null
vm "sysctl -w vfs.nfsv4.pnfs_ds="
mkdir -p out && cp "$cap" out/lease-expire.pcap
python3 "$(dirname "$0")/rpcs.py" "$cap" 2049 2>/dev/null | awk '{ $2 = $3 = ""; print }' |
    sort | uniq -c | sort -rn | head -30
rm -rf "$capd"
