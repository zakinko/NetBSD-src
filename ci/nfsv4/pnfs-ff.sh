#!/bin/sh
# The client of Linux on the flexible file layout (RFC 8435): the storage
# device is nfsd(8) of the server, NFSv3 over TCP on port 2050 through the
# tunnel.  Whether the I/O went there is counted on the wire, with tcpdump
# on the runner's loopback, and whether fencing (s2.2) holds by writing
# after vfs.nfsv4.ff_fence.
vm() { ssh -o LogLevel=ERROR netbsd "$@"; }
ok() { echo "ok     $*"; }
no() { echo "FAILED $*"; }
uname -r
sudo modprobe nfs 2>/dev/null || {
	sudo apt-get install -y -q "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
	sudo modprobe nfs
}
sudo modprobe nfsv4
sudo modprobe nfsv3
sudo modprobe nfs_layout_flexfiles 2>/dev/null || echo "no nfs_layout_flexfiles module"
command -v tcpdump >/dev/null || sudo apt-get install -y -q tcpdump >/dev/null 2>&1
vm "pgrep -x nfsd >/dev/null || /usr/sbin/nfsd -u -n 4
cd /var/tmp/nfsv4 && { pgrep -x nfs3tcp >/dev/null ||
    nohup ./nfs3tcp 2050 </dev/null >nfs3tcp.log 2>&1 & }
sleep 1
sysctl -w 'vfs.nfsv4.ff_ds=tcp 127.0.0.1.8.2 /export/ffds'
netstat -an -f inet | grep '\.2050 '"
num() { vm "sysctl -n vfs.nfsv4.$1"; }
g0=$(num layouts_given) f0=$(num ff_fences)
cap=$(mktemp)
sudo tcpdump -i lo -nn -q -U -w "$cap" 'tcp port 2050' 2>/dev/null &
tp=$!
sleep 1
m=/mnt/nfsv4ff
n=ff.$$
f=$m/$n
sudo mkdir -p "$m"
sudo mount -t nfs -o vers=4.1,proto=tcp,port=2049,addr=127.0.0.1,clientaddr=127.0.0.1,sec=sys,hard 127.0.0.1:/export/pynfs "$m" || exit 1
src=$(mktemp)
dd if=/dev/urandom of="$src" bs=64k count=64 2>/dev/null
sudo dd if="$src" of="$f" bs=64k conv=fsync 2>/dev/null
echo "data files while the layout is held:"
vm "ls -ln /export/ffds"
u=$(vm "stat -f %u /export/ffds/* 2>/dev/null | head -1")
[ -n "$u" ] && [ "$u" -ge 1073741824 ] && ok "data file of a synthetic uid ($u)" ||
    no "data file of a synthetic uid ($u)"
sudo sh -c "echo 3 >/proc/sys/vm/drop_caches"
sudo cmp -s "$src" "$f" && ok "data read back" || no "data read back"

# s2.2: new ids on the data file; the client's next write is refused
# there, and it has to come back for a layout with the new ones.
vm "sysctl -w vfs.nfsv4.ff_fence=1"
sleep 3
u2=$(vm "stat -f %u /export/ffds/* 2>/dev/null | head -1")
f1=$(num ff_fences)
echo "fences $f0 -> $f1, uid $u -> $u2"
[ "$f1" -gt "$f0" ] && [ "$u2" != "$u" ] && ok "fenced" || no "fenced"
dd if=/dev/urandom of="$src.2" bs=64k count=16 2>/dev/null
cat "$src" "$src.2" >"$src.3"
timeout 120 sudo dd if="$src.2" of="$f" bs=64k seek=64 conv=notrunc,fsync 2>&1 | tail -1
sudo sh -c "echo 3 >/proc/sys/vm/drop_caches"
sudo cmp -s "$src.3" "$f" && ok "written after the fence" ||
    no "written after the fence"
dmesg | grep -i -E 'nfs|flexfiles' | tail -5
grep -E '^[[:space:]]+(OPEN|LAYOUTGET|GETDEVICEINFO|LAYOUTRETURN|LAYOUTCOMMIT|READ|WRITE|COMMIT):' /proc/self/mountstats
sudo umount "$m"
g1=$(num layouts_given)
echo "layouts given $g0 -> $g1"
[ "$g1" -gt "$g0" ] && ok "layouts given" || no "layouts given"

# The last layout gone, the lease thread copies the data file back.
i=0
while [ $i -lt 30 ] && [ -n "$(vm 'ls /export/ffds')" ]; do
	sleep 2
	i=$((i + 1))
done
[ -z "$(vm 'ls /export/ffds')" ] && ok "data file removed" ||
    no "data file removed"
vm "cat /export/pynfs/$n" | cmp -s "$src.3" - &&
    ok "metadata file has the data" || no "metadata file has the data"
vm "rm -f /export/pynfs/$n; dmesg | grep nfsv4 | tail -5"

sudo kill "$tp"
wait "$tp" 2>/dev/null
b=$(tcpdump -r "$cap" -nn -q 2>/dev/null | awk '{ n += $NF } END { print n + 0 }')
echo "bytes over port 2050 (the storage device): $b"
[ "$b" -gt 4194304 ] && ok "I/O went to the storage device" ||
    no "I/O went to the storage device"
rm -f "$src" "$src.2" "$src.3" "$cap"
vm "sysctl -w vfs.nfsv4.ff_ds="
