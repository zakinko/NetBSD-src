#!/bin/sh
# The client of Linux on the pNFS file layout (RFC 8881 s13), with this
# server as its own data server: does it get layouts and send its I/O by
# them.  Counts from /proc/self/mountstats.
sudo modprobe nfs 2>/dev/null || {
	sudo apt-get install -y -q "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
	sudo modprobe nfs
}
sudo modprobe nfsv4
sudo modprobe nfs_layout_nfsv41_files 2>/dev/null || echo "no nfs_layout_nfsv41_files module"
ssh -o LogLevel=ERROR netbsd "sysctl -w 'vfs.nfsv4.pnfs_ds=tcp 127.0.0.1.8.1'"
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
ssh -o LogLevel=ERROR netbsd "sysctl -w vfs.nfsv4.pnfs_ds=; dmesg | tail -5"
