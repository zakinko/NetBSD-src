#!/bin/sh
# The client of Linux on the pNFS block layout (RFC 5663): the VM serves
# an FFS file system on a vnd, exports its storage over iSCSI
# (iscsi-target(8), through the tunnel on 3260), and the client finds the
# volume by its signature (blkmapd) and reads and writes the blocks
# itself.  Whether it does is counted on the wire: bytes on 3260 (the
# volume) against 2049 (the metadata server), with tcpdump on the
# runner's loopback.  Then blk.py, the server's side of it by pynfs, and
# fsck_ffs of the file system after a layout for writing left blocks past
# the end of a file.
vm() { ssh -o LogLevel=ERROR netbsd "$@"; }
r() {
	echo "\$ $*"
	if timeout 120 "$@"; then echo "ok     $*"; else echo "FAILED ($?) $*"; fi
}
uname -r
sudo modprobe nfs 2>/dev/null || {
	sudo apt-get install -y -q "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
	sudo modprobe nfs
}
r sudo apt-get install -y -q open-iscsi nfs-common
command -v tcpdump || sudo apt-get install -y -q tcpdump 2>&1 | tail -2
r sudo modprobe nfsv4
r sudo modprobe blocklayoutdriver
r sudo modprobe iscsi_tcp
r sudo systemctl start iscsid

# The file system: FFS of 4 KiB blocks and fragments.  The client of
# Linux takes no layout_blksize above its page size, and the server
# refuses fragments smaller than blocks.  The image is on tmpfs, which
# has no VOP_BMAP, so vnd reads and writes it through the same pages
# that iscsi-target's write(2) goes through.  iscsi-target exports the
# vnd's raw device, the one the server mounts, as Linux's server does,
# where the securelevel lets a mounted disk be opened for writing;
# otherwise the image under it, the same bytes by the same pages.
vm "set -x
sysctl kern.securelevel
mkdir -p /var/tmp/blkt /export/blk
mount | grep -q ' /var/tmp/blkt ' || mount_tmpfs -s 80m tmpfs /var/tmp/blkt
dd if=/dev/zero of=/var/tmp/blkt/blk.img bs=1m count=64 2>/dev/null
vnconfig vnd3 /var/tmp/blkt/blk.img
newfs -O 2 -b 4096 -f 4096 /dev/rvnd3d | tail -1
mount /dev/vnd3d /export/blk
chmod 1777 /export/blk
dumpfs -s /dev/rvnd3d 2>/dev/null | grep -E '^(magic|id|bsize|fsize|sblkno)' | head
grep -q '^/export/blk ' /etc/exports || echo '/export/blk -maproot=root -noresvport' >>/etc/exports
pkill -HUP -x mountd; sleep 1
if [ \$(sysctl -n kern.securelevel) -le 0 ]; then dev=/dev/rvnd3d; else dev=/var/tmp/blkt/blk.img; fi
echo \"exported: \$dev\"
printf 'extent0\t%s\t0\t64MB\ntarget0\trw\textent0\t0.0.0.0/0\n' \$dev >/var/tmp/nfsv4/targets
nohup /usr/sbin/iscsi-target -f /var/tmp/nfsv4/targets </dev/null >/var/tmp/nfsv4/iscsi-target.log 2>&1 &
sleep 2
netstat -an -f inet | grep '\.3260 '
sysctl -w vfs.nfsv4.pnfs_blk=/export/blk
sysctl -w vfs.nfsv4.blk_nohint=1"
ssh -f -N -o ExitOnForwardFailure=yes -L 3260:127.0.0.1:3260 netbsd &&
    echo "ok     tunnel 3260" || echo "FAILED tunnel 3260"
r sudo iscsiadm -m discovery -t sendtargets -p 127.0.0.1:3260
r sudo iscsiadm -m node -p 127.0.0.1:3260 --login
sleep 3
lsblk -o NAME,SIZE,TRAN,VENDOR,MODEL
d=$(lsblk -dn -o NAME,TRAN | awk '$2 == "iscsi" { print $1; exit }')
[ -n "$d" ] && echo "ok     iSCSI disk /dev/$d" || echo "FAILED no iSCSI disk"
sudo dd if="/dev/$d" bs=4096 skip=16 count=1 2>/dev/null | od -A d -t x1 | head -4

# blkmapd answers the kernel's upcall with the device whose bytes match
# the volume's signature; it reads them from the disks it finds.
mount | grep rpc_pipefs || {
	sudo mkdir -p /run/rpc_pipefs
	sudo mount -t rpc_pipefs sunrpc /run/rpc_pipefs
}
sudo pkill -x blkmapd
sudo sh -c 'blkmapd -f -d >/tmp/blkmapd.log 2>&1 &'
sleep 2
pgrep -x blkmapd >/dev/null && echo "ok     blkmapd" || echo "FAILED blkmapd"

sudo rpcdebug -m nfs -s pnfs 2>/dev/null
sudo dmesg -C
capd=$(mktemp -d)
cap=$capd/lo.pcap
sudo tcpdump -Z root -i lo -nn -q -U -w "$cap" 'tcp port 2049 or tcp port 3260' 2>"$cap.err" &
tp=$!
sleep 1
given() { vm "sysctl -n vfs.nfsv4.layouts_given"; }
g0=$(given)
m=/mnt/nfsv4blk
sudo mkdir -p "$m"
sudo mount -t nfs -o vers=4.1,proto=tcp,port=2049,addr=127.0.0.1,clientaddr=127.0.0.1,sec=sys,hard 127.0.0.1:/export/blk "$m" || echo "FAILED mount"
f=$m/blk.$$
src=$(mktemp)
dd if=/dev/urandom of="$src" bs=64k count=64 2>/dev/null
sudo dd if="$src" of="$f" bs=64k conv=fsync 2>/dev/null
sudo sh -c "echo 3 >/proc/sys/vm/drop_caches"
if sudo cmp -s "$src" "$f"; then echo "ok     data read back through the layout"
else echo "FAILED data read back through the layout"; fi
# The server's own view: the size LAYOUTCOMMIT set and the bytes on disk.
here=$(md5sum <"$src" | awk '{ print $1 }')
there=$(vm "md5 </export/blk/blk.$$; ls -l /export/blk/blk.$$" | tee /dev/stderr | head -1)
[ "$here" = "$there" ] && echo "ok     the server reads what the client wrote to the volume" ||
    echo "FAILED the server reads what the client wrote to the volume ($here, $there)"
grep -E '^[[:space:]]+(OPEN|LAYOUTGET|GETDEVICEINFO|LAYOUTRETURN|LAYOUTCOMMIT|READ|WRITE|COMMIT):' /proc/self/mountstats
g1=$(given)
echo "layouts given $g0 -> $g1"
[ "$g1" -gt "$g0" ] && echo "ok     layouts given" || echo "FAILED layouts given"
sudo rm -f "$f"
rm -f "$src"
sudo umount "$m"
sudo rpcdebug -m nfs -c pnfs 2>/dev/null
echo "--- client dmesg (pnfs)"
sudo dmesg | grep -v 'NFS reply\|NFS call ' | tail -60
echo "--- blkmapd"
sudo tail -40 /tmp/blkmapd.log
sudo kill "$tp"
wait "$tp" 2>/dev/null
cat "$cap.err"; ls -l "$cap"
port() {
	tcpdump -r "$cap" -nn -q "tcp port $1" 2>/dev/null |
	    awk '{ n += $NF } END { print n + 0 }'
}
b49=$(port 2049) b3260=$(port 3260)
echo "bytes over 2049 (metadata server) $b49, over 3260 (the volume, iSCSI) $b3260"
# 4 MiB written and 4 MiB read back: 8 MiB of data, if all of it went
# to the volume.
[ "$b3260" -gt 6291456 ] && ok=ok || ok=FAILED
printf '%-6s %s\n' "$ok" "READ and WRITE went to the volume"
[ "$b49" -lt 1048576 ] && ok=ok || ok=FAILED
printf '%-6s %s\n' "$ok" "little went to the metadata server"
mkdir -p out && cp "$cap" out/pnfs-blk.pcap
rm -rf "$capd"

r sudo iscsiadm -m node -p 127.0.0.1:3260 --logout
sudo pkill -x blkmapd
vm "tail -20 /var/tmp/nfsv4/iscsi-target.log; pkill -x iscsi-target"
