#!/bin/sh
# Can the block layout (RFC 5663) be measured here?  Its client reads
# and writes the server's disk itself, so the runner needs an iSCSI
# initiator and the VM a target: open-iscsi from apt, iscsi-target(8)
# from base, through the tunnel on port 3260.  Each step says ok or
# FAILED; nothing here is pNFS yet.
vm() { ssh -o LogLevel=ERROR netbsd "$@"; }
r() {
	echo "\$ $*"
	if timeout 120 "$@"; then echo "ok     $*"; else echo "FAILED ($?) $*"; fi
}
uname -r
r sudo apt-get install -y -q open-iscsi
r sudo modprobe blocklayoutdriver
r sudo modprobe iscsi_tcp
r sudo systemctl start iscsid
vm "ls -l /usr/sbin/iscsi-target
dd if=/dev/zero of=/var/tmp/blk.img bs=1m count=64 2>/dev/null
printf 'BLKPROBE' | dd of=/var/tmp/blk.img bs=512 seek=1 conv=notrunc 2>/dev/null
printf 'extent0\t/var/tmp/blk.img\t0\t64MB\ntarget0\trw\textent0\t0.0.0.0/0\n' >/var/tmp/nfsv4/targets
nohup /usr/sbin/iscsi-target -f /var/tmp/nfsv4/targets </dev/null >/var/tmp/nfsv4/iscsi-target.log 2>&1 &
sleep 2
netstat -an -f inet | grep '\.3260 '"
ssh -f -N -o ExitOnForwardFailure=yes -L 3260:127.0.0.1:3260 netbsd &&
    echo "ok     tunnel 3260" || echo "FAILED tunnel 3260"
r sudo iscsiadm -m discovery -t sendtargets -p 127.0.0.1:3260
r sudo iscsiadm -m node -p 127.0.0.1:3260 --login
sleep 3
lsblk -o NAME,SIZE,TRAN,VENDOR,MODEL
d=$(lsblk -dn -o NAME,TRAN | awk '$2 == "iscsi" { print $1; exit }')
if [ -n "$d" ]; then
	echo "ok     iSCSI disk /dev/$d"
	sudo dd if="/dev/$d" bs=512 skip=1 count=1 2>/dev/null | head -c 8 | grep -q BLKPROBE &&
	    echo "ok     read the VM's image" || echo "FAILED read the VM's image"
else
	echo "FAILED no iSCSI disk"
fi
r sudo iscsiadm -m node -p 127.0.0.1:3260 --logout
vm "cat /var/tmp/nfsv4/iscsi-target.log | tail -20; pkill -x iscsi-target; rm -f /var/tmp/blk.img"
