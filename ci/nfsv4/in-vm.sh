#!/bin/sh
# Load the modules for the running kernel, export a file system and
# leave the server listening.
set -eu
D=/var/tmp/nfsv4
R=$(uname -r)
for k in "$D"/modules/*.kmod; do
	m=$(basename "$k" .kmod)
	mkdir -p "/stand/amd64/$R/modules/$m"
	cp "$k" "/stand/amd64/$R/modules/$m/"
done
sysctl -w kern.module.verbose=1
modload nfsv4
modstat | grep -E '^(xdr|oncrpc|nfsv4)[[:space:]]'
sysctl vfs.nfsv4

# FFS, on its own mount, as an export is of a whole mount.
mkdir -p /export/pynfs
mount_mfs -s 1g swap /export/pynfs
chmod 1777 /export/pynfs
mkdir -p /export/sec
mount_tmpfs -s 8m tmpfs /export/sec
chmod 1777 /export/sec
mkdir -p /export/tmpfs
mount_tmpfs -s 256m tmpfs /export/tmpfs
chmod 1777 /export/tmpfs
# FFS with NFSv4 ACLs: they live in extended attributes, so 2ea.
# A referral, RFC 7530 s8.4.3, on a file system of its own.
mkdir -p /export/ref
mount_tmpfs -s 8m tmpfs /export/ref
mkdir /export/ref/there
# To be migrated, s9.14.
mkdir -p /export/mig
mount_tmpfs -s 8m tmpfs /export/mig
chmod 1777 /export/mig
mkdir -p /export/acl
dd if=/dev/zero of=/var/tmp/acl.img bs=1m count=256
newfs -O 2ea -F -s 256m /var/tmp/acl.img | tail -1
vnconfig vnd1 /var/tmp/acl.img
# What fsck says of UFS2ea fresh from newfs, the control for after.
fsck_ffs -fn /dev/rvnd1d >/var/tmp/nfsv4/fsck-control-ea.txt 2>&1 || :
mount -o nfs4acls /dev/vnd1d /export/acl
chmod 1777 /export/acl
# FFS with quotas.
mkdir -p /export/quota
dd if=/dev/zero of=/var/tmp/quota.img bs=1m count=64
newfs -O 2 -q user -F -s 64m /var/tmp/quota.img | tail -1
vnconfig vnd2 /var/tmp/quota.img
mount /dev/vnd2d /export/quota
chmod 1777 /export/quota
edquota -u -h 2000/0 -s 1000/0 -f /export/quota root
repquota -u /export/quota || :
# FFSv1, for the hole punch: fsck of it fresh is the control for what
# fsck says after, the alternate superblocks in particular.
mkdir -p /export/ffs1
dd if=/dev/zero of=/var/tmp/ffs1.img bs=1m count=128
newfs -O 1 -F -s 128m /var/tmp/ffs1.img | tail -1
vnconfig vnd3 /var/tmp/ffs1.img
fsck_ffs -fn /dev/rvnd3d >/var/tmp/nfsv4/fsck-control.txt 2>&1 || :
mount /dev/vnd3d /export/ffs1
chmod 1777 /export/ffs1
# ZFS: the pool on a file, an ACL set by the port's own tools at the top.
# Without the module or its tools the other exports are still served.
if [ -f "$D/modules/zfs.kmod" ] && command -v zpool >/dev/null; then
	modload zfs
	# The port installs its libraries in /lib, outside the default search.
	export LD_LIBRARY_PATH=/lib
	dd if=/dev/zero of=/var/tmp/tank.img bs=1m count=512
	zpool create -f tank /var/tmp/tank.img
	zfs create -o aclmode=passthrough -o aclinherit=passthrough tank/x
	chmod 1777 /tank/x
	zfs list
fi
mount | grep /export/
# pynfs comes from a high port through the tunnel.
cat >/etc/exports <<EOF
/export/pynfs -maproot=root -noresvport
/export/sec -maproot=root -noresvport
/export/tmpfs -maproot=root -noresvport
/export/acl -maproot=root -noresvport
/export/ref -maproot=root -noresvport
/export/mig -maproot=root -noresvport
/export/quota -maproot=root -noresvport
/export/ffs1 -maproot=root -noresvport
/tank/x -maproot=root -noresvport
EOF
grep -q '^rpcbind=YES' /etc/rc.conf || echo rpcbind=YES >>/etc/rc.conf
/etc/rc.d/rpcbind onestart || :
/usr/sbin/mountd
sleep 2

cd "$D"
cc -g -Wall -o nfsv4d nfsv4d.c
cc -g -Wall -o lockhold lockhold.c
./nfsv4d "$D/stable" </dev/null >nfsv4d.log 2>&1 &
echo $! >nfsv4d.pid
sleep 1
# What COPY_NOTIFY names as the source, RFC 7862 s15.3.3: this server.
sysctl -w vfs.nfsv4.copy_addr=127.0.0.1.8.1
sysctl -w 'vfs.nfsv4.referral=/export/ref/there srv1,srv2:/x/y;srv3:/z'
netstat -an -f inet | grep '\.2049 '
