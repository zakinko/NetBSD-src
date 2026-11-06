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
mount -o nfs4acls /dev/vnd1d /export/acl
chmod 1777 /export/acl
# ZFS: the pool on a file, an ACL set by the port's own tools at the top.
modload zfs
# The port installs its libraries in /lib, outside the default search.
export LD_LIBRARY_PATH=/lib
dd if=/dev/zero of=/var/tmp/tank.img bs=1m count=512
zpool create -f tank /var/tmp/tank.img
zfs create -o aclmode=passthrough -o aclinherit=passthrough tank/x
chmod 1777 /tank/x
zfs list
mount | grep /export/
# pynfs comes from a high port through the tunnel.
cat >/etc/exports <<EOF
/export/pynfs -maproot=root -noresvport
/export/tmpfs -maproot=root -noresvport
/export/acl -maproot=root -noresvport
/export/ref -maproot=root -noresvport
/export/mig -maproot=root -noresvport
/tank/x -maproot=root -noresvport
EOF
grep -q '^rpcbind=YES' /etc/rc.conf || echo rpcbind=YES >>/etc/rc.conf
/etc/rc.d/rpcbind onestart || :
/usr/sbin/mountd
sleep 2

cd "$D"
cc -g -Wall -o nfsv4d nfsv4d.c
./nfsv4d "$D/stable" </dev/null >nfsv4d.log 2>&1 &
echo $! >nfsv4d.pid
sleep 1
sysctl -w 'vfs.nfsv4.referral=/export/ref/there srv1,srv2:/x/y;srv3:/z'
sysctl -w vfs.nfsv4.domain=example.org
sysctl -w 'vfs.nfsv4.idmap=u 1234 alice'
sysctl -w 'vfs.nfsv4.idmap=g 5678 staff'
netstat -an -f inet | grep '\.2049 '
