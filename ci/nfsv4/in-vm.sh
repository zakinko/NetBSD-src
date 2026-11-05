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
mkdir -p /export/acl
dd if=/dev/zero of=/var/tmp/acl.img bs=1m count=256
vnconfig vnd1 /var/tmp/acl.img
newfs -O 2ea /dev/rvnd1d | tail -1
mount -o nfs4acls /dev/vnd1d /export/acl
chmod 1777 /export/acl
mount | grep /export/
# pynfs comes from a high port through the tunnel.
cat >/etc/exports <<EOF
/export/pynfs -maproot=root -noresvport
/export/tmpfs -maproot=root -noresvport
/export/acl -maproot=root -noresvport
EOF
grep -q '^rpcbind=YES' /etc/rc.conf || echo rpcbind=YES >>/etc/rc.conf
/etc/rc.d/rpcbind onestart || :
/usr/sbin/mountd
sleep 2

cd "$D"
cc -g -Wall -o nfsv4d nfsv4d.c
./nfsv4d </dev/null >nfsv4d.log 2>&1 &
sleep 1
netstat -an -f inet | grep '\.2049 '
