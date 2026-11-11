#!/bin/sh
# Load the modules, export one file system, and leave the server on both
# ports: 2049 for what RFC 8267 s5.1 keeps on TCP and for the control,
# and 20049 for RDMA.
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

mkdir -p /export/x
mount_mfs -s 1g swap /export/x
chmod 1777 /export/x
echo '/export/x -maproot=root -noresvport' >/etc/exports
grep -q '^rpcbind=YES' /etc/rc.conf || echo rpcbind=YES >>/etc/rc.conf
/etc/rc.d/rpcbind onestart || :
# MOUNT on a port the tunnel knows, RFC 8267 s5.1.
/usr/sbin/mountd -p 1234
# NLM and NSM, by the stock daemons, on TCP as s5.1 has them.
/usr/sbin/rpc.statd
/usr/sbin/rpc.lockd
sleep 2

cd "$D"
cc -o /var/tmp/tunpipe tunpipe.c
cc -o /var/tmp/try try.c
cc -g -Wall -o nfsv4d nfsv4d.c
cc -g -Wall -DPORT=20049 '-DNODE="vfs.nfsv4.addrdma"' -o nfsrdmad nfsv4d.c
./nfsv4d </dev/null >nfsv4d.log 2>&1 &
./nfsrdmad </dev/null >nfsrdmad.log 2>&1 &
sleep 1
netstat -an -f inet | grep -E '\.(2049|20049) '
