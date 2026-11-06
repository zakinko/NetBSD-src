#!/bin/sh
# Start the stock userland's nfsd on the running kernel.  server.sh on|off
set -eu
MODE=$1
D=/var/tmp/nfsbridge
if [ "$MODE" = on ]; then
	R=$(uname -r)
	mkdir -p "/stand/amd64/$R/modules/nfsv4"
	cp "$D/modules/nfsv4.kmod" "/stand/amd64/$R/modules/nfsv4/"
	modload nfsv4
fi
modstat | grep -E '^(xdr|oncrpc|nfsserver|nfsv4)[[:space:]]' || :
mkdir -p /export/ffs /export/tmpfs
mount_mfs -s 512m swap /export/ffs
mount_tmpfs -s 256m tmpfs /export/tmpfs
chmod 1777 /export/ffs /export/tmpfs
cat >/etc/exports <<EOT
/export/ffs -maproot=root -noresvport -noresvmnt
/export/tmpfs -maproot=root -noresvport -noresvmnt
EOT
/etc/rc.d/rpcbind onestart || :
/usr/sbin/mountd -p 1234
sleep 1
/usr/sbin/nfsd -t -u -n 4
sleep 2
ps -ax | grep -E '[n]fsd|[m]ountd'
netstat -an -f inet | grep '\.2049 '
rpcinfo -p | grep -E 'nfs|mountd' || :
