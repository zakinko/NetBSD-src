#!/bin/sh
# In the VM, after vm-kdc.sh: nfsd(8) of the tree in place of the
# release's, and NFSACL registered with rpcbind in the versions the
# kernel says it serves.  vm-nfsd.sh
set -eu
D=/var/tmp/nfsv4
sysctl vfs.nfsserver.nfsacl
(cd "$D/src/usr.sbin/nfsd" && cc -g -Wall -o "$D/nfsd" nfsd.c -lpthread)
pkill -x nfsd || :
# The sockets close with the last thread of the old nfsd, which may be
# in the kernel for a while yet; a new one that cannot bind registers
# nothing.
i=0
while sockstat -l 2>/dev/null | grep -q '[.:]2049 '; do
	i=$((i + 1))
	[ $i -le 60 ] || { echo 'port 2049 still bound'; sockstat -l | grep 2049; exit 1; }
	sleep 1
done
echo "port 2049 free after ${i}s"
"$D/nfsd" -t -u -n 8
sleep 2
rpcinfo -p | tee "$D/rpcinfo.txt"
for v in 2 3; do
	for p in tcp udp; do
		grep -Eq "^ +100227 +$v +$p +2049 " "$D/rpcinfo.txt" ||
		    { echo "100227 v$v $p not registered"; exit 1; }
	done
done
rpcinfo -t 127.0.0.1 nfs_acl 3
rpcinfo -t 127.0.0.1 nfs_acl 2
