#!/bin/sh
# In the VM, after vm-nfsd.sh: NFSACL registered with rpcbind in the
# versions the kernel says it serves.  vm-nfsreg.sh
set -eu
D=/var/tmp/nfsv4
rpcinfo -p | tee "$D/rpcinfo.txt"
# By number: the release's /etc/rpc has no name for 100227, so rpcinfo
# ends the line at the port, and "nfs_acl" does not resolve.
for v in 2 3; do
	for p in tcp udp; do
		grep -Eq "^ +100227 +$v +$p +2049( |$)" "$D/rpcinfo.txt" ||
		    { echo "100227 v$v $p not registered"; exit 1; }
	done
done
rpcinfo -t 127.0.0.1 100227 3
rpcinfo -t 127.0.0.1 100227 2
