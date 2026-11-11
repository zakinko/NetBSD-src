#!/bin/sh
# In the VM, after vm-kdc.sh: nfsd(8) of the tree in place of the
# release's.  Whether it registered NFSACL is vm-nfsreg.sh, a step of
# its own, so that a failure there does not keep the measurements of
# the steps after it from running.  vm-nfsd.sh
set -eu
D=/var/tmp/nfsv4
sysctl vfs.nfsserver.nfsacl
(cd "$D/src/usr.sbin/nfsd" && cc -g -Wall -o "$D/nfsd" nfsd.c -lpthread)
# The release's nfsd, which vm-kdc.sh started.  Not "pkill -x nfsd":
# in the VM that matched nothing (pgrep -x nfsd exits 1 while plain
# pgrep nfsd finds it), so the old nfsd went on holding port 2049 and
# the new one could not bind it or register.
pkill -f '^/usr/sbin/nfsd' || :
i=0
while pgrep -f '^/usr/sbin/nfsd' >/dev/null; do
	i=$((i + 1))
	[ $i -le 60 ] || { echo 'nfsd still running'; ps -axo pid,stat,wchan,args | grep '[n]fsd'; exit 1; }
	sleep 1
done
echo "nfsd gone after ${i}s"
"$D/nfsd" -t -u -n 8
sleep 2
echo '--- netstat, the new nfsd'; netstat -an | grep '[.]2049 ' || :
