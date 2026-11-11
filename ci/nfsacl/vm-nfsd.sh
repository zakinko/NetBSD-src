#!/bin/sh
# In the VM, after vm-kdc.sh: nfsd(8) of the tree in place of the
# release's.  Whether it registered NFSACL is vm-nfsreg.sh, a step of
# its own, so that a failure there does not keep the measurements of
# the steps after it from running.  vm-nfsd.sh
set -eu
D=/var/tmp/nfsv4
sysctl vfs.nfsserver.nfsacl
(cd "$D/src/usr.sbin/nfsd" && cc -g -Wall -o "$D/nfsd" nfsd.c -lpthread)
pkill -x nfsd || :
# pkill only sends the signal; the threads of nfsd leave the kernel
# after it returns.
i=0
while pgrep -x nfsd >/dev/null; do
	i=$((i + 1))
	[ $i -le 60 ] || { echo 'nfsd still running'; ps -axl | grep nfsd; exit 1; }
	sleep 1
done
echo "nfsd gone after ${i}s"
# What still holds the port with no nfsd: a socket the kernel keeps has
# no descriptor, so it shows in netstat and not in fstat or sockstat.
echo '--- netstat'; netstat -an | grep '[.]2049 ' || :
echo '--- sockstat'; sockstat | grep '[.:]2049' || :
echo '--- fstat'; fstat | grep -w 2049 || :
"$D/nfsd" -t -u -n 8
sleep 2
echo '--- netstat, the new nfsd'; netstat -an | grep '[.]2049 ' || :
