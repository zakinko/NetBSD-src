#!/bin/sh
# The servers again after a reboot.  The exports file and modules are there.
R=$(uname -r)
/etc/rc.d/rpcbind onestart || :
modload nfsv4
modload nlm
sysctl -w vfs.nlm.grace=45
/usr/sbin/mountd -p 1234
sleep 1
/usr/sbin/nfsd -t -u -n 4
sleep 1
# Through rc.d with lockd alone asked for: it has to bring statd with it.
cp /var/tmp/nlm/rpc.lockd/rpc.lockd /usr/sbin/rpc.lockd
cp /var/tmp/nlm/nfslocking /etc/rc.d/nfslocking
printf 'nfs_server=YES\nlockd=YES\nstatd=NO\n' >>/etc/rc.conf
/etc/rc.d/nfslocking start
sleep 2
ps -ax | grep '[r]pc\.'
