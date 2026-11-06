#!/bin/sh
# Put what was built in place and start the servers, with a short grace
# period, then measure it.  server.sh DIR on|off
set -eu
D=$1
MODE=$2
R=$(uname -r)
for k in "$D"/modules/*.kmod; do
	m=$(basename "$k" .kmod)
	mkdir -p "/stand/amd64/$R/modules/$m"
	cp "$k" "/stand/amd64/$R/modules/$m/"
done
modload nfsv4
for p in rpc.lockd; do
	(cd "$D/$p" && make -s NOMAN=yes WARNS=0 >make.log 2>&1) ||
	    { tail -30 "$D/$p/make.log"; exit 1; }
done
cc -g -Wall -o /var/tmp/rawnlm "$D/rawnlm.c" -lpthread
mkdir -p /export/ffs /export/tmpfs /export/real
mount_mfs -s 512m swap /export/ffs
mount_tmpfs -s 256m tmpfs /export/tmpfs
chmod 1777 /export/ffs /export/tmpfs /export/real
cat >/etc/exports <<EOT
/export/ffs -maproot=root -noresvport -noresvmnt
/export/tmpfs -maproot=root -noresvport -noresvmnt
/export/real -maproot=root -noresvport -noresvmnt
EOT
if [ "$MODE" = on ] && [ -f "$D/modules/zfs.kmod" ] && modload zfs; then
	find / -xdev -name 'libzfs.so*' 2>/dev/null | head -5
	L=$(find / -xdev -name 'libzfs.so.7' 2>/dev/null | head -1)
	[ -z "$L" ] || export LD_LIBRARY_PATH=$(dirname "$L")
	dd if=/dev/zero of=/var/tmp/tank.img bs=1m count=512 2>/dev/null
	if zpool create -f tank /var/tmp/tank.img && zfs create tank/x; then
		chmod 1777 /tank/x
		echo '/tank/x -maproot=root -noresvport -noresvmnt' >>/etc/exports
	else
		echo ZFS-NOT-MEASURED
	fi
	unset LD_LIBRARY_PATH
fi
/etc/rc.d/rpcbind onestart || :
ifconfig lo0 alias 127.0.0.2/32
ifconfig lo0 alias 127.0.0.3/32
ifconfig lo0 alias 127.0.0.4/32
ifconfig lo0 alias 127.0.0.5/32
# With -d it says what it is asked, and stays in the foreground.
printf 'daemon.debug\t/var/log/statd.debug\n' >>/etc/syslog.conf
touch /var/log/statd.debug
/etc/rc.d/syslogd onerestart >/dev/null 2>&1 || :
nohup /usr/sbin/rpc.statd -d >/dev/null 2>&1 &
sleep 1
/usr/sbin/mountd -p 1234
sleep 1
/usr/sbin/nfsd -t -u -n 4
sleep 1
modload nlm
sysctl -w vfs.nlm.grace=12
"$D/rpc.lockd/rpc.lockd"
sleep 1
ps -ax | grep -E '[n]fsd|[m]ountd|rpc\.[l]ockd|rpc\.[s]tatd'
rpcinfo -p | grep -E 'nfs|mountd|nlockmgr|status' || :
/var/tmp/rawnlm -g /export/ffs/grace
