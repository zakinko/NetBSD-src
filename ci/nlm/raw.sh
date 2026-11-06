#!/bin/sh
# The two clients, on each file system.  raw.sh on|off
s=0
FS="/export/ffs/raw /export/tmpfs/raw"
[ -d /tank/x ] && FS="$FS /tank/x/raw"
for f in $FS; do
	/var/tmp/rawnlm "$f" || s=1
done
sysctl vfs.nlm
echo '# audit 13: the hosts go idle, and the NSM is told'
sleep 45
sysctl vfs.nlm.nhosts
c=$(grep -c 'un-monitor request' /var/log/statd.debug)
echo "SM_UNMON seen by rpc.statd: $c"
[ "$c" -gt 0 ] || s=1
sysctl vfs.nlm.nhosts
ps -ax | grep '[r]pc\.statd'
kill -9 $(ps -ax | awk '/[r]pc\.statd/ { print $1 }')
sleep 1
ps -ax | grep "[r]pc\.statd" && { echo statd still up; s=1; }
sleep 1
/var/tmp/rawnlm -n /export/ffs/nostatd || s=1
dmesg | grep 'nlm: cannot monitor'
rm -f /var/db/statd.status
nohup /usr/sbin/rpc.statd -d >/dev/null 2>&1 &
sleep 1
/var/tmp/rawnlm -r /export/ffs/nostatd || s=1
ps -ax | grep '[r]pc\.'
exit $s
