#!/bin/sh
# A real reboot of the server, with a lock of the Linux client held on a
# file that survives it.  reboot.sh OUT
OUT=$1
{
	F=/export/real/f
	sudo mkdir -p /mnt/r
	sudo mount -t nfs -o vers=3,proto=tcp,noresvport 10.77.0.2:/export/real /mnt/r
	touch /mnt/r/f; chmod 666 /mnt/r/f
	python3 -c "
import fcntl, time
f = open('/mnt/r/f', 'r+')
fcntl.lockf(f, fcntl.LOCK_EX, 1, 0)
time.sleep(300)" &
	h=$!
	sleep 3
	if ssh netbsd "/var/tmp/try $F 0"; then echo 'FAILED: not held before'; exit 1; fi
	echo 'ok   held before the reboot'
	old=$(ssh netbsd 'sysctl -n kern.boottime')
	ssh netbsd 'sync; (sleep 1; shutdown -r now) >/dev/null 2>&1 &'
	i=0; new=
	while [ $i -lt 60 ]; do
		sleep 5; i=$((i + 1))
		new=$(ssh -o ConnectTimeout=5 netbsd 'sysctl -n kern.boottime' 2>/dev/null) || new=
		[ -n "$new" ] && [ "$new" != "$old" ] && break
		new=
	done
	echo "up again after $((i * 5)) s: $new"
	sudo pkill -f tun.py
	sudo ip link del nb0 2>/dev/null
	sleep 1
	sh ci/nlm/tun-up.sh "$OUT"
	ssh netbsd 'sh /var/tmp/nlm/server2.sh'
	ssh netbsd 'cat /var/db/statd.status | wc -c; sysctl vfs.nlm.grace; ps -ax | grep "[r]pc\."'
	if ssh netbsd "/var/tmp/try $F 0"; then echo 'measure: free just after the reboot'; else echo 'measure: already reclaimed'; fi
	i=0
	while [ $i -lt 30 ]; do
		sleep 3; i=$((i + 1))
		ssh netbsd "/var/tmp/try $F 0" || break
	done
	if ssh netbsd "/var/tmp/try $F 0"; then
		echo "measure: NOT reclaimed in $((i * 3)) s"
	else
		echo "measure: reclaimed, seen after $((i * 3)) s"
	fi
	ssh netbsd 'sysctl vfs.nlm; dmesg | grep nlm: | tail -5'
	sudo dmesg | grep -iE 'lockd|nfs:' | tail -8
	kill $h
	echo done
} >"$OUT/reboot.txt" 2>&1
cat "$OUT/reboot.txt"
