#!/bin/sh
# The NetBSD client against the runner's Linux server: a lock held there
# is lost, the server says it has rebooted, and the client takes it back.
# reclaim.sh OUT
OUT=$1
fails=0
try() { python3 -c "
import fcntl, sys
f = open('/srv/nb/f', 'r+')
try:
    fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 0)
except OSError:
    sys.exit(1)"; }
{
	sudo apt-get install -y -q nfs-kernel-server >/dev/null 2>&1
	sudo mkdir -p /srv/nb; sudo chmod 1777 /srv/nb; touch /srv/nb/f; chmod 666 /srv/nb/f
	echo '/srv/nb *(rw,no_root_squash,insecure,no_subtree_check)' | sudo tee /etc/exports >/dev/null
	sudo sysctl -w fs.nfs.nlm_grace_period=15
	sudo systemctl restart nfs-kernel-server
	sudo exportfs -ra
	ssh netbsd 'sysctl -w vfs.nlm.client=1; mkdir -p /mnt/lx; mount_nfs -3 -T 10.77.0.1:/srv/nb /mnt/lx; mount | grep lx'
	ssh -f netbsd 'nohup sh -c "/var/tmp/try -h 240 /mnt/lx/f 0; echo try \$? >/var/tmp/try.rc" >/dev/null 2>&1 &'
	# The restart above is a grace period, which the client waits out.
	i=0
	while [ $i -lt 30 ] && try; do sleep 2; i=$((i + 1)); done
	echo "held after $((i * 2)) s"
	ssh netbsd 'cat /var/tmp/try.rc 2>/dev/null'
	if try; then echo 'FAILED: the Linux server does not have the lock'; fails=$((fails + 1)); else echo 'ok   the server has the lock'; fi
	# Stopping the server takes lockd and its locks with it.
	sudo systemctl stop nfs-kernel-server
	sleep 2
	if try; then echo 'ok   lost on the server'; else echo 'FAILED: still there'; fails=$((fails + 1)); fi
	sudo systemctl start nfs-kernel-server
	python3 - <<'P'
import socket, struct
def u(i): return struct.pack('>I', i)
def o(b): return u(len(b)) + b + b'\0' * ((4 - len(b) % 4) % 4)
def call(port, prog, vers, proc, args):
    m = u(77) + u(0) + u(2) + u(prog) + u(vers) + u(proc) + u(0) * 4 + args
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('10.77.0.1', 0)); s.settimeout(5); s.sendto(m, ('10.77.0.2', port))
    return s.recv(4096)
b = call(111, 100000, 2, 3, u(100024) + u(1) + u(17) + u(0))
port = struct.unpack('>I', b[-4:])[0]
call(port, 100024, 1, 6, o(b'10.77.0.1') + u(99))
print('SM_NOTIFY sent to', port)
P
	i=0
	while [ $i -lt 45 ]; do
		sleep 2; i=$((i + 1))
		try || break
	done
	echo "after $((i * 2)) s"
	if try; then echo 'FAILED: not reclaimed'; fails=$((fails + 1)); else echo 'ok   reclaimed'; fi
	ssh netbsd 'kill -9 $(ps -ax | awk "/[t]ry -h/ { print \$1 }"); sleep 1; umount /mnt/lx; sysctl -w vfs.nlm.client=0; dmesg | grep nlm: | tail -5'
	sudo systemctl stop nfs-kernel-server
	echo "failures: $fails"
} >"$OUT/reclaim.txt" 2>&1
cat "$OUT/reclaim.txt"
test "$(grep '^failures: ' "$OUT/reclaim.txt" | tail -1)" = "failures: 0"
