#!/bin/sh
# On the runner: the Linux NFS client with xprtsec=tls, through tlshd,
# against whatever answers on the tunnelled 127.0.0.1:2049.  The verdict
# is what the server's side saw; this records the client's.
# linux-tls.sh OUT
OUT=$1
LOG=$OUT/linux-tls.txt
PID=$OUT/tlshd.pid
exec >"$LOG" 2>&1
set -x
# The package's postinst starts tlshd and needrestart asks questions;
# either kept the first attempt from returning (run 42952027560).
echo 'exit 101' | sudo tee /usr/sbin/policy-rc.d >/dev/null
sudo chmod +x /usr/sbin/policy-rc.d
sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 \
    timeout 300 apt-get install -y -q -o Dpkg::Options::=--force-confold \
    ktls-utils nfs-common
sudo rm -f /usr/sbin/policy-rc.d
ls -l /usr/sbin/tlshd || exit 1
sudo modprobe tls
sudo modprobe nfs || {
	sudo env DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y -q \
	    "linux-modules-extra-$(uname -r)"
	sudo modprobe nfs
}
sudo modprobe nfsv4
cat /etc/tlshd.conf
sudo sh -c "/usr/sbin/tlshd -s >$OUT/tlshd.log 2>&1 & echo \$! >$PID"
sleep 2
ps -p "$(cat $PID)" -o pid,cmd
sudo mkdir -p /mnt/tls
sudo timeout 90 mount -t nfs -o vers=4.0,port=2049,xprtsec=tls,retry=0,soft,timeo=50,retrans=1 \
    127.0.0.1:/ /mnt/tls
echo "mount exit $?"
sudo umount -f /mnt/tls 2>/dev/null
sudo kill "$(cat $PID)"
sudo dmesg | tail -20
exit 0
