#!/bin/sh
# On the runner: the Linux NFS client with xprtsec=tls, through tlshd,
# against whatever answers on the tunnelled 127.0.0.1:2049.  The verdict
# is what the server's side saw; this records the client's.
# linux-tls.sh OUT CERTDIR MODE, MODE tls or mtls (the xprtsec= value)
OUT=$1 CERTS=$2 MODE=$3
LOG=$OUT/linux-$MODE.txt
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
dpkg -s ktls-utils | grep -i '^version'
sudo modprobe tls
sudo modprobe nfs || {
	sudo env DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y -q \
	    "linux-modules-extra-$(uname -r)"
	sudo modprobe nfs
}
sudo modprobe nfsv4
cat /etc/tlshd.conf
{
	printf '[debug]\nloglevel=7\ntls=7\nnl=1\n'
	printf '[authenticate.client]\nx509.truststore=%s/ca.pem\n' "$CERTS"
	[ "$MODE" = mtls ] &&
	    printf 'x509.certificate=%s/client.pem\nx509.private_key=%s/client.key\n' \
	    "$CERTS" "$CERTS"
} | sudo tee /etc/tlshd.conf
sudo sh -c "/usr/sbin/tlshd -s >$OUT/tlshd-$MODE.log 2>&1 & echo \$! >$PID"
sleep 2
ps -p "$(cat $PID)" -o pid,cmd
sudo mkdir -p /mnt/tls
sudo timeout 90 mount -t nfs -o vers=4.0,port=2049,xprtsec=$MODE,retry=0,soft,timeo=50,retrans=1 \
    127.0.0.1:/ /mnt/tls
rc=$?
echo "mount exit $rc"
if [ $rc -eq 0 ]; then
	grep /mnt/tls /proc/mounts
	head -c 4194304 /dev/urandom >"$OUT/tls-$MODE.bin"
	d=$(ls /mnt/tls | head -1)
	echo "exported: $(ls /mnt/tls | tr '\n' ' ')"
	# 1777 exports of in-vm.sh.
	for w in /mnt/tls/export/tmpfs /mnt/tls/export/pynfs; do
		sudo cp "$OUT/tls-$MODE.bin" "$w/tls-$MODE.bin" 2>/dev/null && break
	done
	echo "wrote to $w"
	sudo sh -c 'echo 3 >/proc/sys/vm/drop_caches'
	sudo cmp "$OUT/tls-$MODE.bin" "$w/tls-$MODE.bin" && echo "io ok: 4 MB over $MODE"
	sudo rm -f "$w/tls-$MODE.bin"
	sudo umount /mnt/tls && echo "umount ok"
fi
sudo umount -f /mnt/tls 2>/dev/null
sudo kill "$(cat $PID)"
sudo dmesg | tail -20
exit 0
