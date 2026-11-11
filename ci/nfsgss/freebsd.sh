#!/bin/sh
# In the FreeBSD VM: NFSv3 under RPCSEC_GSS over UDP, which the Linux
# client of the runner no longer has.  The NetBSD VM is reached through
# the runner, 10.0.2.2 to a QEMU guest.  freebsd.sh
set -u
S=nfsgss-server.test
D=/var/tmp/nfsgss
B=/var/tmp/udp-alice.bin
fails=0
t() {
	echo "\$ $*"
	if "$@"; then echo ok; else echo "FAILED ($?)"; fails=$((fails + 1)); fi
}
uname -a
grep -q "$S" /etc/hosts || echo "10.0.2.2 $S" >>/etc/hosts
echo "127.0.0.1 nfsgss-freebsd.test" >>/etc/hosts
hostname nfsgss-freebsd.test
cat >/etc/krb5.conf <<EOF
[libdefaults]
	default_realm = NFSGSS.TEST
	dns_lookup_kdc = false
	dns_canonicalize_hostname = false
	rdns = false
	udp_preference_limit = 1
[realms]
	NFSGSS.TEST = {
		kdc = 10.0.2.2:18888
	}
[domain_realm]
	.test = NFSGSS.TEST
EOF
install -m 600 "$D/freebsd.keytab" /etc/krb5.keytab
pw useradd alice -u 2097 -m 2>/dev/null
kldload kgssapi_krb5 2>/dev/null
/usr/sbin/gssd
sleep 1
install -o alice -m 600 "$D/alice.keytab" /var/tmp/alice.keytab
su -m alice -c 'kinit -k -t /var/tmp/alice.keytab alice'
su -m alice -c klist | head -4
echo '--- what the server answers from here'
timeout 30 rpcinfo -p 10.0.2.2 || echo 'rpcinfo -p: no answer'
timeout 30 rpcinfo -u 10.0.2.2 100003 3 || echo 'NFS over UDP: no answer'
timeout 30 rpcinfo -u 10.0.2.2 100005 3 || echo 'MOUNT over UDP: no answer' 
mkdir -p /mnt/u
for sec in krb5 krb5i krb5p; do
	echo "=== UDP, version 3, $sec"
	t timeout 120 mount_nfs -o nfsv3,udp,mntudp,sec=$sec,gssname=host,retrycnt=1 "$S:/export/krb5all" /mnt/u
	nfsstat -m | sed -n '/\/mnt\/u/,+2p'
	t sh -c "nfsstat -m | grep -A2 /mnt/u | grep -q udp"
	t su -m alice -c "echo UDP-$sec >/mnt/u/udp-$sec"
	t su -m alice -c "test \"\$(cat /mnt/u/udp-$sec)\" = UDP-$sec"
	t su -m alice -c "dd if=/dev/random of=$B bs=64k count=16 2>/dev/null && cp $B /mnt/u/b-$sec"
	t umount /mnt/u
	t timeout 120 mount_nfs -o nfsv3,udp,mntudp,sec=$sec,gssname=host,retrycnt=1 "$S:/export/krb5all" /mnt/u
	t su -m alice -c "cmp $B /mnt/u/b-$sec"
	t su -m alice -c "rm -f /mnt/u/b-$sec /mnt/u/udp-$sec"
	t umount /mnt/u
done
echo "freebsd failures: $fails"
test "$fails" = 0
