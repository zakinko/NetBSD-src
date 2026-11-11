#!/bin/sh
# In the FreeBSD VM: NFSv3 under RPCSEC_GSS over UDP, which the Linux
# client of the runner no longer has.  The NetBSD VM is reached through
# the runner, HOST: 192.168.122.2, as anyvm's user-mode network has it,
# where the forwards to the NetBSD VM and rpcb-nat.py listen.
# freebsd.sh HOST
set -u
H=$1
echo "the NetBSD VM through $H"
S=nfsgss-server.test
D=/var/tmp/nfsgss
B=/var/tmp/udp-alice.bin
fails=0
t() {
	echo "\$ $*"
	if "$@"; then echo ok; else echo "FAILED ($?)"; fails=$((fails + 1)); fi
}
uname -a
grep -q "$S" /etc/hosts || echo "$H $S" >>/etc/hosts
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
		kdc = $H:18888
	}
[domain_realm]
	.test = NFSGSS.TEST
EOF
install -m 600 "$D/freebsd.keytab" /etc/krb5.keytab
pw useradd alice -u 2097 -m 2>/dev/null
kldload kgssapi_krb5 2>/dev/null
# nmount got EACCES under all three flavors in run 43307252804: gssd ran
# without -h, which gssname= needs (gssd(8)), and mount_nfs(8) has that
# option for NFSv4 mounts.  For this version 3 mount root also gets a
# ticket of the host principal from the keytab, which is what a mount
# without gssname= uses.
/usr/sbin/gssd -h -v
kinit -k -t /etc/krb5.keytab host/nfsgss-freebsd.test
klist | head -4
sleep 1
install -o alice -m 600 "$D/alice.keytab" /var/tmp/alice.keytab
su -m alice -c 'kinit -k -t /var/tmp/alice.keytab alice'
su -m alice -c klist | head -4
echo '--- what the server answers from here'
timeout 30 rpcinfo -p $H || echo 'rpcinfo -p: no answer'
# rpcbind over UDP first: an answer says the path carries UDP, and the
# silence of NFS then is the server's.
timeout 30 rpcinfo -u $H 100000 2 || echo 'rpcbind over UDP: no answer'
timeout 30 rpcinfo -u $H 100003 3 || echo 'NFS over UDP: no answer'
timeout 30 rpcinfo -u $H 100005 3 || echo 'MOUNT over UDP: no answer' 
mkdir -p /mnt/u
for sec in krb5 krb5i krb5p; do
	echo "=== UDP, version 3, $sec"
	t timeout 120 mount_nfs -o nfsv3,udp,mntudp,sec=$sec,gssname=host,retrycnt=1 "$S:/export/krb5all" /mnt/u
	nfsstat -m | sed -n '/\/mnt\/u/,+2p'
	t sh -c "nfsstat -m | grep -A2 /mnt/u | grep -q udp"
	t su -m alice -c "echo UDP-$sec >/mnt/u/udp-$sec"
	t su -m alice -c "test \"\$(cat /mnt/u/udp-$sec)\" = UDP-$sec"
	# The wire and the retransmissions too: under krb5p the copy got
	# EACCES at its fifteenth 8 KB write in run 43366599456, while
	# krb5 and krb5i went through.
	nfsstat -c -z >/dev/null 2>&1
	tcpdump -i vtnet0 -s0 -w /var/tmp/w-$sec.pcap "udp port 2049 or (ip[6:2] & 0x1fff != 0)" >/dev/null 2>&1 &
	tdp=$!; sleep 1
	t su -m alice -c "dd if=/dev/random of=$B bs=64k count=16 2>/dev/null && cp $B /mnt/u/b-$sec"
	sleep 1; kill $tdp; wait $tdp 2>/dev/null
	nfsstat -c | sed -n '/Rpc Info/,$p' | head -8
	tcpdump -r /var/tmp/w-$sec.pcap -n -vv 2>/dev/null | grep -E 'reply|write' | tail -12
	t umount /mnt/u
	t timeout 120 mount_nfs -o nfsv3,udp,mntudp,sec=$sec,gssname=host,retrycnt=1 "$S:/export/krb5all" /mnt/u
	t su -m alice -c "cmp $B /mnt/u/b-$sec"
	t su -m alice -c "rm -f /mnt/u/b-$sec /mnt/u/udp-$sec"
	t umount /mnt/u
done
echo "freebsd failures: $fails"
test "$fails" = 0
