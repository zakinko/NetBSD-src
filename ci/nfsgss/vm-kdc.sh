#!/bin/sh
# In the VM: a Heimdal KDC, the users, the keytab of the server, and
# the exports for the flavors.  A keytab for the client is left in
# /var/tmp/nfsv4/client.keytab.
set -eu
D=/var/tmp/nfsv4
R=NFSGSS.TEST
cat >/etc/krb5.conf <<EOF
[libdefaults]
	default_realm = $R
	dns_lookup_kdc = false
	dns_canonicalize_hostname = false
	rdns = false
[realms]
	$R = {
		kdc = tcp/127.0.0.1:8888
	}
[domain_realm]
	.test = $R
	nfsgss-server.test = $R
[kdc]
	ports = 8888/tcp
	logging = FILE:/var/tmp/nfsv4/kdc.log
[kadmin]
	default_keys = aes256-cts-hmac-sha384-192:pw-salt aes128-cts-hmac-sha256-128:pw-salt aes256-cts-hmac-sha1-96:pw-salt aes128-cts-hmac-sha1-96:pw-salt
EOF
mkdir -p /var/heimdal
chmod 700 /var/heimdal
kstash --random-key
kadmin -l init --realm-max-ticket-life=1d --realm-max-renewable-life=1d "$R"
id=2097
for u in alice bob; do
	useradd -m -u $id "$u"
	id=$((id + 1))
	kadmin -l add --password="$u-pw" --use-defaults "$u"
done
kadmin -l add --random-key --use-defaults nfs/nfsgss-server.test
kadmin -l add --random-key --use-defaults host/nfsgss-client.test
rm -f /etc/krb5.keytab "$D/client.keytab"
kadmin -l ext_keytab -k /etc/krb5.keytab nfs/nfsgss-server.test
kadmin -l ext_keytab -k "$D/client.keytab" host/nfsgss-client.test
chmod 644 "$D/client.keytab"
kdc --detach --addresses=127.0.0.1 --ports=8888/tcp
sleep 2
netstat -an -f inet | grep 8888
tail -5 "$D/kdc.log" || :

for e in krb5all krb5ponly sysonly; do
	mkdir -p "/export/$e"
	mount_mfs -s 64m swap "/export/$e"
	chmod 1777 "/export/$e"
done
cat >>/etc/exports <<EOF
/export/krb5all -sec=krb5:krb5i:krb5p -maproot=nobody -noresvport -noresvmnt
/export/krb5ponly -sec=krb5p -maproot=nobody -noresvport -noresvmnt
/export/sysonly -sec=sys -maproot=root -noresvport -noresvmnt
EOF
mkdir -p "$D/inc/nfs"
cp "$D/src/sys/nfs/nfs.h" "$D/inc/nfs/"
(cd "$D/src/usr.sbin/mountd" && cc -g -I"$D/inc" -o "$D/mountd" mountd.c get_net.c -lutil)
(cd "$D/src/usr.sbin/gssd" && cc -g -Wall -I/usr/include/krb5 -o "$D/gssd" gssd.c -lgssapi -lkrb5 -lutil)
kill "$(cat /var/run/mountd.pid)" 2>/dev/null || pkill -x mountd || :
sleep 1
"$D/mountd" -p 4002
echo 127.0.0.1 nfsgss-server.test >>/etc/hosts
ktutil -k /etc/krb5.keytab list
"$D/gssd" -d -h nfsgss-server.test </dev/null >"$D/gssd.log" 2>&1 &
echo $! >"$D/gssd.pid"
sleep 1
cat "$D/gssd.log"
ls -l /var/run/gssd.sock
# The owners, RFC 7530 s5.9: vfs.nfsv4 has a table, as the kernel no passwd.
sysctl -w vfs.nfsv4.domain=nfsgss.test
sysctl -w vfs.nfsv4.idmap="u 2097 alice"
sysctl -w vfs.nfsv4.idmap="u 2098 bob"
# nfsd(8) takes the port, for all three versions, as a real server does.
kill "$(cat "$D/nfsv4d.pid")"
sleep 1
/usr/sbin/nfsd -t -u -n 8
sleep 2
netstat -an -f inet | grep '\.2049 '
