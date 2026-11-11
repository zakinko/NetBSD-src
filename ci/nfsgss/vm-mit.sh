#!/bin/sh
# In the VM: DES MAC MD5, RFC 2623 s4.1, with a real client.  Heimdal of
# the base system cannot: its OpenSSL has no DES and the KDC aborts on
# des-cbc-md5.  MIT krb5 1.17 still has DES in its own crypto, so it is
# built here and plays KDC, client and gssd(8) for the time of the test,
# in a realm of its own.
set -u
D=/var/tmp/nfsv4
M=$D/mit
V=1.17.2
R=MITDES.TEST
log() { "$@" >"$D/mit-step.log" 2>&1 || { tail -30 "$D/mit-step.log"; echo "FAILED: $*"; exit 1; }; }
log pkgin -y install gmake
cd "$D"
log ftp -o krb5.tgz "https://kerberos.org/dist/krb5/1.17/krb5-$V.tar.gz"
log tar -xzf krb5.tgz
cd "krb5-$V/src"
# The base system's libedit has readline/readline.h, not the
# editline/readline.h this version asks for; ss works without either.
log ./configure --prefix="$M" --with-crypto-impl=builtin --without-tcl \
    --without-keyutils --without-libedit --without-readline \
    --disable-rpath CFLAGS=-O1
log gmake -j3
log gmake install
mkdir -p "$M/var"
cat >"$D/mit-krb5.conf" <<EOF
[libdefaults]
	default_realm = $R
	allow_weak_crypto = true
	dns_lookup_kdc = false
	dns_canonicalize_hostname = false
	rdns = false
	udp_preference_limit = 1
	permitted_enctypes = des-cbc-md5 des-cbc-crc
	default_tkt_enctypes = des-cbc-md5 des-cbc-crc
	default_tgs_enctypes = des-cbc-md5 des-cbc-crc
[realms]
	$R = {
		kdc = 127.0.0.1:8889
	}
[domain_realm]
	nfsgss-server.test = $R
EOF
cat >"$D/mit-kdc.conf" <<EOF
[kdcdefaults]
	kdc_ports = 8889
	kdc_tcp_ports = 8889
[realms]
	$R = {
		database_name = $M/var/principal
		key_stash_file = $M/var/stash
		master_key_type = aes256-cts
		supported_enctypes = des-cbc-md5:normal des-cbc-crc:normal aes256-cts:normal
	}
EOF
export KRB5_CONFIG="$D/mit-krb5.conf" KRB5_KDC_PROFILE="$D/mit-kdc.conf"
log "$M/sbin/kdb5_util" create -s -P master-pw -r "$R"
log "$M/sbin/kadmin.local" -q "addprinc -randkey -e des-cbc-md5:normal,des-cbc-crc:normal nfs/nfsgss-server.test"
log "$M/sbin/kadmin.local" -q "ktadd -k $D/mit-nfs.keytab -e des-cbc-md5:normal,des-cbc-crc:normal nfs/nfsgss-server.test"
log "$M/sbin/kadmin.local" -q "addprinc -pw alice-pw -e des-cbc-md5:normal,des-cbc-crc:normal alice"
"$M/sbin/krb5kdc" -r "$R"
sleep 1
I="-I$M/include -L$M/lib -Wl,-R$M/lib"
log cc -g $I -o "$D/gssd-mit" "$D/src/usr.sbin/gssd/gssd.c" -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err -lutil
log cc -g $I -o "$D/desprobe-mit" "$D/desprobe.c" -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err
"$M/bin/klist" -k "$D/mit-nfs.keytab" -e | tail -2

# The kernel talks to one gssd, so the MIT one stands in for a while.
kill "$(cat "$D/gssd.pid")"
sleep 1
"$D/gssd-mit" -d -h nfsgss-server.test -k "$D/mit-nfs.keytab" </dev/null >"$D/gssd-mit.log" 2>&1 &
echo $! >"$D/gssd-mit.pid"
sleep 1
rc=0
for e in des-cbc-md5 des-cbc-crc; do
	echo "=== $e"
	sed "s/= des-cbc-md5 des-cbc-crc/= $e/" "$D/mit-krb5.conf" >"$D/mit-$e.conf"
	echo alice-pw | KRB5_CONFIG="$D/mit-$e.conf" KRB5CCNAME="FILE:$D/mit-cc-$e" "$M/bin/kinit" alice >/dev/null
	KRB5_CONFIG="$D/mit-$e.conf" KRB5CCNAME="FILE:$D/mit-cc-$e" "$M/bin/klist" -e | grep -i 'etype' | head -2
	KRB5_CONFIG="$D/mit-$e.conf" KRB5CCNAME="FILE:$D/mit-cc-$e" "$D/desprobe-mit" nfsgss-server.test || { echo "FAILED desprobe $e"; rc=1; }
done
cat "$D/gssd-mit.log"
grep -q 'enctype 3,' "$D/gssd-mit.log" || { echo 'FAILED: no des-cbc-md5 context'; rc=1; }
grep -q 'enctype 1,' "$D/gssd-mit.log" || { echo 'FAILED: no des-cbc-crc context'; rc=1; }
kill "$(cat "$D/gssd-mit.pid")"
sleep 1
"$D/gssd" -d -h nfsgss-server.test </dev/null >>"$D/gssd.log" 2>&1 &
echo $! >"$D/gssd.pid"
echo "mit rc=$rc"
exit $rc
