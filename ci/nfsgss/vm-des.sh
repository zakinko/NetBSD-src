#!/bin/sh
# In the VM: the enctypes of RFC 1964, by the base system's libgssapi.
D=/var/tmp/nfsv4
# des-cbc-md5 is not tried: the KDC of the base system dies of it,
# "can't initialize cipher", with no DES in its OpenSSL.
for e in des3-cbc-sha1; do
	echo "=== $e"
	sed "s/^\\[libdefaults\\]/[libdefaults]\\n\tdefault_etypes = $e\\n\tdefault_etypes_des = $e/" /etc/krb5.conf >"$D/krb5-$e.conf"
	echo alice-pw | KRB5_CONFIG="$D/krb5-$e.conf" KRB5CCNAME="FILE:$D/cc-$e" \
	    kinit --password-file=STDIN alice@NFSGSS.TEST || echo "FAILED kinit $e"
	KRB5_CONFIG="$D/krb5-$e.conf" KRB5CCNAME="FILE:$D/cc-$e" klist -v | grep -E 'Session key|Ticket etype' | head -4
	KRB5_CONFIG="$D/krb5-$e.conf" KRB5CCNAME="FILE:$D/cc-$e" "$D/desprobe" nfsgss-server.test || echo "FAILED desprobe $e"
done
echo '=== UDP, version 3'
echo alice-pw | KRB5CCNAME="FILE:$D/cc-udp" kinit --password-file=STDIN alice@NFSGSS.TEST
KRB5CCNAME="FILE:$D/cc-udp" "$D/desprobe" -u nfsgss-server.test || echo "FAILED desprobe -u"
tail -4 "$D/gssd.log"
tail -6 "$D/kdc.log"
