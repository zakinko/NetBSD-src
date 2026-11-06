#!/bin/sh
# In the VM: the enctypes of RFC 1964, by the base system's libgssapi.
D=/var/tmp/nfsv4
for e in des3-cbc-sha1 des-cbc-md5; do
	echo "=== $e"
	sed "s/^\\[libdefaults\\]/[libdefaults]\\n\tdefault_etypes = $e\\n\tdefault_etypes_des = $e/" /etc/krb5.conf >"$D/krb5-$e.conf"
	echo alice-pw | KRB5_CONFIG="$D/krb5-$e.conf" KRB5CCNAME="FILE:$D/cc-$e" \
	    kinit --password-file=STDIN alice@NFSGSS.TEST || echo "FAILED kinit $e"
	KRB5_CONFIG="$D/krb5-$e.conf" KRB5CCNAME="FILE:$D/cc-$e" klist -v | grep -E 'Session key|Ticket etype' | head -4
	KRB5_CONFIG="$D/krb5-$e.conf" KRB5CCNAME="FILE:$D/cc-$e" "$D/desprobe" nfsgss-server.test || echo "FAILED desprobe $e"
done
tail -4 "$D/gssd.log"
