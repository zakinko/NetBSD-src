#!/bin/sh
# SP4_SSV, RFC 8881 s18.35 and s18.47, by pynfs's EID50 under krb5i, the
# flavor s18.35.3 has an SP4_SSV EXCHANGE_ID come with.  pynfs is set up
# by the runs of it before.  pynfs-ssv.sh OUT
OUT=$1
LOG=$OUT/pynfs-ssv.txt
cd "$HOME/pynfs/nfs4.1" || exit 1
{
	sudo env KRB5CCNAME=FILE:/var/tmp/krb5cc_2097 KRB5_CONFIG=/etc/krb5.conf \
	    timeout 300 python3 ./testserver.py nfsgss-server.test:/export/krb5all \
	    --minorversion=1 --security=krb5i --json="$OUT/pynfs-ssv.json" EID50
	echo "testserver.py exit status $?"
	ssh netbsd 'tail -5 /var/tmp/nfsv4/gssd.log'
} >"$LOG" 2>&1
cat "$LOG"
python3 - "$OUT/pynfs-ssv.json" <<'P'
import json, sys
d = json.load(open(sys.argv[1]))
r = [t for t in d.get('testcase', []) if t.get('code') == 'EID50' or t.get('name', '').endswith('testSSV')]
print(r)
sys.exit(0 if r and not r[0].get('failure') and not r[0].get('skipped') else 1)
P
