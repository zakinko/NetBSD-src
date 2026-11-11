#!/bin/sh
# SP4_SSV, RFC 8881 s18.35 and s18.47, by pynfs's EID50 under krb5i, the
# flavor s18.35.3 has an SP4_SSV EXCHANGE_ID come with.  pynfs is set up
# by the runs of it before.  pynfs-ssv.sh OUT
OUT=$1
LOG=$OUT/pynfs-ssv.txt
cd "$HOME/pynfs/nfs4.1" || exit 1
# pynfs's SSV context is still Python 2: the SSV and its pads are str,
# and EID50 died in hmac.new() ("key: expected bytes") after the server
# had answered the SP4_SSV EXCHANGE_ID (run 43226842274).  The few
# places are made bytes; with the name below, nothing else of pynfs is
# touched.
python3 - nfs4lib.py <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
for a, b in [
    ("self._add_ssv('\\0' * self.ssv_len)", "self._add_ssv(b'\\0' * self.ssv_len)"),
    ("return ''.join(map(lambda x:chr(ord(x[0])^ord(x[1])), zip(a, b)))",
     "return bytes(x ^ y for x, y in zip(a, b))"),
    ('return "".join([chr(random.randint(0, 255)) for i in range(size)])',
     'return bytes(random.randint(0, 255) for i in range(size))'),
    ("pad = '\\0' * (blocksize - offset)", "pad = b'\\0' * (blocksize - offset)"),
    ('ssv_seal_plain_tkn4(cofounder, seqnum, data, "")',
     'ssv_seal_plain_tkn4(cofounder, seqnum, data, b"")'),
]:
    if a in s:
        s = s.replace(a, b)
    elif b not in s:
        sys.exit('pynfs-ssv: not found in nfs4lib.py: ' + a)
open(p, 'w').write(s)
PY
# nfs4client.py names rpc.gss_const, but imports rpc.rpc as rpc; the
# constants are in rpc.security too (run 43271744327).
sed -i 's/rpc\.gss_const\.rpc_gss_svc_privacy/rpc.security.rpc_gss_svc_privacy/' nfs4client.py
grep -q 'rpc.security.rpc_gss_svc_privacy' nfs4client.py ||
    { echo 'pynfs-ssv: nfs4client.py not patched'; exit 1; }
{
	# The tunnel client.sh made is gone by now: linux-client.sh drops its
	# own with pkill -f '[s]sh -f -N .*2049:127.0.0.1:2049', which matches
	# this one too (linux-client-4.1.txt of run 42971381404), and pynfs
	# then failed in connect() with EBADF.  Make it again.
	if ! timeout 5 bash -c '</dev/tcp/10.99.0.1/2049' 2>/dev/null; then
		echo "tunnel to 10.99.0.1:2049 down, remaking it"
		ssh -f -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=10 \
		    -L 10.99.0.1:2049:127.0.0.1:2049 \
		    -L 10.99.0.1:8888:127.0.0.1:8888 netbsd
	fi
	sudo env KRB5CCNAME=FILE:/var/tmp/krb5cc_2097 KRB5_CONFIG=/etc/krb5.conf \
	    timeout 300 python3 ./testserver.py nfsgss-server.test:/export/krb5all \
	    --minorversion=1 --security=krb5i --maketree --json="$OUT/pynfs-ssv.json" EID50
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
