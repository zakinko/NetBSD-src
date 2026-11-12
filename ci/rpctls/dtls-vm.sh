#!/bin/sh
# In the VM: rpc.tlsservd and dtlsclient against OpenSSL 4.1, an nfsd on
# UDP only (TCP 2049 is nfsv4d's), and the client's checks over DTLS.
#   dtls-vm.sh [heavy]   (from /var/tmp/nfsv4, with src/ and certs/ there)
# heavy: the checks three times more, for the hang of run 43088069754,
# and plain UDP against DTLS in calls per second.
set -eu
O=/usr/local/openssl41
D=/var/tmp/nfsv4
cd "$D"
CF="-Wall -Werror -Wno-deprecated-declarations -I$O/include"
LIBS="$O/lib/libssl.a $O/lib/libcrypto.a -lpthread"
cc $CF -Isrc/sys -o rpc.tlsservd41 \
    src/usr.sbin/rpc.tlsservd/rpc.tlsservd.c $LIBS
cc $CF -Isrc/sys/oncrpc -Isrc/tests/oncrpc/gss-shim -o dtlsclient \
    src/ci/rpctls/dtlsclient.c src/sys/oncrpc/tls13_crypto.c $LIBS
/usr/sbin/nfsd -u >nfsd-udp.log 2>&1 || :
sleep 1
netstat -an -f inet | grep '\.2049 ' || :
(./rpc.tlsservd41 -d -c certs/server.pem -k certs/server.key -A certs/ca.pem \
    </dev/null >tlsservd-dtls.log 2>&1 & echo $! >tlsservd41.pid)
sleep 1
rc=0
./dtlsclient 127.0.0.1 2049 certs/ca.pem || rc=$?
if [ "${1:-}" = heavy ]; then
	for i in 1 2 3; do
		echo "--- again, $i"
		./dtlsclient 127.0.0.1 2049 certs/ca.pem >again.txt 2>&1 || rc=$?
		grep -E '^FAIL|failures' again.txt
	done
	for n in 1 4; do
		./dtlsclient 127.0.0.1 2049 certs/ca.pem bench $n 2000 |
		    grep '^bench'
	done
fi
kill "$(cat tlsservd41.pid)" 2>/dev/null || :
sleep 1
echo "--- rpc.tlsservd (OpenSSL 4.1)"
tail -n 30 tlsservd-dtls.log
echo "--- the kernel's DTLS records (options ONCRPC_DTLS_DEBUG)"
dmesg | grep rpcdtls | tail -n 80 || :
exit $rc
