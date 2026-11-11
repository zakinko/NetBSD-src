#!/bin/sh
# In the VM: rpc.tlsservd and dtlsclient against OpenSSL 4.1, an nfsd on
# UDP only (TCP 2049 is nfsv4d's), and the client's checks over DTLS.
#   dtls-vm.sh   (from /var/tmp/nfsv4, with src/ and certs/ there)
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
kill "$(cat tlsservd41.pid)" 2>/dev/null || :
sleep 1
echo "--- rpc.tlsservd (OpenSSL 4.1)"
tail -n 30 tlsservd-dtls.log
exit $rc
