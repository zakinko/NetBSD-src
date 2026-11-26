#!/bin/sh
# A CA, the server's certificate for localhost and 127.0.0.1, a client's
# from the same CA and a rogue one from another.  mkcerts.sh DIR
set -e
D=$1; mkdir -p "$D"; cd "$D"
o() { openssl "$@" 2>/dev/null; }
for ca in ca rogueca; do
	o req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	    -keyout $ca.key -out $ca.pem -days 7 -subj "/CN=rpctls $ca"
done
leaf() {	# name ca san eku
	o req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	    -keyout $1.key -out $1.csr -subj "/CN=$1"
	printf 'subjectAltName=%s\nextendedKeyUsage=%s\n' "$3" "$4" >$1.ext
	o x509 -req -in $1.csr -CA $2.pem -CAkey $2.key -CAcreateserial \
	    -out $1.pem -days 7 -extfile $1.ext
}
leaf server ca "DNS:localhost,DNS:nfsgss-server.test,IP:127.0.0.1" serverAuth
leaf client ca "DNS:rpctls-client.test" clientAuth
leaf rogue rogueca "DNS:rpctls-client.test" clientAuth
ls
