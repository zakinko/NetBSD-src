#!/bin/sh
# Generate the headers lib/libcrypto/Makefile makes from *.h.in (GENH) into
# the tree:  genhdr.sh <src>
# On a release with this OpenSSL /usr/include has them; on 9.4 it is 1.1.1.
o=$1/crypto/external/apache2/openssl
for f in "$o"/dist/include/openssl/*.h.in; do
	h=$o/include/openssl/$(basename "$f" .in)
	[ -s "$h" ] || sh "$o/lib/libcrypto/gen" "$f" > "$h" || exit 1
done
