#!/bin/sh
# Build NetBSD's libcrypto from two trees with the host's make and headers:
#   nbbuild.sh <src> <objdir> <log>
# Only libcrypto.so is needed, for LD_LIBRARY_PATH runs of /usr/bin/openssl.
src=$1 obj=$2 log=$3
mkdir "$obj.lock" 2>/dev/null || { echo "$obj is being built" >&2; exit 1; }
trap 'rmdir "$obj.lock"' EXIT
mkdir -p "$obj"
cd "$src/crypto/external/apache2/openssl/lib/libcrypto" || exit 1
make -j8 NETBSDSRCDIR="$src" MAKEOBJDIR="$obj" \
    MKDOC=no MKMAN=no MKPROFILE=no MKSTATICLIB=no MKLINT=no \
    MKDEBUGLIB=no MKDEBUG=no LIBDO.crypt=_external \
    dependall > "$log" 2>&1
rc=$?
echo "rc $rc" >> "$log"
ls -l "$obj"/libcrypto.so* >> "$log" 2>&1
exit $rc
