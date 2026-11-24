#!/bin/sh
# Build NetBSD's libcrypto from two trees with the host's make and headers:
#   nbbuild.sh <src> <objdir> <log>
# Only libcrypto.so is needed, for LD_LIBRARY_PATH runs of /usr/bin/openssl.
src=$1 obj=$2 log=$3
mkdir "$obj.lock" 2>/dev/null || { echo "$obj is being built" >&2; exit 1; }
trap 'rmdir "$obj.lock"' EXIT
mkdir -p "$obj"
if [ -n "${TREEMK:-}" ]; then sh "$(dirname "$0")/genhdr.sh" "$src" || exit 1; fi
cd "$src/crypto/external/apache2/openssl/lib/libcrypto" || exit 1
# TREEMK=1: an older release's share/mk does not know this OpenSSL; use the
# tree's, do not stop at the older gcc's warnings, and skip the symbol list:
# its nm writes OPENSSL_3.0.0@@OPENSSL_3.0.0 for the version names
make -j8 ${TREEMK:+-k -m "$src/share/mk" NOGCCERROR=yes LIB_EXPSYM=} NETBSDSRCDIR="$src" MAKEOBJDIR="$obj" \
    MKDOC=no MKMAN=no MKPROFILE=no MKSTATICLIB=no MKLINT=no \
    MKDEBUGLIB=no MKDEBUG=no LIBDO.crypt=_external \
    dependall > "$log" 2>&1
rc=$?
echo "rc $rc" >> "$log"
ls -l "$obj"/libcrypto.so* >> "$log" 2>&1
exit $rc
