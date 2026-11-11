#!/bin/sh
# libtirpc for the unit tests, built from its release rather than taken
# from apt: the runner's apt mirror has failed to resolve for whole
# afternoons, and the tests need only the XDR routines.
#   tirpc.sh PREFIX
set -eu
prefix=$1
ver=1.3.4
sum=1e0b0c7231c5fa122e06c0609a76723664d068b0dba3b8219b63e6340b347860
[ -f "$prefix/lib/libtirpc.a" ] && exit 0
work=$(mktemp -d)
curl -fsSL --retry 3 -o "$work/t.tar.bz2" \
    "https://downloads.sourceforge.net/project/libtirpc/libtirpc/$ver/libtirpc-$ver.tar.bz2"
echo "$sum  $work/t.tar.bz2" | sha256sum -c -
tar -C "$work" -xjf "$work/t.tar.bz2"
cd "$work/libtirpc-$ver"
./configure -q --prefix="$prefix" --disable-gssapi --disable-shared >/dev/null
make -s -j"$(nproc)" >/dev/null
make -s install >/dev/null
rm -rf "$work"
