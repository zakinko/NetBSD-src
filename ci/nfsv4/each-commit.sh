#!/bin/sh
# Build the modules at every commit of the series, oldest first, so that
# no step depends on a later one.  each-commit.sh WORK
#
# Each of xdr, oncrpc and nfsv4 that the commit has is built from an
# empty object directory.  Before 2026-11-12 only sys/modules/nfsv4 was
# built, so a commit that changed only sys/oncrpc was never compiled,
# and the one object directory was kept from commit to commit, so make
# compared the mtime of a source just checked out with that of an object
# built in the same second and could skip it: 322acccdd92 changed
# nfsv4_fh.c and the log showed nothing compiled.  An empty directory
# leaves make nothing to compare, and the count below must then be more
# than zero for every module built.
set -eu
T=$1/tools; O=$1/obj; J=$(nproc)
tip=$(git rev-parse HEAD)
base=$(git log --format=%H --grep='^Add the protocol constants' -1 "$tip")
# No base, as in a clone too shallow to reach it, would build nothing and
# pass; say so and fail instead.
if [ -z "$base" ]; then
	echo "each-commit: no commit 'Add the protocol constants' in reach" >&2
	exit 1
fi
n=$(git rev-list --count "$base..$tip")
echo "each-commit: $n commits from $base"
[ "$n" -gt 0 ] || { echo "each-commit: nothing to build" >&2; exit 1; }
built=0 none=0
for c in $(git rev-list --reverse "$base..$tip"); do
	git checkout -q "$c"
	line="$(git log -1 --format=%h "$c")"
	for m in xdr oncrpc nfsv4; do
		d=sys/modules/$m
		[ -d "$d" ] || continue
		# nbmake-amd64 puts the objects of $d in $O/$d (build.sh -O).
		rm -rf "${O:?}/$d"
		(cd "$d" && "$T/bin/nbmake-amd64" MKDEBUG=no obj &&
		    "$T/bin/nbmake-amd64" -j "$J" MKDEBUG=no dependall) \
		    >"$1/c.log" 2>&1 ||
		    { git log -1 --format='=== %h %s' "$c"
		      tail -40 "$1/c.log"; exit 1; }
		k=$(grep -c '^#  *compile' "$1/c.log" || :)
		[ -f "$O/$d/$m.kmod" ] && [ "$k" -gt 0 ] ||
		    { echo "each-commit: $line $m: $k compiled, no $m.kmod" >&2
		      exit 1; }
		line="$line $m=$k"
	done
	case $line in
	*=*)	echo "ok $line"; built=$((built + 1));;
	*)	echo "-- $line has no module yet"; none=$((none + 1));;
	esac
done
git checkout -q "$tip"
echo "each-commit: $built of $n commits built, $none with no module"
[ "$built" -gt 0 ] || { echo "each-commit: nothing was built" >&2; exit 1; }
