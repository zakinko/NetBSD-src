#!/bin/sh
# Build every commit after the one adding this CI, oldest first, so that
# no step of the series depends on a later one.  Incremental, on top of
# the tree build.sh left.  each-commit.sh WORK
set -eu
W=$1
T=$W/tools; O=$W/obj; J=$(nproc)
tip=$(git rev-parse HEAD)
base=$(git log --format=%H --grep='^Build and test sys/oncrpc in CI' -1 "$tip")
for c in $(git rev-list --reverse "$base..$tip"); do
	git checkout -q "$c"
	git log -1 --format='=== %h %s'
	./build.sh -U -m amd64 -j "$J" -O "$O" -T "$T" -u \
	    kernel=ONCRPCT kernel=ONCRPCS >"$W/c.log" 2>&1 ||
	    { tail -40 "$W/c.log"; exit 1; }
	for d in sys/modules/xdr sys/modules/oncrpc sys/modules/solaris \
	    tests/modules/k_oncrpc; do
		[ -d "$d" ] || continue
		(cd "$d" && "$T/bin/nbmake-amd64" -j "$J" MKDEBUG=no \
		    obj dependall) >"$W/c.log" 2>&1 ||
		    { tail -40 "$W/c.log"; exit 1; }
	done
	echo "ok $c"
done
git checkout -q "$tip"
