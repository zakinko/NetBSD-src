#!/bin/sh
# Build every commit of the series on its own, oldest first, on top of
# the objdir of build.sh.  each-commit.sh BASE WORK
set -eu
B=$1; W=$2
T=$W/tools; O=$W/obj; J=$(nproc)
tip=$(git rev-parse HEAD)
k() { ./build.sh -U -m amd64 -j "$J" -O "$O" -T "$T" -u "kernel=$1" >"$W/c.log" 2>&1 || { tail -40 "$W/c.log"; exit 1; }; }
for c in $(git rev-list --reverse "$B..$tip"); do
	git checkout -q "$c"
	git log -1 --format='=== %h %s'
	k NFSBROFF
	if grep -q NFSSERVER_ONCRPC sys/nfs/files.nfs; then k NFSBRON; fi
	for d in sys/modules/oncrpc sys/modules/nfsv4; do
		(cd "$d" && "$T/bin/nbmake-amd64" -j "$J" MKDEBUG=no dependall) \
		    >"$W/c.log" 2>&1 || { tail -40 "$W/c.log"; exit 1; }
	done
	echo "ok $c"
done
git checkout -q "$tip"
