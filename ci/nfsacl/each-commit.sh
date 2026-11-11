#!/bin/sh
# Build the kernel and the modules at every commit of this series, oldest
# first, on top of the objdir of ci/nfsv4/build.sh.  each-commit.sh WORK
set -eu
W=$1; T=$W/tools; O=$W/obj; J=$(nproc)
B=$(cat ci/nfsacl/base)
tip=$(git rev-parse HEAD)
log() { "$@" >"$W/c.log" 2>&1 || { tail -40 "$W/c.log"; exit 1; }; }
# A base not in the clone, or nothing after it, would build nothing and
# pass; that is a failure of the measurement, not a success.
git cat-file -e "$B^{commit}" || { echo "base $B is not in the clone"; exit 1; }
n=$(git rev-list --count "$B..$tip")
echo "building $n commits from $B"
[ "$n" -gt 0 ] || { echo 'no commits to build'; exit 1; }
for c in $(git rev-list --reverse "$B..$tip"); do
	git checkout -q "$c"
	git log -1 --format='=== %h %s'
	log ./build.sh -U -m amd64 -j "$J" -O "$O" -T "$T" -u kernel=NFSV4T
	for d in sys/modules/oncrpc sys/modules/nfsxattr sys/modules/nfsv4; do
		# nfsxattr is not there before the commit that adds it.
		[ -d "$d" ] || continue
		(cd "$d" && log "$T/bin/nbmake-amd64" MKDEBUG=no obj &&
		    log "$T/bin/nbmake-amd64" -j "$J" MKDEBUG=no dependall)
	done
	(cd sys/modules/nfsserver && log "$T/bin/nbmake-amd64" MKDEBUG=no obj &&
	    log "$T/bin/nbmake-amd64" -j "$J" MKDEBUG=no NFSSERVER_ONCRPC=yes \
	    dependall)
	echo "ok $c"
done
git checkout -q "$tip"
echo "built $n commits"
