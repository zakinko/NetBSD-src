#!/bin/sh
# Build the module at every commit of the series, oldest first, so that
# no step depends on a later one.  each-commit.sh WORK
set -eu
T=$1/tools; J=$(nproc)
tip=$(git rev-parse HEAD)
base=$(git log --format=%H --grep='^Add the protocol constants' -1 "$tip")
for c in $(git rev-list --reverse "$base..$tip"); do
	git checkout -q "$c"
	git log -1 --format='=== %h %s'
	[ -d sys/modules/nfsv4 ] || continue
	(cd sys/modules/nfsv4 && "$T/bin/nbmake-amd64" -j "$J" MKDEBUG=no \
	    obj dependall) >"$1/c.log" 2>&1 || { tail -40 "$1/c.log"; exit 1; }
	echo "ok $c"
done
git checkout -q "$tip"
