#!/bin/sh
# Inside a test VM: unpack both trees, build libcrypto from each, run the
# comparison.  Arguments go to nbtest.sh after the two library paths.
#   invm.sh <build|test> [nbtest args...]
w=/root/nb
op=$1; shift
case $op in
build)
	for t in base new; do
		mkdir -p $w/$t && (cd $w/$t && tar xzf $w/nbsrc-$t.tgz) || exit 1
		sh $w/nbbuild.sh $w/$t/src $w/obj-$t $w/build-$t.log
		echo "$t rc $?"; tail -1 $w/build-$t.log
	done
	;;
test)
	cd $w && sh nbtest.sh $w/obj-base $w/obj-new "$@"
	;;
esac
