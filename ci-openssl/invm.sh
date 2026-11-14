#!/bin/sh
# Inside a test VM: unpack the trees, build libcrypto from each, run the
# comparison.
#   invm.sh build            builds the trees named in $BUILDS (base new)
#   invm.sh test [args...]   nbtest.sh $BASELIB obj-new args...
# BASELIB defaults to the base build; /usr/lib compares with the release.
w=/root/nb
op=$1; shift
case $op in
build)
	for t in ${BUILDS:-base new}; do
		mkdir -p $w/$t && (cd $w/$t && tar xzf $w/nbsrc-$t.tgz) || exit 1
		sh $w/nbbuild.sh $w/$t/src $w/obj-$t $w/build-$t.log
		echo "$t rc $?"; tail -1 $w/build-$t.log
	done
	;;
test)
	cd $w && sh nbtest.sh ${BASELIB:-$w/obj-base} $w/obj-new "$@"
	;;
esac
