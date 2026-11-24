#!/bin/sh
# NetBSD/macppc 9.4 from zakinko/netbsd-ci-images, started with its runvm.sh.
# The image has an rtl8139 NIC (qemu's default sungem does not come up
# under NetBSD: "gem0: cannot reset receiver").
#
#   macppc.sh fetch
#   macppc.sh build <base|new|old>   build that tree's libcrypto, copy it out
#   macppc.sh test               compare base and new, try old
set -u
op=$1; shift
ci=$(cd "$(dirname "$0")" && pwd)
NAME=macppc-9.4
VMDIR=${VMDIR:-$PWD/vm}
NCI=$PWD/netbsd-ci-images
O=/root/nb/new/src/crypto/external/apache2/openssl

# read from stdin only where asked to
ssh_() { $(cat "$VMDIR/$NAME.ssh") "$@"; }
put() { for f; do ssh_ "cat > /root/nb/$(basename "$f")" < "$f" || exit 1; done; }
start() {
	(cd "$VMDIR" && DIR=$VMDIR MEM=1536 sh "$NCI/runvm.sh" $NAME 2222) || {
		tail -60 "$VMDIR/$NAME.console.log"; exit 1; }
	ssh_ "uname -a; cc --version | head -1; mkdir -p /root/nb" < /dev/null
	put "$ci/nbbuild.sh" "$ci/nbtest.sh" "$ci/evpcheck.c" "$ci/invm.sh"
}
stop() { (cd "$VMDIR" && DIR=$VMDIR sh "$NCI/stopvm.sh" $NAME) || true; }

case $op in
fetch)
	git clone -q --depth 1 https://github.com/zakinko/netbsd-ci-images.git "$NCI"
	mkdir -p "$VMDIR"
	gh release download images -R zakinko/netbsd-ci-images \
	    -p "$NAME.*" -D "$VMDIR" --clobber || exit 1
	cat "$VMDIR/$NAME.qemu"
	;;
build)
	t=$1
	start
	put nbsrc-$t.tgz
	printf 'BUILDS=%s sh /root/nb/invm.sh build\n' "$t" > cmd-build.sh
	put cmd-build.sh
	s=$(date +%s)
	ssh_ sh /root/nb/cmd-build.sh < /dev/null 2>&1 | tee build-macppc-$t.log
	echo "build took $(( $(date +%s) - s )) s"
	if grep -q "^$t rc 0" build-macppc-$t.log; then
		ssh_ "cd /root/nb/obj-$t && tar cf - libcrypto.so*" < /dev/null > lib-$t.tar
		ls -l lib-$t.tar
		stop
	else
		ssh_ "grep -m5 -B5 -E 'error:|Error code' /root/nb/build-$t.log; tail -30 /root/nb/build-$t.log" < /dev/null
		stop; exit 1
	fi
	;;
test)
	start
	# the system's headers are 1.1.1; compile against the tree's
	put nbsrc-new.tgz
	ssh_ "mkdir -p /root/nb/new && cd /root/nb/new && tar xzf /root/nb/nbsrc-new.tgz" < /dev/null
	for t in base new old; do
		[ -s lib-$t.tar ] || { echo "no lib-$t.tar"; continue; }
		put lib-$t.tar
		ssh_ "mkdir -p /root/nb/obj-$t && cd /root/nb/obj-$t && tar xf /root/nb/lib-$t.tar && ls -l" < /dev/null
	done
	put "$ci/macppc-test.sh"
	ssh_ sh /root/nb/macppc-test.sh < /dev/null 2>&1 | tee test-macppc.log
	stop
	tail -1 test-macppc.log | grep -qx PASS
	;;
esac
