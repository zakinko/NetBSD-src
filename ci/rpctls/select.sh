#!/bin/sh
# Which tests a push needs, from the files it changed, as lines for
# $GITHUB_OUTPUT.  The build and the unit tests always run.
#   vm     the NetBSD VM with the probes of RFC 9289 (kernel, daemon, probes)
#   gss    the KDC and cbprobe too (RPCSEC_GSS, channel bindings)
#   nfsv4  the module built at every commit (sys/fs/nfsv4)
# select.sh BEFORE
before=$1
if [ -z "$before" ] || [ "$before" = 0000000000000000000000000000000000000000 ] ||
    ! git cat-file -e "$before^{commit}" 2>/dev/null; then
	before=HEAD~1
fi
vm=false gss=false nfsv4=false
for f in $(git diff --name-only "$before" HEAD); do
	case $f in
	sys/oncrpc/oncrpc_gss*|sys/oncrpc/gss_*|usr.sbin/gssd/*|ci/rpctls/cbprobe.py|\
	ci/rpctls/cb-client.sh|ci/nfsgss/vm-kdc.sh|.github/workflows/rpctls.yml)
		vm=true gss=true ;;
	sys/oncrpc/tls13_crypto.*|tests/oncrpc/*)
		;;	# the unit tests, in the build job
	sys/oncrpc/*|sys/nfs/*|sys/modules/oncrpc/*|usr.sbin/rpc.tlsservd/*|\
	ci/rpctls/probe*|ci/rpctls/tlsstub.c|ci/rpctls/mkcerts.sh|ci/nfsv4/build.sh|\
	ci/nfsv4/in-vm.sh|ci/oncrpc/swap.sh)
		vm=true ;;
	sys/fs/nfsv4/*|sys/modules/nfsv4/*)
		vm=true nfsv4=true ;;
	esac
done
echo "vm=$vm"
echo "gss=$gss"
echo "nfsv4=$nfsv4"
echo "changed since $before: vm=$vm gss=$gss nfsv4=$nfsv4" >&2
