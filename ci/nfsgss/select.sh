#!/bin/sh
# Which of the push-time tests the change touches.  The files changed are
# those from BEFORE, the tip before the push, to HEAD; when BEFORE cannot
# be had (a new branch, or a force push whose old tip is gone) every test
# is selected.  Prints name=true|false lines for $GITHUB_OUTPUT.
# select.sh BEFORE
set -u
B=${1:-}
all=false
case $B in ''|0000000000000000000000000000000000000000) all=true ;; esac
if [ $all = false ] && ! git cat-file -e "$B^{commit}" 2>/dev/null; then
	git fetch -q --depth=50 origin "$B" 2>/dev/null || all=true
fi
if [ $all = false ]; then
	files=$(git diff --name-only "$B" HEAD) || all=true
fi
[ $all = true ] && files=
# The commits each-commit.sh builds: those the push brought, from where
# the old tip and the new part; all of the series when that is unknown.
if [ $all = false ] && mb=$(git merge-base "$B" HEAD 2>/dev/null); then
	echo "base=$mb"
else
	echo "base="
fi
echo "$files" | sed 's/^/changed: /' >&2

# hit PATTERN...: some changed file matches one of the egrep patterns
hit() {
	[ $all = true ] && { echo true; return; }
	for p; do
		echo "$files" | grep -qE "$p" && { echo true; return; }
	done
	echo false
}
W='^\.github/workflows/nfsgss\.yml$|^ci/nfsgss/select\.sh$'
echo "xdr=$(hit "$W" '^sys/fs/nfsv4/nfsv4_(xdr|proto)' '^tests/fs/nfsv4/t_nfsv4_xdr')"
echo "gssseq=$(hit "$W" '^sys/oncrpc/oncrpc_gss' '^tests/oncrpc/t_gss_seq')"
echo "krb5=$(hit "$W" '^sys/oncrpc/gss_(krb5|mech)' '^tests/oncrpc/(t_gss_krb5|gss-shim)')"
echo "ssv=$(hit "$W" '^sys/oncrpc/gss_(ssv|mech)' '^tests/oncrpc/(t_gss_ssv|gss-shim)')"
# A real Linux client under krb5, krb5i and krb5p, v3 to 4.1, with the
# probes of refusal, expiry, SP4_MACH_CRED and the backchannel: for what
# the RPCSEC_GSS path, gssd, mountd and the 4.1 session code do.
echo "gss=$(hit "$W" '^sys/oncrpc/' '^sys/nfs/' \
    '^sys/fs/nfsv4/nfsv4_(session|cb|xdr|state)' \
    '^usr\.sbin/(gssd|mountd)/' \
    '^ci/nfsgss/(client\.sh|probe\.py|vm-kdc\.sh|noenctypes\.c)$')"
