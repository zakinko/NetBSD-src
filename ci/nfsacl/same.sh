#!/bin/sh
# The client's view of an ACL and the server's are the same.  The client
# reads as $AS, which may be "sudo -u alice" for a Kerberos mount.
# same.sh [-d] CLIENT-PATH SERVER-PATH
H=$(cd "$(dirname "$0")" && pwd)
d=
[ "$1" = -d ] && { d=-d; shift; }
c=$(mktemp); s=$(mktemp)
${AS:-} sh "$H/cacl.sh" $d "$1" >"$c"
ssh -o LogLevel=ERROR netbsd "sh /var/tmp/nfsv4/sacl.sh $d '$2'" >"$s"
echo "--- client $d $1"; cat "$c"
echo "--- server $d $2"; cat "$s"
cmp -s "$c" "$s"; r=$?
rm -f "$c" "$s"
exit $r
