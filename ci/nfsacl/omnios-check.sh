#!/bin/sh
# On the runner: run omnios.sh in the OmniOS VM, and compare each ACL it
# printed with the server's own.  omnios-check.sh OUT
OUT=$1
H=$(cd "$(dirname "$0")" && pwd)
L=$OUT/nfsacl-omnios.txt
scp "$H/omnios.sh" omnios:/var/tmp/omnios.sh
ssh omnios 'sh /var/tmp/omnios.sh' >"$L" 2>&1
awk '/^=== /{f=sprintf("%s/acl.%s", T, $2); print $3 " " $4 > (f ".where"); next}
    f != "" && /^[a-z]+:/{print > f}
    /^\$ |^ok|^FAILED|^failures/{f=""}' T="$OUT" "$L"
for w in "$OUT"/acl.*.where; do
	[ -e "$w" ] || continue
	c=${w%.where}
	read sp d <"$w"
	ssh -o LogLevel=ERROR netbsd "sh /var/tmp/nfsv4/sacl.sh $d '$sp'" >"$c.server"
	if cmp -s "$c" "$c.server"; then echo "same: ${c##*/acl.}"; else
		echo "DIFFERENT: ${c##*/acl.}"; diff "$c" "$c.server"; fi
done | tee -a "$L"
cat "$L"
grep -q '^failures: 0$' "$L" && ! grep -q '^DIFFERENT' "$L"
