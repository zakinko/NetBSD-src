#!/bin/sh
# On the runner: run omnios.sh in the OmniOS VM, and compare each ACL it
# printed with the server's own.  omnios-check.sh OUT
OUT=$1
H=$(cd "$(dirname "$0")" && pwd)
L=$OUT/nfsacl-omnios.txt
scp "$H/omnios.sh" omnios:/var/tmp/omnios.sh
# The calls of the illumos client, to see what runat and ls -l ask.
sudo tcpdump -i any -s 0 -w "$OUT/nfsacl-omnios.pcap" 'tcp port 2049' >/dev/null 2>&1 &
sleep 2
ssh omnios 'sh /var/tmp/omnios.sh' >"$L" 2>&1
sudo pkill -x tcpdump
sleep 1
sudo chmod 644 "$OUT/nfsacl-omnios.pcap" 2>/dev/null
if command -v tshark >/dev/null; then
	tshark -r "$OUT/nfsacl-omnios.pcap" -Y 'nfsacl || nfs' -T fields \
	    -e frame.time_relative -e rpc.program -e rpc.programversion \
	    -e rpc.procedure -e rpc.msgtyp -e nfs.status3 \
	    >"$OUT/nfsacl-omnios-calls.txt" 2>&1 || :
	echo "calls captured: $(wc -l <"$OUT/nfsacl-omnios-calls.txt")"
fi
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
# Named attributes: the list runat gives against the server's, and the
# bytes of a: as the client wrote them, and as the server keeps them
# (getextattr ends its print with a newline).
for v in 3 2; do
	c=$(sed -n "s/^xattr-ls v$v //p" "$L")
	s=$(ssh -o LogLevel=ERROR netbsd "lsextattr -q user /export/pacl/x$v" |
	    tr ' \t' '\n\n' | grep -v '^$' | sort | tr '\n' ' ')
	if [ -n "$c" ] && [ "$c" = "$s" ]; then echo "same: xattr-ls v$v: $c"; else
		echo "DIFFERENT: xattr-ls v$v: client '$c' server '$s'"; fi
	c=$(sed -n "s/^xattr-cat v$v //p" "$L")
	w=$(sed -n "s/^xattr-want v$v //p" "$L")
	if [ -n "$c" ] && [ "$c" = "$w" ]; then echo "same: xattr-cat v$v"; else
		echo "DIFFERENT: xattr-cat v$v: '$c' want '$w'"; fi
	s=$(ssh -o LogLevel=ERROR netbsd "getextattr -q user a /export/pacl/x$v | cksum")
	w=$(sed -n "s/^xattr-wantnl v$v //p" "$L")
	if [ -n "$s" ] && [ "$s" = "$w" ]; then echo "same: xattr-server v$v"; else
		echo "DIFFERENT: xattr-server v$v: '$s' want '$w'"; fi
done | tee -a "$L"
cat "$L"
grep -q '^failures: 0$' "$L" && ! grep -q '^DIFFERENT' "$L"
