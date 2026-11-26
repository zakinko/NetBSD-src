#!/bin/sh
# The connection IDs on the wire, RFC 9147 s4, against what dtlsclient
# says it agreed: its output in $1, cidpcap's lines in $2.  Prints "ok"
# or "FAIL" per check and "probe-dtls-pcap failures N".
#   cidcheck.sh CLIENTOUT CIDPCAPOUT
set -u
out=$1 lines=$2
own=$(awk '$1 == "cid" && $2 == "own" { print $3; exit }' "$out")
peer=$(awk '$1 == "cid" && $2 == "peer" { print $3; exit }' "$out")
new=$(awk '$1 == "cid" && $2 == "new" { print $3; exit }' "$out")
p1=$(awk '$1 == "cid" && $2 == "ports" { print $3; exit }' "$out")
p2=$(awk '$1 == "cid" && $2 == "ports" { print $4; exit }' "$out")
f=0
n() { awk -v d="$1" -v p="$2" -v c="$3" \
    '$1 == d && $2 == p && $4 == c { k++ } END { print k + 0 }' "$lines"; }
t() {	# t COUNT NAME: ok when COUNT > 0
	if [ "$1" -gt 0 ]; then echo "ok $2 ($1)"; else echo "FAIL $2"; f=$((f + 1)); fi
}
# hexline() prints "-" for an empty ID.
if [ -z "$own" ] || [ -z "$peer" ] || [ "$own" = - ] || [ "$peer" = - ] ||
    [ -z "$new" ] || [ "$new" = - ] || [ -z "$p2" ]; then
	echo "FAIL the client did not report its connection IDs and ports"
	echo "probe-dtls-pcap failures 1"
	exit 1
fi
t "$(n to "$p1" "$peer")" "pcap: records to the server carry its ID"
t "$(n from "$p1" "$own")" "pcap: records from the server carry the client's ID"
t "$(n to "$p2" "$peer")" "pcap: from the new port, with the server's ID"
t "$(n from "$p2" "$own")" "pcap: the server's records reach the new port"
t "$(n from "$p2" "$new")" "pcap: after NewConnectionId, the server sends with the new ID"
# From the server only: dtlsclient sends one record without an ID on
# purpose, the garbage of s4.5.2.
none=$(( $(n from "$p1" -) + $(n from "$p2" -) ))
if [ "$none" -eq 0 ]; then
	echo "ok pcap: no record from the server without an ID"
else
	echo "FAIL pcap: $none records from the server without an ID"
	f=$((f + 1))
fi
echo "probe-dtls-pcap failures $f"
[ "$f" -eq 0 ]
